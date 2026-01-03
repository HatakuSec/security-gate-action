/**
 * OSV (Open Source Vulnerabilities) API client
 *
 * Provides functions to query the OSV API for vulnerability data.
 * Uses the batch query endpoint for efficiency.
 *
 * @see https://osv.dev/docs/
 * @module scanners/dependencies/osv-api
 */

import type { Dependency, Ecosystem } from './lockfile-parsers';

/**
 * OSV API endpoint.
 */
const OSV_API_URL = 'https://api.osv.dev/v1';

/**
 * Maximum packages per batch query.
 * OSV API limit is 1000.
 */
const BATCH_SIZE = 1000;

/**
 * Severity level for findings.
 */
export type Severity = 'high' | 'medium' | 'low';

/**
 * Mapping from lockfile ecosystem to OSV ecosystem name.
 */
const ECOSYSTEM_MAP: Record<Ecosystem, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  go: 'Go',
  cargo: 'crates.io',
  rubygems: 'RubyGems',
};

/**
 * OSV query for a single package.
 */
interface OsvQuery {
  package: {
    name: string;
    ecosystem: string;
  };
  version: string;
}

/**
 * Batch query request body.
 */
interface BatchQueryRequest {
  queries: OsvQuery[];
}

/**
 * CVSS severity information.
 */
interface CvssSeverity {
  type: string;
  score: string;
}

/**
 * OSV vulnerability record.
 */
export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: CvssSeverity[];
  references?: Array<{ type: string; url: string }>;
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
    versions?: string[];
  }>;
}

/**
 * Result for a single package in batch query.
 */
interface BatchQueryResult {
  vulns?: OsvVulnerability[];
}

/**
 * Batch query response body.
 */
interface BatchQueryResponse {
  results: BatchQueryResult[];
}

/**
 * A vulnerability finding for a specific dependency.
 */
export interface VulnerabilityFinding {
  /** Vulnerability ID (e.g., GHSA-xxxx-xxxx-xxxx, CVE-2023-xxxx) */
  id: string;
  /** Brief summary of the vulnerability */
  summary: string;
  /** Severity level */
  severity: Severity;
  /** CVSS score if available */
  cvssScore?: number;
  /** Affected dependency */
  dependency: Dependency;
  /** Fixed version if known */
  fixedVersion?: string;
  /** Reference URL */
  referenceUrl?: string;
}

/**
 * Result of vulnerability scanning.
 */
export interface VulnerabilityScanResult {
  /** All vulnerability findings */
  findings: VulnerabilityFinding[];
  /** Total packages scanned */
  packagesScanned: number;
  /** Packages with vulnerabilities */
  packagesVulnerable: number;
  /** Any errors that occurred */
  errors: string[];
}

/**
 * Extract CVSS score from OSV severity data.
 *
 * @param severity - Array of severity entries
 * @returns CVSS score or undefined
 */
function extractCvssScore(severity: CvssSeverity[] | undefined): number | undefined {
  if (!severity || severity.length === 0) {
    return undefined;
  }

  // Look for CVSS_V3 first, then CVSS_V2
  for (const s of severity) {
    if (s.type === 'CVSS_V3' || s.type === 'CVSS_V2') {
      const score = parseFloat(s.score);
      if (!isNaN(score)) {
        return score;
      }
    }
  }

  return undefined;
}

/**
 * Map CVSS score to severity level.
 *
 * Uses CVSS v3 severity ratings:
 * - Critical (9.0-10.0) → high
 * - High (7.0-8.9) → high (we map to medium for 7.0-8.9)
 * - Medium (4.0-6.9) → medium
 * - Low (0.1-3.9) → low
 *
 * Per spec: ≥9.0 → high, 7.0-8.9 → medium, <7.0 → low
 *
 * @param score - CVSS score
 * @returns Severity level
 */
export function cvssToSeverity(score: number | undefined): Severity {
  if (score === undefined) {
    // Default to medium when unknown
    return 'medium';
  }

  if (score >= 9.0) {
    return 'high';
  }
  if (score >= 7.0) {
    return 'medium';
  }
  return 'low';
}

/**
 * Extract fixed version from OSV affected data.
 *
 * @param affected - Affected package data
 * @param packageName - Package name to match
 * @returns Fixed version or undefined
 */
function extractFixedVersion(
  affected: OsvVulnerability['affected'],
  packageName: string
): string | undefined {
  if (!affected) {
    return undefined;
  }

  for (const entry of affected) {
    if (entry.package?.name !== packageName) {
      continue;
    }

    if (entry.ranges) {
      for (const range of entry.ranges) {
        if (range.events) {
          for (const event of range.events) {
            if (event.fixed) {
              return event.fixed;
            }
          }
        }
      }
    }
  }

  return undefined;
}

/**
 * Extract reference URL from OSV references.
 *
 * @param references - Array of references
 * @returns Best reference URL or undefined
 */
function extractReferenceUrl(references: OsvVulnerability['references']): string | undefined {
  if (!references || references.length === 0) {
    return undefined;
  }

  // Priority: ADVISORY > WEB > PACKAGE > others
  const priority = ['ADVISORY', 'WEB', 'PACKAGE'];

  for (const type of priority) {
    const ref = references.find((r) => r.type === type);
    if (ref) {
      return ref.url;
    }
  }

  // Fall back to first reference
  const firstRef = references[0];
  return firstRef?.url;
}

/**
 * Convert OSV vulnerability to our finding format.
 *
 * @param vuln - OSV vulnerability
 * @param dep - Affected dependency
 * @returns Vulnerability finding
 */
function toFinding(vuln: OsvVulnerability, dep: Dependency): VulnerabilityFinding {
  const cvssScore = extractCvssScore(vuln.severity);

  return {
    id: vuln.id,
    summary: vuln.summary ?? vuln.details ?? 'No description available',
    severity: cvssToSeverity(cvssScore),
    cvssScore,
    dependency: dep,
    fixedVersion: extractFixedVersion(vuln.affected, dep.name),
    referenceUrl: extractReferenceUrl(vuln.references),
  };
}

/**
 * Query OSV API for vulnerabilities in a batch of packages.
 *
 * @param dependencies - Dependencies to check
 * @param options - Query options
 * @returns Scan result
 */
export async function queryOsv(
  dependencies: Dependency[],
  options: { verbose?: boolean } = {}
): Promise<VulnerabilityScanResult> {
  const { verbose = false } = options;
  const findings: VulnerabilityFinding[] = [];
  const errors: string[] = [];
  const vulnerablePackages = new Set<string>();

  if (dependencies.length === 0) {
    return {
      findings: [],
      packagesScanned: 0,
      packagesVulnerable: 0,
      errors: [],
    };
  }

  // Build queries for each dependency
  const queries: Array<{ query: OsvQuery; dep: Dependency }> = [];

  for (const dep of dependencies) {
    const osvEcosystem = ECOSYSTEM_MAP[dep.ecosystem];
    if (!osvEcosystem) {
      if (verbose) {
        console.warn(`Unknown ecosystem: ${dep.ecosystem}`);
      }
      continue;
    }

    // Skip dependencies without a version
    if (!dep.version) {
      continue;
    }

    queries.push({
      query: {
        package: {
          name: dep.name,
          ecosystem: osvEcosystem,
        },
        version: dep.version,
      },
      dep,
    });
  }

  // Process in batches
  for (let i = 0; i < queries.length; i += BATCH_SIZE) {
    const batch = queries.slice(i, i + BATCH_SIZE);
    const batchQueries = batch.map((q) => q.query);

    if (verbose) {
      console.log(
        `Querying OSV API: batch ${Math.floor(i / BATCH_SIZE) + 1} ` +
          `(${batchQueries.length} packages)`
      );
    }

    try {
      const response = await fetch(`${OSV_API_URL}/querybatch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ queries: batchQueries } as BatchQueryRequest),
      });

      if (!response.ok) {
        const errorText = await response.text();
        errors.push(`OSV API error (${response.status}): ${errorText}`);
        continue;
      }

      const data = (await response.json()) as BatchQueryResponse;

      // Process results
      for (let j = 0; j < data.results.length; j++) {
        const result = data.results[j];
        const batchItem = batch[j];
        if (!batchItem || !result) {
          continue;
        }
        const dep = batchItem.dep;

        if (result.vulns && result.vulns.length > 0) {
          vulnerablePackages.add(`${dep.ecosystem}:${dep.name}@${dep.version}`);

          for (const vuln of result.vulns) {
            findings.push(toFinding(vuln, dep));
          }
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(`OSV API request failed: ${message}`);
    }
  }

  return {
    findings,
    packagesScanned: queries.length,
    packagesVulnerable: vulnerablePackages.size,
    errors,
  };
}

/**
 * Query OSV for a single package (for testing/debugging).
 *
 * @param name - Package name
 * @param version - Package version
 * @param ecosystem - Package ecosystem
 * @returns Array of vulnerabilities
 */
export async function querySinglePackage(
  name: string,
  version: string,
  ecosystem: Ecosystem
): Promise<OsvVulnerability[]> {
  const osvEcosystem = ECOSYSTEM_MAP[ecosystem];
  if (!osvEcosystem) {
    throw new Error(`Unknown ecosystem: ${ecosystem}`);
  }

  const response = await fetch(`${OSV_API_URL}/query`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      package: { name, ecosystem: osvEcosystem },
      version,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OSV API error (${response.status}): ${errorText}`);
  }

  const data = (await response.json()) as { vulns?: OsvVulnerability[] };
  return data.vulns ?? [];
}
