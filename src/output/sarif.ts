/**
 * SARIF Output Generator
 *
 * Generates SARIF 2.1.0 (Static Analysis Results Interchange Format) output
 * for integration with GitHub Code Scanning and other SARIF consumers.
 *
 * Key safety features:
 * - Never includes raw secrets in output (uses masked snippets)
 * - Deterministic output (no timestamps or random values that would break caching)
 * - Validates output is valid JSON
 *
 * @module output/sarif
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';

import type { Finding, ScanResults, ScannerName } from '../scanners/types';

/** SARIF schema version */
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

/** SARIF version */
const SARIF_VERSION = '2.1.0';

/** Tool information */
const TOOL_NAME = 'security-gate';
const TOOL_SEMANTIC_VERSION = '0.2.0';
const TOOL_FULL_NAME = 'Security Gate Action';
const TOOL_INFO_URI = 'https://github.com/HatakuSec/security-gate-action';

/**
 * SARIF severity levels.
 */
type SarifLevel = 'error' | 'warning' | 'note' | 'none';

/**
 * SARIF Log structure (top-level).
 */
interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

/**
 * SARIF Run structure.
 */
interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  invocations?: SarifInvocation[];
}

/**
 * SARIF Tool structure.
 */
interface SarifTool {
  driver: SarifToolComponent;
}

/**
 * SARIF Tool Component structure.
 */
interface SarifToolComponent {
  name: string;
  semanticVersion: string;
  fullName?: string;
  informationUri?: string;
  rules?: SarifReportingDescriptor[];
}

/**
 * SARIF Reporting Descriptor (rule definition).
 */
interface SarifReportingDescriptor {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration?: {
    level?: SarifLevel;
  };
  helpUri?: string;
  properties?: Record<string, unknown>;
}

/**
 * SARIF Result structure.
 */
interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations?: SarifLocation[];
  fingerprints?: Record<string, string>;
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

/**
 * SARIF Location structure.
 */
interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
  message?: { text: string };
}

/**
 * SARIF Physical Location structure.
 */
interface SarifPhysicalLocation {
  artifactLocation?: SarifArtifactLocation;
  region?: SarifRegion;
}

/**
 * SARIF Artifact Location structure.
 */
interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

/**
 * SARIF Region structure.
 */
interface SarifRegion {
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  snippet?: { text: string };
}

/**
 * SARIF Invocation structure.
 */
interface SarifInvocation {
  executionSuccessful: boolean;
  exitCode?: number;
  toolExecutionNotifications?: SarifNotification[];
}

/**
 * SARIF Notification structure.
 */
interface SarifNotification {
  message: { text: string };
  level: SarifLevel;
}

/**
 * Map finding severity to SARIF level.
 *
 * @param severity - Finding severity
 * @returns SARIF level
 */
function mapSeverityToLevel(severity: string): SarifLevel {
  switch (severity) {
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    default:
      return 'note';
  }
}

/**
 * Get scanner display name for rules.
 *
 * @param scanner - Scanner name
 * @returns Human-readable scanner name
 */
function getScannerDisplayName(scanner: ScannerName): string {
  switch (scanner) {
    case 'secrets':
      return 'Secrets Scanner';
    case 'dependencies':
      return 'Dependency Scanner';
    case 'iac':
      return 'IaC Scanner';
    case 'container':
      return 'Container Scanner';
    default:
      return 'Security Scanner';
  }
}

/**
 * Build a unique rule ID from a finding.
 *
 * @param finding - The finding
 * @returns Rule ID string
 */
function buildRuleId(finding: Finding): string {
  // Use the rule ID if available, otherwise create one from scanner and title
  if (finding.ruleId) {
    return `${finding.scanner}/${finding.ruleId}`;
  }
  // Fallback: create deterministic ID from title
  const sanitisedTitle = finding.title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .substring(0, 50);
  return `${finding.scanner}/${sanitisedTitle}`;
}

/**
 * Collect unique rules from findings.
 *
 * @param findings - Array of findings
 * @returns Array of SARIF rule descriptors
 */
function collectRules(findings: Finding[]): SarifReportingDescriptor[] {
  const rulesMap = new Map<string, SarifReportingDescriptor>();

  for (const finding of findings) {
    const ruleId = buildRuleId(finding);

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.message },
        defaultConfiguration: {
          level: mapSeverityToLevel(finding.severity),
        },
        properties: {
          scanner: finding.scanner,
          scannerDisplayName: getScannerDisplayName(finding.scanner),
        },
      });
    }
  }

  // Sort rules by ID for deterministic output
  return Array.from(rulesMap.values()).sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * Convert a finding to a SARIF result.
 *
 * CRITICAL: Never include raw secret values. Use masked snippets.
 *
 * @param finding - The finding to convert
 * @returns SARIF result
 */
function findingToResult(finding: Finding): SarifResult {
  const ruleId = buildRuleId(finding);

  const result: SarifResult = {
    ruleId,
    level: mapSeverityToLevel(finding.severity),
    message: { text: finding.message },
    locations: [],
    // Note: We intentionally omit fingerprints here.
    // GitHub's upload-sarif action calculates its own content-based fingerprints
    // which are more reliable for tracking findings across runs.
    // Our finding ID is stored in properties for reference.
    properties: {
      scanner: finding.scanner,
      findingId: finding.id,
    },
  };

  // Add location if available
  const location: SarifLocation = {
    physicalLocation: {
      artifactLocation: {
        uri: finding.file,
        uriBaseId: '%SRCROOT%',
      },
    },
  };

  // Add region if line information is available
  if (finding.startLine) {
    const region: SarifRegion = {
      startLine: finding.startLine,
    };

    if (finding.endLine) {
      region.endLine = finding.endLine;
    }

    // Add masked snippet if available
    // CRITICAL: finding.snippet should already be masked by the scanner
    if (finding.snippet) {
      region.snippet = { text: finding.snippet };
    }

    location.physicalLocation!.region = region;
  }

  result.locations = [location];

  return result;
}

/**
 * Generate SARIF output from scan results.
 *
 * @param results - Scan results
 * @returns SARIF log object
 */
export function generateSarif(results: ScanResults): SarifLog {
  // Collect all findings from all scanners
  const allFindings: Finding[] = [];
  for (const scanner of results.scanners) {
    allFindings.push(...scanner.findings);
  }

  // Sort findings by file and line for deterministic output
  allFindings.sort((a, b) => {
    const fileCompare = a.file.localeCompare(b.file);
    if (fileCompare !== 0) {
      return fileCompare;
    }
    return (a.startLine ?? 0) - (b.startLine ?? 0);
  });

  // Collect unique rules
  const rules = collectRules(allFindings);

  // Convert findings to results
  const sarifResults = allFindings.map(findingToResult);

  // Build invocations with execution info
  const invocations: SarifInvocation[] = [
    {
      executionSuccessful: !results.hasErrors,
      toolExecutionNotifications: [],
    },
  ];

  // Add notifications for scanner errors
  for (const scanner of results.scanners) {
    if (scanner.error) {
      invocations[0]!.toolExecutionNotifications!.push({
        message: { text: `${scanner.name} scanner: ${scanner.error}` },
        level: 'warning',
      });
    }
  }

  // Add notifications for allowlist warnings
  if (results.allowlistWarnings && results.allowlistWarnings.length > 0) {
    for (const warning of results.allowlistWarnings) {
      invocations[0]!.toolExecutionNotifications!.push({
        message: { text: warning },
        level: 'warning',
      });
    }
  }

  // Build SARIF log
  const sarifLog: SarifLog = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            semanticVersion: TOOL_SEMANTIC_VERSION,
            fullName: TOOL_FULL_NAME,
            informationUri: TOOL_INFO_URI,
            rules,
          },
        },
        results: sarifResults,
        invocations,
      },
    ],
  };

  return sarifLog;
}

/**
 * Write SARIF output to a file.
 *
 * @param results - Scan results
 * @param outputPath - Path to write the SARIF file
 * @returns True if successful, false otherwise
 */
export function writeSarifToFile(results: ScanResults, outputPath: string): boolean {
  try {
    // Ensure parent directory exists
    const dir = path.dirname(outputPath);
    if (dir && dir !== '.' && !fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Generate SARIF
    const sarifLog = generateSarif(results);

    // Serialise to JSON with consistent formatting (2-space indent, sorted keys)
    const json = JSON.stringify(sarifLog, null, 2);

    // Validate JSON is well-formed (parse it back)
    JSON.parse(json);

    // Write to file
    fs.writeFileSync(outputPath, json, 'utf-8');

    core.info(`SARIF output written to: ${outputPath}`);
    core.info(`  Results: ${sarifLog.runs[0]?.results.length ?? 0} finding(s)`);
    core.info(`  Rules: ${sarifLog.runs[0]?.tool.driver.rules?.length ?? 0} rule(s)`);

    return true;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    core.error(`Failed to write SARIF output: ${message}`);
    return false;
  }
}

/**
 * Options for SARIF generation.
 */
export interface SarifOptions {
  /** Path to write the SARIF file */
  outputPath: string;
}

/**
 * Generate and write SARIF output if configured.
 *
 * @param results - Scan results
 * @param options - SARIF options (or undefined if disabled)
 * @returns Path to the SARIF file, or undefined if not written
 */
export function handleSarifOutput(
  results: ScanResults,
  options: SarifOptions | undefined
): string | undefined {
  if (!options?.outputPath) {
    return undefined;
  }

  const success = writeSarifToFile(results, options.outputPath);
  return success ? options.outputPath : undefined;
}

// Re-export types for testing
export type { SarifLog, SarifRun, SarifResult, SarifLocation };
