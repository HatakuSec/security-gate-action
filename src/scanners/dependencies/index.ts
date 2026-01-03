/**
 * Dependency Scanner
 *
 * Scans lockfiles for dependencies and checks for known vulnerabilities
 * using the OSV (Open Source Vulnerabilities) database.
 *
 * Supported lockfiles:
 * - package-lock.json (npm, v2/v3)
 * - yarn.lock (v1)
 * - requirements.txt (pip)
 * - Pipfile.lock (pip)
 *
 * @module scanners/dependencies
 */

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';

import type { Scanner, ScannerContext, ScannerResult, Finding } from '../types';
import { createFindingId } from '../types';
import {
  getSupportedLockfiles,
  parseLockfile,
  type Dependency,
  type LockfileParseResult,
} from './lockfile-parsers';
import { queryOsv, type VulnerabilityFinding } from './osv-api';

/**
 * Lockfile patterns to search for.
 */
const LOCKFILE_PATTERNS = [
  '**/package-lock.json',
  '**/yarn.lock',
  '**/requirements.txt',
  '**/Pipfile.lock',
];

/**
 * Directories to exclude from scanning.
 */
const EXCLUDE_DIRS = ['node_modules', '.git', 'vendor', 'dist', 'build', '__pycache__'];

/**
 * Find all lockfiles in the scan path.
 *
 * @param scanPath - Root path to scan
 * @param verbose - Enable verbose logging
 * @param globalIgnorePaths - Additional ignore patterns from global config
 * @returns Array of lockfile paths
 */
async function findLockfiles(
  scanPath: string,
  verbose: boolean,
  globalIgnorePaths: string[] = []
): Promise<string[]> {
  const allFiles: string[] = [];

  // Combine default excludes with global ignore paths
  const ignorePatterns = [...EXCLUDE_DIRS.map((d) => `**/${d}/**`), ...globalIgnorePaths];

  for (const pattern of LOCKFILE_PATTERNS) {
    const matches = await glob(pattern, {
      cwd: scanPath,
      absolute: true,
      ignore: ignorePatterns,
      nodir: true,
    });
    allFiles.push(...matches);
  }

  // Remove duplicates
  const uniqueFiles = [...new Set(allFiles)];

  if (verbose) {
    console.log(`Found ${uniqueFiles.length} lockfile(s)`);
    for (const file of uniqueFiles) {
      console.log(`  - ${file}`);
    }
  }

  return uniqueFiles;
}

/**
 * Parse all lockfiles and collect dependencies.
 *
 * @param lockfiles - Array of lockfile paths
 * @param verbose - Enable verbose logging
 * @returns Object with dependencies and parse errors
 */
async function parseAllLockfiles(
  lockfiles: string[],
  verbose: boolean
): Promise<{
  dependencies: Dependency[];
  parseResults: Map<string, LockfileParseResult>;
  errors: string[];
}> {
  const allDependencies: Dependency[] = [];
  const parseResults = new Map<string, LockfileParseResult>();
  const errors: string[] = [];

  for (const lockfilePath of lockfiles) {
    const filename = path.basename(lockfilePath);

    try {
      const content = await fs.promises.readFile(lockfilePath, 'utf-8');
      const result = parseLockfile(filename, content, lockfilePath);

      if (!result) {
        errors.push(`No parser found for ${filename}`);
        continue;
      }

      parseResults.set(lockfilePath, result);

      if (result.warnings && result.warnings.length > 0) {
        errors.push(...result.warnings.map((e) => `${lockfilePath}: ${e}`));
      }

      allDependencies.push(...result.dependencies);

      if (verbose) {
        console.log(`Parsed ${lockfilePath}: ${result.dependencies.length} dependencies`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(`Failed to read ${lockfilePath}: ${message}`);
    }
  }

  return { dependencies: allDependencies, parseResults, errors };
}

/**
 * Deduplicate dependencies by name+version+ecosystem.
 *
 * @param dependencies - Array of dependencies (may have duplicates)
 * @returns Deduplicated array
 */
function deduplicateDependencies(dependencies: Dependency[]): Dependency[] {
  const seen = new Set<string>();
  const result: Dependency[] = [];

  for (const dep of dependencies) {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push(dep);
    }
  }

  return result;
}

/**
 * Convert vulnerability finding to scanner finding.
 *
 * @param vuln - Vulnerability finding from OSV
 * @param lockfilePath - Path to the lockfile containing this dependency
 * @returns Scanner finding
 */
function toScannerFinding(vuln: VulnerabilityFinding, lockfilePath: string): Finding {
  const fixInfo = vuln.fixedVersion ? ` (fix: upgrade to ${vuln.fixedVersion})` : '';
  const ruleId = `DEP-${vuln.id}`;

  return {
    id: createFindingId('dependencies', ruleId, lockfilePath, 1),
    ruleId,
    severity: vuln.severity,
    title: `Vulnerable dependency: ${vuln.dependency.name}@${vuln.dependency.version}`,
    message:
      `${vuln.dependency.name}@${vuln.dependency.version} has vulnerability ${vuln.id}: ` +
      `${vuln.summary}${fixInfo}`,
    file: lockfilePath,
    startLine: 1, // Lockfiles don't have meaningful line numbers for deps
    endLine: 1,
    scanner: 'dependencies',
    snippet: `${vuln.dependency.name}@${vuln.dependency.version}`,
    metadata: {
      vulnerabilityId: vuln.id,
      packageName: vuln.dependency.name,
      packageVersion: vuln.dependency.version,
      ecosystem: vuln.dependency.ecosystem,
      cvssScore: vuln.cvssScore,
      fixedVersion: vuln.fixedVersion,
      referenceUrl: vuln.referenceUrl,
    },
  };
}

/**
 * Dependency scanner that identifies vulnerable packages.
 */
export const dependenciesScanner: Scanner = {
  name: 'dependencies',

  async run(context: ScannerContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    const errors: string[] = [];

    if (context.verbose) {
      console.log('Starting dependency scan...');
      console.log(`Scan path: ${context.workingDirectory}`);
      console.log(`Supported lockfiles: ${getSupportedLockfiles().join(', ')}`);
    }

    // Step 1: Find all lockfiles
    const lockfiles = await findLockfiles(
      context.workingDirectory,
      context.verbose,
      context.ignorePaths
    );

    if (lockfiles.length === 0) {
      if (context.verbose) {
        console.log('No lockfiles found, skipping dependency scan');
      }
      return {
        name: 'dependencies',
        findings: [],
        durationMs: Date.now() - startTime,
        filesScanned: 0,
      };
    }

    // Step 2: Parse all lockfiles
    const {
      dependencies,
      parseResults,
      errors: parseErrors,
    } = await parseAllLockfiles(lockfiles, context.verbose);
    errors.push(...parseErrors);

    if (dependencies.length === 0) {
      if (context.verbose) {
        console.log('No dependencies found in lockfiles');
      }
      return {
        name: 'dependencies',
        findings: [],
        durationMs: Date.now() - startTime,
        filesScanned: lockfiles.length,
        metadata: { errors },
      };
    }

    // Step 3: Deduplicate dependencies
    const uniqueDeps = deduplicateDependencies(dependencies);

    if (context.verbose) {
      console.log(`Found ${dependencies.length} dependencies (${uniqueDeps.length} unique)`);
    }

    // Step 4: Query OSV for vulnerabilities
    const osvResult = await queryOsv(uniqueDeps, { verbose: context.verbose });
    errors.push(...osvResult.errors);

    if (context.verbose) {
      console.log(`OSV scan complete:`);
      console.log(`  - Packages scanned: ${osvResult.packagesScanned}`);
      console.log(`  - Packages vulnerable: ${osvResult.packagesVulnerable}`);
      console.log(`  - Vulnerabilities found: ${osvResult.findings.length}`);
    }

    // Step 5: Convert to scanner findings
    // We need to map findings back to their lockfiles
    const depToLockfile = new Map<string, string>();
    for (const [lockfilePath, result] of parseResults) {
      for (const dep of result.dependencies) {
        const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
        // Keep first occurrence (may appear in multiple lockfiles)
        if (!depToLockfile.has(key)) {
          depToLockfile.set(key, lockfilePath);
        }
      }
    }

    for (const vuln of osvResult.findings) {
      const key = `${vuln.dependency.ecosystem}:${vuln.dependency.name}@${vuln.dependency.version}`;
      const lockfilePath = depToLockfile.get(key) ?? 'unknown';
      findings.push(toScannerFinding(vuln, lockfilePath));
    }

    return {
      name: 'dependencies',
      findings,
      durationMs: Date.now() - startTime,
      filesScanned: lockfiles.length,
      metadata: {
        totalDependencies: dependencies.length,
        uniqueDependencies: uniqueDeps.length,
        packagesScanned: osvResult.packagesScanned,
        packagesVulnerable: osvResult.packagesVulnerable,
        errors: errors.length > 0 ? errors : undefined,
      },
    };
  },
};

// Re-export types and utilities for external use
export { cvssToSeverity } from './osv-api';
export type { VulnerabilityFinding, VulnerabilityScanResult } from './osv-api';
export * from './lockfile-parsers';
