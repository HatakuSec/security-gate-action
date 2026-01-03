/**
 * Scanner Orchestrator
 *
 * Determines which scanners to run based on configuration and repository content,
 * executes them, and aggregates results.
 *
 * @module scanners/orchestrator
 */

import * as core from '@actions/core';
import { existsSync, readdirSync } from 'fs';
import { join } from 'path';

import type { Config } from '../config/schema';
import type {
  Scanner,
  ScannerContext,
  ScannerResult,
  ScanResults,
  ScannerName,
  Finding,
} from './types';
import { applyAllowlist, warnExpiredEntries } from '../policy/exclusions';

import { secretsScanner } from './secrets';
import { dependenciesScanner } from './dependencies';
import { iacScanner } from './iac';
import { containerScanner } from './container';

/** All available scanners */
const SCANNERS: Record<ScannerName, Scanner> = {
  secrets: secretsScanner,
  dependencies: dependenciesScanner,
  iac: iacScanner,
  container: containerScanner,
};

/** Lockfile patterns for dependency detection */
const DEPENDENCY_LOCKFILES = [
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'requirements.txt',
  'Pipfile.lock',
  'poetry.lock',
  'Gemfile.lock',
  'go.sum',
  'Cargo.lock',
];

/** Container file patterns */
const CONTAINER_INDICATORS = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'];

/**
 * Options for running the orchestrator.
 */
export interface OrchestratorOptions {
  /** Working directory to scan */
  workingDirectory: string;
  /** Whether verbose logging is enabled */
  verbose: boolean;
}

/**
 * Detect if the repository has any text files (for secrets scanning).
 * In practice, always returns true for auto mode since we want to scan.
 */
function hasTextFiles(_workingDirectory: string): boolean {
  // For now, assume there are always text files to scan
  // A more sophisticated check would glob for common source extensions
  return true;
}

/**
 * Detect if the repository has lockfiles for dependency scanning.
 */
function hasLockfiles(workingDirectory: string): boolean {
  for (const lockfile of DEPENDENCY_LOCKFILES) {
    const lockfilePath = join(workingDirectory, lockfile);
    if (existsSync(lockfilePath)) {
      core.debug(`Found lockfile: ${lockfile}`);
      return true;
    }
  }
  return false;
}

/**
 * Detect if the repository has IaC files.
 */
function hasIaCFiles(workingDirectory: string): boolean {
  // Check for specific files
  const specificFiles = ['main.tf', 'Chart.yaml', 'template.yaml', 'template.yml'];
  for (const file of specificFiles) {
    if (existsSync(join(workingDirectory, file))) {
      core.debug(`Found IaC file: ${file}`);
      return true;
    }
  }

  // Check for directories
  const directories = ['terraform', 'k8s', 'kubernetes', 'manifests', 'cloudformation'];
  for (const dir of directories) {
    if (existsSync(join(workingDirectory, dir))) {
      core.debug(`Found IaC directory: ${dir}`);
      return true;
    }
  }

  // Check for any .tf files in root
  try {
    const files = readdirSync(workingDirectory);
    for (const file of files) {
      if (file.endsWith('.tf')) {
        core.debug(`Found Terraform file: ${file}`);
        return true;
      }
    }
  } catch {
    // Ignore read errors
  }

  return false;
}

/**
 * Detect if the repository has container files.
 */
function hasContainerFiles(workingDirectory: string): boolean {
  for (const indicator of CONTAINER_INDICATORS) {
    const indicatorPath = join(workingDirectory, indicator);
    if (existsSync(indicatorPath)) {
      core.debug(`Found container file: ${indicator}`);
      return true;
    }
  }
  return false;
}

/**
 * Determine which scanners should run based on mode and content.
 *
 * @param config - Configuration object
 * @param workingDirectory - Directory to check
 * @returns Array of scanner names to run
 */
function determineScanners(config: Config, workingDirectory: string): ScannerName[] {
  const scannersToRun: ScannerName[] = [];
  const { mode, scanners } = config;

  // In explicit mode, only run enabled scanners (no detection gating)
  if (mode === 'explicit') {
    if (scanners.secrets.enabled) {
      scannersToRun.push('secrets');
    }
    if (scanners.dependencies.enabled) {
      scannersToRun.push('dependencies');
    }
    if (scanners.iac.enabled) {
      scannersToRun.push('iac');
    }
    if (scanners.container.enabled) {
      scannersToRun.push('container');
    }
    return scannersToRun;
  }

  // In auto mode, detect which scanners are relevant
  if (scanners.secrets.enabled && hasTextFiles(workingDirectory)) {
    scannersToRun.push('secrets');
  }

  if (scanners.dependencies.enabled && hasLockfiles(workingDirectory)) {
    scannersToRun.push('dependencies');
  }

  if (scanners.iac.enabled && hasIaCFiles(workingDirectory)) {
    scannersToRun.push('iac');
  }

  if (scanners.container.enabled && hasContainerFiles(workingDirectory)) {
    scannersToRun.push('container');
  }

  return scannersToRun;
}

/**
 * Get scanner-specific configuration.
 */
function getScannerConfig(config: Config, scannerName: ScannerName): Record<string, unknown> {
  return config.scanners[scannerName] as Record<string, unknown>;
}

/**
 * Run all applicable scanners and aggregate results.
 *
 * @param config - Security Gate configuration
 * @param options - Orchestrator options
 * @returns Aggregated scan results
 */
export async function runScanners(
  config: Config,
  options: OrchestratorOptions
): Promise<ScanResults> {
  const { workingDirectory, verbose } = options;
  const overallStartTime = Date.now();

  // Determine which scanners to run
  const scannersToRun = determineScanners(config, workingDirectory);

  if (scannersToRun.length === 0) {
    core.info('No scanners to run based on configuration and repository content');
    return {
      scanners: [],
      totalFindings: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      totalDurationMs: Date.now() - overallStartTime,
      totalFilesScanned: 0,
      hasErrors: false,
    };
  }

  core.info(`Running ${scannersToRun.length} scanner(s): ${scannersToRun.join(', ')}`);

  const results: ScannerResult[] = [];
  let hasErrors = false;

  // Run scanners sequentially
  for (const scannerName of scannersToRun) {
    const scanner = SCANNERS[scannerName];
    const scannerConfig = getScannerConfig(config, scannerName);

    const context: ScannerContext = {
      workingDirectory,
      verbose,
      config: scannerConfig,
      ignorePaths: config.ignore?.paths,
    };

    core.info(`🔍 Running ${scannerName} scanner...`);

    try {
      const result = await scanner.run(context);
      results.push(result);

      if (result.error) {
        hasErrors = true;
        core.warning(`${scannerName} scanner completed with error: ${result.error}`);
      } else {
        core.info(
          `   ✓ ${scannerName}: ${result.findings.length} finding(s) in ${result.durationMs}ms`
        );
      }
    } catch (error) {
      hasErrors = true;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      // Create a failed result but continue with other scanners
      results.push({
        name: scannerName,
        findings: [],
        durationMs: 0,
        error: errorMessage,
      });

      core.warning(`${scannerName} scanner failed: ${errorMessage}`);
    }
  }

  // Aggregate results
  let totalFindings = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let totalFilesScanned = 0;

  // Collect all findings for allowlist processing
  let allFindings: Finding[] = [];
  for (const result of results) {
    allFindings = allFindings.concat(result.findings);
    totalFilesScanned += result.filesScanned ?? 0;
  }

  // Apply allowlist to filter suppressed findings
  const allowlistResult = applyAllowlist(allFindings, config.allowlist);
  const activeFindings = allowlistResult.findings;
  const suppressedFindings = allowlistResult.suppressed;

  // Warn about expired allowlist entries
  if (allowlistResult.expiredEntries.length > 0) {
    warnExpiredEntries(allowlistResult.expiredEntries);
  }

  // Log suppressed findings if any
  if (suppressedFindings.length > 0) {
    core.info(`   📋 ${suppressedFindings.length} finding(s) suppressed by allowlist`);
    if (verbose) {
      for (const finding of suppressedFindings) {
        core.debug(`   Suppressed: ${finding.id}`);
      }
    }
  }

  // Count active findings by severity
  totalFindings = activeFindings.length;
  for (const finding of activeFindings) {
    switch (finding.severity) {
      case 'high':
        highCount++;
        break;
      case 'medium':
        mediumCount++;
        break;
      case 'low':
        lowCount++;
        break;
    }
  }

  // Update scanner results with filtered findings
  const filteredResults: ScannerResult[] = results.map((result) => ({
    ...result,
    findings: result.findings.filter((f) => activeFindings.includes(f)),
  }));

  // Generate allowlist warnings (expired entries are already handled above)
  const allowlistWarnings: string[] = allowlistResult.expiredEntries.map(
    (entry) =>
      `Allowlist entry '${entry.id}' has expired (expires: ${entry.expires}). ` +
      `The entry will not suppress findings.`
  );

  return {
    scanners: filteredResults,
    totalFindings,
    highCount,
    mediumCount,
    lowCount,
    totalDurationMs: Date.now() - overallStartTime,
    totalFilesScanned,
    hasErrors,
    suppressedCount: suppressedFindings.length,
    suppressedFindings,
    allowlistWarnings,
  };
}

// Export for testing
export { determineScanners, hasLockfiles, hasIaCFiles, hasContainerFiles };
