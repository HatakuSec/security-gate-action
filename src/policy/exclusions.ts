/**
 * Exclusions and Allowlist Processing
 *
 * Provides functionality for:
 * - Global path exclusions (ignore patterns)
 * - Finding suppression via allowlist entries
 * - Expiry date handling for time-limited suppressions
 *
 * @module policy/exclusions
 */

import * as core from '@actions/core';
import type { Finding } from '../scanners/types';
import type { AllowlistEntry, IgnoreConfig } from '../config/schema';

/**
 * Result of applying allowlist to findings.
 */
export interface AllowlistResult {
  /** Findings that were not suppressed */
  findings: Finding[];
  /** Findings that were suppressed by allowlist entries */
  suppressed: Finding[];
  /** Count of suppressions by scanner */
  suppressedByScanner: Record<string, number>;
  /** Total number of suppressed findings */
  suppressedCount: number;
  /** Allowlist entries that have expired (for warning) */
  expiredEntries: AllowlistEntry[];
}

/**
 * Normalise a glob pattern for consistent matching.
 * - Removes leading ./
 * - Ensures no path traversal (../)
 * - Handles Windows-style paths
 *
 * @param glob - The glob pattern to normalise
 * @returns Normalised glob or null if invalid
 */
export function normaliseGlob(glob: string): string | null {
  // Remove leading ./
  let normalised = glob.replace(/^\.\//, '');

  // Check for path traversal attempts
  if (normalised.includes('../') || normalised.startsWith('..')) {
    return null;
  }

  // Normalise Windows paths
  normalised = normalised.replace(/\\/g, '/');

  // Remove double slashes
  normalised = normalised.replace(/\/+/g, '/');

  return normalised;
}

/**
 * Check if a path should be ignored based on ignore configuration.
 *
 * @param path - Relative file path to check
 * @param ignoreConfig - Ignore configuration from config
 * @param globalExcludePaths - Global exclude_paths from config
 * @returns True if the path should be ignored
 */
export function shouldIgnorePath(
  path: string,
  ignoreConfig?: IgnoreConfig,
  globalExcludePaths?: string[]
): boolean {
  // Combine all ignore sources
  const allPatterns: string[] = [];

  if (ignoreConfig?.paths) {
    allPatterns.push(...ignoreConfig.paths);
  }

  if (globalExcludePaths) {
    allPatterns.push(...globalExcludePaths);
  }

  if (allPatterns.length === 0) {
    return false;
  }

  // Check each pattern
  for (const pattern of allPatterns) {
    const normalisedPattern = normaliseGlob(pattern);
    if (!normalisedPattern) {
      continue; // Skip invalid patterns
    }

    if (matchGlob(path, normalisedPattern)) {
      return true;
    }
  }

  return false;
}

/**
 * Simple glob matching.
 * Supports * (any except /) and ** (any including /).
 *
 * @param path - Path to test
 * @param glob - Glob pattern
 * @returns True if path matches
 */
function matchGlob(path: string, glob: string): boolean {
  // Escape regex special characters except * and **
  let regexPattern = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '{{GLOBSTAR}}')
    .replace(/\*/g, '[^/]*')
    .replace(/\{\{GLOBSTAR\}\}/g, '.*');

  // Anchor pattern
  regexPattern = `^${regexPattern}$`;

  try {
    const regex = new RegExp(regexPattern);
    return regex.test(path);
  } catch {
    return false;
  }
}

/**
 * Check if an allowlist entry's expiry date has passed.
 *
 * @param expires - Expiry date string (ISO 8601)
 * @returns True if expired, false if still valid or no expiry
 */
export function isAllowlistEntryExpired(expires?: string): boolean {
  if (!expires) {
    return false;
  }

  const expiryDate = Date.parse(expires);
  if (isNaN(expiryDate)) {
    // Invalid date format - treat as config error
    throw new Error(`Invalid expiry date format: ${expires}`);
  }

  const now = Date.now();
  return now > expiryDate;
}

/**
 * Check if a finding matches an allowlist entry's criteria.
 *
 * @param finding - The finding to check
 * @param entry - The allowlist entry
 * @returns True if the finding matches all specified criteria
 */
function findingMatchesEntry(finding: Finding, entry: AllowlistEntry): boolean {
  const match = entry.match;

  // If no match criteria, entry doesn't match anything
  if (!match) {
    return false;
  }

  // Check scanner match
  if (match.scanner && finding.scanner !== match.scanner) {
    return false;
  }

  // Check finding_id match (supports prefix matching with *)
  if (match.finding_id) {
    if (match.finding_id.endsWith('*')) {
      const prefix = match.finding_id.slice(0, -1);
      if (!finding.id.startsWith(prefix)) {
        return false;
      }
    } else if (finding.id !== match.finding_id) {
      return false;
    }
  }

  // Check rule_id match
  if (match.rule_id && finding.ruleId !== match.rule_id) {
    return false;
  }

  // Check path_glob match
  if (match.path_glob) {
    const normalisedPattern = normaliseGlob(match.path_glob);
    if (!normalisedPattern || !matchGlob(finding.file, normalisedPattern)) {
      return false;
    }
  }

  // Check message_contains match
  if (match.message_contains) {
    if (!finding.message.includes(match.message_contains)) {
      return false;
    }
  }

  // All specified criteria matched
  return true;
}

/**
 * Apply allowlist to findings, suppressing matching entries.
 *
 * @param findings - Array of findings to process
 * @param allowlist - Allowlist entries from config
 * @returns Result with unsuppressed findings, suppressed findings, and metadata
 */
export function applyAllowlist(findings: Finding[], allowlist?: AllowlistEntry[]): AllowlistResult {
  const result: AllowlistResult = {
    findings: [],
    suppressed: [],
    suppressedByScanner: {},
    suppressedCount: 0,
    expiredEntries: [],
  };

  // If no allowlist, return all findings unchanged
  if (!allowlist || allowlist.length === 0) {
    result.findings = findings;
    return result;
  }

  // Separate expired entries
  const validEntries: AllowlistEntry[] = [];
  for (const entry of allowlist) {
    try {
      if (isAllowlistEntryExpired(entry.expires)) {
        result.expiredEntries.push(entry);
        // Don't add to validEntries - expired entries don't suppress
      } else {
        validEntries.push(entry);
      }
    } catch (err) {
      // Invalid expiry date - treat as config error
      throw new Error(`Allowlist entry '${entry.id}' has invalid expires date: ${entry.expires}`);
    }
  }

  // Process each finding
  for (const finding of findings) {
    let suppressed = false;

    for (const entry of validEntries) {
      if (findingMatchesEntry(finding, entry)) {
        suppressed = true;
        result.suppressed.push(finding);
        result.suppressedCount++;

        // Track by scanner
        const scanner = finding.scanner;
        result.suppressedByScanner[scanner] = (result.suppressedByScanner[scanner] ?? 0) + 1;

        break; // Finding is suppressed, no need to check more entries
      }
    }

    if (!suppressed) {
      result.findings.push(finding);
    }
  }

  return result;
}

/**
 * Emit warnings for expired allowlist entries.
 *
 * @param expiredEntries - Entries that have expired
 */
export function warnExpiredEntries(expiredEntries: AllowlistEntry[]): void {
  for (const entry of expiredEntries) {
    core.warning(
      `Allowlist entry '${entry.id}' has expired (expires: ${entry.expires}). ` +
        `The entry will not suppress findings. Remove or update the expiry date.`
    );
  }
}

/**
 * Get a list of all ignore patterns from config.
 *
 * @param ignoreConfig - Ignore configuration
 * @param globalExcludePaths - Global exclude_paths
 * @returns Array of normalised glob patterns
 */
export function getAllIgnorePatterns(
  ignoreConfig?: IgnoreConfig,
  globalExcludePaths?: string[]
): string[] {
  const patterns: string[] = [];

  if (ignoreConfig?.paths) {
    for (const p of ignoreConfig.paths) {
      const normalised = normaliseGlob(p);
      if (normalised) {
        patterns.push(normalised);
      }
    }
  }

  if (globalExcludePaths) {
    for (const p of globalExcludePaths) {
      const normalised = normaliseGlob(p);
      if (normalised) {
        patterns.push(normalised);
      }
    }
  }

  return patterns;
}
