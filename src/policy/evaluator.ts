/**
 * Policy Evaluator
 *
 * Evaluates findings against threshold policy to determine pass/fail.
 * Implements the policy decision matrix for threshold-based decisions.
 *
 * @module policy/evaluator
 */

import type { Finding, ScanResults } from '../scanners/types';
import type { FailOnThreshold, PolicyResult, SeverityCounts } from './types';
import { THRESHOLD_SEVERITIES, isValidThreshold } from './types';

/**
 * Count findings by severity level.
 *
 * @param findings - Array of findings to count
 * @returns Severity counts including total
 */
export function countFindings(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = {
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
  };

  for (const finding of findings) {
    switch (finding.severity) {
      case 'high':
        counts.high++;
        break;
      case 'medium':
        counts.medium++;
        break;
      case 'low':
        counts.low++;
        break;
    }
    counts.total++;
  }

  return counts;
}

/**
 * Evaluate policy against findings.
 *
 * Policy Decision Matrix ():
 * | fail_on | High | Medium | Low | Result |
 * |---------|------|--------|-----|--------|
 * | high    | ≥1   | any    | any | FAIL   |
 * | high    | 0    | any    | any | PASS   |
 * | medium  | ≥1   | any    | any | FAIL   |
 * | medium  | 0    | ≥1     | any | FAIL   |
 * | medium  | 0    | 0      | any | PASS   |
 * | low     | any≥1| -      | -   | FAIL   |
 *
 * @param findings - Array of findings to evaluate
 * @param failOn - Threshold level (high, medium, low)
 * @returns Policy evaluation result
 */
export function evaluatePolicy(findings: Finding[], failOn: FailOnThreshold): PolicyResult {
  const counts = countFindings(findings);
  const triggerSeverities = THRESHOLD_SEVERITIES[failOn];

  // Check each severity level that can trigger failure
  for (const severity of triggerSeverities) {
    if (counts[severity] > 0) {
      return {
        passed: false,
        failOn,
        counts,
        thresholdTriggered: severity,
        failureReason: formatFailureReason(counts, failOn, severity),
      };
    }
  }

  return {
    passed: true,
    failOn,
    counts,
  };
}

/**
 * Evaluate policy using scan results directly.
 *
 * @param results - Aggregated scan results
 * @param failOn - Threshold level string
 * @returns Policy evaluation result
 */
export function evaluatePolicyFromResults(results: ScanResults, failOn: string): PolicyResult {
  // Validate threshold
  const threshold: FailOnThreshold = isValidThreshold(failOn) ? failOn : 'high';

  // Collect all findings from scanner results
  const allFindings: Finding[] = [];
  for (const scanner of results.scanners) {
    allFindings.push(...scanner.findings);
  }

  return evaluatePolicy(allFindings, threshold);
}

/**
 * Format a human-readable failure reason.
 *
 * @param counts - Severity counts
 * @param failOn - Threshold level
 * @param triggered - Severity that triggered failure
 * @returns Human-readable failure message
 */
function formatFailureReason(
  counts: SeverityCounts,
  failOn: FailOnThreshold,
  triggered: string
): string {
  const parts: string[] = [];

  if (counts.high > 0) {
    parts.push(`${counts.high} high`);
  }
  if (counts.medium > 0) {
    parts.push(`${counts.medium} medium`);
  }
  if (counts.low > 0) {
    parts.push(`${counts.low} low`);
  }

  const findingsStr = parts.join(', ');
  return `Policy check failed: found ${findingsStr} severity findings (threshold: ${failOn}, triggered by: ${triggered})`;
}

/**
 * Check if policy should fail for given counts and threshold.
 * Pure function for easier testing.
 *
 * @param highCount - Number of high-severity findings
 * @param mediumCount - Number of medium-severity findings
 * @param lowCount - Number of low-severity findings
 * @param failOn - Threshold level
 * @returns True if policy should fail
 */
export function shouldFail(
  highCount: number,
  mediumCount: number,
  lowCount: number,
  failOn: FailOnThreshold
): boolean {
  switch (failOn) {
    case 'high':
      return highCount > 0;
    case 'medium':
      return highCount > 0 || mediumCount > 0;
    case 'low':
      return highCount > 0 || mediumCount > 0 || lowCount > 0;
    default:
      // Default to high threshold
      return highCount > 0;
  }
}
