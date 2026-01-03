/**
 * Policy type definitions
 *
 * Defines types for policy evaluation results.
 *
 * @module policy/types
 */

import type { Severity } from '../scanners/types';

/**
 * Threshold level for policy evaluation.
 * Determines which severity levels cause a policy failure.
 */
export type FailOnThreshold = 'high' | 'medium' | 'low';

/**
 * Counts of findings by severity level.
 */
export interface SeverityCounts {
  /** Number of high-severity findings */
  high: number;
  /** Number of medium-severity findings */
  medium: number;
  /** Number of low-severity findings */
  low: number;
  /** Total number of findings */
  total: number;
}

/**
 * Result of policy evaluation.
 */
export interface PolicyResult {
  /** Whether the policy check passed (no findings above threshold) */
  passed: boolean;

  /** The threshold level used for evaluation */
  failOn: FailOnThreshold;

  /** Counts of findings by severity */
  counts: SeverityCounts;

  /** The severity level that triggered the failure (if any) */
  thresholdTriggered?: Severity;

  /** Human-readable reason for failure (if failed) */
  failureReason?: string;
}

/**
 * Mapping of threshold levels to the severities that trigger failure.
 */
export const THRESHOLD_SEVERITIES: Record<FailOnThreshold, readonly Severity[]> = {
  high: ['high'],
  medium: ['high', 'medium'],
  low: ['high', 'medium', 'low'],
} as const;

/**
 * Check if a threshold string is valid.
 *
 * @param value - String to check
 * @returns True if value is a valid threshold
 */
export function isValidThreshold(value: string): value is FailOnThreshold {
  return value === 'high' || value === 'medium' || value === 'low';
}
