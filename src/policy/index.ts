/**
 * Policy module
 *
 * Exports policy evaluation functionality.
 *
 * @module policy
 */

export type { FailOnThreshold, PolicyResult, SeverityCounts } from './types';
export { THRESHOLD_SEVERITIES, isValidThreshold } from './types';
export { countFindings, evaluatePolicy, evaluatePolicyFromResults, shouldFail } from './evaluator';
