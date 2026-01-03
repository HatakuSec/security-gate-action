/**
 * @file Policy Evaluator Tests
 * @description Unit tests for the policy evaluation system.
 *
 * Coverage targets:
 * - countFindings(): 100%
 * - evaluatePolicy(): 100%
 * - shouldFail(): 100%
 *
 * Key test scenarios:
 * - Threshold matrix (all combinations)
 * - Edge cases (empty findings, mixed severities)
 * - Failure reason formatting
 */

import { describe, it, expect } from 'vitest';

import {
  countFindings,
  evaluatePolicy,
  evaluatePolicyFromResults,
  shouldFail,
} from '../../../src/policy/evaluator';
import { isValidThreshold, THRESHOLD_SEVERITIES } from '../../../src/policy/types';
import type { Finding, ScanResults, ScannerResult } from '../../../src/scanners/types';

/**
 * Helper to create a test finding.
 */
function createFinding(
  severity: 'high' | 'medium' | 'low',
  overrides: Partial<Finding> = {}
): Finding {
  return {
    id: `test-${Date.now()}-${Math.random()}`,
    severity,
    title: `Test ${severity} finding`,
    message: `This is a ${severity} severity finding`,
    file: 'test.ts',
    scanner: 'secrets',
    ...overrides,
  };
}

/**
 * Helper to create test scan results.
 */
function createScanResults(findings: Finding[]): ScanResults {
  const scannerResult: ScannerResult = {
    name: 'secrets',
    findings,
    durationMs: 100,
    filesScanned: 10,
  };

  return {
    scanners: [scannerResult],
    totalFindings: findings.length,
    highCount: findings.filter((f) => f.severity === 'high').length,
    mediumCount: findings.filter((f) => f.severity === 'medium').length,
    lowCount: findings.filter((f) => f.severity === 'low').length,
    totalDurationMs: 100,
    totalFilesScanned: 10,
    hasErrors: false,
  };
}

describe('Policy Evaluator', () => {
  describe('countFindings', () => {
    it('should return zero counts for empty array', () => {
      const result = countFindings([]);

      expect(result).toEqual({
        high: 0,
        medium: 0,
        low: 0,
        total: 0,
      });
    });

    it('should count high findings', () => {
      const findings = [createFinding('high'), createFinding('high')];
      const result = countFindings(findings);

      expect(result.high).toBe(2);
      expect(result.total).toBe(2);
    });

    it('should count medium findings', () => {
      const findings = [createFinding('medium')];
      const result = countFindings(findings);

      expect(result.medium).toBe(1);
      expect(result.total).toBe(1);
    });

    it('should count low findings', () => {
      const findings = [createFinding('low'), createFinding('low'), createFinding('low')];
      const result = countFindings(findings);

      expect(result.low).toBe(3);
      expect(result.total).toBe(3);
    });

    it('should count mixed severity findings', () => {
      const findings = [
        createFinding('high'),
        createFinding('medium'),
        createFinding('medium'),
        createFinding('low'),
      ];
      const result = countFindings(findings);

      expect(result.high).toBe(1);
      expect(result.medium).toBe(2);
      expect(result.low).toBe(1);
      expect(result.total).toBe(4);
    });
  });

  describe('shouldFail', () => {
    describe('fail_on: high', () => {
      it('should fail when high > 0', () => {
        expect(shouldFail(1, 0, 0, 'high')).toBe(true);
        expect(shouldFail(5, 10, 20, 'high')).toBe(true);
      });

      it('should pass when high = 0', () => {
        expect(shouldFail(0, 0, 0, 'high')).toBe(false);
        expect(shouldFail(0, 10, 20, 'high')).toBe(false);
      });
    });

    describe('fail_on: medium', () => {
      it('should fail when high > 0', () => {
        expect(shouldFail(1, 0, 0, 'medium')).toBe(true);
      });

      it('should fail when medium > 0 (and high = 0)', () => {
        expect(shouldFail(0, 1, 0, 'medium')).toBe(true);
        expect(shouldFail(0, 5, 10, 'medium')).toBe(true);
      });

      it('should pass when high = 0 and medium = 0', () => {
        expect(shouldFail(0, 0, 0, 'medium')).toBe(false);
        expect(shouldFail(0, 0, 100, 'medium')).toBe(false);
      });
    });

    describe('fail_on: low', () => {
      it('should fail when high > 0', () => {
        expect(shouldFail(1, 0, 0, 'low')).toBe(true);
      });

      it('should fail when medium > 0', () => {
        expect(shouldFail(0, 1, 0, 'low')).toBe(true);
      });

      it('should fail when low > 0', () => {
        expect(shouldFail(0, 0, 1, 'low')).toBe(true);
      });

      it('should pass only when all counts are 0', () => {
        expect(shouldFail(0, 0, 0, 'low')).toBe(false);
      });
    });
  });

  describe('evaluatePolicy', () => {
    describe('with no findings', () => {
      it('should pass with high threshold', () => {
        const result = evaluatePolicy([], 'high');

        expect(result.passed).toBe(true);
        expect(result.failOn).toBe('high');
        expect(result.counts.total).toBe(0);
        expect(result.thresholdTriggered).toBeUndefined();
      });

      it('should pass with medium threshold', () => {
        const result = evaluatePolicy([], 'medium');
        expect(result.passed).toBe(true);
      });

      it('should pass with low threshold', () => {
        const result = evaluatePolicy([], 'low');
        expect(result.passed).toBe(true);
      });
    });

    describe('with high-severity findings', () => {
      it('should fail on high threshold', () => {
        const findings = [createFinding('high')];
        const result = evaluatePolicy(findings, 'high');

        expect(result.passed).toBe(false);
        expect(result.thresholdTriggered).toBe('high');
        expect(result.failureReason).toContain('1 high');
      });

      it('should fail on medium threshold', () => {
        const findings = [createFinding('high')];
        const result = evaluatePolicy(findings, 'medium');

        expect(result.passed).toBe(false);
        expect(result.thresholdTriggered).toBe('high');
      });

      it('should fail on low threshold', () => {
        const findings = [createFinding('high')];
        const result = evaluatePolicy(findings, 'low');

        expect(result.passed).toBe(false);
      });
    });

    describe('with medium-severity findings only', () => {
      it('should pass on high threshold', () => {
        const findings = [createFinding('medium')];
        const result = evaluatePolicy(findings, 'high');

        expect(result.passed).toBe(true);
        expect(result.thresholdTriggered).toBeUndefined();
      });

      it('should fail on medium threshold', () => {
        const findings = [createFinding('medium')];
        const result = evaluatePolicy(findings, 'medium');

        expect(result.passed).toBe(false);
        expect(result.thresholdTriggered).toBe('medium');
      });

      it('should fail on low threshold', () => {
        const findings = [createFinding('medium')];
        const result = evaluatePolicy(findings, 'low');

        expect(result.passed).toBe(false);
      });
    });

    describe('with low-severity findings only', () => {
      it('should pass on high threshold', () => {
        const findings = [createFinding('low')];
        const result = evaluatePolicy(findings, 'high');

        expect(result.passed).toBe(true);
      });

      it('should pass on medium threshold', () => {
        const findings = [createFinding('low')];
        const result = evaluatePolicy(findings, 'medium');

        expect(result.passed).toBe(true);
      });

      it('should fail on low threshold', () => {
        const findings = [createFinding('low')];
        const result = evaluatePolicy(findings, 'low');

        expect(result.passed).toBe(false);
        expect(result.thresholdTriggered).toBe('low');
      });
    });

    describe('failure reason formatting', () => {
      it('should include all severity counts in failure reason', () => {
        const findings = [
          createFinding('high'),
          createFinding('high'),
          createFinding('medium'),
          createFinding('low'),
        ];
        const result = evaluatePolicy(findings, 'high');

        expect(result.failureReason).toContain('2 high');
        expect(result.failureReason).toContain('1 medium');
        expect(result.failureReason).toContain('1 low');
        expect(result.failureReason).toContain('threshold: high');
      });
    });
  });

  describe('evaluatePolicyFromResults', () => {
    it('should evaluate policy from scan results', () => {
      const findings = [createFinding('high')];
      const results = createScanResults(findings);

      const result = evaluatePolicyFromResults(results, 'high');

      expect(result.passed).toBe(false);
      expect(result.counts.high).toBe(1);
    });

    it('should default to high threshold for invalid value', () => {
      const findings = [createFinding('medium')];
      const results = createScanResults(findings);

      const result = evaluatePolicyFromResults(results, 'invalid');

      expect(result.passed).toBe(true); // medium doesn't trigger high threshold
      expect(result.failOn).toBe('high');
    });

    it('should aggregate findings from multiple scanners', () => {
      const secretsResult: ScannerResult = {
        name: 'secrets',
        findings: [createFinding('high', { scanner: 'secrets' })],
        durationMs: 50,
      };
      const depsResult: ScannerResult = {
        name: 'dependencies',
        findings: [createFinding('medium', { scanner: 'dependencies' })],
        durationMs: 50,
      };

      const results: ScanResults = {
        scanners: [secretsResult, depsResult],
        totalFindings: 2,
        highCount: 1,
        mediumCount: 1,
        lowCount: 0,
        totalDurationMs: 100,
        totalFilesScanned: 20,
        hasErrors: false,
      };

      const result = evaluatePolicyFromResults(results, 'high');

      expect(result.counts.total).toBe(2);
      expect(result.counts.high).toBe(1);
      expect(result.counts.medium).toBe(1);
    });
  });

  describe('isValidThreshold', () => {
    it('should return true for valid thresholds', () => {
      expect(isValidThreshold('high')).toBe(true);
      expect(isValidThreshold('medium')).toBe(true);
      expect(isValidThreshold('low')).toBe(true);
    });

    it('should return false for invalid thresholds', () => {
      expect(isValidThreshold('critical')).toBe(false);
      expect(isValidThreshold('')).toBe(false);
      expect(isValidThreshold('HIGH')).toBe(false);
    });
  });

  describe('THRESHOLD_SEVERITIES', () => {
    it('should have correct severities for high threshold', () => {
      expect(THRESHOLD_SEVERITIES.high).toEqual(['high']);
    });

    it('should have correct severities for medium threshold', () => {
      expect(THRESHOLD_SEVERITIES.medium).toEqual(['high', 'medium']);
    });

    it('should have correct severities for low threshold', () => {
      expect(THRESHOLD_SEVERITIES.low).toEqual(['high', 'medium', 'low']);
    });
  });
});
