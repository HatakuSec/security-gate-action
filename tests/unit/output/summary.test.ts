/**
 * @file Summary Generator Tests
 * @description Unit tests for the GitHub Actions summary generation.
 *
 * Coverage targets:
 * - generateSummaryMarkdown(): 100%
 * - generateEmptySummary(): 100%
 *
 * Key test scenarios:
 * - Empty results
 * - Mixed severity findings
 * - Collapsed sections
 * - Correct table formatting
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

import { generateSummaryMarkdown, generateEmptySummary } from '../../../src/output/summary';
import type { Finding, ScanResults, ScannerResult } from '../../../src/scanners/types';
import type { PolicyResult } from '../../../src/policy/types';

// Mock @actions/core
vi.mock('@actions/core', () => ({
  summary: {
    addRaw: vi.fn().mockReturnThis(),
    write: vi.fn().mockResolvedValue(undefined),
  },
}));

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
    file: 'src/test.ts',
    startLine: 42,
    scanner: 'secrets',
    ruleId: 'TEST001',
    ...overrides,
  };
}

/**
 * Helper to create test scan results.
 */
function createScanResults(
  scannerFindings: { name: 'secrets' | 'dependencies' | 'iac' | 'container'; findings: Finding[] }[]
): ScanResults {
  const scanners: ScannerResult[] = scannerFindings.map(({ name, findings }) => ({
    name,
    findings,
    durationMs: 100,
    filesScanned: 10,
  }));

  const allFindings = scanners.flatMap((s) => s.findings);

  return {
    scanners,
    totalFindings: allFindings.length,
    highCount: allFindings.filter((f) => f.severity === 'high').length,
    mediumCount: allFindings.filter((f) => f.severity === 'medium').length,
    lowCount: allFindings.filter((f) => f.severity === 'low').length,
    totalDurationMs: scanners.reduce((sum, s) => sum + s.durationMs, 0),
    totalFilesScanned: scanners.reduce((sum, s) => sum + (s.filesScanned ?? 0), 0),
    hasErrors: false,
  };
}

/**
 * Helper to create a policy result.
 */
function createPolicyResult(
  passed: boolean,
  counts: { high: number; medium: number; low: number }
): PolicyResult {
  return {
    passed,
    failOn: 'high',
    counts: {
      ...counts,
      total: counts.high + counts.medium + counts.low,
    },
    thresholdTriggered: passed ? undefined : 'high',
  };
}

describe('Summary Generator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('generateEmptySummary', () => {
    it('should generate a minimal summary', () => {
      const markdown = generateEmptySummary();

      expect(markdown).toContain('## 🔒 Security Gate Results');
      expect(markdown).toContain('✅ Passed');
      expect(markdown).toContain('no findings');
      expect(markdown).toContain('Security Gate v');
    });
  });

  describe('generateSummaryMarkdown', () => {
    describe('header and status', () => {
      it('should show passed status for no findings', () => {
        const results = createScanResults([{ name: 'secrets', findings: [] }]);
        const policy = createPolicyResult(true, { high: 0, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain('## 🔒 Security Gate Results');
        expect(markdown).toContain('✅ Passed');
        expect(markdown).toContain('no findings');
      });

      it('should show failed status with counts', () => {
        const findings = [createFinding('high')];
        const results = createScanResults([{ name: 'secrets', findings }]);
        const policy = createPolicyResult(false, { high: 1, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain('❌ Failed');
        expect(markdown).toContain('1 high');
        expect(markdown).toContain('threshold: high');
      });

      it('should show scan metadata', () => {
        const results = createScanResults([{ name: 'secrets', findings: [] }]);
        const policy = createPolicyResult(true, { high: 0, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain('**Scanned**:');
        expect(markdown).toContain('scanner');
        expect(markdown).toContain('file');
      });
    });

    describe('category table', () => {
      it('should generate findings table with all scanners', () => {
        const results = createScanResults([
          { name: 'secrets', findings: [createFinding('high', { scanner: 'secrets' })] },
          {
            name: 'dependencies',
            findings: [createFinding('medium', { scanner: 'dependencies' })],
          },
        ]);
        const policy = createPolicyResult(false, { high: 1, medium: 1, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain('### Findings by Category');
        expect(markdown).toContain('| Scanner | High | Medium | Low |');
        expect(markdown).toContain('🔑 Secrets');
        expect(markdown).toContain('📦 Dependencies');
      });

      it('should show correct counts per scanner', () => {
        const results = createScanResults([
          {
            name: 'secrets',
            findings: [
              createFinding('high', { scanner: 'secrets' }),
              createFinding('high', { scanner: 'secrets' }),
            ],
          },
        ]);
        const policy = createPolicyResult(false, { high: 2, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        // Table row should have "2" in the high column
        expect(markdown).toMatch(/Secrets\s*\|\s*2\s*\|\s*0\s*\|\s*0/);
      });
    });

    describe('high severity section', () => {
      it('should show high findings expanded', () => {
        const finding = createFinding('high', {
          title: 'Critical Secret Leak',
          message: 'Found AWS key in code',
          file: 'config.ts',
          startLine: 10,
          ruleId: 'SEC001',
        });
        const results = createScanResults([{ name: 'secrets', findings: [finding] }]);
        const policy = createPolicyResult(false, { high: 1, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain('### High Severity Findings');
        expect(markdown).toContain('Critical Secret Leak');
        expect(markdown).toContain('SEC001');
        expect(markdown).toContain('config.ts:10');
        expect(markdown).toContain('Found AWS key in code');
      });

      it('should include code snippet if present', () => {
        const finding = createFinding('high', {
          snippet: 'const key = "AKIA************LE";',
        });
        const results = createScanResults([{ name: 'secrets', findings: [finding] }]);
        const policy = createPolicyResult(false, { high: 1, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain('```');
        expect(markdown).toContain('AKIA************LE');
      });

      it('should not show high section if no high findings', () => {
        const finding = createFinding('medium');
        const results = createScanResults([{ name: 'secrets', findings: [finding] }]);
        const policy = createPolicyResult(true, { high: 0, medium: 1, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).not.toContain('### High Severity Findings');
      });
    });

    describe('collapsed sections', () => {
      it('should collapse medium findings', () => {
        const finding = createFinding('medium');
        const results = createScanResults([{ name: 'secrets', findings: [finding] }]);
        const policy = createPolicyResult(true, { high: 0, medium: 1, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain('<details>');
        expect(markdown).toContain('Medium Severity Findings (1)');
        expect(markdown).toContain('</details>');
      });

      it('should collapse low findings', () => {
        const finding = createFinding('low');
        const results = createScanResults([{ name: 'secrets', findings: [finding] }]);
        const policy = createPolicyResult(true, { high: 0, medium: 0, low: 1 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain('<details>');
        expect(markdown).toContain('Low Severity Findings (1)');
        expect(markdown).toContain('</details>');
      });
    });

    describe('footer', () => {
      it('should include version footer', () => {
        const results = createScanResults([{ name: 'secrets', findings: [] }]);
        const policy = createPolicyResult(true, { high: 0, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain('---');
        expect(markdown).toContain('_Security Gate v');
      });
    });

    describe('line number formatting', () => {
      it('should show single line number', () => {
        const finding = createFinding('high', {
          startLine: 42,
          endLine: 42,
        });
        const results = createScanResults([{ name: 'secrets', findings: [finding] }]);
        const policy = createPolicyResult(false, { high: 1, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain(':42');
        expect(markdown).not.toContain(':42-42');
      });

      it('should show line range', () => {
        const finding = createFinding('high', {
          startLine: 10,
          endLine: 15,
        });
        const results = createScanResults([{ name: 'secrets', findings: [finding] }]);
        const policy = createPolicyResult(false, { high: 1, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain(':10-15');
      });

      it('should handle missing line numbers', () => {
        const finding = createFinding('high', {
          startLine: undefined,
          endLine: undefined,
        });
        const results = createScanResults([{ name: 'secrets', findings: [finding] }]);
        const policy = createPolicyResult(false, { high: 1, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        // File path without line number
        expect(markdown).toContain('`src/test.ts`');
        expect(markdown).not.toContain(':undefined');
      });
    });

    describe('scanner icons', () => {
      it('should use correct emoji for each scanner', () => {
        const results = createScanResults([
          { name: 'secrets', findings: [createFinding('high', { scanner: 'secrets' })] },
          { name: 'dependencies', findings: [createFinding('high', { scanner: 'dependencies' })] },
          { name: 'iac', findings: [createFinding('high', { scanner: 'iac' })] },
          { name: 'container', findings: [createFinding('high', { scanner: 'container' })] },
        ]);
        const policy = createPolicyResult(false, { high: 4, medium: 0, low: 0 });

        const markdown = generateSummaryMarkdown(results, policy);

        expect(markdown).toContain('🔑');
        expect(markdown).toContain('📦');
        expect(markdown).toContain('🏗️');
        expect(markdown).toContain('🐳');
      });
    });
  });
});
