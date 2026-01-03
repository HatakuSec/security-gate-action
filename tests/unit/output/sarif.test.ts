/**
 * SARIF Output Tests
 *
 * Tests for SARIF 2.1.0 output generation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as core from '@actions/core';
import type { Finding, ScanResults, ScannerResult } from '../../../src/scanners/types';
import {
  generateSarif,
  writeSarifToFile,
  handleSarifOutput,
  type SarifLog,
} from '../../../src/output/sarif';

// Mock @actions/core
vi.mock('@actions/core', () => ({
  info: vi.fn(),
  error: vi.fn(),
  warning: vi.fn(),
  debug: vi.fn(),
}));

/**
 * Create a mock finding for testing.
 */
function createMockFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'secrets:SEC001:config.ts:42',
    severity: 'high',
    title: 'Hardcoded API Key',
    message: 'Found hardcoded API key that may expose sensitive data',
    file: 'src/config.ts',
    startLine: 42,
    endLine: 42,
    ruleId: 'SEC001',
    scanner: 'secrets',
    snippet: 'const key = "***MASKED***";',
    ...overrides,
  };
}

/**
 * Create mock scan results for testing.
 */
function createMockScanResults(findings: Finding[] = []): ScanResults {
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

describe('SARIF output', () => {
  let tempDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sarif-test-'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    // Clean up temp directory
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('generateSarif', () => {
    it('should generate valid SARIF 2.1.0 structure', () => {
      const results = createMockScanResults([createMockFinding()]);

      const sarif = generateSarif(results);

      expect(sarif.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0]?.tool.driver.name).toBe('security-gate');
    });

    it('should include tool information', () => {
      const results = createMockScanResults([]);

      const sarif = generateSarif(results);

      const driver = sarif.runs[0]?.tool.driver;
      expect(driver?.name).toBe('security-gate');
      expect(driver?.semanticVersion).toBe('0.2.0');
      expect(driver?.fullName).toBe('Security Gate Action');
      expect(driver?.informationUri).toContain('github.com');
    });

    it('should convert findings to results', () => {
      const finding = createMockFinding({
        severity: 'high',
        file: 'src/app.ts',
        startLine: 10,
        endLine: 12,
      });
      const results = createMockScanResults([finding]);

      const sarif = generateSarif(results);

      expect(sarif.runs[0]?.results).toHaveLength(1);

      const result = sarif.runs[0]?.results[0];
      expect(result?.ruleId).toBe('secrets/SEC001');
      expect(result?.level).toBe('error');
      expect(result?.message.text).toContain('hardcoded API key');
    });

    it('should map severity levels correctly', () => {
      const findings = [
        createMockFinding({ severity: 'high', id: 'high-1' }),
        createMockFinding({ severity: 'medium', id: 'medium-1' }),
        createMockFinding({ severity: 'low', id: 'low-1' }),
      ];
      const results = createMockScanResults(findings);

      const sarif = generateSarif(results);

      const levels = sarif.runs[0]?.results.map((r) => r.level);
      expect(levels).toContain('error');
      expect(levels).toContain('warning');
      expect(levels).toContain('note');
    });

    it('should include location information', () => {
      const finding = createMockFinding({
        file: 'src/config.ts',
        startLine: 42,
        endLine: 45,
        snippet: 'const key = "***MASKED***";',
      });
      const results = createMockScanResults([finding]);

      const sarif = generateSarif(results);

      const location = sarif.runs[0]?.results[0]?.locations?.[0];
      expect(location?.physicalLocation?.artifactLocation?.uri).toBe('src/config.ts');
      expect(location?.physicalLocation?.region?.startLine).toBe(42);
      expect(location?.physicalLocation?.region?.endLine).toBe(45);
      expect(location?.physicalLocation?.region?.snippet?.text).toBe('const key = "***MASKED***";');
    });

    it('should use masked snippets (no raw secrets)', () => {
      const finding = createMockFinding({
        snippet: 'const apiKey = "***MASKED***";',
      });
      const results = createMockScanResults([finding]);

      const sarif = generateSarif(results);

      const snippet =
        sarif.runs[0]?.results[0]?.locations?.[0]?.physicalLocation?.region?.snippet?.text;
      expect(snippet).toContain('***MASKED***');
      expect(snippet).not.toContain('sk_live');
    });

    it('should extract unique rules from findings', () => {
      const findings = [
        createMockFinding({ ruleId: 'SEC001', title: 'API Key' }),
        createMockFinding({ ruleId: 'SEC001', title: 'API Key', id: 'secrets:SEC001:other.ts:1' }),
        createMockFinding({
          ruleId: 'SEC002',
          title: 'Private Key',
          id: 'secrets:SEC002:keys.ts:1',
        }),
      ];
      const results = createMockScanResults(findings);

      const sarif = generateSarif(results);

      const rules = sarif.runs[0]?.tool.driver.rules;
      expect(rules).toHaveLength(2);
      expect(rules?.map((r) => r.id).sort()).toEqual(['secrets/SEC001', 'secrets/SEC002']);
    });

    it('should handle findings without line numbers', () => {
      const finding = createMockFinding({
        startLine: undefined,
        endLine: undefined,
      });
      const results = createMockScanResults([finding]);

      const sarif = generateSarif(results);

      const location = sarif.runs[0]?.results[0]?.locations?.[0];
      expect(location?.physicalLocation?.artifactLocation?.uri).toBe('src/config.ts');
      expect(location?.physicalLocation?.region).toBeUndefined();
    });

    it('should store finding ID in properties', () => {
      const finding = createMockFinding({ id: 'secrets:SEC001:config.ts:42' });
      const results = createMockScanResults([finding]);

      const sarif = generateSarif(results);

      const result = sarif.runs[0]?.results[0];
      // Finding ID is stored in properties for reference
      // We don't provide fingerprints - GitHub's upload-sarif calculates content-based ones
      expect(result?.properties?.findingId).toBe('secrets:SEC001:config.ts:42');
    });

    it('should handle multiple scanners', () => {
      const secretsFinding = createMockFinding({ scanner: 'secrets' });
      const iacFinding = createMockFinding({
        scanner: 'iac',
        ruleId: 'AVD-AWS-0086',
        id: 'iac:AVD-AWS-0086:main.tf:10',
      });

      const results: ScanResults = {
        scanners: [
          { name: 'secrets', findings: [secretsFinding], durationMs: 50, filesScanned: 5 },
          { name: 'iac', findings: [iacFinding], durationMs: 100, filesScanned: 3 },
        ],
        totalFindings: 2,
        highCount: 2,
        mediumCount: 0,
        lowCount: 0,
        totalDurationMs: 150,
        totalFilesScanned: 8,
        hasErrors: false,
      };

      const sarif = generateSarif(results);

      expect(sarif.runs[0]?.results).toHaveLength(2);
      expect(sarif.runs[0]?.tool.driver.rules).toHaveLength(2);
    });

    it('should include invocation with execution status', () => {
      const results = createMockScanResults([]);

      const sarif = generateSarif(results);

      const invocation = sarif.runs[0]?.invocations?.[0];
      expect(invocation?.executionSuccessful).toBe(true);
    });

    it('should report scanner errors in invocation', () => {
      const results: ScanResults = {
        scanners: [
          {
            name: 'secrets',
            findings: [],
            durationMs: 50,
            filesScanned: 0,
            error: 'Scanner failed',
          },
        ],
        totalFindings: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        totalDurationMs: 50,
        totalFilesScanned: 0,
        hasErrors: true,
      };

      const sarif = generateSarif(results);

      const invocation = sarif.runs[0]?.invocations?.[0];
      expect(invocation?.executionSuccessful).toBe(false);
      expect(invocation?.toolExecutionNotifications?.[0]?.message.text).toContain('Scanner failed');
    });

    it('should include allowlist warnings', () => {
      const results: ScanResults = {
        ...createMockScanResults([]),
        allowlistWarnings: ['Allowlist entry "test" has expired'],
      };

      const sarif = generateSarif(results);

      const invocation = sarif.runs[0]?.invocations?.[0];
      expect(
        invocation?.toolExecutionNotifications?.some((n) => n.message.text.includes('expired'))
      ).toBe(true);
    });

    it('should produce deterministic output (sorted)', () => {
      const findings = [
        createMockFinding({ file: 'z.ts', id: 'z-finding' }),
        createMockFinding({ file: 'a.ts', id: 'a-finding' }),
        createMockFinding({ file: 'm.ts', id: 'm-finding' }),
      ];
      const results = createMockScanResults(findings);

      const sarif1 = generateSarif(results);
      const sarif2 = generateSarif(results);

      // Results should be in deterministic order
      expect(JSON.stringify(sarif1)).toBe(JSON.stringify(sarif2));

      // Should be sorted by file
      const files = sarif1.runs[0]?.results.map(
        (r) => r.locations?.[0]?.physicalLocation?.artifactLocation?.uri
      );
      expect(files).toEqual(['a.ts', 'm.ts', 'z.ts']);
    });
  });

  describe('writeSarifToFile', () => {
    it('should write SARIF to file', () => {
      const results = createMockScanResults([createMockFinding()]);
      const outputPath = path.join(tempDir, 'results.sarif');

      const success = writeSarifToFile(results, outputPath);

      expect(success).toBe(true);
      expect(fs.existsSync(outputPath)).toBe(true);

      // Verify content is valid JSON
      const content = fs.readFileSync(outputPath, 'utf-8');
      const parsed = JSON.parse(content);
      expect(parsed.$schema).toContain('sarif');
    });

    it('should create parent directories if needed', () => {
      const results = createMockScanResults([]);
      const outputPath = path.join(tempDir, 'nested', 'dir', 'results.sarif');

      const success = writeSarifToFile(results, outputPath);

      expect(success).toBe(true);
      expect(fs.existsSync(outputPath)).toBe(true);
    });

    it('should log file information', () => {
      const results = createMockScanResults([createMockFinding()]);
      const outputPath = path.join(tempDir, 'results.sarif');

      writeSarifToFile(results, outputPath);

      expect(core.info).toHaveBeenCalledWith(expect.stringContaining('SARIF output written'));
      expect(core.info).toHaveBeenCalledWith(expect.stringContaining('Results:'));
      expect(core.info).toHaveBeenCalledWith(expect.stringContaining('Rules:'));
    });

    it('should return false on write error', () => {
      const results = createMockScanResults([]);
      const invalidPath = '/nonexistent/readonly/path/results.sarif';

      const success = writeSarifToFile(results, invalidPath);

      expect(success).toBe(false);
      expect(core.error).toHaveBeenCalledWith(expect.stringContaining('Failed to write SARIF'));
    });
  });

  describe('handleSarifOutput', () => {
    it('should return undefined when options are undefined', () => {
      const results = createMockScanResults([]);

      const result = handleSarifOutput(results, undefined);

      expect(result).toBeUndefined();
    });

    it('should return undefined when outputPath is empty', () => {
      const results = createMockScanResults([]);

      const result = handleSarifOutput(results, { outputPath: '' });

      expect(result).toBeUndefined();
    });

    it('should return path on success', () => {
      const results = createMockScanResults([createMockFinding()]);
      const outputPath = path.join(tempDir, 'results.sarif');

      const result = handleSarifOutput(results, { outputPath });

      expect(result).toBe(outputPath);
      expect(fs.existsSync(outputPath)).toBe(true);
    });

    it('should return undefined on failure', () => {
      const results = createMockScanResults([]);
      const invalidPath = '/nonexistent/readonly/path/results.sarif';

      const result = handleSarifOutput(results, { outputPath: invalidPath });

      expect(result).toBeUndefined();
    });
  });

  describe('SARIF validation', () => {
    it('should produce valid JSON that can be parsed', () => {
      const findings = [
        createMockFinding({ scanner: 'secrets', ruleId: 'SEC001' }),
        createMockFinding({ scanner: 'dependencies', ruleId: 'DEP-GHSA-1234', id: 'dep-finding' }),
        createMockFinding({ scanner: 'iac', ruleId: 'AVD-AWS-0086', id: 'iac-finding' }),
      ];
      const results = createMockScanResults(findings);
      const outputPath = path.join(tempDir, 'validation-test.sarif');

      writeSarifToFile(results, outputPath);

      // Read and parse
      const content = fs.readFileSync(outputPath, 'utf-8');
      const parsed = JSON.parse(content) as SarifLog;

      // Validate structure
      expect(parsed.$schema).toBeDefined();
      expect(parsed.version).toBe('2.1.0');
      expect(parsed.runs).toBeInstanceOf(Array);
      expect(parsed.runs[0]?.tool.driver).toBeDefined();
      expect(parsed.runs[0]?.results).toBeInstanceOf(Array);
    });

    it('should handle special characters in messages', () => {
      const finding = createMockFinding({
        message: 'Found "secret" with special chars: <>&',
        snippet: 'const x = "test<>&";',
      });
      const results = createMockScanResults([finding]);
      const outputPath = path.join(tempDir, 'special-chars.sarif');

      writeSarifToFile(results, outputPath);

      const content = fs.readFileSync(outputPath, 'utf-8');
      const parsed = JSON.parse(content);

      expect(parsed.runs[0].results[0].message.text).toContain('<>&');
    });

    it('should handle Unicode characters', () => {
      const finding = createMockFinding({
        message: 'Found token: 🔐 secret',
        title: 'API Key 🔑',
      });
      const results = createMockScanResults([finding]);
      const outputPath = path.join(tempDir, 'unicode.sarif');

      writeSarifToFile(results, outputPath);

      const content = fs.readFileSync(outputPath, 'utf-8');
      const parsed = JSON.parse(content);

      expect(parsed.runs[0].results[0].message.text).toContain('🔐');
    });
  });
});
