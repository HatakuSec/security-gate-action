/**
 * Exclusions and Allowlist Processing Tests
 *
 * Tests for global path exclusions and finding suppression via allowlist.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as core from '@actions/core';
import type { Finding } from '../../../src/scanners/types';
import type { AllowlistEntry, IgnoreConfig } from '../../../src/config/schema';
import {
  normaliseGlob,
  shouldIgnorePath,
  isAllowlistEntryExpired,
  applyAllowlist,
  warnExpiredEntries,
  getAllIgnorePatterns,
} from '../../../src/policy/exclusions';

// Mock @actions/core
vi.mock('@actions/core', () => ({
  warning: vi.fn(),
  debug: vi.fn(),
  info: vi.fn(),
}));

/**
 * Create a mock finding for testing.
 */
function createMockFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'test:TEST001:file.ts:1',
    severity: 'high',
    title: 'Test Finding',
    message: 'This is a test finding',
    file: 'src/file.ts',
    startLine: 1,
    endLine: 1,
    ruleId: 'TEST001',
    scanner: 'secrets',
    ...overrides,
  };
}

describe('exclusions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('normaliseGlob', () => {
    it('should return pattern unchanged when valid', () => {
      expect(normaliseGlob('**/*.ts')).toBe('**/*.ts');
      expect(normaliseGlob('src/**')).toBe('src/**');
      expect(normaliseGlob('*.md')).toBe('*.md');
    });

    it('should remove leading ./ from patterns', () => {
      expect(normaliseGlob('./*.ts')).toBe('*.ts');
      expect(normaliseGlob('./src/file.ts')).toBe('src/file.ts');
    });

    it('should reject path traversal attempts', () => {
      expect(normaliseGlob('../secrets.txt')).toBeNull();
      expect(normaliseGlob('src/../../../etc/passwd')).toBeNull();
      expect(normaliseGlob('..')).toBeNull();
    });

    it('should normalise Windows-style paths', () => {
      expect(normaliseGlob('src\\file.ts')).toBe('src/file.ts');
      expect(normaliseGlob('docs\\**\\*.md')).toBe('docs/**/*.md');
    });

    it('should remove double slashes', () => {
      expect(normaliseGlob('src//file.ts')).toBe('src/file.ts');
      expect(normaliseGlob('src///nested//file.ts')).toBe('src/nested/file.ts');
    });
  });

  describe('shouldIgnorePath', () => {
    it('should return false when no ignore config', () => {
      expect(shouldIgnorePath('src/file.ts')).toBe(false);
      expect(shouldIgnorePath('src/file.ts', undefined, undefined)).toBe(false);
    });

    it('should return false when ignore paths are empty', () => {
      const ignoreConfig: IgnoreConfig = { paths: [] };
      expect(shouldIgnorePath('src/file.ts', ignoreConfig)).toBe(false);
    });

    it('should match exact file paths', () => {
      const ignoreConfig: IgnoreConfig = { paths: ['README.md', 'docs/FIXTURES.md'] };
      expect(shouldIgnorePath('README.md', ignoreConfig)).toBe(true);
      expect(shouldIgnorePath('docs/FIXTURES.md', ignoreConfig)).toBe(true);
      expect(shouldIgnorePath('src/file.ts', ignoreConfig)).toBe(false);
    });

    it('should match glob patterns', () => {
      const ignoreConfig: IgnoreConfig = { paths: ['*.md', 'docs/**'] };
      // *.md only matches files in root (no subdirectories)
      expect(shouldIgnorePath('README.md', ignoreConfig)).toBe(true);
      // docs/** matches any file under docs/
      expect(shouldIgnorePath('docs/guide.md', ignoreConfig)).toBe(true);
      expect(shouldIgnorePath('docs/api/reference.ts', ignoreConfig)).toBe(true);
      expect(shouldIgnorePath('src/file.ts', ignoreConfig)).toBe(false);
    });

    it('should combine ignore config with global exclude paths', () => {
      const ignoreConfig: IgnoreConfig = { paths: ['*.md'] };
      const globalExcludePaths = ['tests/**', 'fixtures/**'];

      expect(shouldIgnorePath('README.md', ignoreConfig, globalExcludePaths)).toBe(true);
      expect(shouldIgnorePath('tests/test.ts', ignoreConfig, globalExcludePaths)).toBe(true);
      expect(shouldIgnorePath('fixtures/data.json', ignoreConfig, globalExcludePaths)).toBe(true);
      expect(shouldIgnorePath('src/main.ts', ignoreConfig, globalExcludePaths)).toBe(false);
    });

    it('should ignore invalid patterns with path traversal', () => {
      const ignoreConfig: IgnoreConfig = { paths: ['../secrets.txt', 'valid.md'] };
      // Invalid patterns are skipped, valid ones still work
      expect(shouldIgnorePath('valid.md', ignoreConfig)).toBe(true);
      expect(shouldIgnorePath('../secrets.txt', ignoreConfig)).toBe(false);
    });
  });

  describe('isAllowlistEntryExpired', () => {
    it('should return false when no expires date', () => {
      expect(isAllowlistEntryExpired(undefined)).toBe(false);
      expect(isAllowlistEntryExpired('')).toBe(false);
    });

    it('should return false for future dates', () => {
      const futureDate = new Date(Date.now() + 86400000).toISOString().split('T')[0];
      expect(isAllowlistEntryExpired(futureDate)).toBe(false);
    });

    it('should return true for past dates', () => {
      expect(isAllowlistEntryExpired('2020-01-01')).toBe(true);
      expect(isAllowlistEntryExpired('2023-01-01')).toBe(true);
    });

    it('should return true for today (expires at start of day)', () => {
      const today = new Date().toISOString().split('T')[0];
      // Today's date at midnight is considered expired since we're past midnight
      // This is the expected behaviour: date-only means "valid until midnight of that date"
      expect(isAllowlistEntryExpired(today)).toBe(true);
    });

    it('should handle ISO 8601 datetime format', () => {
      const futureDateTime = new Date(Date.now() + 86400000).toISOString();
      expect(isAllowlistEntryExpired(futureDateTime)).toBe(false);

      expect(isAllowlistEntryExpired('2020-01-01T00:00:00Z')).toBe(true);
    });

    it('should throw for invalid date formats', () => {
      expect(() => isAllowlistEntryExpired('not-a-date')).toThrow();
      expect(() => isAllowlistEntryExpired('2024/13/45')).toThrow();
    });
  });

  describe('applyAllowlist', () => {
    it('should return all findings when no allowlist', () => {
      const findings = [createMockFinding(), createMockFinding({ id: 'test:TEST002:file2.ts:1' })];

      const result = applyAllowlist(findings, undefined);

      expect(result.findings).toHaveLength(2);
      expect(result.suppressed).toHaveLength(0);
      expect(result.suppressedCount).toBe(0);
    });

    it('should return all findings when allowlist is empty', () => {
      const findings = [createMockFinding()];

      const result = applyAllowlist(findings, []);

      expect(result.findings).toHaveLength(1);
      expect(result.suppressed).toHaveLength(0);
    });

    it('should suppress finding by file path match', () => {
      const findings = [
        createMockFinding({ file: 'src/legacy/old-code.ts' }),
        createMockFinding({ file: 'src/new-code.ts', id: 'test:TEST001:new-code.ts:1' }),
      ];

      const allowlist: AllowlistEntry[] = [
        {
          id: 'allow-legacy',
          reason: 'Legacy code, will be removed',
          match: { path_glob: 'src/legacy/**' },
        },
      ];

      const result = applyAllowlist(findings, allowlist);

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.file).toBe('src/new-code.ts');
      expect(result.suppressed).toHaveLength(1);
      expect(result.suppressed[0]?.file).toBe('src/legacy/old-code.ts');
      expect(result.suppressedCount).toBe(1);
      expect(result.suppressedByScanner.secrets).toBe(1);
    });

    it('should suppress finding by rule_id match', () => {
      const findings = [
        createMockFinding({ ruleId: 'SEC001' }),
        createMockFinding({ ruleId: 'SEC002', id: 'test:SEC002:file.ts:1' }),
      ];

      const allowlist: AllowlistEntry[] = [
        {
          id: 'allow-sec001',
          reason: 'False positive in our codebase',
          match: { rule_id: 'SEC001' },
        },
      ];

      const result = applyAllowlist(findings, allowlist);

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.ruleId).toBe('SEC002');
      expect(result.suppressed).toHaveLength(1);
      expect(result.suppressed[0]?.ruleId).toBe('SEC001');
    });

    it('should suppress finding by finding_id match', () => {
      const findings = [
        createMockFinding({ id: 'secrets:SEC001:config.ts:42' }),
        createMockFinding({ id: 'secrets:SEC001:config.ts:100' }),
      ];

      const allowlist: AllowlistEntry[] = [
        {
          id: 'allow-specific',
          reason: 'This specific finding is a false positive',
          match: { finding_id: 'secrets:SEC001:config.ts:42' },
        },
      ];

      const result = applyAllowlist(findings, allowlist);

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.id).toBe('secrets:SEC001:config.ts:100');
      expect(result.suppressed).toHaveLength(1);
    });

    it('should suppress finding by scanner match', () => {
      const findings = [
        createMockFinding({ scanner: 'secrets' }),
        createMockFinding({ scanner: 'dependencies', id: 'deps:DEP001:package.json:1' }),
      ];

      const allowlist: AllowlistEntry[] = [
        {
          id: 'allow-all-deps',
          reason: 'Dependencies are tracked separately',
          match: { scanner: 'dependencies' },
        },
      ];

      const result = applyAllowlist(findings, allowlist);

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.scanner).toBe('secrets');
      expect(result.suppressedByScanner.dependencies).toBe(1);
    });

    it('should require all criteria to match when multiple specified', () => {
      const findings = [
        createMockFinding({ file: 'src/config.ts', ruleId: 'SEC001' }),
        createMockFinding({
          file: 'src/config.ts',
          ruleId: 'SEC002',
          id: 'test:SEC002:config.ts:1',
        }),
        createMockFinding({ file: 'src/other.ts', ruleId: 'SEC001', id: 'test:SEC001:other.ts:1' }),
      ];

      const allowlist: AllowlistEntry[] = [
        {
          id: 'allow-specific-combo',
          reason: 'SEC001 in config.ts is expected',
          match: { path_glob: 'src/config.ts', rule_id: 'SEC001' },
        },
      ];

      const result = applyAllowlist(findings, allowlist);

      expect(result.findings).toHaveLength(2);
      expect(result.suppressed).toHaveLength(1);
      expect(result.suppressed[0]?.ruleId).toBe('SEC001');
      expect(result.suppressed[0]?.file).toBe('src/config.ts');
    });

    it('should not suppress findings with expired allowlist entries', () => {
      const findings = [createMockFinding()];

      const allowlist: AllowlistEntry[] = [
        {
          id: 'expired-entry',
          reason: 'This used to be allowed',
          expires: '2020-01-01',
          match: { path_glob: '**/*' },
        },
      ];

      const result = applyAllowlist(findings, allowlist);

      expect(result.findings).toHaveLength(1);
      expect(result.suppressed).toHaveLength(0);
      expect(result.expiredEntries).toHaveLength(1);
      expect(result.expiredEntries[0]?.id).toBe('expired-entry');
    });

    it('should track suppressions by scanner', () => {
      const findings = [
        createMockFinding({ scanner: 'secrets' }),
        createMockFinding({ scanner: 'secrets', id: 'test:SEC002:file.ts:1' }),
        createMockFinding({ scanner: 'dependencies', id: 'deps:DEP001:package.json:1' }),
        createMockFinding({ scanner: 'iac', id: 'iac:IAC001:main.tf:1' }),
      ];

      const allowlist: AllowlistEntry[] = [
        {
          id: 'allow-all',
          reason: 'Suppress everything for testing',
          match: { path_glob: '**/*' },
        },
      ];

      const result = applyAllowlist(findings, allowlist);

      expect(result.suppressedByScanner.secrets).toBe(2);
      expect(result.suppressedByScanner.dependencies).toBe(1);
      expect(result.suppressedByScanner.iac).toBe(1);
      expect(result.suppressedCount).toBe(4);
    });

    it('should throw for invalid expiry date format', () => {
      const findings = [createMockFinding()];

      const allowlist: AllowlistEntry[] = [
        {
          id: 'invalid-date',
          reason: 'Has invalid date',
          expires: 'not-a-valid-date',
          match: { path_glob: '**/*' },
        },
      ];

      expect(() => applyAllowlist(findings, allowlist)).toThrow(
        /Allowlist entry 'invalid-date' has invalid expires date/
      );
    });

    it('should handle multiple allowlist entries', () => {
      const findings = [
        createMockFinding({ file: 'src/legacy.ts', ruleId: 'SEC001' }),
        createMockFinding({ file: 'tests/test.ts', ruleId: 'SEC002', id: 'test:SEC002:test.ts:1' }),
        createMockFinding({ file: 'src/new.ts', ruleId: 'SEC003', id: 'test:SEC003:new.ts:1' }),
      ];

      const allowlist: AllowlistEntry[] = [
        {
          id: 'allow-legacy',
          reason: 'Legacy code',
          match: { path_glob: 'src/legacy.ts' },
        },
        {
          id: 'allow-tests',
          reason: 'Test files',
          match: { path_glob: 'tests/**' },
        },
      ];

      const result = applyAllowlist(findings, allowlist);

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.file).toBe('src/new.ts');
      expect(result.suppressed).toHaveLength(2);
    });
  });

  describe('warnExpiredEntries', () => {
    it('should emit warning for each expired entry', () => {
      const expiredEntries: AllowlistEntry[] = [
        {
          id: 'expired-1',
          reason: 'Test entry 1',
          expires: '2020-01-01',
          match: { path_glob: '**/*' },
        },
        {
          id: 'expired-2',
          reason: 'Test entry 2',
          expires: '2021-06-15',
          match: { rule_id: 'SEC001' },
        },
      ];

      warnExpiredEntries(expiredEntries);

      expect(core.warning).toHaveBeenCalledTimes(2);
      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining("Allowlist entry 'expired-1' has expired")
      );
      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining("Allowlist entry 'expired-2' has expired")
      );
    });

    it('should not emit warnings when no expired entries', () => {
      warnExpiredEntries([]);

      expect(core.warning).not.toHaveBeenCalled();
    });
  });

  describe('getAllIgnorePatterns', () => {
    it('should return empty array when no config', () => {
      expect(getAllIgnorePatterns()).toEqual([]);
      expect(getAllIgnorePatterns(undefined, undefined)).toEqual([]);
    });

    it('should return patterns from ignore config', () => {
      const ignoreConfig: IgnoreConfig = { paths: ['*.md', 'docs/**'] };

      const patterns = getAllIgnorePatterns(ignoreConfig);

      expect(patterns).toContain('*.md');
      expect(patterns).toContain('docs/**');
    });

    it('should return patterns from global exclude paths', () => {
      const globalPaths = ['tests/**', 'fixtures/**'];

      const patterns = getAllIgnorePatterns(undefined, globalPaths);

      expect(patterns).toContain('tests/**');
      expect(patterns).toContain('fixtures/**');
    });

    it('should combine patterns from both sources', () => {
      const ignoreConfig: IgnoreConfig = { paths: ['*.md'] };
      const globalPaths = ['tests/**'];

      const patterns = getAllIgnorePatterns(ignoreConfig, globalPaths);

      expect(patterns).toContain('*.md');
      expect(patterns).toContain('tests/**');
      expect(patterns).toHaveLength(2);
    });

    it('should filter out invalid patterns', () => {
      const ignoreConfig: IgnoreConfig = { paths: ['valid.md', '../invalid.txt'] };

      const patterns = getAllIgnorePatterns(ignoreConfig);

      expect(patterns).toContain('valid.md');
      expect(patterns).not.toContain('../invalid.txt');
      expect(patterns).toHaveLength(1);
    });

    it('should normalise patterns', () => {
      const ignoreConfig: IgnoreConfig = { paths: ['./*.md', 'docs//nested//file.ts'] };

      const patterns = getAllIgnorePatterns(ignoreConfig);

      expect(patterns).toContain('*.md');
      expect(patterns).toContain('docs/nested/file.ts');
    });
  });
});
