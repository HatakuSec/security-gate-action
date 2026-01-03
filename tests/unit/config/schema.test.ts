/**
 * @file Configuration Schema Tests
 * @description Unit tests for Zod schema validation.
 *
 * Coverage targets:
 * - validateConfig(): 100%
 * - Schema definitions: 100%
 */

import { describe, it, expect } from 'vitest';
import {
  validateConfig,
  ConfigValidationError,
  RootConfigSchema,
  SeveritySchema,
  ModeSchema,
  CustomRuleSchema,
  AllowlistEntrySchema,
  RULE_LIMITS,
} from '../../../src/config/schema';

describe('config schema', () => {
  describe('SeveritySchema', () => {
    it('accepts valid severity values', () => {
      expect(SeveritySchema.parse('high')).toBe('high');
      expect(SeveritySchema.parse('medium')).toBe('medium');
      expect(SeveritySchema.parse('low')).toBe('low');
    });

    it('rejects invalid severity values', () => {
      expect(() => SeveritySchema.parse('critical')).toThrow();
      expect(() => SeveritySchema.parse('HIGH')).toThrow();
      expect(() => SeveritySchema.parse('')).toThrow();
    });
  });

  describe('ModeSchema', () => {
    it('accepts valid mode values', () => {
      expect(ModeSchema.parse('auto')).toBe('auto');
      expect(ModeSchema.parse('explicit')).toBe('explicit');
    });

    it('rejects invalid mode values', () => {
      expect(() => ModeSchema.parse('manual')).toThrow();
      expect(() => ModeSchema.parse('AUTO')).toThrow();
    });
  });

  describe('RootConfigSchema', () => {
    it('applies defaults for missing fields', () => {
      const result = RootConfigSchema.parse({});

      expect(result.version).toBe('1');
      expect(result.fail_on).toBe('high');
      expect(result.mode).toBe('auto');
      expect(result.scanners.secrets.enabled).toBe(true);
      expect(result.scanners.dependencies.enabled).toBe(true);
      expect(result.scanners.iac.enabled).toBe(true);
      expect(result.scanners.container.enabled).toBe(true);
    });

    it('accepts complete valid configuration', () => {
      const config = {
        version: '1',
        fail_on: 'medium',
        mode: 'explicit',
        scanners: {
          secrets: {
            enabled: false,
            exclude_paths: ['*.test.ts'],
          },
          dependencies: {
            enabled: true,
            ignore_cves: ['CVE-2021-1234'],
          },
          iac: {
            enabled: true,
            skip_checks: ['AVD-AWS-0001'],
          },
          container: {
            enabled: false,
            dockerfile_paths: ['docker/Dockerfile'],
          },
        },
      };

      const result = RootConfigSchema.parse(config);

      expect(result.fail_on).toBe('medium');
      expect(result.scanners.secrets.enabled).toBe(false);
      expect(result.scanners.secrets.exclude_paths).toEqual(['*.test.ts']);
      expect(result.scanners.dependencies.ignore_cves).toEqual(['CVE-2021-1234']);
    });

    it('handles partial scanner configuration', () => {
      const config = {
        scanners: {
          secrets: {
            enabled: false,
          },
        },
      };

      const result = RootConfigSchema.parse(config);

      expect(result.scanners.secrets.enabled).toBe(false);
      expect(result.scanners.dependencies.enabled).toBe(true); // Default
    });
  });

  describe('validateConfig', () => {
    it('returns validated config for valid input', () => {
      const config = validateConfig({
        version: '1',
        fail_on: 'high',
        mode: 'auto',
      });

      expect(config.version).toBe('1');
      expect(config.fail_on).toBe('high');
      expect(config.mode).toBe('auto');
    });

    it('throws ConfigValidationError for invalid input', () => {
      expect(() =>
        validateConfig({
          fail_on: 'invalid',
        })
      ).toThrow(ConfigValidationError);
    });

    it('provides access to validation errors', () => {
      try {
        validateConfig({ fail_on: 'invalid', mode: 'bad' });
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ConfigValidationError);
        const validationError = error as ConfigValidationError;
        expect(validationError.errors.length).toBeGreaterThan(0);
      }
    });

    it('formats errors as readable string', () => {
      try {
        validateConfig({ fail_on: 'invalid' });
        expect.fail('Should have thrown');
      } catch (error) {
        const validationError = error as ConfigValidationError;
        const formatted = validationError.formatErrors();

        expect(formatted).toContain('fail_on');
      }
    });
  });

  // ==========================================================================
  // Advanced Schema Tests: Custom Rules, Ignore, Allowlist
  // ==========================================================================

  describe('CustomRuleSchema', () => {
    it('accepts a valid custom rule', () => {
      const rule = {
        id: 'CUSTOM-001',
        name: 'Custom Token Pattern',
        regex: 'TOKEN_[A-Z0-9]{16}',
        type: 'secret',
      };

      const result = CustomRuleSchema.parse(rule);

      expect(result.id).toBe('CUSTOM-001');
      expect(result.name).toBe('Custom Token Pattern');
      expect(result.severity).toBe('medium'); // default
      expect(result.flags).toBe('g'); // default
    });

    it('rejects invalid rule ID pattern', () => {
      expect(() =>
        CustomRuleSchema.parse({
          id: 'lowercase',
          name: 'Test',
          regex: 'test',
        })
      ).toThrow();

      expect(() =>
        CustomRuleSchema.parse({
          id: 'ab', // too short
          name: 'Test',
          regex: 'test',
        })
      ).toThrow();
    });

    it('rejects ID exceeding maximum length', () => {
      const longId = 'A'.repeat(RULE_LIMITS.MAX_RULE_ID_LENGTH + 1);
      expect(() =>
        CustomRuleSchema.parse({
          id: longId,
          name: 'Test',
          regex: 'test',
        })
      ).toThrow();
    });

    it('rejects regex exceeding maximum length', () => {
      const longRegex = 'a'.repeat(RULE_LIMITS.MAX_REGEX_LENGTH + 1);
      expect(() =>
        CustomRuleSchema.parse({
          id: 'RULE-001',
          name: 'Test',
          regex: longRegex,
        })
      ).toThrow();
    });

    it('rejects invalid flags', () => {
      expect(() =>
        CustomRuleSchema.parse({
          id: 'RULE-001',
          name: 'Test',
          regex: 'test',
          flags: 'gx', // x is not allowed
        })
      ).toThrow();
    });

    it('accepts valid flags', () => {
      const result = CustomRuleSchema.parse({
        id: 'RULE-001',
        name: 'Test',
        regex: 'test',
        flags: 'gim',
      });

      expect(result.flags).toBe('gim');
    });

    it('rejects too many file globs', () => {
      const tooManyGlobs = Array.from({ length: 30 }, (_, i) => `*.ext${i}`);
      expect(() =>
        CustomRuleSchema.parse({
          id: 'RULE-001',
          name: 'Test',
          regex: 'test',
          file_globs: tooManyGlobs,
        })
      ).toThrow();
    });

    it('accepts rule with inline allowlist', () => {
      const result = CustomRuleSchema.parse({
        id: 'RULE-001',
        name: 'Test',
        regex: 'test',
        allowlist: [{ pattern: 'TEST_ALLOWED', reason: 'Test value' }],
      });

      expect(result.allowlist).toHaveLength(1);
      expect(result.allowlist![0].pattern).toBe('TEST_ALLOWED');
    });
  });

  describe('AllowlistEntrySchema', () => {
    it('accepts a valid allowlist entry', () => {
      const entry = {
        id: 'allow-001',
        reason: 'Known safe value for testing',
        match: {
          scanner: 'secrets',
          rule_id: 'SEC001',
        },
      };

      const result = AllowlistEntrySchema.parse(entry);

      expect(result.id).toBe('allow-001');
      expect(result.reason).toBe('Known safe value for testing');
      expect(result.match?.scanner).toBe('secrets');
    });

    it('accepts entry with valid expiry date', () => {
      const result = AllowlistEntrySchema.parse({
        id: 'allow-002',
        reason: 'Temporary exception',
        expires: '2026-03-01',
        match: { scanner: 'secrets' },
      });

      expect(result.expires).toBe('2026-03-01');
    });

    it('rejects invalid expiry date format', () => {
      expect(() =>
        AllowlistEntrySchema.parse({
          id: 'allow-003',
          reason: 'Test',
          expires: 'not-a-date',
          match: { scanner: 'secrets' },
        })
      ).toThrow();
    });

    it('requires at least one match criterion', () => {
      expect(() =>
        AllowlistEntrySchema.parse({
          id: 'allow-004',
          reason: 'Test',
          match: {}, // empty match
        })
      ).toThrow();
    });

    it('accepts entry with path glob match', () => {
      const result = AllowlistEntrySchema.parse({
        id: 'allow-005',
        reason: 'Ignore test files',
        match: { path_glob: 'tests/**/*.ts' },
      });

      expect(result.match?.path_glob).toBe('tests/**/*.ts');
    });

    it('accepts entry with finding_id match', () => {
      const result = AllowlistEntrySchema.parse({
        id: 'allow-006',
        reason: 'Ignore specific finding',
        match: { finding_id: 'secrets:SEC001:file.ts:10' },
      });

      expect(result.match?.finding_id).toBe('secrets:SEC001:file.ts:10');
    });
  });

  describe('RootConfigSchema advanced fields', () => {
    it('accepts config with custom rules', () => {
      const config = {
        version: '1',
        rules: [
          {
            id: 'CUSTOM-001',
            name: 'Internal Token',
            regex: 'INT_[A-Z0-9]{20}',
          },
        ],
      };

      const result = RootConfigSchema.parse(config);

      expect(result.rules).toHaveLength(1);
      expect(result.rules![0].id).toBe('CUSTOM-001');
    });

    it('accepts config with exclude_paths', () => {
      const config = {
        version: '1',
        exclude_paths: ['*.test.ts', 'fixtures/**'],
      };

      const result = RootConfigSchema.parse(config);

      expect(result.exclude_paths).toEqual(['*.test.ts', 'fixtures/**']);
    });

    it('accepts config with ignore', () => {
      const config = {
        version: '1',
        ignore: {
          paths: ['vendor/**', 'node_modules/**'],
        },
      };

      const result = RootConfigSchema.parse(config);

      expect(result.ignore?.paths).toEqual(['vendor/**', 'node_modules/**']);
    });

    it('accepts config with allowlist', () => {
      const config = {
        version: '1',
        allowlist: [
          {
            id: 'test-allow-1',
            reason: 'Test exception',
            match: { scanner: 'secrets' },
          },
        ],
      };

      const result = RootConfigSchema.parse(config);

      expect(result.allowlist).toHaveLength(1);
    });

    it('rejects too many allowlist entries', () => {
      const tooMany = Array.from({ length: 201 }, (_, i) => ({
        id: `allow-${i}`,
        reason: 'Test',
        match: { scanner: 'secrets' as const },
      }));

      expect(() =>
        RootConfigSchema.parse({
          version: '1',
          allowlist: tooMany,
        })
      ).toThrow();
    });
  });
});
