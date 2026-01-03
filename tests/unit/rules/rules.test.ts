/**
 * @file Custom Rules Engine Tests
 * @description Unit tests for custom rule parsing, validation, and ReDoS protection.
 */

import { describe, it, expect } from 'vitest';
import {
  compileRules,
  compileRule,
  validateRegexSafety,
  fileMatchesGlobs,
  isMatchAllowlisted,
  RuleValidationError,
  UnsafeRegexError,
} from '../../../src/rules';
import type { CustomRule } from '../../../src/config/schema';

/**
 * Helper to create a valid custom rule with defaults.
 */
function createValidRule(overrides: Partial<CustomRule> = {}): CustomRule {
  return {
    id: 'TEST-001',
    name: 'Test Rule',
    type: 'secret',
    regex: 'TEST_[A-Z0-9]{10}',
    severity: 'medium',
    flags: 'g',
    ...overrides,
  };
}

describe('Custom Rules Engine', () => {
  describe('validateRegexSafety', () => {
    it('accepts simple patterns', () => {
      expect(() => validateRegexSafety('test', 'RULE-001')).not.toThrow();
      expect(() => validateRegexSafety('[A-Z]{10}', 'RULE-001')).not.toThrow();
      expect(() => validateRegexSafety('prefix_[a-z0-9]+_suffix', 'RULE-001')).not.toThrow();
    });

    it('rejects nested quantifiers: (a+)+', () => {
      expect(() => validateRegexSafety('(a+)+', 'RULE-001')).toThrow(UnsafeRegexError);
      expect(() => validateRegexSafety('(x*)*', 'RULE-001')).toThrow(UnsafeRegexError);
    });

    it('rejects nested quantifiers: complex example', () => {
      expect(() => validateRegexSafety('(\\w+)+', 'RULE-001')).toThrow(UnsafeRegexError);
    });

    it('rejects multiple greedy wildcards: .*.*', () => {
      expect(() => validateRegexSafety('.*.*', 'RULE-001')).toThrow(UnsafeRegexError);
      expect(() => validateRegexSafety('a.*.*b', 'RULE-001')).toThrow(UnsafeRegexError);
    });

    it('rejects alternation with quantifier', () => {
      expect(() => validateRegexSafety('(a|b)+', 'RULE-001')).toThrow(UnsafeRegexError);
      expect(() => validateRegexSafety('(foo|bar)*', 'RULE-001')).toThrow(UnsafeRegexError);
    });

    it('rejects patterns exceeding maximum length', () => {
      const longPattern = 'a'.repeat(600);
      expect(() => validateRegexSafety(longPattern, 'RULE-001')).toThrow(UnsafeRegexError);
    });

    it('rejects too many quantifiers', () => {
      // 15 quantifiers should exceed the limit of 10
      const pattern = 'a+b+c+d+e+f+g+h+i+j+k+';
      expect(() => validateRegexSafety(pattern, 'RULE-001')).toThrow(UnsafeRegexError);
    });

    it('rejects too many alternations', () => {
      // 20 alternations should exceed the limit of 15
      const parts = Array.from({ length: 20 }, (_, i) => `word${i}`);
      const pattern = parts.join('|');
      expect(() => validateRegexSafety(pattern, 'RULE-001')).toThrow(UnsafeRegexError);
    });

    it('rejects too deep nesting', () => {
      // 7 levels of nesting should exceed the limit of 5
      const pattern = '((((((a))))))';
      expect(() => validateRegexSafety(pattern, 'RULE-001')).toThrow(UnsafeRegexError);
    });

    it('rejects too many groups', () => {
      // 15 groups should exceed the limit of 10
      const pattern = '(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)(l)';
      expect(() => validateRegexSafety(pattern, 'RULE-001')).toThrow(UnsafeRegexError);
    });

    it('rejects adjacent quantified character classes', () => {
      expect(() => validateRegexSafety('[a-z]+[0-9]+', 'RULE-001')).toThrow(UnsafeRegexError);
    });
  });

  describe('compileRule', () => {
    it('compiles a valid rule', () => {
      const rule = createValidRule();
      const compiled = compileRule(rule);

      expect(compiled.id).toBe('TEST-001');
      expect(compiled.name).toBe('Test Rule');
      expect(compiled.severity).toBe('medium');
      expect(compiled.regex).toBeInstanceOf(RegExp);
      expect(compiled.isCustom).toBe(true);
    });

    it('preserves file globs', () => {
      const rule = createValidRule({ file_globs: ['*.ts', 'src/**/*.js'] });
      const compiled = compileRule(rule);

      expect(compiled.fileGlobs).toEqual(['*.ts', 'src/**/*.js']);
    });

    it('extracts allowlist patterns', () => {
      const rule = createValidRule({
        allowlist: [
          { pattern: 'TEST_ALLOWED001', reason: 'Test value' },
          { pattern: 'TEST_ALLOWED002' },
        ],
      });
      const compiled = compileRule(rule);

      expect(compiled.allowlist).toEqual(['TEST_ALLOWED001', 'TEST_ALLOWED002']);
    });

    it('throws on invalid regex syntax', () => {
      const rule = createValidRule({ regex: '[unclosed' });

      expect(() => compileRule(rule)).toThrow(RuleValidationError);
    });

    it('throws on unsafe regex', () => {
      const rule = createValidRule({ regex: '(a+)+' });

      expect(() => compileRule(rule)).toThrow(UnsafeRegexError);
    });

    it('applies flags correctly', () => {
      const rule = createValidRule({ regex: 'test', flags: 'gi' });
      const compiled = compileRule(rule);

      expect(compiled.regex.flags).toContain('g');
      expect(compiled.regex.flags).toContain('i');
    });
  });

  describe('compileRules', () => {
    it('compiles multiple valid rules', () => {
      const rules = [
        createValidRule({ id: 'RULE-001' }),
        createValidRule({ id: 'RULE-002', name: 'Second Rule' }),
      ];

      const compiled = compileRules(rules);

      expect(compiled).toHaveLength(2);
      expect(compiled[0].id).toBe('RULE-001');
      expect(compiled[1].id).toBe('RULE-002');
    });

    it('rejects duplicate rule IDs', () => {
      const rules = [createValidRule({ id: 'DUPE-001' }), createValidRule({ id: 'DUPE-001' })];

      expect(() => compileRules(rules)).toThrow(RuleValidationError);
      expect(() => compileRules(rules)).toThrow(/Duplicate rule ID/);
    });

    it('rejects too many rules', () => {
      const rules = Array.from({ length: 51 }, (_, i) =>
        createValidRule({ id: `RULE-${String(i).padStart(3, '0')}` })
      );

      expect(() => compileRules(rules)).toThrow(RuleValidationError);
      expect(() => compileRules(rules)).toThrow(/Too many custom rules/);
    });

    it('returns empty array for empty input', () => {
      const compiled = compileRules([]);
      expect(compiled).toEqual([]);
    });
  });

  describe('fileMatchesGlobs', () => {
    it('returns true when no globs specified', () => {
      expect(fileMatchesGlobs('any/file.ts', undefined)).toBe(true);
      expect(fileMatchesGlobs('any/file.ts', [])).toBe(true);
    });

    it('matches exact filename globs', () => {
      expect(fileMatchesGlobs('config.ts', ['config.ts'])).toBe(true);
      expect(fileMatchesGlobs('other.ts', ['config.ts'])).toBe(false);
    });

    it('matches wildcard globs', () => {
      expect(fileMatchesGlobs('config.ts', ['*.ts'])).toBe(true);
      expect(fileMatchesGlobs('config.js', ['*.ts'])).toBe(false);
    });

    it('matches double-star globs', () => {
      expect(fileMatchesGlobs('src/utils/config.ts', ['src/**/*.ts'])).toBe(true);
      expect(fileMatchesGlobs('tests/config.ts', ['src/**/*.ts'])).toBe(false);
    });

    it('matches against multiple globs (OR logic)', () => {
      expect(fileMatchesGlobs('file.ts', ['*.ts', '*.js'])).toBe(true);
      expect(fileMatchesGlobs('file.js', ['*.ts', '*.js'])).toBe(true);
      expect(fileMatchesGlobs('file.py', ['*.ts', '*.js'])).toBe(false);
    });
  });

  describe('isMatchAllowlisted', () => {
    it('returns false when no allowlist', () => {
      expect(isMatchAllowlisted('value', undefined)).toBe(false);
      expect(isMatchAllowlisted('value', [])).toBe(false);
    });

    it('matches exact values', () => {
      expect(isMatchAllowlisted('TEST_ALLOWED', ['TEST_ALLOWED'])).toBe(true);
      expect(isMatchAllowlisted('TEST_OTHER', ['TEST_ALLOWED'])).toBe(false);
    });

    it('matches substrings', () => {
      expect(isMatchAllowlisted('PREFIX_TEST_SUFFIX', ['TEST'])).toBe(true);
    });

    it('matches multiple patterns (OR logic)', () => {
      expect(isMatchAllowlisted('AAA', ['AAA', 'BBB'])).toBe(true);
      expect(isMatchAllowlisted('BBB', ['AAA', 'BBB'])).toBe(true);
      expect(isMatchAllowlisted('CCC', ['AAA', 'BBB'])).toBe(false);
    });
  });
});
