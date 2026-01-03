/**
 * @file Secret Pattern Tests
 * @description Tests for individual secret detection patterns (SEC001-SEC010)
 */

import { describe, it, expect } from 'vitest';
import {
  SECRET_PATTERNS,
  getPatternById,
  getPatternsBySeverity,
} from '../../../../src/scanners/secrets/patterns';

describe('Secret Patterns', () => {
  describe('pattern collection', () => {
    it('contains all 10 patterns', () => {
      expect(SECRET_PATTERNS).toHaveLength(10);
    });

    it('has unique IDs', () => {
      const ids = SECRET_PATTERNS.map((p) => p.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it('all patterns have required fields', () => {
      for (const pattern of SECRET_PATTERNS) {
        expect(pattern.id).toMatch(/^SEC\d{3}$/);
        expect(pattern.name).toBeTruthy();
        expect(pattern.regex).toBeInstanceOf(RegExp);
        expect(['high', 'medium', 'low']).toContain(pattern.severity);
        expect(pattern.message).toBeTruthy();
      }
    });
  });

  describe('getPatternById', () => {
    it('returns pattern for valid ID', () => {
      const pattern = getPatternById('SEC001');
      expect(pattern).toBeDefined();
      expect(pattern?.name).toBe('AWS Access Key');
    });

    it('returns undefined for invalid ID', () => {
      expect(getPatternById('SEC999')).toBeUndefined();
      expect(getPatternById('INVALID')).toBeUndefined();
    });
  });

  describe('getPatternsBySeverity', () => {
    it('returns high severity patterns', () => {
      const highPatterns = getPatternsBySeverity('high');
      expect(highPatterns.length).toBeGreaterThan(0);
      highPatterns.forEach((p) => expect(p.severity).toBe('high'));
    });

    it('returns medium severity patterns', () => {
      const mediumPatterns = getPatternsBySeverity('medium');
      expect(mediumPatterns.length).toBeGreaterThan(0);
      mediumPatterns.forEach((p) => expect(p.severity).toBe('medium'));
    });
  });

  describe('SEC001 - AWS Access Key', () => {
    const pattern = getPatternById('SEC001')!;

    it('matches valid AWS access key', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('AKIAIOSFODNN7EXAMPLE')).toBe(true);
    });

    it('matches access key in context', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('aws_access_key_id = AKIAI44QH8DHBEXAMPLE')).toBe(true);
    });

    it('does not match short key', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('AKIA123')).toBe(false);
    });

    it('does not match wrong prefix', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('BKIAIOSFODNN7EXAMPLE')).toBe(false);
    });

    it('does not match lowercase', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('akiaiosfodnn7example')).toBe(false);
    });
  });

  describe('SEC002 - AWS Secret Key', () => {
    const pattern = getPatternById('SEC002')!;

    it('matches single-quoted secret key', () => {
      pattern.regex.lastIndex = 0;
      expect(
        pattern.regex.test("aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'")
      ).toBe(true);
    });

    it('matches double-quoted secret key', () => {
      pattern.regex.lastIndex = 0;
      expect(
        pattern.regex.test('aws_secret_access_key = "abcdefghijABCDEFGHIJ0123456789+/EXAMPLE="')
      ).toBe(true);
    });

    it('is case insensitive for key name', () => {
      pattern.regex.lastIndex = 0;
      expect(
        pattern.regex.test("AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'")
      ).toBe(true);
    });

    it('does not match without quotes', () => {
      pattern.regex.lastIndex = 0;
      expect(
        pattern.regex.test('aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
      ).toBe(false);
    });
  });

  describe('SEC003 - GitHub Token (classic PAT)', () => {
    const pattern = getPatternById('SEC003')!;

    it('matches valid GitHub PAT', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789')).toBe(true);
    });

    it('matches in code context', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('const token = "ghp_TestTokenForSecurityGateScannerABC123";')).toBe(
        true
      );
    });

    it('does not match short token', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('ghp_abc123')).toBe(false);
    });

    it('does not match wrong prefix', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('ghx_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789')).toBe(false);
    });
  });

  describe('SEC004 - GitHub OAuth Token', () => {
    const pattern = getPatternById('SEC004')!;

    it('matches valid GitHub OAuth token', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('gho_xYzAbCdEfGhIjKlMnOpQrStUvWxYz0123456')).toBe(true);
    });

    it('does not match short token', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('gho_short')).toBe(false);
    });
  });

  describe('SEC005 - GitHub Fine-Grained PAT', () => {
    const pattern = getPatternById('SEC005')!;

    it('matches valid fine-grained PAT', () => {
      pattern.regex.lastIndex = 0;
      expect(
        pattern.regex.test(
          'github_pat_11ABCDEFGHIJKLMNOPQRST_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijklmnopqrstuvwxyzABC'
        )
      ).toBe(true);
    });

    it('does not match incomplete token', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('github_pat_11ABCDEFGH')).toBe(false);
    });
  });

  describe('SEC006 - Private Key', () => {
    const pattern = getPatternById('SEC006')!;

    it('matches RSA private key header', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
    });

    it('matches EC private key header', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('-----BEGIN EC PRIVATE KEY-----')).toBe(true);
    });

    it('matches OpenSSH private key header', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('-----BEGIN OPENSSH PRIVATE KEY-----')).toBe(true);
    });

    it('does not match public key', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('-----BEGIN PUBLIC KEY-----')).toBe(false);
    });
  });

  describe('SEC007 - Generic API Key', () => {
    const pattern = getPatternById('SEC007')!;

    it('matches api_key assignment', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test("api_key = 'abcdefghij1234567890abcdef'")).toBe(true);
    });

    it('matches apiKey with colon', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('apiKey: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"')).toBe(true);
    });

    it('matches API-KEY format', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test("API-KEY = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'")).toBe(true);
    });

    it('does not match short value', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test("api_key = 'short'")).toBe(false);
    });

    it('is case insensitive', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test("API_KEY = 'abcdefghij1234567890abcdef'")).toBe(true);
    });
  });

  describe('SEC008 - Generic Secret', () => {
    const pattern = getPatternById('SEC008')!;

    it('matches secret assignment', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test("secret = 'mysecretvalue123'")).toBe(true);
    });

    it('matches password assignment', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('password = "SuperSecretPass123!"')).toBe(true);
    });

    it('matches passwd assignment', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test("passwd: 'anotherPassword99'")).toBe(true);
    });

    it('does not match short value (under 8 chars)', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test("password = 'short'")).toBe(false);
    });

    it('is case insensitive for key name', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test("SECRET = 'mysecretvalue123'")).toBe(true);
    });
  });

  describe('SEC009 - Slack Token', () => {
    const pattern = getPatternById('SEC009')!;

    it('matches xoxb bot token', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('xoxb-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx')).toBe(
        true
      );
    });

    it('matches xoxp user token', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('xoxp-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx')).toBe(
        true
      );
    });

    it('matches xoxa app token', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('xoxa-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx')).toBe(
        true
      );
    });

    it('does not match invalid prefix', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('xoxz-123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx')).toBe(
        false
      );
    });

    it('does not match short numbers', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('xoxb-12345-12345-AbCdEfGhIjKlMnOpQrStUvWx')).toBe(false);
    });
  });

  describe('SEC010 - Stripe Live Key', () => {
    const pattern = getPatternById('SEC010')!;

    it('matches valid Stripe live key', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('sk_live_AbCdEfGhIjKlMnOpQrStUvWx')).toBe(true);
    });

    it('does not match test key', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('sk_test_AbCdEfGhIjKlMnOpQrStUvWx')).toBe(false);
    });

    it('does not match short key', () => {
      pattern.regex.lastIndex = 0;
      expect(pattern.regex.test('sk_live_abc123')).toBe(false);
    });
  });
});
