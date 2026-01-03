/**
 * @file Masking Utilities Tests
 * @description Unit tests for secret masking and snippet generation.
 *
 * Coverage targets:
 * - maskSecret(): 100%
 * - registerSecrets(): 100%
 * - maskSnippet(): 100%
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as core from '@actions/core';
import { maskSecret, registerSecrets, maskSnippet } from '../../../src/utils/masking';

// Mock @actions/core
vi.mock('@actions/core', () => ({
  setSecret: vi.fn(),
}));

describe('masking utilities', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('maskSecret', () => {
    it('masks long secrets keeping first 4 and last 2 characters', () => {
      const result = maskSecret('AKIAIOSFODNN7EXAMPLE');
      // 20 char input: 4 visible start + 14 masked + 2 visible end = 20
      expect(result).toMatch(/^AKIA\*+LE$/);
      expect(result).toHaveLength(20);
      expect(result).not.toContain('IOSFODNN7EXAM'); // Middle should be masked
    });

    it('masks medium-length secrets correctly', () => {
      const result = maskSecret('12345678');
      expect(result).toBe('1234**78');
      expect(result).toHaveLength(8);
    });

    it('fully masks short secrets (less than 8 characters)', () => {
      expect(maskSecret('short')).toBe('*****');
      expect(maskSecret('abc')).toBe('***');
      expect(maskSecret('a')).toBe('*');
    });

    it('returns empty string for empty input', () => {
      expect(maskSecret('')).toBe('');
    });

    it('returns empty string for null/undefined-like input', () => {
      expect(maskSecret(null as unknown as string)).toBe('');
      expect(maskSecret(undefined as unknown as string)).toBe('');
    });

    it('handles exactly 8 character secrets', () => {
      const result = maskSecret('abcdefgh');
      expect(result).toBe('abcd**gh');
    });

    it('handles secrets with special characters', () => {
      const result = maskSecret('abc123!@#$%^&*()xyz');
      expect(result).toContain('abc1');
      expect(result).toContain('yz');
      expect(result).toContain('*');
    });
  });

  describe('registerSecrets', () => {
    it('calls core.setSecret for each unique non-empty value', () => {
      registerSecrets(['secret1', 'secret2', 'secret3']);

      expect(core.setSecret).toHaveBeenCalledTimes(3);
      expect(core.setSecret).toHaveBeenCalledWith('secret1');
      expect(core.setSecret).toHaveBeenCalledWith('secret2');
      expect(core.setSecret).toHaveBeenCalledWith('secret3');
    });

    it('skips empty strings', () => {
      registerSecrets(['secret1', '', 'secret2']);

      expect(core.setSecret).toHaveBeenCalledTimes(2);
      expect(core.setSecret).toHaveBeenCalledWith('secret1');
      expect(core.setSecret).toHaveBeenCalledWith('secret2');
    });

    it('skips whitespace-only strings', () => {
      registerSecrets(['secret1', '   ', '\t\n', 'secret2']);

      expect(core.setSecret).toHaveBeenCalledTimes(2);
    });

    it('deduplicates values', () => {
      registerSecrets(['secret1', 'secret1', 'secret2', 'secret1']);

      expect(core.setSecret).toHaveBeenCalledTimes(2);
    });

    it('handles empty array', () => {
      registerSecrets([]);

      expect(core.setSecret).not.toHaveBeenCalled();
    });
  });

  describe('maskSnippet', () => {
    it('replaces matched secret with masked version', () => {
      const line = 'const apiKey = "AKIAIOSFODNN7EXAMPLE";';
      const result = maskSnippet(line, 'AKIAIOSFODNN7EXAMPLE');

      expect(result).toMatch(/const apiKey = "AKIA\*+LE";/);
      expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
    });

    it('truncates long lines with ellipsis', () => {
      const longLine = 'a'.repeat(200);
      const result = maskSnippet(longLine, 'notfound', 50);

      expect(result).toHaveLength(50);
      expect(result.endsWith('...')).toBe(true);
    });

    it('handles empty line', () => {
      expect(maskSnippet('', 'secret')).toBe('');
    });

    it('handles empty match', () => {
      const line = 'some code here';
      expect(maskSnippet(line, '')).toBe('some code here');
    });

    it('handles null inputs gracefully', () => {
      expect(maskSnippet(null as unknown as string, 'match')).toBe('');
      expect(maskSnippet('line', null as unknown as string)).toBe('line');
    });

    it('uses default max length of 120', () => {
      const longLine = 'x'.repeat(200);
      const result = maskSnippet(longLine, 'notfound');

      expect(result).toHaveLength(120);
    });

    it('preserves short lines under max length', () => {
      const line = 'short line';
      const result = maskSnippet(line, 'notfound');

      expect(result).toBe('short line');
    });
  });
});
