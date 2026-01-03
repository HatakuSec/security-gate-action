/**
 * @file Configuration Loader Tests
 * @description Unit tests for the configuration loading and validation system.
 *
 * Coverage targets:
 * - loadConfig(): 100%
 * - mergeWithDefaults: 100%
 * - validateConfig(): 90%
 *
 * Key test scenarios:
 * - Valid YAML parsing
 * - Invalid YAML handling
 * - Schema validation errors
 * - Default value merging
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import * as core from '@actions/core';

import { loadConfig, ConfigParseError } from '../../../src/config/loader';
import { ConfigValidationError } from '../../../src/config/schema';
import { DEFAULT_CONFIG } from '../../../src/config/defaults';

// Mock @actions/core
vi.mock('@actions/core', () => ({
  debug: vi.fn(),
  warning: vi.fn(),
  info: vi.fn(),
}));

describe('config loader', () => {
  let testDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    testDir = join(tmpdir(), `security-gate-config-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('loadConfig', () => {
    describe('default config generation', () => {
      it('returns defaults when no config file exists', async () => {
        const result = await loadConfig({ workingDirectory: testDir });

        expect(result.usingDefaults).toBe(true);
        expect(result.configFile).toBeNull();
        expect(result.config).toEqual(DEFAULT_CONFIG);
      });

      it('emits debug message when using defaults', async () => {
        await loadConfig({ workingDirectory: testDir });

        expect(core.debug).toHaveBeenCalledWith(
          expect.stringContaining('No configuration file found')
        );
      });

      it('warns when explicit config path not found', async () => {
        await loadConfig({
          workingDirectory: testDir,
          configPath: 'custom-config.yml',
        });

        expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('not found'));
      });
    });

    describe('valid YAML parsing', () => {
      it('parses valid YAML configuration', async () => {
        const configContent = `
version: "1"
fail_on: medium
mode: explicit
scanners:
  secrets:
    enabled: true
  dependencies:
    enabled: false
`;
        writeFileSync(join(testDir, '.security-gate.yml'), configContent);

        const result = await loadConfig({ workingDirectory: testDir });

        expect(result.usingDefaults).toBe(false);
        expect(result.config.fail_on).toBe('medium');
        expect(result.config.mode).toBe('explicit');
        expect(result.config.scanners.secrets.enabled).toBe(true);
        expect(result.config.scanners.dependencies.enabled).toBe(false);
      });

      it('finds alternative config filenames', async () => {
        writeFileSync(join(testDir, '.security-gate.yaml'), 'version: "1"\nfail_on: low');

        const result = await loadConfig({ workingDirectory: testDir });

        expect(result.usingDefaults).toBe(false);
        expect(result.config.fail_on).toBe('low');
      });

      it('handles empty config file', async () => {
        writeFileSync(join(testDir, '.security-gate.yml'), '');

        const result = await loadConfig({ workingDirectory: testDir });

        expect(result.usingDefaults).toBe(true);
        expect(result.config).toEqual(DEFAULT_CONFIG);
      });

      it('handles config with only comments', async () => {
        writeFileSync(
          join(testDir, '.security-gate.yml'),
          '# This is a comment\n# Another comment'
        );

        const result = await loadConfig({ workingDirectory: testDir });

        expect(result.usingDefaults).toBe(true);
      });
    });

    describe('invalid YAML syntax', () => {
      it('throws ConfigParseError for invalid YAML', async () => {
        writeFileSync(join(testDir, '.security-gate.yml'), 'invalid: yaml: content:\n  - broken');

        await expect(loadConfig({ workingDirectory: testDir })).rejects.toThrow(ConfigParseError);
      });

      it('includes file path in parse error', async () => {
        writeFileSync(join(testDir, '.security-gate.yml'), 'invalid: yaml: : :bad');

        try {
          await loadConfig({ workingDirectory: testDir });
          expect.fail('Should have thrown');
        } catch (error) {
          expect(error).toBeInstanceOf(ConfigParseError);
          expect((error as ConfigParseError).filePath).toContain('.security-gate.yml');
        }
      });
    });

    describe('schema validation errors', () => {
      it('throws ConfigValidationError for invalid fail_on', async () => {
        writeFileSync(join(testDir, '.security-gate.yml'), 'version: "1"\nfail_on: critical');

        await expect(loadConfig({ workingDirectory: testDir })).rejects.toThrow(
          ConfigValidationError
        );
      });

      it('throws ConfigValidationError for invalid mode', async () => {
        writeFileSync(join(testDir, '.security-gate.yml'), 'version: "1"\nmode: manual');

        await expect(loadConfig({ workingDirectory: testDir })).rejects.toThrow(
          ConfigValidationError
        );
      });

      it('throws ConfigValidationError for invalid scanner enabled type', async () => {
        writeFileSync(
          join(testDir, '.security-gate.yml'),
          'version: "1"\nscanners:\n  secrets:\n    enabled: "yes"'
        );

        await expect(loadConfig({ workingDirectory: testDir })).rejects.toThrow(
          ConfigValidationError
        );
      });

      it('provides actionable error messages', async () => {
        writeFileSync(join(testDir, '.security-gate.yml'), 'version: "1"\nfail_on: invalid');

        try {
          await loadConfig({ workingDirectory: testDir });
          expect.fail('Should have thrown');
        } catch (error) {
          expect(error).toBeInstanceOf(ConfigValidationError);
          const validationError = error as ConfigValidationError;
          expect(validationError.formatErrors()).toContain('fail_on');
        }
      });
    });

    describe('merge behaviour', () => {
      it('merges user config with defaults', async () => {
        writeFileSync(join(testDir, '.security-gate.yml'), 'version: "1"\nfail_on: low');

        const result = await loadConfig({ workingDirectory: testDir });

        // User-specified value
        expect(result.config.fail_on).toBe('low');
        // Default values
        expect(result.config.mode).toBe('auto');
        expect(result.config.scanners.secrets.enabled).toBe(true);
      });

      it('user values override defaults', async () => {
        writeFileSync(
          join(testDir, '.security-gate.yml'),
          `
version: "1"
scanners:
  secrets:
    enabled: false
    exclude_paths:
      - "*.test.ts"
`
        );

        const result = await loadConfig({ workingDirectory: testDir });

        expect(result.config.scanners.secrets.enabled).toBe(false);
        expect(result.config.scanners.secrets.exclude_paths).toEqual(['*.test.ts']);
        // Other scanners still have defaults
        expect(result.config.scanners.dependencies.enabled).toBe(true);
      });

      it('partial scanner config merges correctly', async () => {
        writeFileSync(
          join(testDir, '.security-gate.yml'),
          `
version: "1"
scanners:
  dependencies:
    ignore_cves:
      - CVE-2021-1234
`
        );

        const result = await loadConfig({ workingDirectory: testDir });

        // Dependencies has user override
        expect(result.config.scanners.dependencies.ignore_cves).toEqual(['CVE-2021-1234']);
        expect(result.config.scanners.dependencies.enabled).toBe(true);
        // Other scanners are defaults
        expect(result.config.scanners.secrets.enabled).toBe(true);
      });
    });

    describe('custom config path', () => {
      it('loads from custom config path', async () => {
        mkdirSync(join(testDir, 'config'), { recursive: true });
        writeFileSync(join(testDir, 'config', 'security.yml'), 'version: "1"\nfail_on: medium');

        const result = await loadConfig({
          workingDirectory: testDir,
          configPath: 'config/security.yml',
        });

        expect(result.config.fail_on).toBe('medium');
        expect(result.configFile).toContain('security.yml');
      });
    });
  });
});
