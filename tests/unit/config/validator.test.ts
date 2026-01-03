/**
 * @file Configuration Validator Tests
 * @description Unit tests for semantic configuration validation.
 *
 * Coverage targets:
 * - validateConfigSemantics(): 100%
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import * as core from '@actions/core';

import { validateConfigSemantics, ConfigSemanticError } from '../../../src/config/validator';
import { getDefaultConfig } from '../../../src/config/defaults';

// Mock @actions/core
vi.mock('@actions/core', () => ({
  warning: vi.fn(),
}));

describe('config validator', () => {
  let testDir: string;

  beforeEach(() => {
    vi.clearAllMocks();
    testDir = join(tmpdir(), `security-gate-validator-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('validateConfigSemantics', () => {
    describe('scanner enablement validation', () => {
      it('passes when at least one scanner is enabled', () => {
        const config = getDefaultConfig();
        config.scanners.secrets.enabled = true;
        config.scanners.dependencies.enabled = false;
        config.scanners.iac.enabled = false;
        config.scanners.container.enabled = false;

        expect(() => validateConfigSemantics(config)).not.toThrow();
      });

      it('throws when no scanners are enabled', () => {
        const config = getDefaultConfig();
        config.scanners.secrets.enabled = false;
        config.scanners.dependencies.enabled = false;
        config.scanners.iac.enabled = false;
        config.scanners.container.enabled = false;

        expect(() => validateConfigSemantics(config)).toThrow(ConfigSemanticError);
      });

      it('error message is actionable', () => {
        const config = getDefaultConfig();
        config.scanners.secrets.enabled = false;
        config.scanners.dependencies.enabled = false;
        config.scanners.iac.enabled = false;
        config.scanners.container.enabled = false;

        try {
          validateConfigSemantics(config);
          expect.fail('Should have thrown');
        } catch (error) {
          expect(error).toBeInstanceOf(ConfigSemanticError);
          expect((error as Error).message).toContain('enabled');
        }
      });
    });

    describe('path validation', () => {
      it('warns when secrets include_paths do not exist', () => {
        const config = getDefaultConfig();
        config.scanners.secrets.include_paths = ['nonexistent/path'];

        validateConfigSemantics(config, { workingDirectory: testDir });

        expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('include path'));
      });

      it('warns when container dockerfile_paths do not exist', () => {
        const config = getDefaultConfig();
        config.scanners.container.dockerfile_paths = ['docker/Dockerfile.prod'];

        validateConfigSemantics(config, { workingDirectory: testDir });

        expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Dockerfile path'));
      });

      it('does not warn when paths exist', () => {
        const config = getDefaultConfig();
        config.scanners.secrets.include_paths = ['src'];

        mkdirSync(join(testDir, 'src'), { recursive: true });

        validateConfigSemantics(config, { workingDirectory: testDir });

        expect(core.warning).not.toHaveBeenCalled();
      });

      it('skips path validation when validatePaths is false', () => {
        const config = getDefaultConfig();
        config.scanners.secrets.include_paths = ['nonexistent'];

        validateConfigSemantics(config, {
          workingDirectory: testDir,
          validatePaths: false,
        });

        expect(core.warning).not.toHaveBeenCalled();
      });
    });

    describe('default config validation', () => {
      it('default config passes validation', () => {
        const config = getDefaultConfig();

        expect(() => validateConfigSemantics(config)).not.toThrow();
      });
    });
  });
});
