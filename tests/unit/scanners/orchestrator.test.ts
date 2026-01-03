/**
 * @file Scanner Orchestrator Tests
 * @description Unit tests for scanner orchestration and detection.
 *
 * Coverage targets:
 * - runScanners(): 90%
 * - determineScanners(): 100%
 * - Detection heuristics: 90%
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import * as core from '@actions/core';

import {
  runScanners,
  determineScanners,
  hasLockfiles,
  hasIaCFiles,
  hasContainerFiles,
} from '../../../src/scanners/orchestrator';
import { getDefaultConfig } from '../../../src/config/defaults';

// Mock @actions/core
vi.mock('@actions/core', () => ({
  debug: vi.fn(),
  info: vi.fn(),
  warning: vi.fn(),
}));

describe('scanner orchestrator', () => {
  let testDir: string;
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.clearAllMocks();
    testDir = join(tmpdir(), `security-gate-orchestrator-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });

    // Mock fetch to prevent real OSV API calls
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ results: [] }),
    });
  });

  afterEach(() => {
    // Restore original fetch
    globalThis.fetch = originalFetch;

    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('detection heuristics', () => {
    describe('hasLockfiles', () => {
      it('detects package-lock.json', () => {
        writeFileSync(join(testDir, 'package-lock.json'), '{}');

        expect(hasLockfiles(testDir)).toBe(true);
      });

      it('detects yarn.lock', () => {
        writeFileSync(join(testDir, 'yarn.lock'), '');

        expect(hasLockfiles(testDir)).toBe(true);
      });

      it('detects pnpm-lock.yaml', () => {
        writeFileSync(join(testDir, 'pnpm-lock.yaml'), '');

        expect(hasLockfiles(testDir)).toBe(true);
      });

      it('detects requirements.txt', () => {
        writeFileSync(join(testDir, 'requirements.txt'), '');

        expect(hasLockfiles(testDir)).toBe(true);
      });

      it('detects Pipfile.lock', () => {
        writeFileSync(join(testDir, 'Pipfile.lock'), '{}');

        expect(hasLockfiles(testDir)).toBe(true);
      });

      it('detects go.sum', () => {
        writeFileSync(join(testDir, 'go.sum'), '');

        expect(hasLockfiles(testDir)).toBe(true);
      });

      it('returns false when no lockfiles present', () => {
        expect(hasLockfiles(testDir)).toBe(false);
      });
    });

    describe('hasIaCFiles', () => {
      it('detects main.tf', () => {
        writeFileSync(join(testDir, 'main.tf'), '');

        expect(hasIaCFiles(testDir)).toBe(true);
      });

      it('detects .tf files in root', () => {
        writeFileSync(join(testDir, 'providers.tf'), '');

        expect(hasIaCFiles(testDir)).toBe(true);
      });

      it('detects kubernetes directory', () => {
        mkdirSync(join(testDir, 'kubernetes'), { recursive: true });

        expect(hasIaCFiles(testDir)).toBe(true);
      });

      it('detects k8s directory', () => {
        mkdirSync(join(testDir, 'k8s'), { recursive: true });

        expect(hasIaCFiles(testDir)).toBe(true);
      });

      it('detects terraform directory', () => {
        mkdirSync(join(testDir, 'terraform'), { recursive: true });

        expect(hasIaCFiles(testDir)).toBe(true);
      });

      it('detects Chart.yaml (Helm)', () => {
        writeFileSync(join(testDir, 'Chart.yaml'), '');

        expect(hasIaCFiles(testDir)).toBe(true);
      });

      it('returns false when no IaC files present', () => {
        writeFileSync(join(testDir, 'index.ts'), '');

        expect(hasIaCFiles(testDir)).toBe(false);
      });
    });

    describe('hasContainerFiles', () => {
      it('detects Dockerfile', () => {
        writeFileSync(join(testDir, 'Dockerfile'), '');

        expect(hasContainerFiles(testDir)).toBe(true);
      });

      it('detects docker-compose.yml', () => {
        writeFileSync(join(testDir, 'docker-compose.yml'), '');

        expect(hasContainerFiles(testDir)).toBe(true);
      });

      it('detects docker-compose.yaml', () => {
        writeFileSync(join(testDir, 'docker-compose.yaml'), '');

        expect(hasContainerFiles(testDir)).toBe(true);
      });

      it('returns false when no container files present', () => {
        expect(hasContainerFiles(testDir)).toBe(false);
      });
    });
  });

  describe('determineScanners', () => {
    describe('explicit mode', () => {
      it('runs only enabled scanners regardless of detection', () => {
        const config = getDefaultConfig();
        config.mode = 'explicit';
        config.scanners.secrets.enabled = true;
        config.scanners.dependencies.enabled = false;
        config.scanners.iac.enabled = true;
        config.scanners.container.enabled = false;

        const result = determineScanners(config, testDir);

        expect(result).toEqual(['secrets', 'iac']);
      });

      it('returns empty array when all scanners disabled', () => {
        const config = getDefaultConfig();
        config.mode = 'explicit';
        config.scanners.secrets.enabled = false;
        config.scanners.dependencies.enabled = false;
        config.scanners.iac.enabled = false;
        config.scanners.container.enabled = false;

        const result = determineScanners(config, testDir);

        expect(result).toEqual([]);
      });
    });

    describe('auto mode', () => {
      it('runs secrets scanner when enabled (always has text files)', () => {
        const config = getDefaultConfig();
        config.mode = 'auto';

        const result = determineScanners(config, testDir);

        expect(result).toContain('secrets');
      });

      it('runs dependencies scanner when lockfiles present', () => {
        writeFileSync(join(testDir, 'package-lock.json'), '{}');
        const config = getDefaultConfig();
        config.mode = 'auto';

        const result = determineScanners(config, testDir);

        expect(result).toContain('dependencies');
      });

      it('skips dependencies scanner when no lockfiles present', () => {
        const config = getDefaultConfig();
        config.mode = 'auto';

        const result = determineScanners(config, testDir);

        expect(result).not.toContain('dependencies');
      });

      it('runs iac scanner when IaC files present', () => {
        writeFileSync(join(testDir, 'main.tf'), '');
        const config = getDefaultConfig();
        config.mode = 'auto';

        const result = determineScanners(config, testDir);

        expect(result).toContain('iac');
      });

      it('runs container scanner when Dockerfile present', () => {
        writeFileSync(join(testDir, 'Dockerfile'), '');
        const config = getDefaultConfig();
        config.mode = 'auto';

        const result = determineScanners(config, testDir);

        expect(result).toContain('container');
      });

      it('respects enabled flags even in auto mode', () => {
        writeFileSync(join(testDir, 'Dockerfile'), '');
        const config = getDefaultConfig();
        config.mode = 'auto';
        config.scanners.container.enabled = false;

        const result = determineScanners(config, testDir);

        expect(result).not.toContain('container');
      });
    });
  });

  describe('runScanners', () => {
    it('returns empty results when no scanners to run', async () => {
      const config = getDefaultConfig();
      config.mode = 'auto';
      config.scanners.secrets.enabled = false;
      // No lockfiles, IaC, or container files

      const result = await runScanners(config, {
        workingDirectory: testDir,
        verbose: false,
      });

      expect(result.totalFindings).toBe(0);
      expect(result.scanners).toHaveLength(0);
      expect(result.hasErrors).toBe(false);
    });

    it('runs all applicable scanners', async () => {
      writeFileSync(join(testDir, 'package-lock.json'), '{}');
      writeFileSync(join(testDir, 'Dockerfile'), '');
      const config = getDefaultConfig();
      config.mode = 'auto';

      const result = await runScanners(config, {
        workingDirectory: testDir,
        verbose: false,
      });

      const scannerNames = result.scanners.map((s) => s.name);
      expect(scannerNames).toContain('secrets');
      expect(scannerNames).toContain('dependencies');
      expect(scannerNames).toContain('container');
    }, 30000);

    it('continues running other scanners when one fails', async () => {
      // This tests the error handling - stub scanners don't fail,
      // but we can verify the structure is correct
      const config = getDefaultConfig();
      config.mode = 'explicit';
      config.scanners.secrets.enabled = true;
      config.scanners.dependencies.enabled = true;
      config.scanners.iac.enabled = false;
      config.scanners.container.enabled = false;

      const result = await runScanners(config, {
        workingDirectory: testDir,
        verbose: true,
      });

      expect(result.scanners).toHaveLength(2);
      expect(result.hasErrors).toBe(false);
    });

    it('aggregates counts correctly', async () => {
      // With stub scanners returning 0 findings
      const config = getDefaultConfig();
      config.mode = 'explicit';

      const result = await runScanners(config, {
        workingDirectory: testDir,
        verbose: false,
      });

      expect(result.totalFindings).toBe(0);
      expect(result.highCount).toBe(0);
      expect(result.mediumCount).toBe(0);
      expect(result.lowCount).toBe(0);
    });

    it('tracks total duration', async () => {
      const config = getDefaultConfig();
      config.mode = 'explicit';
      config.scanners.secrets.enabled = true;

      const result = await runScanners(config, {
        workingDirectory: testDir,
        verbose: false,
      });

      expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
    });

    it('logs scanner progress when running', async () => {
      const config = getDefaultConfig();
      config.mode = 'explicit';
      config.scanners.secrets.enabled = true;
      config.scanners.dependencies.enabled = false;
      config.scanners.iac.enabled = false;
      config.scanners.container.enabled = false;

      await runScanners(config, {
        workingDirectory: testDir,
        verbose: false,
      });

      expect(core.info).toHaveBeenCalledWith(expect.stringContaining('Running'));
      expect(core.info).toHaveBeenCalledWith(expect.stringContaining('secrets'));
    });
  });
});
