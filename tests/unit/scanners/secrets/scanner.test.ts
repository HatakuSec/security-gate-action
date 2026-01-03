/**
 * @file Secrets Scanner Tests
 * @description Tests for the secrets scanner implementation
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join, resolve } from 'path';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'fs';
import { secretsScanner } from '../../../../src/scanners/secrets';
import type { ScannerContext } from '../../../../src/scanners/types';

// Mock @actions/core
vi.mock('@actions/core', () => ({
  debug: vi.fn(),
  warning: vi.fn(),
  info: vi.fn(),
  error: vi.fn(),
  setSecret: vi.fn(),
}));

const FIXTURES_DIR = resolve(__dirname, '../../../fixtures/secrets');
const TEMP_DIR = resolve(__dirname, '../../../temp-secrets-test');

describe('SecretsScanner', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Create temp directory for tests
    if (!existsSync(TEMP_DIR)) {
      mkdirSync(TEMP_DIR, { recursive: true });
    }
  });

  afterEach(() => {
    // Clean up temp directory
    if (existsSync(TEMP_DIR)) {
      rmSync(TEMP_DIR, { recursive: true, force: true });
    }
  });

  describe('basic functionality', () => {
    it('has correct scanner name', () => {
      expect(secretsScanner.name).toBe('secrets');
    });

    it('returns ScannerResult shape', async () => {
      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      expect(result).toHaveProperty('name', 'secrets');
      expect(result).toHaveProperty('findings');
      expect(result).toHaveProperty('durationMs');
      expect(result).toHaveProperty('filesScanned');
      expect(Array.isArray(result.findings)).toBe(true);
      expect(typeof result.durationMs).toBe('number');
    });
  });

  describe('secret detection', () => {
    it('detects AWS access keys in fixture', async () => {
      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      const awsFindings = result.findings.filter((f) => f.ruleId === 'SEC001');
      expect(awsFindings.length).toBeGreaterThan(0);
    });

    it('detects GitHub tokens in fixture', async () => {
      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      const ghpFindings = result.findings.filter((f) => f.ruleId === 'SEC003');
      const ghoFindings = result.findings.filter((f) => f.ruleId === 'SEC004');

      expect(ghpFindings.length).toBeGreaterThan(0);
      expect(ghoFindings.length).toBeGreaterThan(0);
    });

    it('detects private key headers', async () => {
      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      const pkFindings = result.findings.filter((f) => f.ruleId === 'SEC006');
      expect(pkFindings.length).toBeGreaterThan(0);
    });

    it('does not detect secrets in clean file', async () => {
      // Create a temp dir with only the clean file
      const cleanDir = join(TEMP_DIR, 'clean-only');
      mkdirSync(cleanDir, { recursive: true });
      writeFileSync(
        join(cleanDir, 'clean.ts'),
        `
        const config = { name: 'test' };
        const url = 'https://example.com';
        export default config;
        `
      );

      const context: ScannerContext = {
        workingDirectory: cleanDir,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('finding properties', () => {
    it('includes correct severity from pattern', async () => {
      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      // SEC001 should be high severity
      const awsFindings = result.findings.filter((f) => f.ruleId === 'SEC001');
      awsFindings.forEach((f) => expect(f.severity).toBe('high'));

      // SEC007/SEC008 should be medium severity
      const mediumFindings = result.findings.filter(
        (f) => f.ruleId === 'SEC007' || f.ruleId === 'SEC008'
      );
      mediumFindings.forEach((f) => expect(f.severity).toBe('medium'));
    });

    it('includes file path in finding', async () => {
      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      result.findings.forEach((f) => {
        expect(f.file).toBeTruthy();
        expect(typeof f.file).toBe('string');
      });
    });

    it('includes line number in finding', async () => {
      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      result.findings.forEach((f) => {
        expect(f.startLine).toBeGreaterThan(0);
        expect(f.endLine).toBeGreaterThan(0);
      });
    });

    it('includes scanner name in finding', async () => {
      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      result.findings.forEach((f) => {
        expect(f.scanner).toBe('secrets');
      });
    });

    it('includes unique ID for each finding', async () => {
      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      const ids = result.findings.map((f) => f.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });
  });

  describe('secret masking', () => {
    it('masks secrets in snippets', async () => {
      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      // Find a finding with a snippet
      const findingsWithSnippets = result.findings.filter((f) => f.snippet);

      for (const finding of findingsWithSnippets) {
        // Snippet should contain asterisks (masked)
        expect(finding.snippet).toContain('*');

        // Should NOT contain full AWS access key patterns
        expect(finding.snippet).not.toMatch(/AKIA[0-9A-Z]{16}/);
        // Should NOT contain full GitHub token patterns
        expect(finding.snippet).not.toMatch(/ghp_[A-Za-z0-9]{36}/);
        expect(finding.snippet).not.toMatch(/gho_[A-Za-z0-9]{36}/);
      }
    });

    it('calls core.setSecret for detected values', async () => {
      const core = await import('@actions/core');

      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: false,
        config: {},
      };

      await secretsScanner.run(context);

      // setSecret should have been called for each detected secret
      expect(core.setSecret).toHaveBeenCalled();
    });
  });

  describe('file handling', () => {
    it('skips files over 1MB', async () => {
      // Create a file larger than 1MB
      const largeDir = join(TEMP_DIR, 'large-file-test');
      mkdirSync(largeDir, { recursive: true });

      const largeContent = 'x'.repeat(1024 * 1024 + 1000); // Just over 1MB
      writeFileSync(join(largeDir, 'large.txt'), largeContent);

      // Also create a small file with a secret to verify scanning works
      writeFileSync(join(largeDir, 'small.txt'), 'AKIAIOSFODNN7EXAMPLE');

      const context: ScannerContext = {
        workingDirectory: largeDir,
        verbose: true,
        config: {},
      };

      const result = await secretsScanner.run(context);

      // Should find the secret in small.txt but not crash on large.txt
      expect(result.filesScanned).toBe(2); // Both files are "scanned" (one skipped)
      expect(result.findings.length).toBe(1); // Only from small.txt
    });

    it('skips binary files', async () => {
      const binaryDir = join(TEMP_DIR, 'binary-test');
      mkdirSync(binaryDir, { recursive: true });

      // Create a file with null bytes (binary)
      const binaryContent = Buffer.from([0x00, 0x01, 0x02, 0x00, 0x03]);
      writeFileSync(join(binaryDir, 'binary.dat'), binaryContent);

      // Create text file with secret
      writeFileSync(join(binaryDir, 'text.txt'), 'AKIAIOSFODNN7EXAMPLE');

      const context: ScannerContext = {
        workingDirectory: binaryDir,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      // Should only find the secret in text.txt
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].file).toBe('text.txt');
    });

    it('skips files with binary extensions', async () => {
      const extDir = join(TEMP_DIR, 'ext-test');
      mkdirSync(extDir, { recursive: true });

      // Create files with binary extensions (content doesn't matter)
      writeFileSync(join(extDir, 'image.png'), 'AKIAIOSFODNN7EXAMPLE');
      writeFileSync(join(extDir, 'archive.zip'), 'AKIAIOSFODNN7EXAMPLE');

      // Create text file with secret
      writeFileSync(join(extDir, 'config.txt'), 'AKIAIOSFODNN7EXAMPLE');

      const context: ScannerContext = {
        workingDirectory: extDir,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      // Should only find the secret in config.txt
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].file).toBe('config.txt');
    });
  });

  describe('directory exclusions', () => {
    it('skips node_modules directory', async () => {
      const projectDir = join(TEMP_DIR, 'node-modules-test');
      const nodeModulesDir = join(projectDir, 'node_modules', 'some-package');
      mkdirSync(nodeModulesDir, { recursive: true });

      // Put a secret in node_modules
      writeFileSync(join(nodeModulesDir, 'index.js'), 'AKIAIOSFODNN7EXAMPLE');

      // Put a secret in the main project
      writeFileSync(join(projectDir, 'app.js'), 'AKIAI44QH8DHBEXAMPLE');

      const context: ScannerContext = {
        workingDirectory: projectDir,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      // Should only find the secret in app.js, not in node_modules
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].file).toBe('app.js');
    });

    it('skips .git directory', async () => {
      const projectDir = join(TEMP_DIR, 'git-test');
      const gitDir = join(projectDir, '.git', 'objects');
      mkdirSync(gitDir, { recursive: true });

      // Put a secret in .git
      writeFileSync(join(gitDir, 'pack-123'), 'AKIAIOSFODNN7EXAMPLE');

      // Put a secret in the main project
      writeFileSync(join(projectDir, 'src.js'), 'AKIAI44QH8DHBEXAMPLE');

      const context: ScannerContext = {
        workingDirectory: projectDir,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      // Should only find the secret in src.js, not in .git
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].file).toBe('src.js');
    });

    it('skips dist directory', async () => {
      const projectDir = join(TEMP_DIR, 'dist-test');
      const distDir = join(projectDir, 'dist');
      mkdirSync(distDir, { recursive: true });

      // Put a secret in dist
      writeFileSync(join(distDir, 'bundle.js'), 'AKIAIOSFODNN7EXAMPLE');

      // Put a secret in the main project
      writeFileSync(join(projectDir, 'main.js'), 'AKIAI44QH8DHBEXAMPLE');

      const context: ScannerContext = {
        workingDirectory: projectDir,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      // Should only find the secret in main.js, not in dist
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].file).toBe('main.js');
    });
  });

  describe('error handling', () => {
    it('handles missing directory gracefully', async () => {
      const context: ScannerContext = {
        workingDirectory: '/nonexistent/path/that/does/not/exist',
        verbose: false,
        config: {},
      };

      // Should not throw, should return result with possible error
      const result = await secretsScanner.run(context);

      expect(result.name).toBe('secrets');
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('handles empty directory', async () => {
      const emptyDir = join(TEMP_DIR, 'empty-dir');
      mkdirSync(emptyDir, { recursive: true });

      const context: ScannerContext = {
        workingDirectory: emptyDir,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      expect(result.findings).toHaveLength(0);
      expect(result.filesScanned).toBe(0);
    });
  });

  describe('verbose mode', () => {
    it('logs debug messages when verbose is true', async () => {
      const core = await import('@actions/core');

      const context: ScannerContext = {
        workingDirectory: FIXTURES_DIR,
        verbose: true,
        config: {},
      };

      await secretsScanner.run(context);

      expect(core.debug).toHaveBeenCalled();
    });

    it('does not log debug messages when verbose is false', async () => {
      const core = await import('@actions/core');

      // Create a simple test directory
      const simpleDir = join(TEMP_DIR, 'simple');
      mkdirSync(simpleDir, { recursive: true });
      writeFileSync(join(simpleDir, 'file.txt'), 'no secrets here');

      const context: ScannerContext = {
        workingDirectory: simpleDir,
        verbose: false,
        config: {},
      };

      vi.clearAllMocks();
      await secretsScanner.run(context);

      expect(core.debug).not.toHaveBeenCalled();
    });
  });

  describe('multiple findings per file', () => {
    it('detects multiple secrets in one file', async () => {
      const multiDir = join(TEMP_DIR, 'multi-secret');
      mkdirSync(multiDir, { recursive: true });

      writeFileSync(
        join(multiDir, 'config.js'),
        `
        const awsKey = 'AKIAIOSFODNN7EXAMPLE';
        const ghToken = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789';
        const stripeKey = 'sk_live_AbCdEfGhIjKlMnOpQrStUvWx';
        `
      );

      const context: ScannerContext = {
        workingDirectory: multiDir,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      // Should find all three secrets
      expect(result.findings.length).toBe(3);

      const ruleIds = result.findings.map((f) => f.ruleId);
      expect(ruleIds).toContain('SEC001'); // AWS
      expect(ruleIds).toContain('SEC003'); // GitHub
      expect(ruleIds).toContain('SEC010'); // Stripe
    });

    it('detects multiple secrets on same line', async () => {
      const sameLineDir = join(TEMP_DIR, 'same-line');
      mkdirSync(sameLineDir, { recursive: true });

      writeFileSync(
        join(sameLineDir, 'env.txt'),
        'AWS_KEY=AKIAIOSFODNN7EXAMPLE GH_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'
      );

      const context: ScannerContext = {
        workingDirectory: sameLineDir,
        verbose: false,
        config: {},
      };

      const result = await secretsScanner.run(context);

      // Should find both secrets
      expect(result.findings.length).toBe(2);
    });
  });
});
