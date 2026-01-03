/**
 * Container Scanner Unit Tests
 *
 * Tests for the container scanner, including Dockerfile detection,
 * rule application, and Trivy output parsing.
 *
 * @module tests/unit/scanners/container/index
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';
import { tmpdir } from 'os';

import { containerScanner, parseTrivyFsOutput } from '../../../../src/scanners/container';
import type { ScannerContext } from '../../../../src/scanners/types';

// Mock the trivy module
vi.mock('../../../../src/scanners/iac/trivy', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../src/scanners/iac/trivy')>();
  return {
    ...original,
    getTrivyPath: vi.fn().mockRejectedValue(new Error('Trivy not available in tests')),
  };
});

// Path to test fixtures
const FIXTURES_DIR = path.join(__dirname, '../../../fixtures/container');

describe('Container Scanner', () => {
  let tempDir: string;

  beforeEach(() => {
    vi.restoreAllMocks();
    // Create a temp directory for tests
    tempDir = fs.mkdtempSync(path.join(tmpdir(), 'container-scanner-test-'));
  });

  afterEach(() => {
    // Clean up temp directory
    try {
      fs.rmSync(tempDir, { recursive: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('metadata', () => {
    it('should have correct name', () => {
      expect(containerScanner.name).toBe('container');
    });

    it('should have run method', () => {
      expect(typeof containerScanner.run).toBe('function');
    });
  });

  describe('run', () => {
    it('should return empty results when no Dockerfiles found', async () => {
      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      expect(result.name).toBe('container');
      expect(result.findings).toHaveLength(0);
      expect(result.filesScanned).toBe(0);
      expect(result.metadata?.dockerfilesFound).toBe(0);
    });

    it('should detect Dockerfiles', async () => {
      // Create a simple Dockerfile
      fs.writeFileSync(path.join(tempDir, 'Dockerfile'), 'FROM node:18\nCMD ["node"]');
      // Create .dockerignore to avoid DOCK006
      fs.writeFileSync(path.join(tempDir, '.dockerignore'), 'node_modules');

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      expect(result.metadata?.dockerfilesFound).toBe(1);
      expect(result.filesScanned).toBe(1);
    });

    it('should detect Dockerfile.* variants', async () => {
      fs.writeFileSync(path.join(tempDir, 'Dockerfile.dev'), 'FROM node:18');
      fs.writeFileSync(path.join(tempDir, 'Dockerfile.prod'), 'FROM node:18-alpine');
      fs.writeFileSync(path.join(tempDir, '.dockerignore'), 'node_modules');

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      expect(result.metadata?.dockerfilesFound).toBe(2);
    });

    it('should apply Dockerfile rules and find issues', async () => {
      // Create a Dockerfile with issues
      fs.writeFileSync(
        path.join(tempDir, 'Dockerfile'),
        `FROM node:latest
RUN sudo apt-get update
CMD ["node", "index.js"]`
      );

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      // Should find at least: DOCK001 (latest), DOCK002 (no USER), DOCK003 (no HEALTHCHECK), DOCK004 (sudo), DOCK006 (no .dockerignore)
      expect(result.findings.length).toBeGreaterThanOrEqual(5);

      // Check that findings have correct structure
      for (const finding of result.findings) {
        expect(finding.scanner).toBe('container');
        expect(finding.file).toBe('Dockerfile');
        expect(finding.ruleId).toMatch(/^DOCK00\d$/);
      }
    });

    it('should find no issues in good Dockerfile', async () => {
      // Copy good Dockerfile from fixtures
      const goodContent = fs.readFileSync(path.join(FIXTURES_DIR, 'Dockerfile.good'), 'utf-8');
      fs.writeFileSync(path.join(tempDir, 'Dockerfile'), goodContent);
      fs.writeFileSync(path.join(tempDir, '.dockerignore'), 'node_modules');

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      // Filter to only Dockerfile rule findings (not Trivy)
      const ruleFindings = result.findings.filter((f) => f.ruleId?.startsWith('DOCK'));
      expect(ruleFindings).toHaveLength(0);
    });

    it('should handle verbose mode', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      fs.writeFileSync(path.join(tempDir, 'Dockerfile'), 'FROM node:18');
      fs.writeFileSync(path.join(tempDir, '.dockerignore'), 'node_modules');

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: true,
      };

      await containerScanner.run(context);

      expect(consoleSpy).toHaveBeenCalled();
      expect(consoleSpy.mock.calls.some((call) => String(call[0]).includes('container scan'))).toBe(
        true
      );

      consoleSpy.mockRestore();
    });

    it('should exclude node_modules', async () => {
      // Create Dockerfile in node_modules (should be ignored)
      const nodeModulesDir = path.join(tempDir, 'node_modules', 'some-package');
      fs.mkdirSync(nodeModulesDir, { recursive: true });
      fs.writeFileSync(path.join(nodeModulesDir, 'Dockerfile'), 'FROM node:latest');

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      expect(result.metadata?.dockerfilesFound).toBe(0);
    });

    it('should exclude .git directory', async () => {
      const gitDir = path.join(tempDir, '.git', 'hooks');
      fs.mkdirSync(gitDir, { recursive: true });
      fs.writeFileSync(path.join(gitDir, 'Dockerfile'), 'FROM node:latest');

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      expect(result.metadata?.dockerfilesFound).toBe(0);
    });

    it('should handle .dockerignore detection', async () => {
      // Create Dockerfile without .dockerignore
      fs.writeFileSync(
        path.join(tempDir, 'Dockerfile'),
        'FROM node:18\nUSER node\nHEALTHCHECK CMD curl localhost'
      );

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      // Should find DOCK006 (no .dockerignore)
      const dock006 = result.findings.find((f) => f.ruleId === 'DOCK006');
      expect(dock006).toBeDefined();
    });

    it('should not flag DOCK006 when .dockerignore exists', async () => {
      fs.writeFileSync(
        path.join(tempDir, 'Dockerfile'),
        'FROM node:18\nUSER node\nHEALTHCHECK CMD curl localhost'
      );
      fs.writeFileSync(path.join(tempDir, '.dockerignore'), 'node_modules');

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      // Should NOT find DOCK006
      const dock006 = result.findings.find((f) => f.ruleId === 'DOCK006');
      expect(dock006).toBeUndefined();
    });

    it('should scan Dockerfiles in subdirectories', async () => {
      const subDir = path.join(tempDir, 'services', 'api');
      fs.mkdirSync(subDir, { recursive: true });
      fs.writeFileSync(path.join(subDir, 'Dockerfile'), 'FROM node:18');
      fs.writeFileSync(path.join(tempDir, '.dockerignore'), 'node_modules');

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      expect(result.metadata?.dockerfilesFound).toBe(1);
      expect(result.findings.some((f) => f.file.includes('services/api'))).toBe(true);
    });
  });

  describe('parseTrivyFsOutput', () => {
    it('should parse fixture file correctly', () => {
      const jsonContent = fs.readFileSync(path.join(FIXTURES_DIR, 'trivy-fs-output.json'), 'utf-8');
      const { findings, filesScanned } = parseTrivyFsOutput(jsonContent, FIXTURES_DIR);

      expect(filesScanned).toBe(2);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should extract vulnerabilities', () => {
      const jsonContent = fs.readFileSync(path.join(FIXTURES_DIR, 'trivy-fs-output.json'), 'utf-8');
      const { findings } = parseTrivyFsOutput(jsonContent, FIXTURES_DIR);

      // Find the lodash vulnerability
      const lodashVuln = findings.find((f) => f.checkId === 'CVE-2022-12345');
      expect(lodashVuln).toBeDefined();
      expect(lodashVuln?.severity).toBe('high');
      expect(lodashVuln?.title).toContain('lodash');
    });

    it('should extract misconfigurations', () => {
      const jsonContent = fs.readFileSync(path.join(FIXTURES_DIR, 'trivy-fs-output.json'), 'utf-8');
      const { findings } = parseTrivyFsOutput(jsonContent, FIXTURES_DIR);

      // Find the root user misconfiguration
      const rootMisconfig = findings.find((f) => f.checkId === 'AVD-DS-0002');
      expect(rootMisconfig).toBeDefined();
      expect(rootMisconfig?.severity).toBe('high');
    });

    it('should not include passed checks', () => {
      const jsonContent = fs.readFileSync(path.join(FIXTURES_DIR, 'trivy-fs-output.json'), 'utf-8');
      const { findings } = parseTrivyFsOutput(jsonContent, FIXTURES_DIR);

      // DS001 has status PASS in the fixture
      const passedCheck = findings.find((f) => f.checkId === 'AVD-DS-0001');
      expect(passedCheck).toBeUndefined();
    });

    it('should handle empty output', () => {
      const { findings, filesScanned } = parseTrivyFsOutput('', '/test');
      expect(findings).toHaveLength(0);
      expect(filesScanned).toBe(0);
    });

    it('should handle empty Results array', () => {
      const emptyOutput = JSON.stringify({ Results: [] });
      const { findings, filesScanned } = parseTrivyFsOutput(emptyOutput, '/test');
      expect(findings).toHaveLength(0);
      expect(filesScanned).toBe(0);
    });

    it('should handle invalid JSON gracefully', () => {
      const { findings, filesScanned } = parseTrivyFsOutput('invalid json {', '/test');
      expect(findings).toHaveLength(0);
      expect(filesScanned).toBe(0);
    });

    it('should map severities correctly', () => {
      const jsonContent = fs.readFileSync(path.join(FIXTURES_DIR, 'trivy-fs-output.json'), 'utf-8');
      const { findings } = parseTrivyFsOutput(jsonContent, FIXTURES_DIR);

      const highSeverity = findings.filter((f) => f.severity === 'high');
      const mediumSeverity = findings.filter((f) => f.severity === 'medium');
      const lowSeverity = findings.filter((f) => f.severity === 'low');

      // Based on fixture: 2 HIGH (vulnerability + misconfig), 1 MEDIUM (vulnerability), 1 LOW (misconfig)
      expect(highSeverity.length).toBeGreaterThanOrEqual(2);
      expect(mediumSeverity.length).toBeGreaterThanOrEqual(1);
      expect(lowSeverity.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('actual fixtures', () => {
    it('should find all expected issues in Dockerfile.bad', async () => {
      const context: ScannerContext = {
        config: {},
        workingDirectory: FIXTURES_DIR,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      // Filter to only rule findings from Dockerfile.bad
      const badFileFindings = result.findings.filter(
        (f) => f.file === 'Dockerfile.bad' && f.ruleId?.startsWith('DOCK')
      );

      // Should find multiple rule violations
      expect(badFileFindings.length).toBeGreaterThanOrEqual(5);

      // Check specific rules
      const ruleIds = badFileFindings.map((f) => f.ruleId);
      expect(ruleIds).toContain('DOCK001'); // latest tag
      expect(ruleIds).toContain('DOCK004'); // sudo
      expect(ruleIds).toContain('DOCK008'); // curl | sh
    });

    it('should find no rule issues in Dockerfile.good', async () => {
      const context: ScannerContext = {
        config: {},
        workingDirectory: FIXTURES_DIR,
        verbose: false,
      };

      const result = await containerScanner.run(context);

      // Filter to only rule findings from Dockerfile.good
      const goodFileFindings = result.findings.filter(
        (f) => f.file === 'Dockerfile.good' && f.ruleId?.startsWith('DOCK')
      );

      expect(goodFileFindings).toHaveLength(0);
    });
  });
});
