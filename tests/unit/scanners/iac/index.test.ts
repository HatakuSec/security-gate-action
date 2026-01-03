/**
 * IaC Scanner Unit Tests
 *
 * Tests for the main IaC scanner, including file detection and integration.
 *
 * @module tests/unit/scanners/iac/index
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';
import { tmpdir } from 'os';

import { iacScanner } from '../../../../src/scanners/iac';
import type { ScannerContext } from '../../../../src/scanners/types';

// Mock the trivy module
vi.mock('../../../../src/scanners/iac/trivy', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../src/scanners/iac/trivy')>();
  return {
    ...original,
    runTrivy: vi.fn(),
    getTrivyPath: vi.fn().mockResolvedValue('trivy'),
  };
});

// Import the mocked module
import * as trivyModule from '../../../../src/scanners/iac/trivy';

// Path to test fixtures
const FIXTURES_DIR = path.join(__dirname, '../../../fixtures/iac');

describe('IaC Scanner', () => {
  let tempDir: string;

  beforeEach(() => {
    vi.restoreAllMocks();
    // Create a temp directory for tests
    tempDir = fs.mkdtempSync(path.join(tmpdir(), 'iac-scanner-test-'));
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
      expect(iacScanner.name).toBe('iac');
    });

    it('should have run method', () => {
      expect(typeof iacScanner.run).toBe('function');
    });
  });

  describe('run', () => {
    it('should return empty results when no IaC files found', async () => {
      // Create an empty directory
      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await iacScanner.run(context);

      expect(result.name).toBe('iac');
      expect(result.findings).toHaveLength(0);
      expect(result.filesScanned).toBe(0);
      expect(result.metadata?.terraformFiles).toBe(0);
      expect(result.metadata?.kubernetesFiles).toBe(0);
    });

    it('should detect Terraform files', async () => {
      // Create a simple .tf file
      fs.writeFileSync(path.join(tempDir, 'main.tf'), 'resource "null_resource" "test" {}');

      // Mock Trivy to return empty results
      vi.mocked(trivyModule.runTrivy).mockResolvedValue({
        success: true,
        findings: [],
        filesScanned: 1,
      });

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await iacScanner.run(context);

      expect(result.metadata?.terraformFiles).toBe(1);
      expect(trivyModule.runTrivy).toHaveBeenCalledWith(
        expect.objectContaining({
          workingDirectory: tempDir,
        })
      );
    });

    it('should detect Kubernetes manifests', async () => {
      // Create a K8s manifest
      const k8sContent = `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: test
      image: nginx
`;
      fs.writeFileSync(path.join(tempDir, 'pod.yaml'), k8sContent);

      // Mock Trivy to return empty results
      vi.mocked(trivyModule.runTrivy).mockResolvedValue({
        success: true,
        findings: [],
        filesScanned: 1,
      });

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await iacScanner.run(context);

      expect(result.metadata?.kubernetesFiles).toBe(1);
    });

    it('should not detect non-Kubernetes YAML files', async () => {
      // Create a regular YAML file (not K8s)
      const yamlContent = `name: my-app
version: 1.0.0
dependencies:
  - lodash
`;
      fs.writeFileSync(path.join(tempDir, 'config.yaml'), yamlContent);

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await iacScanner.run(context);

      // Should return empty (no K8s manifest, no .tf files)
      expect(result.metadata?.kubernetesFiles).toBe(0);
      expect(result.metadata?.terraformFiles).toBe(0);
    });

    it('should convert Trivy findings to scanner findings', async () => {
      // Create a .tf file to trigger scanning
      fs.writeFileSync(path.join(tempDir, 'main.tf'), 'resource "null_resource" "test" {}');

      // Mock Trivy to return findings
      vi.mocked(trivyModule.runTrivy).mockResolvedValue({
        success: true,
        findings: [
          {
            checkId: 'AVD-AWS-0086',
            title: 'S3 bucket public access',
            message: 'Bucket has public access enabled',
            severity: 'high',
            file: 'main.tf',
            startLine: 1,
            endLine: 5,
            resolution: 'Disable public access',
            references: ['https://example.com'],
            resource: 'aws_s3_bucket.test',
            provider: 'aws',
          },
        ],
        filesScanned: 1,
      });

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await iacScanner.run(context);

      expect(result.findings).toHaveLength(1);
      const finding = result.findings[0];
      expect(finding.ruleId).toBe('AVD-AWS-0086');
      expect(finding.severity).toBe('high');
      expect(finding.title).toBe('S3 bucket public access');
      expect(finding.file).toBe('main.tf');
      expect(finding.startLine).toBe(1);
      expect(finding.endLine).toBe(5);
      expect(finding.scanner).toBe('iac');
      expect(finding.metadata?.resource).toBe('aws_s3_bucket.test');
      expect(finding.metadata?.provider).toBe('aws');
    });

    it('should handle Trivy execution failure', async () => {
      // Create a .tf file to trigger scanning
      fs.writeFileSync(path.join(tempDir, 'main.tf'), 'resource "null_resource" "test" {}');

      // Mock Trivy to fail
      vi.mocked(trivyModule.runTrivy).mockResolvedValue({
        success: false,
        findings: [],
        error: 'Trivy execution failed: binary not found',
        filesScanned: 0,
      });

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await iacScanner.run(context);

      expect(result.findings).toHaveLength(0);
      expect(result.error).toContain('Trivy execution failed');
      expect(result.metadata?.errors).toContain('Trivy execution failed: binary not found');
    });

    it('should handle verbose mode', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      // Create a .tf file
      fs.writeFileSync(path.join(tempDir, 'main.tf'), 'resource "null_resource" "test" {}');

      // Mock Trivy
      vi.mocked(trivyModule.runTrivy).mockResolvedValue({
        success: true,
        findings: [],
        filesScanned: 1,
      });

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: true,
      };

      await iacScanner.run(context);

      expect(consoleSpy).toHaveBeenCalled();
      expect(consoleSpy.mock.calls.some((call) => String(call[0]).includes('IaC scan'))).toBe(true);

      consoleSpy.mockRestore();
    });

    it('should use actual fixtures and parse findings correctly', async () => {
      // Load the fixture JSON
      const fixtureJson = fs.readFileSync(path.join(FIXTURES_DIR, 'trivy-output.json'), 'utf-8');
      const fixtureData = JSON.parse(fixtureJson) as {
        Results: Array<{
          Misconfigurations?: Array<{ Status?: string }>;
        }>;
      };

      // Calculate expected findings from fixture
      let expectedFindings = 0;
      for (const result of fixtureData.Results) {
        if (result?.Misconfigurations) {
          for (const m of result.Misconfigurations) {
            if (m?.Status === 'FAIL') {
              expectedFindings++;
            }
          }
        }
      }

      // Mock Trivy to return parsed findings from fixture
      vi.mocked(trivyModule.runTrivy).mockResolvedValue({
        success: true,
        findings: trivyModule.parseTrivyOutput(fixtureJson, FIXTURES_DIR).findings,
        filesScanned: 3,
      });

      // Use actual fixtures directory
      const context: ScannerContext = {
        config: {},
        workingDirectory: FIXTURES_DIR,
        verbose: false,
      };

      const result = await iacScanner.run(context);

      expect(result.findings.length).toBe(expectedFindings);
      expect(result.findings.every((f) => f.scanner === 'iac')).toBe(true);
      expect(result.findings.every((f) => f.id.startsWith('iac:'))).toBe(true);
    });

    it('should exclude .tools directory from scanning', async () => {
      // Create .tools directory with a .tf file (should be excluded)
      const toolsDir = path.join(tempDir, '.tools');
      fs.mkdirSync(toolsDir, { recursive: true });
      fs.writeFileSync(path.join(toolsDir, 'tool.tf'), 'resource "null_resource" "test" {}');

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await iacScanner.run(context);

      // Should not find any files (the .tools directory is excluded)
      expect(result.metadata?.terraformFiles).toBe(0);
    });

    it('should find .tfvars files', async () => {
      // Create a .tfvars file
      fs.writeFileSync(path.join(tempDir, 'variables.tfvars'), 'region = "us-east-1"');

      // Mock Trivy
      vi.mocked(trivyModule.runTrivy).mockResolvedValue({
        success: true,
        findings: [],
        filesScanned: 1,
      });

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await iacScanner.run(context);

      expect(result.metadata?.terraformFiles).toBe(1);
    });

    it('should handle multiple file types', async () => {
      // Create both Terraform and Kubernetes files
      fs.writeFileSync(path.join(tempDir, 'main.tf'), 'resource "null_resource" "test" {}');
      fs.writeFileSync(
        path.join(tempDir, 'deploy.yaml'),
        'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: test'
      );

      // Mock Trivy
      vi.mocked(trivyModule.runTrivy).mockResolvedValue({
        success: true,
        findings: [],
        filesScanned: 2,
      });

      const context: ScannerContext = {
        config: {},
        workingDirectory: tempDir,
        verbose: false,
      };

      const result = await iacScanner.run(context);

      expect(result.metadata?.terraformFiles).toBe(1);
      expect(result.metadata?.kubernetesFiles).toBe(1);
    });
  });
});
