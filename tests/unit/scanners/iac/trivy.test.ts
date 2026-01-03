/**
 * Trivy Integration Unit Tests
 *
 * Tests for Trivy output parsing and severity mapping.
 *
 * @module tests/unit/scanners/iac/trivy
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

import { mapTrivySeverity, parseTrivyOutput } from '../../../../src/scanners/iac/trivy';

// Path to test fixtures
const FIXTURES_DIR = path.join(__dirname, '../../../fixtures/iac');

describe('Trivy Integration', () => {
  describe('mapTrivySeverity', () => {
    it('should map CRITICAL to high', () => {
      expect(mapTrivySeverity('CRITICAL')).toBe('high');
    });

    it('should map HIGH to high', () => {
      expect(mapTrivySeverity('HIGH')).toBe('high');
    });

    it('should map MEDIUM to medium', () => {
      expect(mapTrivySeverity('MEDIUM')).toBe('medium');
    });

    it('should map LOW to low', () => {
      expect(mapTrivySeverity('LOW')).toBe('low');
    });

    it('should map UNKNOWN to low', () => {
      expect(mapTrivySeverity('UNKNOWN')).toBe('low');
    });

    it('should handle lowercase input', () => {
      expect(mapTrivySeverity('high')).toBe('high');
      expect(mapTrivySeverity('medium')).toBe('medium');
      expect(mapTrivySeverity('low')).toBe('low');
    });

    it('should handle mixed case input', () => {
      expect(mapTrivySeverity('High')).toBe('high');
      expect(mapTrivySeverity('Medium')).toBe('medium');
    });

    it('should default unknown values to low', () => {
      expect(mapTrivySeverity('INVALID')).toBe('low');
      expect(mapTrivySeverity('')).toBe('low');
    });
  });

  describe('parseTrivyOutput', () => {
    it('should parse fixture file correctly', () => {
      const jsonContent = fs.readFileSync(path.join(FIXTURES_DIR, 'trivy-output.json'), 'utf-8');
      const { findings, filesScanned } = parseTrivyOutput(jsonContent, FIXTURES_DIR);

      expect(filesScanned).toBe(3);
      expect(findings.length).toBeGreaterThan(0);
    });

    it('should extract correct fields from Terraform findings', () => {
      const jsonContent = fs.readFileSync(path.join(FIXTURES_DIR, 'trivy-output.json'), 'utf-8');
      const { findings } = parseTrivyOutput(jsonContent, FIXTURES_DIR);

      // Find the S3 public access finding
      const s3Finding = findings.find((f) => f.checkId === 'AVD-AWS-0086');

      expect(s3Finding).toBeDefined();
      expect(s3Finding?.title).toBe('S3 Access block should block public ACLs');
      expect(s3Finding?.severity).toBe('high');
      expect(s3Finding?.file).toBe('insecure-s3.tf');
      expect(s3Finding?.startLine).toBe(5);
      expect(s3Finding?.endLine).toBe(14);
      expect(s3Finding?.resource).toBe('aws_s3_bucket.public_bucket');
      expect(s3Finding?.provider).toBe('aws');
      expect(s3Finding?.resolution).toContain('Enable blocking');
      expect(s3Finding?.references).toContain('https://avd.aquasec.com/misconfig/avd-aws-0086');
    });

    it('should extract correct fields from Kubernetes findings', () => {
      const jsonContent = fs.readFileSync(path.join(FIXTURES_DIR, 'trivy-output.json'), 'utf-8');
      const { findings } = parseTrivyOutput(jsonContent, FIXTURES_DIR);

      // Find the privileged container finding
      const k8sFinding = findings.find((f) => f.checkId === 'AVD-KSV-0001');

      expect(k8sFinding).toBeDefined();
      expect(k8sFinding?.title).toBe('Container is privileged');
      expect(k8sFinding?.severity).toBe('high');
      expect(k8sFinding?.file).toBe('insecure-k8s.yaml');
      expect(k8sFinding?.resource).toBe('Deployment/insecure-deployment');
      expect(k8sFinding?.provider).toBe('kubernetes');
    });

    it('should not include passed checks', () => {
      // Create a minimal output with a passed check
      const passedOutput = JSON.stringify({
        Results: [
          {
            Target: 'test.tf',
            Class: 'config',
            Type: 'terraform',
            Misconfigurations: [
              {
                ID: 'TEST001',
                Title: 'Passed Check',
                Message: 'This check passed',
                Severity: 'HIGH',
                Status: 'PASS',
              },
              {
                ID: 'TEST002',
                Title: 'Failed Check',
                Message: 'This check failed',
                Severity: 'HIGH',
                Status: 'FAIL',
              },
            ],
          },
        ],
      });

      const { findings } = parseTrivyOutput(passedOutput, '/test');
      expect(findings).toHaveLength(1);
      expect(findings[0].checkId).toBe('TEST002');
    });

    it('should handle empty output', () => {
      const { findings, filesScanned } = parseTrivyOutput('', '/test');
      expect(findings).toHaveLength(0);
      expect(filesScanned).toBe(0);
    });

    it('should handle empty Results array', () => {
      const emptyOutput = JSON.stringify({ Results: [] });
      const { findings, filesScanned } = parseTrivyOutput(emptyOutput, '/test');
      expect(findings).toHaveLength(0);
      expect(filesScanned).toBe(0);
    });

    it('should handle array output format', () => {
      const arrayOutput = JSON.stringify([
        {
          Target: 'test.tf',
          Class: 'config',
          Type: 'terraform',
          Misconfigurations: [
            {
              ID: 'TEST001',
              Title: 'Test Finding',
              Message: 'Test message',
              Severity: 'MEDIUM',
              Status: 'FAIL',
            },
          ],
        },
      ]);

      const { findings, filesScanned } = parseTrivyOutput(arrayOutput, '/test');
      expect(filesScanned).toBe(1);
      expect(findings).toHaveLength(1);
    });

    it('should handle missing optional fields', () => {
      const minimalOutput = JSON.stringify({
        Results: [
          {
            Target: 'test.tf',
            Misconfigurations: [
              {
                ID: 'TEST001',
                Title: 'Minimal Finding',
                Severity: 'LOW',
                Status: 'FAIL',
              },
            ],
          },
        ],
      });

      const { findings } = parseTrivyOutput(minimalOutput, '/test');
      expect(findings).toHaveLength(1);
      expect(findings[0].message).toBe('No description available');
      expect(findings[0].resolution).toBeUndefined();
      expect(findings[0].references).toBeUndefined();
    });

    it('should prefer AVDID over ID for checkId', () => {
      const output = JSON.stringify({
        Results: [
          {
            Target: 'test.tf',
            Misconfigurations: [
              {
                ID: 'OLD-ID',
                AVDID: 'AVD-NEW-001',
                Title: 'Test',
                Severity: 'HIGH',
                Status: 'FAIL',
              },
            ],
          },
        ],
      });

      const { findings } = parseTrivyOutput(output, '/test');
      expect(findings[0].checkId).toBe('AVD-NEW-001');
    });

    it('should make absolute paths relative', () => {
      const workingDir = '/home/user/project';
      const output = JSON.stringify({
        Results: [
          {
            Target: '/home/user/project/infra/main.tf',
            Misconfigurations: [
              {
                ID: 'TEST001',
                Title: 'Test',
                Severity: 'HIGH',
                Status: 'FAIL',
              },
            ],
          },
        ],
      });

      const { findings } = parseTrivyOutput(output, workingDir);
      expect(findings[0].file).toBe('infra/main.tf');
    });

    it('should throw on invalid JSON', () => {
      expect(() => parseTrivyOutput('invalid json {', '/test')).toThrow(
        'Failed to parse Trivy JSON output'
      );
    });

    it('should handle null results gracefully', () => {
      const output = JSON.stringify({
        Results: [null, { Target: 'test.tf', Misconfigurations: [] }],
      });

      const { findings, filesScanned } = parseTrivyOutput(output, '/test');
      expect(filesScanned).toBe(1);
      expect(findings).toHaveLength(0);
    });

    it('should handle null misconfigurations gracefully', () => {
      const output = JSON.stringify({
        Results: [
          {
            Target: 'test.tf',
            Misconfigurations: [
              null,
              {
                ID: 'TEST001',
                Title: 'Valid',
                Severity: 'HIGH',
                Status: 'FAIL',
              },
            ],
          },
        ],
      });

      const { findings } = parseTrivyOutput(output, '/test');
      expect(findings).toHaveLength(1);
    });

    it('should count correct number of high/medium/low findings', () => {
      const jsonContent = fs.readFileSync(path.join(FIXTURES_DIR, 'trivy-output.json'), 'utf-8');
      const { findings } = parseTrivyOutput(jsonContent, FIXTURES_DIR);

      const highCount = findings.filter((f) => f.severity === 'high').length;
      const mediumCount = findings.filter((f) => f.severity === 'medium').length;
      const lowCount = findings.filter((f) => f.severity === 'low').length;

      // Based on our fixture: 7 HIGH, 2 MEDIUM, 0 LOW
      expect(highCount).toBe(7);
      expect(mediumCount).toBe(2);
      expect(lowCount).toBe(0);
    });
  });
});
