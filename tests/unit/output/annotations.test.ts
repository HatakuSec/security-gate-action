/**
 * @file Annotations Emitter Tests
 * @description Unit tests for the GitHub Actions annotation emission.
 *
 * Coverage targets:
 * - emitAnnotations(): 100%
 * - getAnnotationLevel(): 100%
 * - getSeverityIcon(): 100%
 *
 * Key test scenarios:
 * - Severity to annotation level mapping
 * - Annotation capping
 * - Properties building
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as core from '@actions/core';

import {
  emitAnnotations,
  emitFindingAnnotations,
  getAnnotationLevel,
  getSeverityIcon,
} from '../../../src/output/annotations';
import type { Finding, ScanResults, ScannerResult } from '../../../src/scanners/types';

// Mock @actions/core
vi.mock('@actions/core', () => ({
  error: vi.fn(),
  warning: vi.fn(),
  notice: vi.fn(),
}));

/**
 * Helper to create a test finding.
 */
function createFinding(
  severity: 'high' | 'medium' | 'low',
  overrides: Partial<Finding> = {}
): Finding {
  return {
    id: `test-${Date.now()}-${Math.random()}`,
    severity,
    title: `Test ${severity} finding`,
    message: `This is a ${severity} severity finding`,
    file: 'src/test.ts',
    startLine: 42,
    scanner: 'secrets',
    ruleId: 'TEST001',
    ...overrides,
  };
}

/**
 * Helper to create test scan results.
 */
function createScanResults(findings: Finding[]): ScanResults {
  const scannerResult: ScannerResult = {
    name: 'secrets',
    findings,
    durationMs: 100,
    filesScanned: 10,
  };

  return {
    scanners: [scannerResult],
    totalFindings: findings.length,
    highCount: findings.filter((f) => f.severity === 'high').length,
    mediumCount: findings.filter((f) => f.severity === 'medium').length,
    lowCount: findings.filter((f) => f.severity === 'low').length,
    totalDurationMs: 100,
    totalFilesScanned: 10,
    hasErrors: false,
  };
}

describe('Annotations Emitter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getAnnotationLevel', () => {
    it('should return error for high severity', () => {
      expect(getAnnotationLevel('high')).toBe('error');
    });

    it('should return warning for medium severity', () => {
      expect(getAnnotationLevel('medium')).toBe('warning');
    });

    it('should return notice for low severity', () => {
      expect(getAnnotationLevel('low')).toBe('notice');
    });
  });

  describe('getSeverityIcon', () => {
    it('should return red circle for high', () => {
      expect(getSeverityIcon('high')).toBe('🔴');
    });

    it('should return yellow circle for medium', () => {
      expect(getSeverityIcon('medium')).toBe('🟡');
    });

    it('should return blue circle for low', () => {
      expect(getSeverityIcon('low')).toBe('🔵');
    });
  });

  describe('emitFindingAnnotations', () => {
    it('should emit error for high severity finding', () => {
      const finding = createFinding('high');
      emitFindingAnnotations([finding]);

      expect(core.error).toHaveBeenCalledTimes(1);
      expect(core.error).toHaveBeenCalledWith(
        expect.stringContaining('high severity finding'),
        expect.objectContaining({
          title: 'TEST001: Test high finding',
          file: 'src/test.ts',
          startLine: 42,
        })
      );
    });

    it('should emit warning for medium severity finding', () => {
      const finding = createFinding('medium');
      emitFindingAnnotations([finding]);

      expect(core.warning).toHaveBeenCalledTimes(1);
      expect(core.warning).toHaveBeenCalledWith(
        expect.stringContaining('medium severity finding'),
        expect.objectContaining({
          title: 'TEST001: Test medium finding',
        })
      );
    });

    it('should emit notice for low severity finding', () => {
      const finding = createFinding('low');
      emitFindingAnnotations([finding]);

      expect(core.notice).toHaveBeenCalledTimes(1);
      expect(core.notice).toHaveBeenCalledWith(
        expect.stringContaining('low severity finding'),
        expect.objectContaining({
          title: 'TEST001: Test low finding',
        })
      );
    });

    it('should include file and line in annotation', () => {
      const finding = createFinding('high', {
        file: 'config/secrets.ts',
        startLine: 100,
        endLine: 105,
      });
      emitFindingAnnotations([finding]);

      expect(core.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          file: 'config/secrets.ts',
          startLine: 100,
          endLine: 105,
        })
      );
    });

    it('should use title without ruleId if not present', () => {
      const finding = createFinding('high', { ruleId: undefined });
      emitFindingAnnotations([finding]);

      expect(core.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          title: 'Test high finding',
        })
      );
    });

    it('should include snippet in message if present', () => {
      const finding = createFinding('high', {
        snippet: 'const secret = "****";',
      });
      emitFindingAnnotations([finding]);

      expect(core.error).toHaveBeenCalledWith(
        expect.stringContaining('const secret = "****";'),
        expect.any(Object)
      );
    });

    it('should emit multiple annotations for multiple findings', () => {
      const findings = [createFinding('high'), createFinding('medium'), createFinding('low')];
      emitFindingAnnotations(findings);

      expect(core.error).toHaveBeenCalledTimes(1);
      expect(core.warning).toHaveBeenCalledTimes(1);
      expect(core.notice).toHaveBeenCalledTimes(1);
    });

    it('should cap annotations at limit', () => {
      // Create 60 findings (more than 50 limit)
      const findings = Array.from({ length: 60 }, (_, i) =>
        createFinding('high', { id: `finding-${i}` })
      );

      const result = emitFindingAnnotations(findings);

      expect(result.emitted).toBe(50);
      expect(result.skipped).toBe(10);
      expect(result.capped).toBe(true);
      expect(core.error).toHaveBeenCalledTimes(50);
      expect(core.notice).toHaveBeenCalledWith(
        expect.stringContaining('10 additional findings not annotated')
      );
    });

    it('should prioritise high severity when capping', () => {
      // Create findings: 30 low, 20 medium, 10 high = 60 total
      const findings = [
        ...Array.from({ length: 30 }, () => createFinding('low')),
        ...Array.from({ length: 20 }, () => createFinding('medium')),
        ...Array.from({ length: 10 }, () => createFinding('high')),
      ];

      emitFindingAnnotations(findings);

      // All 10 high should be emitted
      expect(core.error).toHaveBeenCalledTimes(10);
      // All 20 medium should be emitted
      expect(core.warning).toHaveBeenCalledTimes(20);
      // Only 20 of 30 low should be emitted (50 - 10 - 20 = 20)
      // Note: The first notice call is for the capping message
      // So we expect 20 notice calls for low findings + 1 for the cap message
      expect(core.notice).toHaveBeenCalledTimes(21);
    });

    it('should return correct result for empty findings', () => {
      const result = emitFindingAnnotations([]);

      expect(result.emitted).toBe(0);
      expect(result.skipped).toBe(0);
      expect(result.capped).toBe(false);
    });
  });

  describe('emitAnnotations', () => {
    it('should collect findings from all scanners', () => {
      const secretsFinding = createFinding('high', { scanner: 'secrets' });
      const depsFinding = createFinding('medium', { scanner: 'dependencies' });

      const results: ScanResults = {
        scanners: [
          { name: 'secrets', findings: [secretsFinding], durationMs: 50 },
          { name: 'dependencies', findings: [depsFinding], durationMs: 50 },
        ],
        totalFindings: 2,
        highCount: 1,
        mediumCount: 1,
        lowCount: 0,
        totalDurationMs: 100,
        totalFilesScanned: 20,
        hasErrors: false,
      };

      const result = emitAnnotations(results);

      expect(result.emitted).toBe(2);
      expect(core.error).toHaveBeenCalledTimes(1);
      expect(core.warning).toHaveBeenCalledTimes(1);
    });

    it('should handle scan results with no findings', () => {
      const results = createScanResults([]);

      const result = emitAnnotations(results);

      expect(result.emitted).toBe(0);
      expect(core.error).not.toHaveBeenCalled();
      expect(core.warning).not.toHaveBeenCalled();
      expect(core.notice).not.toHaveBeenCalled();
    });
  });
});
