/**
 * Dependency Scanner Unit Tests
 *
 * Tests for the main dependency scanner.
 *
 * @module tests/unit/scanners/dependencies/index
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as path from 'path';

import { dependenciesScanner } from '../../../../src/scanners/dependencies';
import type { ScannerContext } from '../../../../src/scanners/types';

// Path to test fixtures
const FIXTURES_DIR = path.join(__dirname, '../../../fixtures/lockfiles');

describe('Dependency Scanner', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
    // Mock fetch to prevent real OSV API calls
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ results: [] }),
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('metadata', () => {
    it('should have correct name', () => {
      expect(dependenciesScanner.name).toBe('dependencies');
    });

    it('should have run method', () => {
      expect(typeof dependenciesScanner.run).toBe('function');
    });
  });

  describe('run', () => {
    it('should return empty results when no lockfiles found', async () => {
      const context: ScannerContext = {
        config: {
          version: '1.0',
          scanners: { dependencies: true },
          thresholds: { high: 0, medium: 5, low: 10 },
        },
        workingDirectory: path.join(__dirname, 'nonexistent'),
        verbose: false,
      };

      const result = await dependenciesScanner.run(context);

      expect(result.name).toBe('dependencies');
      expect(result.findings).toHaveLength(0);
      expect(result.filesScanned).toBe(0);
    });

    it('should find and parse lockfiles', async () => {
      // Mock fetch to return no vulnerabilities
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            results: Array(20).fill({ vulns: [] }),
          }),
      });

      const context: ScannerContext = {
        config: {
          version: '1.0',
          scanners: { dependencies: true },
          thresholds: { high: 0, medium: 5, low: 10 },
        },
        workingDirectory: FIXTURES_DIR,
        verbose: false,
      };

      const result = await dependenciesScanner.run(context);

      expect(result.name).toBe('dependencies');
      expect(result.filesScanned).toBeGreaterThan(0);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it('should report metadata about scanned packages', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            results: Array(20).fill({ vulns: [] }),
          }),
      });

      const context: ScannerContext = {
        config: {
          version: '1.0',
          scanners: { dependencies: true },
          thresholds: { high: 0, medium: 5, low: 10 },
        },
        workingDirectory: FIXTURES_DIR,
        verbose: false,
      };

      const result = await dependenciesScanner.run(context);

      expect(result.metadata).toBeDefined();
      expect(result.metadata?.totalDependencies).toBeGreaterThan(0);
      expect(result.metadata?.uniqueDependencies).toBeGreaterThan(0);
    });

    it('should convert vulnerabilities to findings', async () => {
      // Mock fetch to return a vulnerability
      globalThis.fetch = vi.fn().mockImplementation((_url: string) => {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              results: [
                {
                  vulns: [
                    {
                      id: 'GHSA-test-vuln',
                      summary: 'Test vulnerability in lodash',
                      severity: [{ type: 'CVSS_V3', score: '9.8' }],
                      affected: [
                        {
                          package: { name: 'lodash', ecosystem: 'npm' },
                          ranges: [
                            {
                              type: 'SEMVER',
                              events: [{ fixed: '4.17.22' }],
                            },
                          ],
                        },
                      ],
                      references: [{ type: 'ADVISORY', url: 'https://example.com' }],
                    },
                  ],
                },
                // Rest of packages have no vulns
                ...Array(19).fill({ vulns: [] }),
              ],
            }),
        });
      });

      const context: ScannerContext = {
        config: {
          version: '1.0',
          scanners: { dependencies: true },
          thresholds: { high: 0, medium: 5, low: 10 },
        },
        workingDirectory: FIXTURES_DIR,
        verbose: false,
      };

      const result = await dependenciesScanner.run(context);

      // Should have at least one finding
      expect(result.findings.length).toBeGreaterThan(0);

      const finding = result.findings[0];
      expect(finding.ruleId).toContain('DEP-');
      expect(finding.severity).toBe('high');
      expect(finding.message).toContain('vulnerability');
      expect(finding.file).toBeTruthy();
    });

    it('should handle verbose mode', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            results: Array(20).fill({ vulns: [] }),
          }),
      });

      const context: ScannerContext = {
        config: {
          version: '1.0',
          scanners: { dependencies: true },
          thresholds: { high: 0, medium: 5, low: 10 },
        },
        workingDirectory: FIXTURES_DIR,
        verbose: true,
      };

      await dependenciesScanner.run(context);

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it('should handle API errors gracefully', async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('API unavailable'));

      const context: ScannerContext = {
        config: {
          version: '1.0',
          scanners: { dependencies: true },
          thresholds: { high: 0, medium: 5, low: 10 },
        },
        workingDirectory: FIXTURES_DIR,
        verbose: false,
      };

      // Should not throw
      const result = await dependenciesScanner.run(context);

      expect(result.name).toBe('dependencies');
      expect(result.metadata?.errors).toBeDefined();
      expect(result.metadata?.errors.length).toBeGreaterThan(0);
    });
  });
});
