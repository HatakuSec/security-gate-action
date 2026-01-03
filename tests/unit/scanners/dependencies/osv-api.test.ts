/**
 * OSV API Client Unit Tests
 *
 * Tests for OSV vulnerability API client.
 *
 * @module tests/unit/scanners/dependencies/osv-api
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { cvssToSeverity } from '../../../../src/scanners/dependencies/osv-api';
import type { Dependency } from '../../../../src/scanners/dependencies/lockfile-parsers';

describe('OSV API', () => {
  describe('cvssToSeverity', () => {
    it('should return high for CVSS >= 9.0', () => {
      expect(cvssToSeverity(9.0)).toBe('high');
      expect(cvssToSeverity(9.5)).toBe('high');
      expect(cvssToSeverity(10.0)).toBe('high');
    });

    it('should return medium for CVSS 7.0-8.9', () => {
      expect(cvssToSeverity(7.0)).toBe('medium');
      expect(cvssToSeverity(8.0)).toBe('medium');
      expect(cvssToSeverity(8.9)).toBe('medium');
    });

    it('should return low for CVSS < 7.0', () => {
      expect(cvssToSeverity(0)).toBe('low');
      expect(cvssToSeverity(3.5)).toBe('low');
      expect(cvssToSeverity(6.9)).toBe('low');
    });

    it('should return medium when score is undefined', () => {
      expect(cvssToSeverity(undefined)).toBe('medium');
    });
  });

  // Note: We don't test the actual API calls in unit tests
  // as they would require network access. Integration tests
  // with mocked fetch should be used for full coverage.
});

describe('OSV API - Mocked', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    // Reset fetch mock before each test
    vi.restoreAllMocks();
  });

  afterEach(() => {
    // Restore original fetch
    globalThis.fetch = originalFetch;
  });

  describe('queryOsv', () => {
    it('should handle empty dependencies array', async () => {
      // Dynamically import to get fresh module with mocked fetch
      const { queryOsv } = await import('../../../../src/scanners/dependencies/osv-api');

      const result = await queryOsv([]);

      expect(result.findings).toHaveLength(0);
      expect(result.packagesScanned).toBe(0);
      expect(result.packagesVulnerable).toBe(0);
      expect(result.errors).toHaveLength(0);
    });

    it('should handle API errors gracefully', async () => {
      // Mock fetch to return an error
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });

      const { queryOsv } = await import('../../../../src/scanners/dependencies/osv-api');

      const deps: Dependency[] = [{ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }];

      const result = await queryOsv(deps);

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain('OSV API error');
    });

    it('should handle network errors gracefully', async () => {
      // Mock fetch to throw an error
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

      const { queryOsv } = await import('../../../../src/scanners/dependencies/osv-api');

      const deps: Dependency[] = [{ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }];

      const result = await queryOsv(deps);

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain('Network error');
    });

    it('should skip dependencies without versions', async () => {
      // Mock fetch to track calls
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ results: [{ vulns: [] }] }),
      });
      globalThis.fetch = mockFetch;

      const { queryOsv } = await import('../../../../src/scanners/dependencies/osv-api');

      const deps: Dependency[] = [
        { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
        { name: 'no-version', version: '', ecosystem: 'npm' },
      ];

      await queryOsv(deps);

      // Should only have one query (lodash)
      if (mockFetch.mock.calls.length > 0) {
        const body = JSON.parse(mockFetch.mock.calls[0][1].body as string) as {
          queries: Array<{ package: { name: string } }>;
        };
        expect(body.queries).toHaveLength(1);
        expect(body.queries[0].package.name).toBe('lodash');
      }
    });

    it('should parse vulnerability findings correctly', async () => {
      // Mock fetch with vulnerability response
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            results: [
              {
                vulns: [
                  {
                    id: 'GHSA-test-1234-5678',
                    summary: 'Test vulnerability',
                    severity: [{ type: 'CVSS_V3', score: '9.8' }],
                    affected: [
                      {
                        package: { name: 'lodash', ecosystem: 'npm' },
                        ranges: [
                          {
                            type: 'SEMVER',
                            events: [{ introduced: '0' }, { fixed: '4.17.22' }],
                          },
                        ],
                      },
                    ],
                    references: [{ type: 'ADVISORY', url: 'https://example.com/advisory' }],
                  },
                ],
              },
            ],
          }),
      });

      const { queryOsv } = await import('../../../../src/scanners/dependencies/osv-api');

      const deps: Dependency[] = [{ name: 'lodash', version: '4.17.21', ecosystem: 'npm' }];

      const result = await queryOsv(deps);

      expect(result.packagesScanned).toBe(1);
      expect(result.packagesVulnerable).toBe(1);
      expect(result.findings).toHaveLength(1);

      const finding = result.findings[0];
      expect(finding.id).toBe('GHSA-test-1234-5678');
      expect(finding.summary).toBe('Test vulnerability');
      expect(finding.severity).toBe('high'); // CVSS 9.8 maps to high
      expect(finding.cvssScore).toBe(9.8);
      expect(finding.fixedVersion).toBe('4.17.22');
      expect(finding.referenceUrl).toBe('https://example.com/advisory');
      expect(finding.dependency.name).toBe('lodash');
    });

    it('should handle multiple vulnerabilities for same package', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            results: [
              {
                vulns: [
                  { id: 'GHSA-1', summary: 'Vuln 1' },
                  { id: 'GHSA-2', summary: 'Vuln 2' },
                ],
              },
            ],
          }),
      });

      const { queryOsv } = await import('../../../../src/scanners/dependencies/osv-api');

      const deps: Dependency[] = [{ name: 'test-pkg', version: '1.0.0', ecosystem: 'npm' }];

      const result = await queryOsv(deps);

      expect(result.packagesVulnerable).toBe(1);
      expect(result.findings).toHaveLength(2);
      expect(result.findings[0].id).toBe('GHSA-1');
      expect(result.findings[1].id).toBe('GHSA-2');
    });

    it('should map ecosystems correctly', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ results: [{ vulns: [] }, { vulns: [] }] }),
      });
      globalThis.fetch = mockFetch;

      const { queryOsv } = await import('../../../../src/scanners/dependencies/osv-api');

      const deps: Dependency[] = [
        { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
        { name: 'flask', version: '2.3.2', ecosystem: 'pypi' },
      ];

      await queryOsv(deps);

      expect(mockFetch).toHaveBeenCalled();
      const body = JSON.parse(mockFetch.mock.calls[0][1].body as string) as {
        queries: Array<{ package: { ecosystem: string } }>;
      };
      expect(body.queries).toHaveLength(2);
      expect(body.queries[0].package.ecosystem).toBe('npm');
      expect(body.queries[1].package.ecosystem).toBe('PyPI');
    });
  });
});
