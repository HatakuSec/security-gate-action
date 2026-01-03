/**
 * Lockfile Parsers Unit Tests
 *
 * Tests for npm, yarn, and Python lockfile parsers.
 *
 * @module tests/unit/scanners/dependencies/lockfile-parsers
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

import {
  npmParser,
  yarnParser,
  requirementsParser,
  pipfileLockParser,
  getParserForFile,
  getSupportedLockfiles,
  parseLockfile,
  ALL_PARSERS,
} from '../../../../src/scanners/dependencies/lockfile-parsers';

// Path to test fixtures
const FIXTURES_DIR = path.join(__dirname, '../../../fixtures/lockfiles');

describe('Lockfile Parser Types', () => {
  describe('ALL_PARSERS', () => {
    it('should contain all parsers', () => {
      expect(ALL_PARSERS).toHaveLength(4);
      expect(ALL_PARSERS).toContain(npmParser);
      expect(ALL_PARSERS).toContain(yarnParser);
      expect(ALL_PARSERS).toContain(requirementsParser);
      expect(ALL_PARSERS).toContain(pipfileLockParser);
    });
  });

  describe('getParserForFile', () => {
    it('should return npm parser for package-lock.json', () => {
      expect(getParserForFile('package-lock.json')).toBe(npmParser);
    });

    it('should return yarn parser for yarn.lock', () => {
      expect(getParserForFile('yarn.lock')).toBe(yarnParser);
    });

    it('should return requirements parser for requirements.txt', () => {
      expect(getParserForFile('requirements.txt')).toBe(requirementsParser);
    });

    it('should return pipfile lock parser for Pipfile.lock', () => {
      expect(getParserForFile('Pipfile.lock')).toBe(pipfileLockParser);
    });

    it('should return undefined for unsupported files', () => {
      expect(getParserForFile('unknown.lock')).toBeUndefined();
      expect(getParserForFile('Gemfile.lock')).toBeUndefined();
      expect(getParserForFile('go.sum')).toBeUndefined();
    });
  });

  describe('getSupportedLockfiles', () => {
    it('should return all supported lockfile names', () => {
      const supported = getSupportedLockfiles();
      expect(supported).toContain('package-lock.json');
      expect(supported).toContain('yarn.lock');
      expect(supported).toContain('requirements.txt');
      expect(supported).toContain('Pipfile.lock');
    });
  });
});

describe('NPM Parser', () => {
  describe('parser metadata', () => {
    it('should have correct filenames and ecosystem', () => {
      expect(npmParser.filenames).toEqual(['package-lock.json']);
      expect(npmParser.ecosystem).toBe('npm');
    });
  });

  describe('parse', () => {
    it('should parse package-lock.json v3 format', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-lock.json'), 'utf-8');
      const result = npmParser.parse(content, 'package-lock.json');

      expect(result.warnings).toBeUndefined();
      expect(result.dependencies.length).toBeGreaterThan(0);

      // Check for expected packages
      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('lodash');
      expect(names).toContain('express');
      expect(names).toContain('typescript');
    });

    it('should identify dev dependencies', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-lock.json'), 'utf-8');
      const result = npmParser.parse(content, 'package-lock.json');

      const typescript = result.dependencies.find((d) => d.name === 'typescript');
      expect(typescript).toBeDefined();
      expect(typescript?.isDev).toBe(true);

      const express = result.dependencies.find((d) => d.name === 'express');
      expect(express).toBeDefined();
      expect(express?.isDev).toBeFalsy();
    });

    it('should extract correct versions', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-lock.json'), 'utf-8');
      const result = npmParser.parse(content, 'package-lock.json');

      const lodash = result.dependencies.find((d) => d.name === 'lodash');
      expect(lodash?.version).toBe('4.17.21');

      const express = result.dependencies.find((d) => d.name === 'express');
      expect(express?.version).toBe('4.18.2');
    });

    it('should set ecosystem to npm', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'package-lock.json'), 'utf-8');
      const result = npmParser.parse(content, 'package-lock.json');

      for (const dep of result.dependencies) {
        expect(dep.ecosystem).toBe('npm');
      }
    });

    it('should handle invalid JSON gracefully', () => {
      const result = npmParser.parse('not valid json', 'package-lock.json');

      expect(result.dependencies).toHaveLength(0);
      expect(result.warnings).toBeDefined();
      expect(result.warnings!.length).toBeGreaterThan(0);
      expect(result.warnings![0]).toContain('Failed to parse');
    });

    it('should handle empty packages object', () => {
      const content = JSON.stringify({
        name: 'empty-project',
        lockfileVersion: 3,
        packages: {},
      });
      const result = npmParser.parse(content, 'package-lock.json');

      expect(result.dependencies).toHaveLength(0);
      expect(result.warnings).toBeUndefined();
    });
  });
});

describe('Yarn Parser', () => {
  describe('parser metadata', () => {
    it('should have correct filenames and ecosystem', () => {
      expect(yarnParser.filenames).toEqual(['yarn.lock']);
      expect(yarnParser.ecosystem).toBe('npm');
    });
  });

  describe('parse', () => {
    it('should parse yarn.lock v1 format', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'yarn.lock'), 'utf-8');
      const result = yarnParser.parse(content, 'yarn.lock');

      expect(result.warnings).toBeUndefined();
      expect(result.dependencies.length).toBeGreaterThan(0);

      // Check for expected packages
      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('lodash');
      expect(names).toContain('express');
      expect(names).toContain('typescript');
    });

    it('should extract correct versions', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'yarn.lock'), 'utf-8');
      const result = yarnParser.parse(content, 'yarn.lock');

      const lodash = result.dependencies.find((d) => d.name === 'lodash');
      expect(lodash?.version).toBe('4.17.21');

      const express = result.dependencies.find((d) => d.name === 'express');
      expect(express?.version).toBe('4.18.2');
    });

    it('should set ecosystem to npm', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'yarn.lock'), 'utf-8');
      const result = yarnParser.parse(content, 'yarn.lock');

      for (const dep of result.dependencies) {
        expect(dep.ecosystem).toBe('npm');
      }
    });

    it('should handle empty lockfile', () => {
      const content = '# yarn lockfile v1\n\n';
      const result = yarnParser.parse(content, 'yarn.lock');

      expect(result.dependencies).toHaveLength(0);
      expect(result.warnings).toBeUndefined();
    });

    it('should handle scoped packages', () => {
      const content = `# yarn lockfile v1

"@types/node@^18.0.0":
  version "18.16.0"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-18.16.0.tgz"
`;
      const result = yarnParser.parse(content, 'yarn.lock');

      expect(result.dependencies).toHaveLength(1);
      expect(result.dependencies[0].name).toBe('@types/node');
      expect(result.dependencies[0].version).toBe('18.16.0');
    });
  });
});

describe('Requirements.txt Parser', () => {
  describe('parser metadata', () => {
    it('should have correct filenames and ecosystem', () => {
      // Note: may include requirements-dev.txt, requirements-prod.txt etc.
      expect(requirementsParser.filenames).toContain('requirements.txt');
      expect(requirementsParser.ecosystem).toBe('pypi');
    });
  });

  describe('parse', () => {
    it('should parse requirements.txt', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'requirements.txt'), 'utf-8');
      const result = requirementsParser.parse(content, 'requirements.txt');

      expect(result.warnings).toBeUndefined();
      expect(result.dependencies.length).toBeGreaterThan(0);

      // Check for expected packages
      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('flask');
      expect(names).toContain('requests');
      expect(names).toContain('django');
    });

    it('should extract pinned versions', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'requirements.txt'), 'utf-8');
      const result = requirementsParser.parse(content, 'requirements.txt');

      const flask = result.dependencies.find((d) => d.name === 'flask');
      expect(flask?.version).toBe('2.3.2');

      const django = result.dependencies.find((d) => d.name === 'django');
      expect(django?.version).toBe('4.2.1');
    });

    it('should set ecosystem to pypi', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'requirements.txt'), 'utf-8');
      const result = requirementsParser.parse(content, 'requirements.txt');

      for (const dep of result.dependencies) {
        expect(dep.ecosystem).toBe('pypi');
      }
    });

    it('should skip comments and empty lines', () => {
      const content = `
# This is a comment
flask==2.3.2

# Another comment
requests==2.31.0
`;
      const result = requirementsParser.parse(content, 'requirements.txt');

      expect(result.dependencies).toHaveLength(2);
    });

    it('should handle packages with extras', () => {
      const content = 'requests[security]==2.31.0\ncelery[redis,auth]==5.3.0';
      const result = requirementsParser.parse(content, 'requirements.txt');

      expect(result.dependencies).toHaveLength(2);
      // Package name may include extra or strip it
      const names = result.dependencies.map((d) => d.name);
      expect(names.some((n) => n.includes('requests'))).toBe(true);
      expect(names.some((n) => n.includes('celery'))).toBe(true);
    });

    it('should handle packages with various version specifiers', () => {
      const content = 'flask==2.3.2\nnumpy>=1.24.0';
      const result = requirementsParser.parse(content, 'requirements.txt');

      // Should have at least flask with pinned version
      const flask = result.dependencies.find((d) => d.name === 'flask');
      expect(flask).toBeDefined();
      expect(flask?.version).toBe('2.3.2');
    });

    it('should skip VCS and URL packages', () => {
      const content = `
-e git+https://github.com/example/pkg.git#egg=pkg
https://example.com/package.tar.gz
flask==2.3.2
`;
      const result = requirementsParser.parse(content, 'requirements.txt');

      // Should only have flask
      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('flask');
      expect(names.length).toBeLessThanOrEqual(2);
    });
  });
});

describe('Pipfile.lock Parser', () => {
  describe('parser metadata', () => {
    it('should have correct filenames and ecosystem', () => {
      expect(pipfileLockParser.filenames).toEqual(['Pipfile.lock']);
      expect(pipfileLockParser.ecosystem).toBe('pypi');
    });
  });

  describe('parse', () => {
    it('should parse Pipfile.lock', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'Pipfile.lock'), 'utf-8');
      const result = pipfileLockParser.parse(content, 'Pipfile.lock');

      expect(result.warnings).toBeUndefined();
      expect(result.dependencies.length).toBeGreaterThan(0);

      // Check for expected packages
      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('flask');
      expect(names).toContain('requests');
      expect(names).toContain('django');
      expect(names).toContain('pytest');
    });

    it('should identify dev dependencies', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'Pipfile.lock'), 'utf-8');
      const result = pipfileLockParser.parse(content, 'Pipfile.lock');

      const pytest = result.dependencies.find((d) => d.name === 'pytest');
      expect(pytest).toBeDefined();
      expect(pytest?.isDev).toBe(true);

      const flask = result.dependencies.find((d) => d.name === 'flask');
      expect(flask).toBeDefined();
      expect(flask?.isDev).toBeFalsy();
    });

    it('should extract correct versions', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'Pipfile.lock'), 'utf-8');
      const result = pipfileLockParser.parse(content, 'Pipfile.lock');

      const flask = result.dependencies.find((d) => d.name === 'flask');
      expect(flask?.version).toBe('2.3.2');

      const pytest = result.dependencies.find((d) => d.name === 'pytest');
      expect(pytest?.version).toBe('7.3.1');
    });

    it('should set ecosystem to pypi', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'Pipfile.lock'), 'utf-8');
      const result = pipfileLockParser.parse(content, 'Pipfile.lock');

      for (const dep of result.dependencies) {
        expect(dep.ecosystem).toBe('pypi');
      }
    });

    it('should handle invalid JSON gracefully', () => {
      const result = pipfileLockParser.parse('not valid json', 'Pipfile.lock');

      expect(result.dependencies).toHaveLength(0);
      expect(result.warnings).toBeDefined();
      expect(result.warnings!.length).toBeGreaterThan(0);
    });

    it('should handle empty sections', () => {
      const content = JSON.stringify({
        _meta: { hash: {} },
        default: {},
        develop: {},
      });
      const result = pipfileLockParser.parse(content, 'Pipfile.lock');

      expect(result.dependencies).toHaveLength(0);
      expect(result.warnings).toBeUndefined();
    });
  });
});

describe('parseLockfile', () => {
  it('should use correct parser based on filename', () => {
    const npmContent = fs.readFileSync(path.join(FIXTURES_DIR, 'package-lock.json'), 'utf-8');
    const result = parseLockfile('package-lock.json', npmContent, '/test/package-lock.json');

    expect(result).toBeDefined();
    expect(result!.dependencies.length).toBeGreaterThan(0);
    expect(result!.dependencies[0].ecosystem).toBe('npm');
  });

  it('should return undefined for unsupported files', () => {
    const result = parseLockfile('unknown.lock', '{}', '/test/unknown.lock');

    expect(result).toBeUndefined();
  });
});
