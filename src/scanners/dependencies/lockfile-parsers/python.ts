/**
 * Python lockfile parser
 *
 * Parses requirements.txt and Pipfile.lock to extract dependencies.
 *
 * @module scanners/dependencies/lockfile-parsers/python
 */

import type { Dependency, LockfileParser, LockfileParseResult } from './types';

/**
 * Pipfile.lock structure (simplified)
 */
interface PipfileLock {
  default?: Record<string, PipfilePackage>;
  develop?: Record<string, PipfilePackage>;
}

interface PipfilePackage {
  version?: string;
  hashes?: string[];
}

/**
 * Parse requirements.txt format.
 *
 * Supports:
 * - package==version
 * - package>=version
 * - package~=version
 * - Comments (#)
 * - -r includes (noted but not followed)
 * - -e editable installs (skipped)
 */
function parseRequirementsTxt(content: string, _filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (rawLine === undefined) {
      continue;
    }
    const line = rawLine.trim();
    const lineNumber = i + 1;

    // Skip empty lines and comments
    if (line === '' || line.startsWith('#')) {
      continue;
    }

    // Skip -r (include), -e (editable), -i (index), etc.
    if (line.startsWith('-')) {
      continue;
    }

    // Parse package specifier
    // Formats: pkg==1.0.0, pkg>=1.0.0, pkg~=1.0.0, pkg[extra]==1.0.0
    const match = line.match(/^([a-zA-Z0-9_-]+(?:\[[^\]]+\])?)\s*([=~><]+)\s*([^\s;#]+)/);

    if (match?.[1] && match[3]) {
      // Remove extras from package name: package[extra] -> package
      const rawName = match[1];
      const name = rawName.replace(/\[.*\]$/, '').toLowerCase();
      const version = match[3];

      dependencies.push({
        name,
        version,
        ecosystem: 'pypi',
        line: lineNumber,
      });
    } else {
      // Try to match package name only (no version specified)
      const nameOnlyMatch = line.match(/^([a-zA-Z0-9_-]+(?:\[[^\]]+\])?)\s*$/);
      if (nameOnlyMatch?.[1]) {
        const rawName = nameOnlyMatch[1];
        const name = rawName.replace(/\[.*\]$/, '').toLowerCase();

        dependencies.push({
          name,
          version: '*', // Unknown version
          ecosystem: 'pypi',
          line: lineNumber,
        });
      }
    }
  }

  return dependencies;
}

/**
 * Parse Pipfile.lock JSON format.
 */
function parsePipfileLock(
  content: string,
  filePath: string
): { deps: Dependency[]; warnings: string[] } {
  const dependencies: Dependency[] = [];
  const warnings: string[] = [];

  try {
    const lockfile = JSON.parse(content) as PipfileLock;

    // Parse default (production) dependencies
    if (lockfile.default) {
      for (const [name, pkg] of Object.entries(lockfile.default)) {
        if (pkg.version) {
          // Version format is "==1.0.0", strip the operator
          const version = pkg.version.replace(/^[=~><]+/, '');
          dependencies.push({
            name: name.toLowerCase(),
            version,
            ecosystem: 'pypi',
            isDev: false,
          });
        }
      }
    }

    // Parse develop (dev) dependencies
    if (lockfile.develop) {
      for (const [name, pkg] of Object.entries(lockfile.develop)) {
        if (pkg.version) {
          const version = pkg.version.replace(/^[=~><]+/, '');
          dependencies.push({
            name: name.toLowerCase(),
            version,
            ecosystem: 'pypi',
            isDev: true,
          });
        }
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    warnings.push(`Failed to parse ${filePath}: ${message}`);
  }

  return { deps: dependencies, warnings };
}

/**
 * Requirements.txt parser.
 */
export const requirementsParser: LockfileParser = {
  filenames: ['requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt'],
  ecosystem: 'pypi',

  parse(content: string, filePath: string): LockfileParseResult {
    const warnings: string[] = [];
    let dependencies: Dependency[] = [];

    try {
      dependencies = parseRequirementsTxt(content, filePath);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      warnings.push(`Failed to parse ${filePath}: ${message}`);
    }

    return {
      dependencies,
      lockfilePath: filePath,
      ecosystem: 'pypi',
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  },
};

/**
 * Pipfile.lock parser.
 */
export const pipfileLockParser: LockfileParser = {
  filenames: ['Pipfile.lock'],
  ecosystem: 'pypi',

  parse(content: string, filePath: string): LockfileParseResult {
    const { deps, warnings } = parsePipfileLock(content, filePath);

    return {
      dependencies: deps,
      lockfilePath: filePath,
      ecosystem: 'pypi',
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  },
};
