/**
 * Yarn lockfile parser
 *
 * Parses yarn.lock (v1 format) to extract dependencies.
 *
 * @module scanners/dependencies/lockfile-parsers/yarn
 */

import type { Dependency, LockfileParser, LockfileParseResult } from './types';

/**
 * Parse a yarn.lock v1 file.
 *
 * yarn.lock v1 format example:
 * ```
 * lodash@^4.17.21:
 *   version "4.17.21"
 *   resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
 *   integrity sha512-...
 *
 * "@scope/package@^1.0.0":
 *   version "1.2.3"
 *   ...
 * ```
 */
function parseYarnLockV1(content: string, _filePath: string): Dependency[] {
  const dependencies: Dependency[] = [];
  const lines = content.split('\n');

  let currentPackageSpecs: string[] = [];
  let currentVersion: string | null = null;
  let currentLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) {
      continue;
    }
    const lineNumber = i + 1;

    // Skip comments and empty lines
    if (line.startsWith('#') || line.trim() === '') {
      continue;
    }

    // Package specification line (not indented, ends with colon)
    // Can be multiple specs on one line: "pkg@^1.0.0, pkg@^2.0.0:"
    if (!line.startsWith(' ') && line.endsWith(':')) {
      // Save previous package if we have one
      if (currentPackageSpecs.length > 0 && currentVersion) {
        for (const spec of currentPackageSpecs) {
          const name = extractPackageName(spec);
          if (name) {
            dependencies.push({
              name,
              version: currentVersion,
              ecosystem: 'npm',
              line: currentLine,
            });
          }
        }
      }

      // Start new package
      currentLine = lineNumber;
      currentVersion = null;

      // Parse package specs (remove trailing colon)
      const specLine = line.slice(0, -1);
      currentPackageSpecs = specLine.split(', ').map((s) => s.trim());
    }
    // Version line (indented, starts with "version")
    else if (line.trim().startsWith('version ')) {
      const versionMatch = line.match(/version\s+"([^"]+)"/);
      if (versionMatch?.[1]) {
        currentVersion = versionMatch[1];
      }
    }
  }

  // Don't forget the last package
  if (currentPackageSpecs.length > 0 && currentVersion) {
    for (const spec of currentPackageSpecs) {
      const name = extractPackageName(spec);
      if (name) {
        dependencies.push({
          name,
          version: currentVersion,
          ecosystem: 'npm',
          line: currentLine,
        });
      }
    }
  }

  // Deduplicate (same name + version)
  const seen = new Set<string>();
  return dependencies.filter((dep) => {
    const key = `${dep.name}@${dep.version}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

/**
 * Extract package name from a yarn.lock package specification.
 *
 * Examples:
 * - "lodash@^4.17.21" -> "lodash"
 * - "@scope/package@^1.0.0" -> "@scope/package"
 * - "\"@scope/package@^1.0.0\"" -> "@scope/package"
 */
function extractPackageName(spec: string): string | null {
  // Remove surrounding quotes if present
  let cleaned = spec.trim();
  if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
    cleaned = cleaned.slice(1, -1);
  }

  // Handle scoped packages (@scope/name@version)
  if (cleaned.startsWith('@')) {
    const match = cleaned.match(/^(@[^@]+)@/);
    return match?.[1] ?? null;
  }

  // Handle regular packages (name@version)
  const atIndex = cleaned.indexOf('@');
  if (atIndex > 0) {
    return cleaned.substring(0, atIndex);
  }

  return null;
}

/**
 * Yarn lockfile parser.
 */
export const yarnParser: LockfileParser = {
  filenames: ['yarn.lock'],
  ecosystem: 'npm', // Yarn uses npm ecosystem for OSV queries

  parse(content: string, filePath: string): LockfileParseResult {
    const warnings: string[] = [];
    let dependencies: Dependency[] = [];

    try {
      // Check for yarn.lock v2+ (uses YAML format with __metadata)
      if (content.includes('__metadata:')) {
        warnings.push(
          `${filePath}: Yarn v2+ lockfile detected. Only Yarn v1 format is currently supported.`
        );
        return {
          dependencies: [],
          lockfilePath: filePath,
          ecosystem: 'npm',
          warnings,
        };
      }

      dependencies = parseYarnLockV1(content, filePath);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      warnings.push(`Failed to parse ${filePath}: ${message}`);
    }

    return {
      dependencies,
      lockfilePath: filePath,
      ecosystem: 'npm',
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  },
};
