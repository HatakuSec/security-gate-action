/**
 * NPM lockfile parser
 *
 * Parses package-lock.json (v2 and v3 formats) to extract dependencies.
 *
 * @module scanners/dependencies/lockfile-parsers/npm
 */

import type { Dependency, LockfileParser, LockfileParseResult } from './types';

/**
 * package-lock.json v2/v3 structure (simplified)
 */
interface PackageLockV2V3 {
  lockfileVersion?: number;
  packages?: Record<string, PackageLockPackage>;
  dependencies?: Record<string, PackageLockDependency>;
}

interface PackageLockPackage {
  version?: string;
  resolved?: string;
  dev?: boolean;
  optional?: boolean;
}

interface PackageLockDependency {
  version?: string;
  resolved?: string;
  dev?: boolean;
  optional?: boolean;
  dependencies?: Record<string, PackageLockDependency>;
}

/**
 * Parse package-lock.json v2/v3 format using the `packages` field.
 */
function parsePackagesField(
  packages: Record<string, PackageLockPackage>,
  _filePath: string
): Dependency[] {
  const dependencies: Dependency[] = [];

  for (const [path, pkg] of Object.entries(packages)) {
    // Skip the root package (empty string key)
    if (path === '' || !pkg.version) {
      continue;
    }

    // Extract package name from path (e.g., "node_modules/lodash" -> "lodash")
    // Handle scoped packages: "node_modules/@scope/pkg" -> "@scope/pkg"
    const match = path.match(/node_modules\/(.+)$/);
    if (!match?.[1]) {
      continue;
    }

    const name = match[1];
    // pkg.version is guaranteed to be defined due to the check at the start of the loop
    const version = pkg.version;

    dependencies.push({
      name,
      version,
      ecosystem: 'npm',
      isDev: pkg.dev === true,
    });
  }

  return dependencies;
}

/**
 * Parse package-lock.json v1 format using the `dependencies` field.
 * Also serves as fallback for v2 when `packages` is missing.
 */
function parseDependenciesField(
  deps: Record<string, PackageLockDependency>,
  filePath: string,
  isDev = false
): Dependency[] {
  const dependencies: Dependency[] = [];

  for (const [name, dep] of Object.entries(deps)) {
    if (!dep.version) {
      continue;
    }

    dependencies.push({
      name,
      version: dep.version,
      ecosystem: 'npm',
      isDev: isDev || dep.dev === true,
    });

    // Recursively parse nested dependencies
    if (dep.dependencies) {
      dependencies.push(
        ...parseDependenciesField(dep.dependencies, filePath, isDev || dep.dev === true)
      );
    }
  }

  return dependencies;
}

/**
 * NPM package-lock.json parser.
 */
export const npmParser: LockfileParser = {
  filenames: ['package-lock.json'],
  ecosystem: 'npm',

  parse(content: string, filePath: string): LockfileParseResult {
    const warnings: string[] = [];
    let dependencies: Dependency[] = [];

    try {
      const lockfile = JSON.parse(content) as PackageLockV2V3;
      const version = lockfile.lockfileVersion ?? 1;

      // v2 and v3 use `packages` field
      if (version >= 2 && lockfile.packages) {
        dependencies = parsePackagesField(lockfile.packages, filePath);
      }
      // v1 or fallback uses `dependencies` field
      else if (lockfile.dependencies) {
        dependencies = parseDependenciesField(lockfile.dependencies, filePath);
      }

      // Deduplicate dependencies (same name + version)
      const seen = new Set<string>();
      dependencies = dependencies.filter((dep) => {
        const key = `${dep.name}@${dep.version}`;
        if (seen.has(key)) {
          return false;
        }
        seen.add(key);
        return true;
      });
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
