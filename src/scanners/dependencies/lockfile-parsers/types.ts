/**
 * Lockfile parser type definitions
 *
 * Common types used by all lockfile parsers.
 *
 * @module scanners/dependencies/lockfile-parsers/types
 */

/**
 * Supported package ecosystems.
 */
export type Ecosystem = 'npm' | 'pypi' | 'go' | 'rubygems' | 'cargo';

/**
 * A dependency extracted from a lockfile.
 */
export interface Dependency {
  /** Package name */
  name: string;

  /** Resolved version string */
  version: string;

  /** Package ecosystem (npm, pypi, etc.) */
  ecosystem: Ecosystem;

  /** Whether this is a dev/test dependency */
  isDev?: boolean;

  /** Line number in the lockfile where this dependency is defined */
  line?: number;
}

/**
 * Result from parsing a lockfile.
 */
export interface LockfileParseResult {
  /** List of dependencies extracted */
  dependencies: Dependency[];

  /** Path to the lockfile */
  lockfilePath: string;

  /** Ecosystem of the lockfile */
  ecosystem: Ecosystem;

  /** Any warnings encountered during parsing */
  warnings?: string[];
}

/**
 * Interface for lockfile parsers.
 */
export interface LockfileParser {
  /** Supported lockfile filenames */
  readonly filenames: readonly string[];

  /** Ecosystem this parser handles */
  readonly ecosystem: Ecosystem;

  /**
   * Parse a lockfile and extract dependencies.
   *
   * @param content - Raw lockfile content
   * @param filePath - Path to the lockfile (for error messages)
   * @returns Parse result with dependencies
   */
  parse(content: string, filePath: string): LockfileParseResult;
}
