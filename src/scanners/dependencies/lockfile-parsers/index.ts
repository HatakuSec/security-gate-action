/**
 * Lockfile parsers index
 *
 * Exports all lockfile parsers and a unified parsing function.
 *
 * @module scanners/dependencies/lockfile-parsers
 */

import { npmParser } from './npm';
import { yarnParser } from './yarn';
import { requirementsParser, pipfileLockParser } from './python';
import type { LockfileParser, LockfileParseResult } from './types';

export * from './types';
export { npmParser } from './npm';
export { yarnParser } from './yarn';
export { requirementsParser, pipfileLockParser } from './python';

/**
 * All available lockfile parsers.
 */
export const ALL_PARSERS: readonly LockfileParser[] = [
  npmParser,
  yarnParser,
  requirementsParser,
  pipfileLockParser,
];

/**
 * Map of filename to parser.
 */
const PARSER_MAP: Map<string, LockfileParser> = new Map();

// Build the parser map
for (const parser of ALL_PARSERS) {
  for (const filename of parser.filenames) {
    PARSER_MAP.set(filename, parser);
  }
}

/**
 * Get the parser for a given lockfile filename.
 *
 * @param filename - The lockfile filename (e.g., "package-lock.json")
 * @returns The parser or undefined if not supported
 */
export function getParserForFile(filename: string): LockfileParser | undefined {
  return PARSER_MAP.get(filename);
}

/**
 * Get all supported lockfile filenames.
 *
 * @returns Array of supported filenames
 */
export function getSupportedLockfiles(): string[] {
  return Array.from(PARSER_MAP.keys());
}

/**
 * Parse a lockfile using the appropriate parser.
 *
 * @param filename - The lockfile filename
 * @param content - The lockfile content
 * @param filePath - Full path to the lockfile (for error messages)
 * @returns Parse result or undefined if parser not found
 */
export function parseLockfile(
  filename: string,
  content: string,
  filePath: string
): LockfileParseResult | undefined {
  const parser = getParserForFile(filename);
  if (!parser) {
    return undefined;
  }
  return parser.parse(content, filePath);
}
