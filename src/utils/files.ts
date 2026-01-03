/**
 * File system utilities
 *
 * Provides helpers for finding files, detecting binary files,
 * and working with file paths.
 *
 * @module utils/files
 */

import { glob } from 'glob';
import { readFileSync, statSync, existsSync, openSync, readSync, closeSync } from 'fs';
import { extname, resolve } from 'path';

/** Options for file finding */
export interface FindFilesOptions {
  /** Working directory (default: process.cwd()) */
  cwd?: string;
  /** Patterns to ignore (default: common ignores) */
  ignore?: string[];
  /** Maximum number of files to return */
  maxFiles?: number;
  /** Whether to follow symlinks (default: false) */
  followSymlinks?: boolean;
}

/** Default patterns to ignore when scanning */
const DEFAULT_IGNORE_PATTERNS = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/coverage/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/vendor/**',
  '**/__pycache__/**',
  '**/.venv/**',
  '**/venv/**',
  '**/.terraform/**',
];

/** Maximum bytes to read for binary detection */
const BINARY_CHECK_BYTES = 8192;

/**
 * Find files matching glob patterns.
 *
 * @param patterns - Glob pattern(s) to match
 * @param options - Search options
 * @returns Array of matched file paths (absolute)
 *
 * @example
 * const tsFiles = await findFiles(['**\/*.ts'], { cwd: './src' });
 */
export async function findFiles(
  patterns: string | string[],
  options: FindFilesOptions = {}
): Promise<string[]> {
  const {
    cwd = process.cwd(),
    ignore = DEFAULT_IGNORE_PATTERNS,
    maxFiles,
    followSymlinks = false,
  } = options;

  const patternArray = Array.isArray(patterns) ? patterns : [patterns];
  const absoluteCwd = resolve(cwd);

  const results: string[] = [];

  for (const pattern of patternArray) {
    const matches = await glob(pattern, {
      cwd: absoluteCwd,
      ignore,
      absolute: true,
      nodir: true,
      follow: followSymlinks,
    });

    for (const match of matches) {
      if (maxFiles && results.length >= maxFiles) {
        break;
      }
      if (!results.includes(match)) {
        results.push(match);
      }
    }

    if (maxFiles && results.length >= maxFiles) {
      break;
    }
  }

  return results;
}

/**
 * Check if a file appears to be binary by looking for null bytes.
 *
 * @param filePath - Path to the file to check
 * @returns True if file appears to be binary
 *
 * @example
 * if (isBinaryFile('./image.png')) {
 *   // Skip binary file
 * }
 */
export function isBinaryFile(filePath: string): boolean {
  try {
    // Check if file exists and is readable
    if (!existsSync(filePath)) {
      return false;
    }

    const stats = statSync(filePath);
    if (!stats.isFile()) {
      return false;
    }

    // Read first chunk of file
    const fd = openSync(filePath, 'r');
    const buffer = Buffer.alloc(Math.min(BINARY_CHECK_BYTES, stats.size));
    readSync(fd, buffer, 0, buffer.length, 0);
    closeSync(fd);

    // Check for null bytes (strong indicator of binary)
    for (let i = 0; i < buffer.length; i++) {
      if (buffer[i] === 0) {
        return true;
      }
    }

    return false;
  } catch {
    // If we can't read the file, assume it's not binary
    return false;
  }
}

/**
 * Get file extension (lowercase, without dot).
 *
 * @param filePath - Path to the file
 * @returns Lowercase extension without dot, or empty string if none
 *
 * @example
 * getFileExtension('src/index.ts') // 'ts'
 * getFileExtension('Dockerfile') // ''
 * getFileExtension('.gitignore') // 'gitignore'
 */
export function getFileExtension(filePath: string): string {
  const ext = extname(filePath);

  // Handle dotfiles like .gitignore, .env
  if (!ext && filePath.includes('/')) {
    const filename = filePath.split('/').pop() ?? '';
    if (filename.startsWith('.') && !filename.includes('.', 1)) {
      return filename.substring(1).toLowerCase();
    }
  } else if (!ext && filePath.startsWith('.') && !filePath.includes('.', 1)) {
    return filePath.substring(1).toLowerCase();
  }

  return ext ? ext.substring(1).toLowerCase() : '';
}

/**
 * Check if a path exists (file or directory).
 *
 * @param path - Path to check
 * @returns True if path exists
 */
export function pathExists(path: string): boolean {
  return existsSync(path);
}

/**
 * Read a text file safely, returning null on error.
 *
 * @param filePath - Path to the file
 * @param maxSize - Maximum file size in bytes (default: 1MB)
 * @returns File contents or null if unreadable/too large
 */
export function readTextFile(filePath: string, maxSize: number = 1024 * 1024): string | null {
  try {
    const stats = statSync(filePath);

    if (stats.size > maxSize) {
      return null;
    }

    return readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

/**
 * Get file size in bytes.
 *
 * @param filePath - Path to the file
 * @returns File size in bytes, or -1 if not accessible
 */
export function getFileSize(filePath: string): number {
  try {
    const stats = statSync(filePath);
    return stats.size;
  } catch {
    return -1;
  }
}
