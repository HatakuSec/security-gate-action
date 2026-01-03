/**
 * Secrets Scanner
 *
 * Detects leaked credentials and API keys in source files using
 * high-signal regex patterns and custom rules. Never logs actual secret values.
 *
 * @module scanners/secrets
 */

import * as core from '@actions/core';
import { relative } from 'path';

import type { Scanner, ScannerContext, ScannerResult, Finding } from '../types';
import { createFindingId } from '../types';
import { SECRET_PATTERNS, type SecretPattern } from './patterns';
import { findFiles, isBinaryFile, readTextFile, getFileSize } from '../../utils/files';
import { registerSecrets, maskSnippet } from '../../utils/masking';
import {
  compileRules,
  fileMatchesGlobs,
  isMatchAllowlisted,
  type CompiledRule,
  RuleValidationError,
  UnsafeRegexError,
} from '../../rules';
import type { CustomRule } from '../../config/schema';

/** Maximum file size to scan (1 MB) */
const MAX_FILE_SIZE_BYTES = 1024 * 1024;

/** Default directories to exclude from scanning */
const EXCLUDED_DIRECTORIES = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/coverage/**',
  '**/.next/**',
  '**/.turbo/**',
  '**/.cache/**',
  '**/vendor/**',
  '**/__pycache__/**',
  '**/.venv/**',
  '**/venv/**',
  '**/.terraform/**',
];

/** File extensions that are typically binary or non-source */
const BINARY_EXTENSIONS = new Set([
  'png',
  'jpg',
  'jpeg',
  'gif',
  'bmp',
  'ico',
  'webp',
  'svg',
  'pdf',
  'zip',
  'tar',
  'gz',
  'rar',
  '7z',
  'exe',
  'dll',
  'so',
  'dylib',
  'bin',
  'obj',
  'o',
  'a',
  'lib',
  'wasm',
  'woff',
  'woff2',
  'ttf',
  'eot',
  'otf',
  'mp3',
  'mp4',
  'wav',
  'avi',
  'mov',
  'mkv',
  'db',
  'sqlite',
  'sqlite3',
]);

/**
 * Match result from scanning a line with built-in patterns.
 */
interface LineMatch {
  /** The pattern that matched */
  pattern: SecretPattern;
  /** The matched value (the actual secret) */
  matchValue: string;
  /** Column position (0-indexed) */
  column: number;
}

/**
 * Match result from scanning a line with custom rules.
 */
interface CustomRuleMatch {
  /** The compiled rule that matched */
  rule: CompiledRule;
  /** The matched value */
  matchValue: string;
  /** Column position (0-indexed) */
  column: number;
}

/**
 * Scan a single line for secrets using built-in patterns.
 *
 * @param line - The line of text to scan
 * @returns Array of matches found in the line
 */
function scanLineBuiltIn(line: string): LineMatch[] {
  const matches: LineMatch[] = [];

  for (const pattern of SECRET_PATTERNS) {
    // Reset regex state for global patterns
    pattern.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(line)) !== null) {
      matches.push({
        pattern,
        matchValue: match[0],
        column: match.index,
      });
    }
  }

  return matches;
}

/**
 * Scan a single line with custom rules.
 *
 * @param line - The line of text to scan
 * @param rules - Compiled custom rules
 * @param filePath - File path for glob matching
 * @returns Array of custom rule matches
 */
function scanLineCustomRules(
  line: string,
  rules: CompiledRule[],
  filePath: string
): CustomRuleMatch[] {
  const matches: CustomRuleMatch[] = [];

  for (const rule of rules) {
    // Check if this file matches the rule's globs
    if (!fileMatchesGlobs(filePath, rule.fileGlobs)) {
      continue;
    }

    // Reset regex state for global patterns
    rule.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = rule.regex.exec(line)) !== null) {
      const matchValue = match[0];

      // Check inline allowlist
      if (isMatchAllowlisted(matchValue, rule.allowlist)) {
        continue;
      }

      matches.push({
        rule,
        matchValue,
        column: match.index,
      });
    }
  }

  return matches;
}

/**
 * Scan a file for secrets with built-in patterns and custom rules.
 *
 * @param filePath - Absolute path to the file
 * @param workingDirectory - Working directory for relative path calculation
 * @param verbose - Whether to log debug information
 * @param customRules - Optional compiled custom rules
 * @returns Array of findings from the file
 */
function scanFile(
  filePath: string,
  workingDirectory: string,
  verbose: boolean,
  customRules: CompiledRule[] = []
): Finding[] {
  const findings: Finding[] = [];
  const relativePath = relative(workingDirectory, filePath);

  // Check file size
  const fileSize = getFileSize(filePath);
  if (fileSize < 0) {
    if (verbose) {
      core.debug(`Secrets scanner: cannot read file ${relativePath}`);
    }
    return findings;
  }

  if (fileSize > MAX_FILE_SIZE_BYTES) {
    if (verbose) {
      core.debug(
        `Secrets scanner: skipping ${relativePath} (${(fileSize / 1024 / 1024).toFixed(2)} MB exceeds 1 MB limit)`
      );
    }
    return findings;
  }

  // Check if binary
  if (isBinaryFile(filePath)) {
    if (verbose) {
      core.debug(`Secrets scanner: skipping binary file ${relativePath}`);
    }
    return findings;
  }

  // Read file content
  const content = readTextFile(filePath, MAX_FILE_SIZE_BYTES);
  if (content === null) {
    if (verbose) {
      core.debug(`Secrets scanner: failed to read ${relativePath}`);
    }
    return findings;
  }

  // Scan line by line
  const lines = content.split('\n');

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    if (line === undefined) {
      continue;
    }
    const lineNumber = lineIndex + 1; // 1-indexed

    // Scan with built-in patterns
    const builtInMatches = scanLineBuiltIn(line);

    for (const match of builtInMatches) {
      // CRITICAL: Register the secret immediately to prevent log leakage
      registerSecrets([match.matchValue]);

      // Create masked snippet
      const maskedSnippet = maskSnippet(line, match.matchValue);

      // Create finding
      const finding: Finding = {
        id: createFindingId('secrets', match.pattern.id, relativePath, lineNumber),
        severity: match.pattern.severity,
        title: match.pattern.name,
        message: match.pattern.message,
        file: relativePath,
        startLine: lineNumber,
        endLine: lineNumber,
        ruleId: match.pattern.id,
        scanner: 'secrets',
        snippet: maskedSnippet,
        metadata: {
          column: match.column,
          patternId: match.pattern.id,
          patternName: match.pattern.name,
          isCustomRule: false,
        },
      };

      findings.push(finding);

      if (verbose) {
        core.debug(`Secrets scanner: found ${match.pattern.id} in ${relativePath}:${lineNumber}`);
      }
    }

    // Scan with custom rules
    if (customRules.length > 0) {
      const customMatches = scanLineCustomRules(line, customRules, relativePath);

      for (const match of customMatches) {
        // CRITICAL: Register the secret immediately to prevent log leakage
        registerSecrets([match.matchValue]);

        // Create masked snippet
        const maskedSnippet = maskSnippet(line, match.matchValue);

        // Create finding with CUSTOM prefix for custom rule IDs
        const findingId = createFindingId(
          'secrets',
          `CUSTOM:${match.rule.id}`,
          relativePath,
          lineNumber
        );

        const finding: Finding = {
          id: findingId,
          severity: match.rule.severity,
          title: match.rule.name,
          message: match.rule.description ?? `Custom rule ${match.rule.id} matched`,
          file: relativePath,
          startLine: lineNumber,
          endLine: lineNumber,
          ruleId: match.rule.id,
          scanner: 'secrets',
          snippet: maskedSnippet,
          metadata: {
            column: match.column,
            ruleId: match.rule.id,
            ruleName: match.rule.name,
            isCustomRule: true,
          },
        };

        findings.push(finding);

        if (verbose) {
          core.debug(
            `Secrets scanner: custom rule ${match.rule.id} matched in ${relativePath}:${lineNumber}`
          );
        }
      }
    }
  }

  return findings;
}

/**
 * Get the file extension from a path.
 */
function getExtension(filePath: string): string {
  const lastDot = filePath.lastIndexOf('.');
  if (lastDot === -1 || lastDot === filePath.length - 1) {
    return '';
  }
  return filePath.substring(lastDot + 1).toLowerCase();
}

/**
 * Check if a file should be skipped based on extension.
 */
function shouldSkipByExtension(filePath: string): boolean {
  const ext = getExtension(filePath);
  return BINARY_EXTENSIONS.has(ext);
}

/**
 * Secrets scanner that detects leaked credentials and API keys.
 */
export const secretsScanner: Scanner = {
  name: 'secrets',

  async run(context: ScannerContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    let filesScanned = 0;
    let error: string | undefined;

    try {
      const { workingDirectory, verbose, config } = context;

      if (verbose) {
        core.debug(`Secrets scanner: starting scan in ${workingDirectory}`);
      }

      // Compile custom rules if provided
      let customRules: CompiledRule[] = [];
      const rawRules = config.rules as CustomRule[] | undefined;
      if (rawRules && rawRules.length > 0) {
        try {
          customRules = compileRules(rawRules);
          if (verbose) {
            core.debug(`Secrets scanner: compiled ${customRules.length} custom rules`);
          }
        } catch (err) {
          if (err instanceof RuleValidationError || err instanceof UnsafeRegexError) {
            // Re-throw rule validation errors as scanner errors with exit code 2
            throw new Error(`Custom rule validation failed: ${err.message}`);
          }
          throw err;
        }
      }

      // Find all text files, excluding common non-source directories
      // Combine with global ignore paths from config
      const ignorePatterns = [...EXCLUDED_DIRECTORIES];
      if (context.ignorePaths && context.ignorePaths.length > 0) {
        ignorePatterns.push(...context.ignorePaths);
        if (verbose) {
          core.debug(
            `Secrets scanner: adding ${context.ignorePaths.length} global ignore patterns`
          );
        }
      }

      const files = await findFiles(['**/*'], {
        cwd: workingDirectory,
        ignore: ignorePatterns,
      });

      if (verbose) {
        core.debug(`Secrets scanner: found ${files.length} candidate files`);
      }

      // Scan each file
      for (const filePath of files) {
        // Skip binary extensions before reading
        if (shouldSkipByExtension(filePath)) {
          if (verbose) {
            core.debug(
              `Secrets scanner: skipping ${relative(workingDirectory, filePath)} (binary extension)`
            );
          }
          continue;
        }

        const fileFindings = scanFile(filePath, workingDirectory, verbose, customRules);
        findings.push(...fileFindings);
        filesScanned++;
      }

      if (verbose) {
        core.debug(
          `Secrets scanner: scanned ${filesScanned} files, found ${findings.length} findings`
        );
      }
    } catch (err) {
      error = err instanceof Error ? err.message : 'Unknown error in secrets scanner';
      core.warning(`Secrets scanner encountered an error: ${error}`);
    }

    return {
      name: 'secrets',
      findings,
      durationMs: Date.now() - startTime,
      filesScanned,
      error,
    };
  },
};

// Re-export patterns and rules for testing
export { SECRET_PATTERNS, type SecretPattern } from './patterns';
export {
  compileRules,
  compileRule,
  validateRegexSafety,
  fileMatchesGlobs,
  isMatchAllowlisted,
  type CompiledRule,
  RuleValidationError,
  UnsafeRegexError,
} from '../../rules';
