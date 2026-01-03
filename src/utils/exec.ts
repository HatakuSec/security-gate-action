/**
 * Safe command execution utilities
 *
 * Wraps @actions/exec with timeout support and output capture.
 * Uses argument arrays to prevent shell injection.
 *
 * @module utils/exec
 */

import * as exec from '@actions/exec';

/** Result of executing a command */
export interface ExecResult {
  /** Process exit code */
  exitCode: number;
  /** Captured stdout */
  stdout: string;
  /** Captured stderr */
  stderr: string;
}

/** Options for command execution */
export interface ExecOptions {
  /** Working directory for the command */
  cwd?: string;
  /** Timeout in milliseconds (default: 5 minutes) */
  timeout?: number;
  /** Environment variables to set */
  env?: Record<string, string>;
  /** Whether to ignore non-zero exit codes (default: false) */
  ignoreReturnCode?: boolean;
  /** Whether to suppress output to the Actions log (default: false) */
  silent?: boolean;
}

/** Default timeout: 5 minutes */
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Execute a command safely with timeout and output capture.
 *
 * Uses argument arrays to prevent shell injection attacks.
 * Always captures stdout and stderr regardless of exit code.
 *
 * @param command - The command to execute (path to binary)
 * @param args - Array of arguments (never concatenated into shell string)
 * @param options - Execution options
 * @returns Promise resolving to execution result
 * @throws Error if command fails and ignoreReturnCode is false
 *
 * @example
 * const result = await safeExec('trivy', ['config', '--format', 'json', '.']);
 * if (result.exitCode === 0) {
 *   const data = JSON.parse(result.stdout);
 * }
 */
export async function safeExec(
  command: string,
  args: string[] = [],
  options: ExecOptions = {}
): Promise<ExecResult> {
  const {
    cwd,
    timeout = DEFAULT_TIMEOUT_MS,
    env,
    ignoreReturnCode = false,
    silent = false,
  } = options;

  let stdout = '';
  let stderr = '';

  // Create a timeout promise
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(`Command timed out after ${timeout}ms: ${command}`));
    }, timeout);
  });

  const execPromise = (async (): Promise<ExecResult> => {
    // Filter out undefined values from process.env
    const filteredProcessEnv: Record<string, string> = {};
    for (const [key, value] of Object.entries(process.env)) {
      if (value !== undefined) {
        filteredProcessEnv[key] = value;
      }
    }

    const exitCode = await exec.exec(command, args, {
      cwd,
      env: env ? { ...filteredProcessEnv, ...env } : undefined,
      ignoreReturnCode: true, // We handle return code ourselves
      silent,
      listeners: {
        stdout: (data: Buffer) => {
          stdout += data.toString();
        },
        stderr: (data: Buffer) => {
          stderr += data.toString();
        },
      },
    });

    return { exitCode, stdout, stderr };
  })();

  try {
    const result = await Promise.race([execPromise, timeoutPromise]);

    // Clear timeout on success
    if (timeoutId) {
      clearTimeout(timeoutId);
    }

    // Check exit code if not ignoring
    if (!ignoreReturnCode && result.exitCode !== 0) {
      const errorMessage = stderr.trim() || `Command failed with exit code ${result.exitCode}`;
      throw new Error(errorMessage);
    }

    return result;
  } catch (error) {
    // Clear timeout on error
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    throw error;
  }
}

/**
 * Check if a command exists in PATH.
 *
 * @param command - Command name to check
 * @returns True if command is available
 */
export async function commandExists(command: string): Promise<boolean> {
  try {
    const whichCommand = process.platform === 'win32' ? 'where' : 'which';
    const result = await safeExec(whichCommand, [command], {
      ignoreReturnCode: true,
      silent: true,
      timeout: 5000,
    });
    return result.exitCode === 0;
  } catch {
    return false;
  }
}
