/**
 * Trivy Integration
 *
 * Handles Trivy binary detection, installation, execution, and output parsing
 * for Infrastructure-as-Code scanning.
 *
 * @module scanners/iac/trivy
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as http from 'http';
import * as https from 'https';
import { createWriteStream, mkdirSync, chmodSync, existsSync } from 'fs';
import { pipeline } from 'stream/promises';
import { createGunzip } from 'zlib';
import * as tar from 'tar';

import { safeExec, commandExists, type ExecResult } from '../../utils/exec';
import type { Severity } from '../types';

/** Trivy version to download if not available */
const TRIVY_VERSION = '0.58.0';

/** Default timeout for Trivy execution (10 minutes) */
const TRIVY_TIMEOUT_MS = 10 * 60 * 1000;

/** Download timeout (5 minutes) */
const DOWNLOAD_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Trivy result structure for IaC scanning.
 * Based on Trivy JSON output format.
 */
export interface TrivyResult {
  Target: string;
  Class?: string;
  Type?: string;
  MisconfSummary?: {
    Successes: number;
    Failures: number;
    Exceptions: number;
  };
  Misconfigurations?: TrivyMisconfiguration[];
}

/**
 * A single misconfiguration finding from Trivy.
 */
export interface TrivyMisconfiguration {
  Type?: string;
  ID: string;
  AVDID?: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Namespace?: string;
  Query?: string;
  Resolution?: string;
  Severity?: string;
  PrimaryURL?: string;
  References?: string[];
  Status?: string;
  Layer?: {
    Digest?: string;
    DiffID?: string;
  };
  CauseMetadata?: {
    Resource?: string;
    Provider?: string;
    Service?: string;
    StartLine?: number;
    EndLine?: number;
    Code?: {
      Lines?: Array<{
        Number: number;
        Content: string;
        IsCause: boolean;
        Annotation?: string;
        Truncated?: boolean;
        Highlighted?: string;
        FirstCause: boolean;
        LastCause: boolean;
      }>;
    };
  };
}

/**
 * Parsed finding from Trivy output.
 */
export interface ParsedTrivyFinding {
  /** Check/rule ID (e.g., AVD-AWS-0086) */
  checkId: string;
  /** Short title */
  title: string;
  /** Detailed message */
  message: string;
  /** Severity level */
  severity: Severity;
  /** File path (relative) */
  file: string;
  /** Start line number (1-indexed) */
  startLine?: number;
  /** End line number (1-indexed) */
  endLine?: number;
  /** Resolution/remediation guidance */
  resolution?: string;
  /** Reference URLs */
  references?: string[];
  /** Resource name (for IaC) */
  resource?: string;
  /** Provider (e.g., aws, gcp) */
  provider?: string;
}

/**
 * Result from running Trivy.
 */
export interface TrivyExecutionResult {
  /** Whether execution was successful */
  success: boolean;
  /** Parsed findings */
  findings: ParsedTrivyFinding[];
  /** Raw output for debugging */
  rawOutput?: string;
  /** Error message if failed */
  error?: string;
  /** Number of files scanned */
  filesScanned: number;
}

/**
 * Options for Trivy execution.
 */
export interface TrivyOptions {
  /** Working directory to scan */
  workingDirectory: string;
  /** Whether verbose logging is enabled */
  verbose?: boolean;
  /** Custom timeout in ms */
  timeout?: number;
  /** Custom Trivy binary path */
  trivyPath?: string;
}

/**
 * Raw parsed JSON from Trivy output.
 */
interface TrivyRawOutput {
  Results?: TrivyResult[];
  [key: string]: unknown;
}

/**
 * Map Trivy severity to our normalised severity levels.
 *
 * @param trivySeverity - Trivy severity string (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
 * @returns Normalised severity
 */
export function mapTrivySeverity(trivySeverity: string): Severity {
  const upper = trivySeverity.toUpperCase();
  switch (upper) {
    case 'CRITICAL':
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
    case 'UNKNOWN':
    default:
      return 'low';
  }
}

/**
 * Get the platform-specific Trivy download URL.
 *
 * @param version - Trivy version
 * @returns Download URL for the current platform
 */
function getTrivyDownloadUrl(version: string): string {
  const platform = os.platform();
  const arch = os.arch();

  // Map Node.js platform/arch to Trivy naming
  let trivyPlatform: string;
  let trivyArch: string;

  switch (platform) {
    case 'darwin':
      trivyPlatform = 'macOS';
      break;
    case 'linux':
      trivyPlatform = 'Linux';
      break;
    case 'win32':
      trivyPlatform = 'Windows';
      break;
    default:
      throw new Error(`Unsupported platform: ${platform}`);
  }

  switch (arch) {
    case 'x64':
      trivyArch = '64bit';
      break;
    case 'arm64':
      trivyArch = 'ARM64';
      break;
    default:
      throw new Error(`Unsupported architecture: ${arch}`);
  }

  const extension = platform === 'win32' ? 'zip' : 'tar.gz';
  return `https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_${trivyPlatform}-${trivyArch}.${extension}`;
}

/**
 * Get the local tools directory for caching Trivy.
 *
 * @param workingDirectory - Base working directory
 * @returns Path to tools directory
 */
function getToolsCacheDir(workingDirectory: string): string {
  // Use .tools directory in the working directory, or fall back to temp
  const toolsDir = path.join(workingDirectory, '.tools', 'trivy');
  return toolsDir;
}

/**
 * Download a file from URL to a local path.
 *
 * @param url - URL to download from
 * @param destPath - Destination file path
 * @param timeout - Timeout in milliseconds
 */
async function downloadFile(url: string, destPath: string, timeout: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      reject(new Error(`Download timed out after ${timeout}ms`));
    }, timeout);

    const makeRequest = (requestUrl: string): void => {
      const req = https.get(requestUrl);

      req.on('response', (response: http.IncomingMessage) => {
        const statusCode: number = response.statusCode ?? 0;
        const headers: http.IncomingHttpHeaders = response.headers;

        if (statusCode === 302 || statusCode === 301) {
          // Follow redirect
          const redirectUrl: string | undefined = headers.location;
          if (!redirectUrl) {
            clearTimeout(timeoutId);
            reject(new Error('Redirect without location header'));
            return;
          }
          makeRequest(redirectUrl);
          return;
        }

        if (statusCode !== 200) {
          clearTimeout(timeoutId);
          reject(new Error(`Failed to download: HTTP ${statusCode}`));
          return;
        }

        const fileStream = createWriteStream(destPath);
        response.pipe(fileStream);

        fileStream.on('finish', () => {
          clearTimeout(timeoutId);
          fileStream.close();
          resolve();
        });

        fileStream.on('error', (err: Error) => {
          clearTimeout(timeoutId);
          try {
            fs.unlinkSync(destPath);
          } catch {
            // Ignore cleanup errors
          }
          reject(err);
        });
      });

      req.on('error', (err: Error) => {
        clearTimeout(timeoutId);
        reject(err);
      });
    };

    makeRequest(url);
  });
}

/**
 * Extract a tar.gz archive.
 *
 * @param archivePath - Path to the archive
 * @param destDir - Destination directory
 */
async function extractTarGz(archivePath: string, destDir: string): Promise<void> {
  const readStream = fs.createReadStream(archivePath);
  const gunzip = createGunzip();

  await pipeline(readStream, gunzip, tar.extract({ cwd: destDir }));
}

/**
 * Download and install Trivy binary.
 *
 * @param workingDirectory - Working directory for tool cache
 * @param verbose - Whether to log progress
 * @returns Path to the Trivy binary
 */
export async function installTrivy(workingDirectory: string, verbose: boolean): Promise<string> {
  const toolsDir = getToolsCacheDir(workingDirectory);
  const trivyBinary = path.join(toolsDir, process.platform === 'win32' ? 'trivy.exe' : 'trivy');

  // Check if already installed
  if (existsSync(trivyBinary)) {
    if (verbose) {
      console.log(`Trivy already installed at: ${trivyBinary}`);
    }
    return trivyBinary;
  }

  if (verbose) {
    console.log(`Installing Trivy ${TRIVY_VERSION}...`);
  }

  // Create tools directory
  mkdirSync(toolsDir, { recursive: true });

  const downloadUrl = getTrivyDownloadUrl(TRIVY_VERSION);
  const archivePath = path.join(toolsDir, 'trivy.tar.gz');

  if (verbose) {
    console.log(`Downloading from: ${downloadUrl}`);
  }

  // Download the archive
  await downloadFile(downloadUrl, archivePath, DOWNLOAD_TIMEOUT_MS);

  if (verbose) {
    console.log('Extracting Trivy...');
  }

  // Extract the archive
  await extractTarGz(archivePath, toolsDir);

  // Make executable on Unix
  if (process.platform !== 'win32') {
    chmodSync(trivyBinary, 0o755);
  }

  // Clean up archive
  try {
    fs.unlinkSync(archivePath);
  } catch {
    // Ignore cleanup errors
  }

  if (verbose) {
    console.log(`Trivy installed successfully at: ${trivyBinary}`);
  }

  return trivyBinary;
}

/**
 * Find or install Trivy binary.
 *
 * @param workingDirectory - Working directory
 * @param verbose - Whether to log progress
 * @returns Path to Trivy binary
 */
export async function getTrivyPath(workingDirectory: string, verbose: boolean): Promise<string> {
  // First check if trivy is in PATH
  if (await commandExists('trivy')) {
    if (verbose) {
      console.log('Using system Trivy from PATH');
    }
    return 'trivy';
  }

  // Check if already installed in tools cache
  const toolsDir = getToolsCacheDir(workingDirectory);
  const cachedBinary = path.join(toolsDir, process.platform === 'win32' ? 'trivy.exe' : 'trivy');

  if (existsSync(cachedBinary)) {
    if (verbose) {
      console.log(`Using cached Trivy: ${cachedBinary}`);
    }
    return cachedBinary;
  }

  // Download and install
  return await installTrivy(workingDirectory, verbose);
}

/**
 * Parse Trivy JSON output into normalised findings.
 *
 * @param jsonOutput - Raw JSON output from Trivy
 * @param workingDirectory - Working directory (for making paths relative)
 * @returns Parsed findings
 */
export function parseTrivyOutput(
  jsonOutput: string,
  workingDirectory: string
): { findings: ParsedTrivyFinding[]; filesScanned: number } {
  const findings: ParsedTrivyFinding[] = [];
  let filesScanned = 0;

  if (!jsonOutput.trim()) {
    return { findings, filesScanned };
  }

  let results: TrivyResult[];

  try {
    const parsed: unknown = JSON.parse(jsonOutput);

    // Handle different Trivy output structures
    // Trivy can output either { Results: [...] } or just [...]
    if (Array.isArray(parsed)) {
      results = parsed as TrivyResult[];
    } else if (typeof parsed === 'object' && parsed !== null) {
      const obj = parsed as TrivyRawOutput;
      if (obj.Results && Array.isArray(obj.Results)) {
        results = obj.Results;
      } else {
        // Single result object
        results = [parsed as TrivyResult];
      }
    } else {
      results = [];
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to parse Trivy JSON output: ${message}`);
  }

  for (const result of results) {
    if (!result) {
      continue;
    }

    filesScanned++;

    // Get file path, make it relative
    let filePath = result.Target ?? 'unknown';
    if (path.isAbsolute(filePath)) {
      filePath = path.relative(workingDirectory, filePath);
    }

    const misconfigs = result.Misconfigurations ?? [];

    for (const misconfig of misconfigs) {
      if (!misconfig) {
        continue;
      }

      // Skip passed checks
      if (misconfig.Status === 'PASS') {
        continue;
      }

      // Get check ID (prefer AVDID over ID)
      const checkId = misconfig.AVDID ?? misconfig.ID ?? 'UNKNOWN';

      // Map severity
      const severity = mapTrivySeverity(misconfig.Severity ?? 'UNKNOWN');

      // Extract line numbers from CauseMetadata
      let startLine: number | undefined;
      let endLine: number | undefined;
      let resource: string | undefined;
      let provider: string | undefined;

      if (misconfig.CauseMetadata) {
        startLine = misconfig.CauseMetadata.StartLine;
        endLine = misconfig.CauseMetadata.EndLine;
        resource = misconfig.CauseMetadata.Resource;
        provider = misconfig.CauseMetadata.Provider;
      }

      // Build references array
      const references: string[] = [];
      if (misconfig.PrimaryURL) {
        references.push(misconfig.PrimaryURL);
      }
      if (misconfig.References) {
        for (const ref of misconfig.References) {
          if (ref && !references.includes(ref)) {
            references.push(ref);
          }
        }
      }

      findings.push({
        checkId,
        title: misconfig.Title ?? 'Unknown Issue',
        message: misconfig.Message ?? misconfig.Description ?? 'No description available',
        severity,
        file: filePath,
        startLine,
        endLine,
        resolution: misconfig.Resolution ?? undefined,
        references: references.length > 0 ? references : undefined,
        resource,
        provider,
      });
    }
  }

  return { findings, filesScanned };
}

/**
 * Run Trivy against a directory and return parsed results.
 *
 * @param options - Execution options
 * @returns Execution result with findings
 */
export async function runTrivy(options: TrivyOptions): Promise<TrivyExecutionResult> {
  const { workingDirectory, verbose = false, timeout = TRIVY_TIMEOUT_MS, trivyPath } = options;

  try {
    // Get Trivy binary path
    const trivy = trivyPath ?? (await getTrivyPath(workingDirectory, verbose));

    if (verbose) {
      console.log(`Running Trivy IaC scan on: ${workingDirectory}`);
    }

    // Build command arguments
    const args = [
      'config',
      '--format',
      'json',
      '--severity',
      'CRITICAL,HIGH,MEDIUM,LOW',
      '--exit-code',
      '0', // Don't fail on findings
      workingDirectory,
    ];

    // Execute Trivy
    const result: ExecResult = await safeExec(trivy, args, {
      timeout,
      ignoreReturnCode: true, // We handle exit codes ourselves
      silent: !verbose,
    });

    // Trivy exits with 0 on success (even with findings when --exit-code 0)
    // Non-zero typically means an error occurred
    if (result.exitCode !== 0 && !result.stdout.trim()) {
      // Real error - no output and non-zero exit
      return {
        success: false,
        findings: [],
        error: result.stderr || `Trivy exited with code ${result.exitCode}`,
        filesScanned: 0,
      };
    }

    // Parse output
    const { findings, filesScanned } = parseTrivyOutput(result.stdout, workingDirectory);

    if (verbose) {
      console.log(`Trivy scan complete: ${findings.length} findings in ${filesScanned} targets`);
    }

    return {
      success: true,
      findings,
      rawOutput: result.stdout,
      filesScanned,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      findings: [],
      error: `Trivy execution failed: ${message}`,
      filesScanned: 0,
    };
  }
}

/**
 * Check if Trivy is available (either in PATH or can be installed).
 *
 * @returns True if Trivy is available or can be installed
 */
export function isTrivyAvailable(): boolean {
  // We can always attempt to install Trivy
  return true;
}
