/**
 * Scanner type definitions
 *
 * Defines the common interfaces for all security scanners.
 *
 * @module scanners/types
 */

/**
 * Severity levels for findings.
 * Ordered from most to least severe.
 */
export type Severity = 'high' | 'medium' | 'low';

/**
 * List of all severity levels in order of severity (highest first).
 */
export const SEVERITY_ORDER: readonly Severity[] = ['high', 'medium', 'low'];

/**
 * Names of available scanners.
 */
export type ScannerName = 'secrets' | 'dependencies' | 'iac' | 'container';

/**
 * A security finding from a scanner.
 */
export interface Finding {
  /** Unique identifier for this finding instance */
  id: string;

  /** Severity level of the finding */
  severity: Severity;

  /** Short title describing the finding */
  title: string;

  /** Detailed message with context */
  message: string;

  /** File path where the finding was detected (relative to working directory) */
  file: string;

  /** Starting line number (1-indexed) */
  startLine?: number;

  /** Ending line number (1-indexed), same as startLine if single line */
  endLine?: number;

  /** Rule/check ID that triggered this finding (e.g., SEC001, AVD-AWS-0086) */
  ruleId?: string;

  /** Name of the scanner that produced this finding */
  scanner: ScannerName;

  /** Masked code snippet showing the finding context */
  snippet?: string;

  /** Additional metadata specific to the scanner */
  metadata?: Record<string, unknown>;
}

/**
 * Result from running a scanner.
 */
export interface ScannerResult {
  /** Scanner name */
  name: ScannerName;

  /** List of findings detected */
  findings: Finding[];

  /** Execution duration in milliseconds */
  durationMs: number;

  /** Error message if scanner failed (findings may still be partial) */
  error?: string;

  /** Number of files scanned */
  filesScanned?: number;

  /** Additional metadata specific to the scanner */
  metadata?: Record<string, unknown>;
}

/**
 * Context passed to scanners for execution.
 */
export interface ScannerContext {
  /** Working directory to scan */
  workingDirectory: string;

  /** Whether verbose logging is enabled */
  verbose: boolean;

  /** Scanner-specific configuration */
  config: Record<string, unknown>;

  /**
   * Global ignore paths (glob patterns) from root config.
   * Scanners should skip files matching these patterns.
   */
  ignorePaths?: string[];
}

/**
 * Interface that all scanners must implement.
 */
export interface Scanner {
  /** Human-readable name of the scanner */
  readonly name: ScannerName;

  /**
   * Run the scanner and return findings.
   *
   * @param context - Execution context with config and options
   * @returns Promise resolving to scanner results
   */
  run(context: ScannerContext): Promise<ScannerResult>;
}

/**
 * Aggregated results from all scanners.
 */
export interface ScanResults {
  /** Results from each scanner */
  scanners: ScannerResult[];

  /** Total number of findings across all scanners */
  totalFindings: number;

  /** Count of high-severity findings */
  highCount: number;

  /** Count of medium-severity findings */
  mediumCount: number;

  /** Count of low-severity findings */
  lowCount: number;

  /** Total execution duration in milliseconds */
  totalDurationMs: number;

  /** Total files scanned across all scanners */
  totalFilesScanned: number;

  /** Whether any scanner had an error */
  hasErrors: boolean;

  /** Number of findings suppressed by allowlist */
  suppressedCount?: number;

  /** Findings suppressed by allowlist (for reporting) */
  suppressedFindings?: Finding[];

  /** Warnings about expired allowlist entries */
  allowlistWarnings?: string[];
}

/**
 * Count findings by severity.
 *
 * @param findings - Array of findings to count
 * @returns Object with counts by severity
 */
export function countFindingsBySeverity(findings: Finding[]): {
  high: number;
  medium: number;
  low: number;
} {
  const counts = { high: 0, medium: 0, low: 0 };

  for (const finding of findings) {
    counts[finding.severity]++;
  }

  return counts;
}

/**
 * Create a unique finding ID.
 *
 * @param scanner - Scanner name
 * @param ruleId - Rule identifier
 * @param file - File path
 * @param line - Line number
 * @returns Unique finding ID
 */
export function createFindingId(
  scanner: ScannerName,
  ruleId: string,
  file: string,
  line?: number
): string {
  const parts = [scanner, ruleId, file];
  if (line !== undefined) {
    parts.push(String(line));
  }
  return parts.join(':');
}
