/**
 * Container Scanner
 *
 * Validates Dockerfiles against security best practices (DOCK001-DOCK008)
 * and optionally runs Trivy filesystem scan for additional checks.
 *
 * @module scanners/container
 */

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';

import type { Scanner, ScannerContext, ScannerResult, Finding, Severity } from '../types';
import { createFindingId } from '../types';
import {
  parseDockerfile,
  runDockerfileRules,
  DOCKERFILE_RULES,
  type DockerfileRuleFinding,
  type DockerfileRuleContext,
} from './dockerfile-rules';
import { safeExec, type ExecResult } from '../../utils/exec';
import { getTrivyPath, mapTrivySeverity, type ParsedTrivyFinding } from '../iac/trivy';

/** Dockerfile patterns to search for */
const DOCKERFILE_PATTERNS = ['**/Dockerfile', '**/Dockerfile.*', '**/*.dockerfile'];

/** Directories to exclude from scanning */
const EXCLUDED_DIRECTORIES = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/vendor/**',
  '**/__pycache__/**',
  '**/.venv/**',
  '**/venv/**',
  '**/.terraform/**',
  '**/.tools/**',
  '**/coverage/**',
];

/** Timeout for Trivy execution (5 minutes) */
const TRIVY_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Result from Trivy filesystem scan.
 */
interface TrivyFsResult {
  success: boolean;
  findings: ParsedTrivyFinding[];
  error?: string;
}

/**
 * Raw Trivy result from JSON output.
 */
interface TrivyResultItem {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
}

/**
 * Trivy vulnerability structure.
 */
interface TrivyVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  References?: string[];
}

/**
 * Trivy misconfiguration structure.
 */
interface TrivyMisconfiguration {
  ID?: string;
  AVDID?: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Resolution?: string;
  Severity?: string;
  Status?: string;
  PrimaryURL?: string;
  References?: string[];
  CauseMetadata?: {
    Resource?: string;
    Provider?: string;
    StartLine?: number;
    EndLine?: number;
  };
}

/**
 * Raw Trivy output structure.
 */
interface TrivyOutput {
  Results?: TrivyResultItem[];
}

/**
 * Find all Dockerfiles in the working directory.
 *
 * @param workingDirectory - Directory to search
 * @param globalIgnorePaths - Additional ignore patterns from global config
 * @returns Array of Dockerfile paths
 */
async function findDockerfiles(
  workingDirectory: string,
  globalIgnorePaths: string[] = []
): Promise<string[]> {
  const dockerfiles: string[] = [];

  // Combine default excludes with global ignore paths
  const ignorePatterns = [...EXCLUDED_DIRECTORIES, ...globalIgnorePaths];

  for (const pattern of DOCKERFILE_PATTERNS) {
    const matches = await glob(pattern, {
      cwd: workingDirectory,
      ignore: ignorePatterns,
      nodir: true,
      absolute: false,
    });
    dockerfiles.push(...matches);
  }

  // Deduplicate
  return [...new Set(dockerfiles)];
}

/**
 * Check if a .dockerignore file exists relative to a Dockerfile.
 *
 * @param dockerfilePath - Relative path to Dockerfile
 * @param workingDirectory - Working directory
 * @returns True if .dockerignore exists
 */
function hasDockerignore(dockerfilePath: string, workingDirectory: string): boolean {
  const dockerfileDir = path.dirname(path.join(workingDirectory, dockerfilePath));

  // Check for .dockerignore in same directory as Dockerfile
  if (fs.existsSync(path.join(dockerfileDir, '.dockerignore'))) {
    return true;
  }

  // Check for .dockerignore in working directory (root)
  if (fs.existsSync(path.join(workingDirectory, '.dockerignore'))) {
    return true;
  }

  return false;
}

/**
 * Convert a Dockerfile rule finding to a scanner Finding.
 *
 * @param ruleFinding - Finding from Dockerfile rules
 * @param dockerfilePath - Path to the Dockerfile
 * @returns Normalised Finding
 */
function toFinding(ruleFinding: DockerfileRuleFinding, dockerfilePath: string): Finding {
  const rule = DOCKERFILE_RULES.find((r) => r.id === ruleFinding.ruleId);
  const severity: Severity = rule?.severity ?? 'medium';

  return {
    id: createFindingId('container', ruleFinding.ruleId, dockerfilePath, ruleFinding.lineNumber),
    severity,
    title: rule?.description ?? ruleFinding.ruleId,
    message: ruleFinding.message,
    file: dockerfilePath,
    startLine: ruleFinding.lineNumber,
    endLine: ruleFinding.endLineNumber ?? ruleFinding.lineNumber,
    ruleId: ruleFinding.ruleId,
    scanner: 'container',
    snippet: ruleFinding.snippet,
  };
}

/**
 * Parse Trivy filesystem scan JSON output.
 *
 * @param jsonOutput - Raw JSON output from Trivy
 * @param workingDirectory - Working directory for relative paths
 * @returns Parsed findings
 */
export function parseTrivyFsOutput(
  jsonOutput: string,
  workingDirectory: string
): { findings: ParsedTrivyFinding[]; filesScanned: number } {
  const findings: ParsedTrivyFinding[] = [];
  let filesScanned = 0;

  if (!jsonOutput.trim()) {
    return { findings, filesScanned };
  }

  let parsed: TrivyOutput;
  try {
    parsed = JSON.parse(jsonOutput) as TrivyOutput;
  } catch {
    // Don't fail on parse errors, just return empty
    return { findings, filesScanned };
  }

  const results = parsed.Results ?? [];

  for (const result of results) {
    if (!result) {
      continue;
    }

    filesScanned++;

    // Make path relative
    let target = result.Target ?? '';
    if (target.startsWith(workingDirectory)) {
      target = path.relative(workingDirectory, target);
    }

    // Process vulnerabilities
    const vulns = result.Vulnerabilities ?? [];
    for (const vuln of vulns) {
      if (!vuln) {
        continue;
      }

      findings.push({
        checkId: vuln.VulnerabilityID ?? 'UNKNOWN',
        title: vuln.Title ?? `Vulnerability in ${vuln.PkgName ?? 'unknown'}`,
        message: vuln.Description ?? 'No description',
        severity: mapTrivySeverity(vuln.Severity ?? 'UNKNOWN'),
        file: target,
        resolution: vuln.FixedVersion ? `Upgrade to ${vuln.FixedVersion}` : undefined,
        references: vuln.References,
      });
    }

    // Process misconfigurations
    const misconfigs = result.Misconfigurations ?? [];
    for (const misconfig of misconfigs) {
      if (!misconfig || misconfig.Status !== 'FAIL') {
        continue;
      }

      findings.push({
        checkId: misconfig.AVDID ?? misconfig.ID ?? 'UNKNOWN',
        title: misconfig.Title ?? 'Misconfiguration',
        message: misconfig.Message ?? misconfig.Description ?? 'No description',
        severity: mapTrivySeverity(misconfig.Severity ?? 'UNKNOWN'),
        file: target,
        startLine: misconfig.CauseMetadata?.StartLine,
        endLine: misconfig.CauseMetadata?.EndLine,
        resolution: misconfig.Resolution,
        references: misconfig.References,
        resource: misconfig.CauseMetadata?.Resource,
        provider: misconfig.CauseMetadata?.Provider,
      });
    }
  }

  return { findings, filesScanned };
}

/**
 * Run Trivy filesystem scan on the Dockerfile context.
 *
 * @param contextPath - Path to scan (directory containing Dockerfile)
 * @param workingDirectory - Working directory
 * @param verbose - Enable verbose logging
 * @returns Trivy scan result
 */
async function runTrivyFsScan(
  contextPath: string,
  workingDirectory: string,
  verbose: boolean
): Promise<TrivyFsResult> {
  try {
    // Get Trivy binary (will install if needed)
    const trivyPath = await getTrivyPath(workingDirectory, verbose);

    if (verbose) {
      console.log(`Running Trivy fs scan on: ${contextPath}`);
    }

    const args = [
      'fs',
      '--format',
      'json',
      '--scanners',
      'vuln,config',
      '--severity',
      'CRITICAL,HIGH,MEDIUM,LOW',
      '--exit-code',
      '0', // Don't fail on findings
      contextPath,
    ];

    const result: ExecResult = await safeExec(trivyPath, args, {
      timeout: TRIVY_TIMEOUT_MS,
      ignoreReturnCode: true,
      silent: !verbose,
      cwd: workingDirectory,
    });

    if (result.exitCode !== 0 && !result.stdout.trim()) {
      return {
        success: false,
        findings: [],
        error: result.stderr || `Trivy exited with code ${result.exitCode}`,
      };
    }

    const { findings } = parseTrivyFsOutput(result.stdout, workingDirectory);

    if (verbose) {
      console.log(`Trivy fs scan complete: ${findings.length} findings`);
    }

    return {
      success: true,
      findings,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      findings: [],
      error: `Trivy fs scan failed: ${message}`,
    };
  }
}

/**
 * Scan a single Dockerfile.
 *
 * @param dockerfilePath - Relative path to Dockerfile
 * @param workingDirectory - Working directory
 * @param verbose - Enable verbose logging
 * @returns Findings from rule checks
 */
function scanDockerfile(
  dockerfilePath: string,
  workingDirectory: string,
  verbose: boolean
): DockerfileRuleFinding[] {
  const fullPath = path.join(workingDirectory, dockerfilePath);

  let content: string;
  try {
    content = fs.readFileSync(fullPath, 'utf-8');
  } catch (error) {
    if (verbose) {
      const message = error instanceof Error ? error.message : String(error);
      console.log(`Failed to read ${dockerfilePath}: ${message}`);
    }
    return [];
  }

  // Parse Dockerfile
  const instructions = parseDockerfile(content);

  if (verbose) {
    console.log(`Parsed ${dockerfilePath}: ${instructions.length} instructions`);
  }

  // Build context
  const context: DockerfileRuleContext = {
    dockerfilePath,
    hasDockerignore: hasDockerignore(dockerfilePath, workingDirectory),
    content,
  };

  // Run rules
  const { findings } = runDockerfileRules(instructions, context);

  return findings;
}

/**
 * Container scanner that validates Dockerfiles and container configurations.
 */
export const containerScanner: Scanner = {
  name: 'container',

  async run(context: ScannerContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const { workingDirectory, verbose } = context;
    const findings: Finding[] = [];
    const errors: string[] = [];

    if (verbose) {
      console.log(`Starting container scan in: ${workingDirectory}`);
    }

    // Find all Dockerfiles
    const dockerfiles = await findDockerfiles(workingDirectory, context.ignorePaths);

    if (verbose) {
      console.log(`Found ${dockerfiles.length} Dockerfile(s)`);
    }

    if (dockerfiles.length === 0) {
      return {
        name: 'container',
        findings: [],
        durationMs: Date.now() - startTime,
        filesScanned: 0,
        metadata: {
          dockerfilesFound: 0,
          rulesChecked: DOCKERFILE_RULES.length,
          trivyEnabled: false,
        },
      };
    }

    // Scan each Dockerfile with rules
    let ruleFindings = 0;
    for (const dockerfile of dockerfiles) {
      if (verbose) {
        console.log(`Scanning ${dockerfile}...`);
      }

      const dockerRuleFindings = scanDockerfile(dockerfile, workingDirectory, verbose);

      // Convert to normalised findings
      for (const ruleFinding of dockerRuleFindings) {
        findings.push(toFinding(ruleFinding, dockerfile));
        ruleFindings++;
      }
    }

    if (verbose) {
      console.log(`Dockerfile rules found ${ruleFindings} issues`);
    }

    // Optionally run Trivy fs scan
    let trivyEnabled = false;
    let trivyFindings = 0;

    // Run Trivy on the working directory if Dockerfiles are present
    const trivyResult = await runTrivyFsScan(workingDirectory, workingDirectory, verbose);

    if (trivyResult.success) {
      trivyEnabled = true;
      trivyFindings = trivyResult.findings.length;

      // Convert Trivy findings
      for (const trivyFinding of trivyResult.findings) {
        findings.push({
          id: createFindingId(
            'container',
            trivyFinding.checkId,
            trivyFinding.file,
            trivyFinding.startLine ?? 0
          ),
          severity: trivyFinding.severity,
          title: trivyFinding.title,
          message: trivyFinding.message,
          file: trivyFinding.file,
          startLine: trivyFinding.startLine,
          endLine: trivyFinding.endLine,
          ruleId: trivyFinding.checkId,
          scanner: 'container',
          metadata: {
            resolution: trivyFinding.resolution,
            references: trivyFinding.references,
            resource: trivyFinding.resource,
            provider: trivyFinding.provider,
          },
        });
      }
    } else if (trivyResult.error) {
      // Don't fail the whole scan, just note the error
      errors.push(trivyResult.error);
      if (verbose) {
        console.log(`Trivy scan error (non-fatal): ${trivyResult.error}`);
      }
    }

    if (verbose) {
      console.log(`Container scan complete: ${findings.length} total findings`);
      console.log(`  - Dockerfile rules: ${ruleFindings}`);
      console.log(`  - Trivy findings: ${trivyFindings}`);
    }

    return {
      name: 'container',
      findings,
      durationMs: Date.now() - startTime,
      filesScanned: dockerfiles.length,
      error: errors.length > 0 ? errors.join('; ') : undefined,
      metadata: {
        dockerfilesFound: dockerfiles.length,
        dockerfiles,
        rulesChecked: DOCKERFILE_RULES.length,
        ruleFindings,
        trivyEnabled,
        trivyFindings,
        errors: errors.length > 0 ? errors : undefined,
      },
    };
  },
};
