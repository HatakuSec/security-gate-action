/**
 * Infrastructure-as-Code Scanner
 *
 * Detects misconfigurations in Terraform and Kubernetes files using Trivy.
 * Handles automatic Trivy installation if not available in PATH.
 *
 * @module scanners/iac
 */

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';

import type { Scanner, ScannerContext, ScannerResult, Finding } from '../types';
import { createFindingId } from '../types';
import { runTrivy, type ParsedTrivyFinding } from './trivy';

/** Terraform file patterns */
const TERRAFORM_PATTERNS = ['**/*.tf', '**/*.tfvars'];

/** YAML file patterns (potential Kubernetes manifests) */
const YAML_PATTERNS = ['**/*.yaml', '**/*.yml'];

/** Directories to exclude from scanning */
const EXCLUDED_DIRECTORIES = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/.terraform/**',
  '**/vendor/**',
  '**/.tools/**',
];

/**
 * Check if a YAML file is likely a Kubernetes manifest.
 * Uses a simple heuristic: presence of `apiVersion:` and `kind:`.
 *
 * @param filePath - Path to the YAML file
 * @returns True if file appears to be a Kubernetes manifest
 */
function isKubernetesManifest(filePath: string): boolean {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    // Simple heuristic: check for Kubernetes-specific fields
    const hasApiVersion = /^apiVersion:/m.test(content);
    const hasKind = /^kind:/m.test(content);
    return hasApiVersion && hasKind;
  } catch {
    return false;
  }
}

/**
 * Find all IaC files in the working directory.
 *
 * @param workingDirectory - Directory to search
 * @param globalIgnorePaths - Additional ignore patterns from global config
 * @returns Object with terraform and kubernetes file arrays
 */
async function findIaCFiles(
  workingDirectory: string,
  globalIgnorePaths: string[] = []
): Promise<{
  terraformFiles: string[];
  kubernetesFiles: string[];
  totalFiles: number;
}> {
  const terraformFiles: string[] = [];
  const kubernetesFiles: string[] = [];

  // Combine default excludes with global ignore paths
  const ignorePatterns = [...EXCLUDED_DIRECTORIES, ...globalIgnorePaths];

  // Find Terraform files
  for (const pattern of TERRAFORM_PATTERNS) {
    const matches = await glob(pattern, {
      cwd: workingDirectory,
      ignore: ignorePatterns,
      nodir: true,
      absolute: false,
    });
    terraformFiles.push(...matches);
  }

  // Find potential Kubernetes YAML files
  for (const pattern of YAML_PATTERNS) {
    const matches = await glob(pattern, {
      cwd: workingDirectory,
      ignore: ignorePatterns,
      nodir: true,
      absolute: false,
    });

    // Filter to only actual Kubernetes manifests
    for (const match of matches) {
      const fullPath = path.join(workingDirectory, match);
      if (isKubernetesManifest(fullPath)) {
        kubernetesFiles.push(match);
      }
    }
  }

  // Deduplicate
  const uniqueTerraform = [...new Set(terraformFiles)];
  const uniqueKubernetes = [...new Set(kubernetesFiles)];

  return {
    terraformFiles: uniqueTerraform,
    kubernetesFiles: uniqueKubernetes,
    totalFiles: uniqueTerraform.length + uniqueKubernetes.length,
  };
}

/**
 * Check if any IaC files exist in the working directory.
 *
 * @param workingDirectory - Directory to check
 * @returns True if IaC files are present
 */
export async function hasIaCFiles(workingDirectory: string): Promise<boolean> {
  const { totalFiles } = await findIaCFiles(workingDirectory);
  return totalFiles > 0;
}

/**
 * Get list of supported IaC file types.
 *
 * @returns Array of supported file patterns
 */
export function getSupportedIaCPatterns(): string[] {
  return [...TERRAFORM_PATTERNS, ...YAML_PATTERNS.map((p) => `${p} (Kubernetes only)`)];
}

/**
 * Convert a Trivy finding to a normalised scanner Finding.
 *
 * @param trivyFinding - Parsed Trivy finding
 * @param _workingDirectory - Working directory (for relative paths)
 * @returns Normalised Finding object
 */
function toScannerFinding(trivyFinding: ParsedTrivyFinding, _workingDirectory: string): Finding {
  const ruleId = trivyFinding.checkId;

  // Build detailed message
  let message = trivyFinding.message;
  if (trivyFinding.resolution) {
    message += ` Resolution: ${trivyFinding.resolution}`;
  }
  if (trivyFinding.resource) {
    message += ` Resource: ${trivyFinding.resource}`;
  }

  return {
    id: createFindingId('iac', ruleId, trivyFinding.file, trivyFinding.startLine),
    ruleId,
    severity: trivyFinding.severity,
    title: trivyFinding.title,
    message,
    file: trivyFinding.file,
    startLine: trivyFinding.startLine,
    endLine: trivyFinding.endLine,
    scanner: 'iac',
    metadata: {
      provider: trivyFinding.provider,
      resource: trivyFinding.resource,
      references: trivyFinding.references,
    },
  };
}

/**
 * IaC scanner that detects infrastructure misconfigurations.
 */
export const iacScanner: Scanner = {
  name: 'iac',

  async run(context: ScannerContext): Promise<ScannerResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    const errors: string[] = [];

    if (context.verbose) {
      console.log('Starting IaC scan...');
      console.log(`Scan path: ${context.workingDirectory}`);
      console.log(`Supported patterns: ${getSupportedIaCPatterns().join(', ')}`);
    }

    // Step 1: Find IaC files
    const { terraformFiles, kubernetesFiles, totalFiles } = await findIaCFiles(
      context.workingDirectory,
      context.ignorePaths
    );

    if (context.verbose) {
      console.log(`Found ${terraformFiles.length} Terraform file(s)`);
      console.log(`Found ${kubernetesFiles.length} Kubernetes manifest(s)`);
    }

    // If no IaC files found, return early
    if (totalFiles === 0) {
      if (context.verbose) {
        console.log('No IaC files found, skipping scan');
      }
      return {
        name: 'iac',
        findings: [],
        durationMs: Date.now() - startTime,
        filesScanned: 0,
        metadata: {
          terraformFiles: 0,
          kubernetesFiles: 0,
        },
      };
    }

    // Step 2: Run Trivy on the working directory
    const trivyResult = await runTrivy({
      workingDirectory: context.workingDirectory,
      verbose: context.verbose,
    });

    if (!trivyResult.success) {
      errors.push(trivyResult.error ?? 'Unknown Trivy error');

      if (context.verbose) {
        console.log(`Trivy execution failed: ${trivyResult.error}`);
      }

      return {
        name: 'iac',
        findings: [],
        durationMs: Date.now() - startTime,
        filesScanned: 0,
        error: trivyResult.error,
        metadata: {
          terraformFiles: terraformFiles.length,
          kubernetesFiles: kubernetesFiles.length,
          errors,
        },
      };
    }

    // Step 3: Convert Trivy findings to scanner findings
    for (const trivyFinding of trivyResult.findings) {
      findings.push(toScannerFinding(trivyFinding, context.workingDirectory));
    }

    if (context.verbose) {
      console.log(`IaC scan complete:`);
      console.log(`  - Files scanned: ${trivyResult.filesScanned}`);
      console.log(`  - Findings: ${findings.length}`);
      console.log(`  - High: ${findings.filter((f) => f.severity === 'high').length}`);
      console.log(`  - Medium: ${findings.filter((f) => f.severity === 'medium').length}`);
      console.log(`  - Low: ${findings.filter((f) => f.severity === 'low').length}`);
    }

    return {
      name: 'iac',
      findings,
      durationMs: Date.now() - startTime,
      filesScanned: trivyResult.filesScanned,
      metadata: {
        terraformFiles: terraformFiles.length,
        kubernetesFiles: kubernetesFiles.length,
        errors: errors.length > 0 ? errors : undefined,
      },
    };
  },
};
