/**
 * Configuration validator
 *
 * Additional validation beyond schema validation.
 * Checks semantic constraints like "at least one scanner enabled".
 *
 * @module config/validator
 */

import * as core from '@actions/core';
import { existsSync } from 'fs';
import { resolve } from 'path';

import type { Config } from './schema';

/**
 * Error thrown when configuration fails semantic validation.
 */
export class ConfigSemanticError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigSemanticError';
  }
}

/**
 * Options for configuration validation.
 */
export interface ValidateConfigOptions {
  /** Working directory for path validation */
  workingDirectory?: string;
  /** Whether to validate that configured paths exist */
  validatePaths?: boolean;
}

/**
 * Validate that at least one scanner is enabled.
 *
 * @param config - Configuration to validate
 * @throws ConfigSemanticError if no scanners are enabled
 */
function validateScannersEnabled(config: Config): void {
  const { scanners } = config;

  const anyEnabled =
    scanners.secrets.enabled ||
    scanners.dependencies.enabled ||
    scanners.iac.enabled ||
    scanners.container.enabled;

  if (!anyEnabled) {
    throw new ConfigSemanticError(
      'At least one scanner must be enabled. ' +
        "Set 'enabled: true' for at least one scanner in the configuration."
    );
  }
}

/**
 * Validate that configured paths exist (warning only).
 *
 * @param config - Configuration to validate
 * @param workingDirectory - Base directory for path resolution
 */
function validatePathsExist(config: Config, workingDirectory: string): void {
  const { scanners } = config;

  // Check secrets include_paths
  if (scanners.secrets.include_paths) {
    for (const path of scanners.secrets.include_paths) {
      const absolutePath = resolve(workingDirectory, path);
      if (!existsSync(absolutePath)) {
        core.warning(`Secrets scanner: include path '${path}' does not exist`);
      }
    }
  }

  // Check container dockerfile_paths
  if (scanners.container.dockerfile_paths) {
    for (const path of scanners.container.dockerfile_paths) {
      const absolutePath = resolve(workingDirectory, path);
      if (!existsSync(absolutePath)) {
        core.warning(`Container scanner: Dockerfile path '${path}' does not exist`);
      }
    }
  }
}

/**
 * Validate configuration semantically.
 *
 * Performs validation beyond schema validation:
 * - Ensures at least one scanner is enabled
 * - Optionally validates that configured paths exist
 *
 * @param config - Configuration to validate
 * @param options - Validation options
 * @throws ConfigSemanticError if validation fails
 */
export function validateConfigSemantics(config: Config, options: ValidateConfigOptions = {}): void {
  const { workingDirectory = process.cwd(), validatePaths = true } = options;

  // Check that at least one scanner is enabled
  validateScannersEnabled(config);

  // Optionally validate paths (warnings only, doesn't throw)
  if (validatePaths) {
    validatePathsExist(config, workingDirectory);
  }
}
