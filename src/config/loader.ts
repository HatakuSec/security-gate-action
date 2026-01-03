/**
 * Configuration loader
 *
 * Loads, parses, and validates the Security Gate configuration file.
 * Merges user configuration with defaults.
 *
 * @module config/loader
 */

import * as core from '@actions/core';
import { readFileSync, existsSync } from 'fs';
import { resolve, join } from 'path';
import { load as yamlLoad } from 'js-yaml';

import { type Config, type PartialConfig, validateConfig, ConfigValidationError } from './schema';
import {
  DEFAULT_CONFIG_FILENAME,
  ALTERNATIVE_CONFIG_FILENAMES,
  getDefaultConfig,
} from './defaults';

/**
 * Error thrown when configuration file has invalid YAML syntax.
 */
export class ConfigParseError extends Error {
  constructor(
    message: string,
    public readonly filePath: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'ConfigParseError';
  }
}

/**
 * Error thrown when configuration file cannot be read.
 */
export class ConfigReadError extends Error {
  constructor(
    message: string,
    public readonly filePath: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'ConfigReadError';
  }
}

// Re-export for convenience
export { ConfigValidationError };

/**
 * Options for loading configuration.
 */
export interface LoadConfigOptions {
  /** Path to configuration file (relative to workingDirectory or absolute) */
  configPath?: string;
  /** Working directory (default: process.cwd()) */
  workingDirectory?: string;
}

/**
 * Result of loading configuration.
 */
export interface LoadConfigResult {
  /** The loaded and validated configuration */
  config: Config;
  /** Path to the configuration file that was loaded (null if using defaults) */
  configFile: string | null;
  /** Whether default configuration is being used */
  usingDefaults: boolean;
}

/**
 * Find the configuration file path.
 *
 * @param configPath - Explicit config path (if provided)
 * @param workingDirectory - Base directory to search from
 * @returns Resolved path to config file, or null if not found
 */
function findConfigFile(configPath: string | undefined, workingDirectory: string): string | null {
  // If explicit path provided, use it directly
  if (configPath && configPath !== DEFAULT_CONFIG_FILENAME) {
    const absolutePath = resolve(workingDirectory, configPath);
    return existsSync(absolutePath) ? absolutePath : null;
  }

  // Check default filename
  const defaultPath = join(workingDirectory, DEFAULT_CONFIG_FILENAME);
  if (existsSync(defaultPath)) {
    return defaultPath;
  }

  // Check alternative filenames
  for (const filename of ALTERNATIVE_CONFIG_FILENAMES) {
    const altPath = join(workingDirectory, filename);
    if (existsSync(altPath)) {
      return altPath;
    }
  }

  return null;
}

/**
 * Deep merge two configuration objects.
 * User values override defaults; arrays are replaced, not merged.
 *
 * @param defaults - Default configuration
 * @param user - User-provided configuration
 * @returns Merged configuration
 */
function mergeConfigs(defaults: Config, user: PartialConfig): Config {
  const merged: Config = { ...defaults };

  // Merge top-level scalar properties
  if (user.version !== undefined) {
    merged.version = user.version;
  }
  if (user.fail_on !== undefined) {
    merged.fail_on = user.fail_on;
  }
  if (user.mode !== undefined) {
    merged.mode = user.mode;
  }

  // Deep merge scanners configuration
  if (user.scanners) {
    merged.scanners = {
      secrets: { ...defaults.scanners.secrets, ...user.scanners.secrets },
      dependencies: {
        ...defaults.scanners.dependencies,
        ...user.scanners.dependencies,
      },
      iac: { ...defaults.scanners.iac, ...user.scanners.iac },
      container: { ...defaults.scanners.container, ...user.scanners.container },
    };
  }

  // Merge exclude_paths (array replacement, not merge)
  if (user.exclude_paths !== undefined) {
    merged.exclude_paths = user.exclude_paths;
  }

  // Merge custom rules (array replacement)
  // Note: Zod validation will apply defaults (type, severity, flags) after merge
  if (user.rules !== undefined) {
    merged.rules = user.rules as Config['rules'];
  }

  // Merge ignore config
  if (user.ignore !== undefined) {
    merged.ignore = user.ignore;
  }

  // Merge allowlist (array replacement)
  if (user.allowlist !== undefined) {
    merged.allowlist = user.allowlist;
  }

  return merged;
}

/**
 * Load and validate the Security Gate configuration.
 *
 * @param options - Loading options
 * @returns Loaded configuration result
 * @throws ConfigParseError if YAML syntax is invalid
 * @throws ConfigValidationError if schema validation fails
 * @throws ConfigReadError if file cannot be read
 */
export function loadConfig(options: LoadConfigOptions = {}): Promise<LoadConfigResult> {
  return Promise.resolve().then(() => {
    const { configPath, workingDirectory = process.cwd() } = options;

    const resolvedWorkDir = resolve(workingDirectory);
    const configFile = findConfigFile(configPath, resolvedWorkDir);

    // If no config file found, use defaults
    if (!configFile) {
      if (configPath && configPath !== DEFAULT_CONFIG_FILENAME) {
        // Explicit path was provided but file doesn't exist - warn but continue
        core.warning(`Configuration file not found at '${configPath}', using defaults`);
      } else {
        core.debug('No configuration file found, using defaults');
      }

      return {
        config: getDefaultConfig(),
        configFile: null,
        usingDefaults: true,
      };
    }

    // Read the configuration file
    let fileContent: string;
    try {
      fileContent = readFileSync(configFile, 'utf-8');
    } catch (error) {
      throw new ConfigReadError(
        `Failed to read configuration file: ${configFile}`,
        configFile,
        error instanceof Error ? error : undefined
      );
    }

    // Parse YAML
    let parsedYaml: unknown;
    try {
      parsedYaml = yamlLoad(fileContent);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown YAML parse error';
      throw new ConfigParseError(
        `Invalid YAML syntax in configuration file: ${message}`,
        configFile,
        error instanceof Error ? error : undefined
      );
    }

    // Handle empty file
    if (parsedYaml === null || parsedYaml === undefined) {
      core.debug('Configuration file is empty, using defaults');
      return {
        config: getDefaultConfig(),
        configFile,
        usingDefaults: true,
      };
    }

    // Merge with defaults and validate
    const defaults = getDefaultConfig();
    const merged = mergeConfigs(defaults, parsedYaml as PartialConfig);

    try {
      const validatedConfig = validateConfig(merged);
      return {
        config: validatedConfig,
        configFile,
        usingDefaults: false,
      };
    } catch (error) {
      if (error instanceof ConfigValidationError) {
        throw new ConfigValidationError(
          `Configuration validation failed in '${configFile}':\n${error.formatErrors()}`,
          error.errors
        );
      }
      throw error;
    }
  });
}
