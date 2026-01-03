/**
 * Default configuration values
 *
 * Provides the default configuration used when no config file exists
 * or when fields are omitted from the user's configuration.
 *
 * @module config/defaults
 */

import type { Config } from './schema';

/**
 * Default configuration with sensible defaults.
 *
 * - fail_on: high (only high-severity findings cause failure)
 * - mode: auto (detect and run relevant scanners)
 * - All scanners enabled by default
 */
export const DEFAULT_CONFIG: Config = {
  version: '1',
  fail_on: 'high',
  mode: 'auto',
  scanners: {
    secrets: {
      enabled: true,
    },
    dependencies: {
      enabled: true,
    },
    iac: {
      enabled: true,
    },
    container: {
      enabled: true,
    },
  },
};

/**
 * Default configuration file name.
 */
export const DEFAULT_CONFIG_FILENAME = '.security-gate.yml';

/**
 * Alternative configuration file names (checked in order).
 */
export const ALTERNATIVE_CONFIG_FILENAMES = [
  '.security-gate.yaml',
  'security-gate.yml',
  'security-gate.yaml',
];

/**
 * Get a fresh copy of the default configuration.
 * Returns a deep copy to prevent accidental mutation.
 *
 * @returns Deep copy of default configuration
 */
export function getDefaultConfig(): Config {
  return JSON.parse(JSON.stringify(DEFAULT_CONFIG)) as Config;
}
