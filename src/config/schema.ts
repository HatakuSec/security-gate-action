/**
 * Configuration schema definitions using Zod
 *
 * Defines the validation schemas for the Security Gate configuration file.
 * All configuration is validated against these schemas at runtime.
 *
 * @module config/schema
 */

import { z } from 'zod';

/**
 * Severity level schema.
 * Determines the minimum severity that causes the action to fail.
 */
export const SeveritySchema = z.enum(['high', 'medium', 'low']);
export type Severity = z.infer<typeof SeveritySchema>;

// =============================================================================
// Custom Rules, Ignore, and Allowlist schemas
// =============================================================================

/**
 * Limits for custom rules to prevent abuse/ReDoS.
 */
export const RULE_LIMITS = {
  /** Maximum number of custom rules */
  MAX_RULES: 50,
  /** Maximum regex pattern length */
  MAX_REGEX_LENGTH: 500,
  /** Maximum number of file globs per rule */
  MAX_GLOBS_PER_RULE: 25,
  /** Maximum allowlist entries per rule */
  MAX_ALLOWLIST_PER_RULE: 50,
  /** Minimum rule ID length */
  MIN_RULE_ID_LENGTH: 3,
  /** Maximum rule ID length */
  MAX_RULE_ID_LENGTH: 32,
} as const;

/**
 * Regex pattern for valid rule IDs.
 * Allows uppercase letters, numbers, underscores, and hyphens.
 */
const RULE_ID_PATTERN = /^[A-Z0-9_-]{3,32}$/;

/**
 * Valid regex flags for custom rules.
 * Only allows safe, common flags.
 */
const VALID_FLAGS = new Set(['g', 'i', 'm', 's', 'u']);

/**
 * Custom rule type (currently only 'secret', extensible for future).
 */
export const CustomRuleTypeSchema = z.enum(['secret']);
export type CustomRuleType = z.infer<typeof CustomRuleTypeSchema>;

/**
 * Rule-level allowlist entry for suppressing specific matches.
 */
export const RuleAllowlistEntrySchema = z.object({
  /** Pattern or value to allowlist (exact match or simple glob) */
  pattern: z.string().min(1).max(200),
  /** Reason for allowlisting */
  reason: z.string().min(1).max(500).optional(),
});
export type RuleAllowlistEntry = z.infer<typeof RuleAllowlistEntrySchema>;

/**
 * Custom rule schema for secrets detection extension.
 */
export const CustomRuleSchema = z
  .object({
    /** Unique rule identifier (uppercase letters, numbers, underscores, hyphens) */
    id: z
      .string()
      .min(RULE_LIMITS.MIN_RULE_ID_LENGTH)
      .max(RULE_LIMITS.MAX_RULE_ID_LENGTH)
      .regex(RULE_ID_PATTERN, {
        message: `Rule ID must match pattern ${RULE_ID_PATTERN.source}`,
      }),

    /** Human-readable name */
    name: z.string().min(1).max(100),

    /** Optional description of what this rule detects */
    description: z.string().max(500).optional(),

    /** Severity level for findings (default: medium) */
    severity: SeveritySchema.default('medium'),

    /** Rule type (currently only 'secret') */
    type: CustomRuleTypeSchema.default('secret'),

    /** Regex pattern string (validated for ReDoS safety separately) */
    regex: z.string().min(1).max(RULE_LIMITS.MAX_REGEX_LENGTH),

    /** Regex flags (default: 'g'; allowed: g, i, m, s, u) */
    flags: z
      .string()
      .default('g')
      .refine(
        (flags) => {
          const chars = flags.split('');
          return chars.every((c) => VALID_FLAGS.has(c));
        },
        { message: `Flags must only contain: ${[...VALID_FLAGS].join(', ')}` }
      ),

    /** File glob patterns to apply this rule to (default: all scannable files) */
    file_globs: z.array(z.string().min(1).max(200)).max(RULE_LIMITS.MAX_GLOBS_PER_RULE).optional(),

    /** Inline allowlist for this specific rule */
    allowlist: z.array(RuleAllowlistEntrySchema).max(RULE_LIMITS.MAX_ALLOWLIST_PER_RULE).optional(),
  })
  .strict();

export type CustomRule = z.infer<typeof CustomRuleSchema>;

/**
 * Array of custom rules with limit enforcement.
 */
export const CustomRulesArraySchema = z.array(CustomRuleSchema).max(RULE_LIMITS.MAX_RULES);

/**
 * Global allowlist entry for suppressing findings.
 */
export const AllowlistEntrySchema = z
  .object({
    /** Unique identifier for this allowlist entry */
    id: z.string().min(1).max(64),

    /** Reason for allowlisting (required for audit trail) */
    reason: z.string().min(1).max(500),

    /** Optional expiry date (ISO 8601 format, e.g., 2026-03-01) */
    expires: z
      .string()
      .optional()
      .refine(
        (val) => {
          if (!val) {
            return true;
          }
          const date = Date.parse(val);
          return !isNaN(date);
        },
        { message: 'expires must be a valid ISO 8601 date (e.g., 2026-03-01)' }
      ),

    /** Match criteria */
    match: z
      .object({
        /** Scanner to match (secrets, dependencies, iac, container) */
        scanner: z.enum(['secrets', 'dependencies', 'iac', 'container']).optional(),

        /** Exact finding ID or prefix match (e.g., 'SEC001' or 'DEP-GHSA-*') */
        finding_id: z.string().max(200).optional(),

        /** Rule ID to match (e.g., 'SEC001' or custom rule ID) */
        rule_id: z.string().max(64).optional(),

        /** File path glob pattern */
        path_glob: z.string().max(300).optional(),

        /** Substring match in finding message (limited length) */
        message_contains: z.string().max(100).optional(),
      })
      .optional()
      .refine(
        (match) => {
          // At least one match criterion must be specified
          if (!match) {
            return true;
          }
          return Boolean(
            match.scanner ??
            match.finding_id ??
            match.rule_id ??
            match.path_glob ??
            match.message_contains
          );
        },
        { message: 'At least one match criterion must be specified in allowlist entry' }
      ),
  })
  .strict();

export type AllowlistEntry = z.infer<typeof AllowlistEntrySchema>;

/**
 * Ignore configuration for excluding paths globally.
 */
export const IgnoreConfigSchema = z.object({
  /** Glob patterns for paths to exclude from all scanners */
  paths: z.array(z.string().min(1).max(300)).max(100).optional(),
});
export type IgnoreConfig = z.infer<typeof IgnoreConfigSchema>;

/**
 * Execution mode schema.
 * - auto: Detect which scanners to run based on repository content
 * - explicit: Only run scanners that are explicitly enabled
 */
export const ModeSchema = z.enum(['auto', 'explicit']);
export type Mode = z.infer<typeof ModeSchema>;

/**
 * Base scanner configuration shared by all scanners.
 */
const BaseScannerConfigSchema = z.object({
  /** Whether this scanner is enabled */
  enabled: z.boolean().default(true),
});

/**
 * Secrets scanner configuration.
 */
export const SecretsConfigSchema = BaseScannerConfigSchema.extend({
  /** Additional file patterns to scan */
  include_paths: z.array(z.string()).optional(),
  /** File patterns to exclude from scanning */
  exclude_paths: z.array(z.string()).optional(),
});
export type SecretsConfig = z.infer<typeof SecretsConfigSchema>;

/**
 * Dependency scanner configuration.
 */
export const DependenciesConfigSchema = BaseScannerConfigSchema.extend({
  /** CVE IDs to ignore */
  ignore_cves: z.array(z.string()).optional(),
});
export type DependenciesConfig = z.infer<typeof DependenciesConfigSchema>;

/**
 * Infrastructure-as-Code scanner configuration.
 */
export const IaCConfigSchema = BaseScannerConfigSchema.extend({
  /** Check IDs to skip */
  skip_checks: z.array(z.string()).optional(),
});
export type IaCConfig = z.infer<typeof IaCConfigSchema>;

/**
 * Container scanner configuration.
 */
export const ContainerConfigSchema = BaseScannerConfigSchema.extend({
  /** Paths to Dockerfiles to scan */
  dockerfile_paths: z.array(z.string()).optional(),
});
export type ContainerConfig = z.infer<typeof ContainerConfigSchema>;

/**
 * Scanner configuration collection.
 */
export const ScannersConfigSchema = z.object({
  secrets: SecretsConfigSchema.optional().default({ enabled: true }),
  dependencies: DependenciesConfigSchema.optional().default({ enabled: true }),
  iac: IaCConfigSchema.optional().default({ enabled: true }),
  container: ContainerConfigSchema.optional().default({ enabled: true }),
});
export type ScannersConfig = z.infer<typeof ScannersConfigSchema>;

/**
 * Root configuration schema.
 * This is the complete schema for .security-gate.yml
 */
export const RootConfigSchema = z.object({
  /** Schema version (currently only "1" is supported) */
  version: z.string().default('1'),

  /** Minimum severity level that causes the action to fail */
  fail_on: SeveritySchema.default('high'),

  /** Execution mode: auto-detect or explicit scanner selection */
  mode: ModeSchema.default('auto'),

  /** Scanner-specific configuration */
  scanners: ScannersConfigSchema.optional().default({}),

  // Additional config fields

  /** Global path exclusions (applies to all scanners) */
  exclude_paths: z.array(z.string().min(1).max(300)).max(100).optional(),

  /** Custom secret detection rules */
  rules: CustomRulesArraySchema.optional(),

  /** Global ignore configuration */
  ignore: IgnoreConfigSchema.optional(),

  /** Global allowlist for suppressing findings */
  allowlist: z.array(AllowlistEntrySchema).max(200).optional(),
});

/**
 * Fully resolved configuration type (after defaults applied).
 */
export type Config = z.infer<typeof RootConfigSchema>;

/**
 * Partial configuration type (as provided by user before defaults).
 */
export type PartialConfig = z.input<typeof RootConfigSchema>;

/**
 * Configuration validation error.
 */
export class ConfigValidationError extends Error {
  constructor(
    message: string,
    public readonly errors: z.ZodError['errors']
  ) {
    super(message);
    this.name = 'ConfigValidationError';
  }

  /**
   * Format validation errors as a human-readable string.
   */
  formatErrors(): string {
    return this.errors
      .map((err) => {
        const path = err.path.join('.');
        return path ? `  - ${path}: ${err.message}` : `  - ${err.message}`;
      })
      .join('\n');
  }
}

/**
 * Validate and parse configuration object.
 *
 * @param data - Raw configuration data to validate
 * @returns Validated and typed configuration
 * @throws ConfigValidationError if validation fails
 */
export function validateConfig(data: unknown): Config {
  const result = RootConfigSchema.safeParse(data);

  if (!result.success) {
    throw new ConfigValidationError('Configuration validation failed', result.error.errors);
  }

  return result.data;
}
