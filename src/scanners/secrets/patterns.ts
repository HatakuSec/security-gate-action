/**
 * Secret pattern definitions
 *
 * Defines high-signal patterns for detecting leaked credentials and API keys.
 * Patterns are ordered by ID (SEC001-SEC010) for consistent rule IDs.
 *
 * @module scanners/secrets/patterns
 */

import type { Severity } from '../types';

/**
 * A pattern for detecting secrets in source files.
 */
export interface SecretPattern {
  /** Unique pattern identifier (e.g., SEC001) */
  id: string;
  /** Human-readable name */
  name: string;
  /** Compiled regular expression */
  regex: RegExp;
  /** Severity level of the finding */
  severity: Severity;
  /** Message template for findings */
  message: string;
}

/**
 * High-signal secret patterns for detecting leaked credentials.
 *
 * These patterns are designed to minimise false positives whilst
 * catching common credential leaks.
 */
export const SECRET_PATTERNS: readonly SecretPattern[] = [
  // SEC001: AWS Access Key
  {
    id: 'SEC001',
    name: 'AWS Access Key',
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: 'high',
    message: 'AWS access key ID detected. Rotate this key immediately.',
  },

  // SEC002: AWS Secret Key
  {
    id: 'SEC002',
    name: 'AWS Secret Key',
    regex: /aws_secret_access_key\s*=\s*['"][A-Za-z0-9/+=]{40}['"]/gi,
    severity: 'high',
    message: 'AWS secret access key detected. Rotate this key immediately.',
  },

  // SEC003: GitHub Token (classic PAT)
  {
    id: 'SEC003',
    name: 'GitHub Token',
    regex: /ghp_[A-Za-z0-9]{36}/g,
    severity: 'high',
    message: 'GitHub personal access token detected. Revoke and regenerate this token.',
  },

  // SEC004: GitHub OAuth Token
  {
    id: 'SEC004',
    name: 'GitHub OAuth Token',
    regex: /gho_[A-Za-z0-9]{36}/g,
    severity: 'high',
    message: 'GitHub OAuth token detected. Revoke this token immediately.',
  },

  // SEC005: GitHub PAT (fine-grained)
  {
    id: 'SEC005',
    name: 'GitHub Fine-Grained PAT',
    regex: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/g,
    severity: 'high',
    message:
      'GitHub fine-grained personal access token detected. Revoke and regenerate this token.',
  },

  // SEC006: Private Key
  {
    id: 'SEC006',
    name: 'Private Key',
    regex: /-----BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----/g,
    severity: 'high',
    message: 'Private key header detected. Remove this key and generate a new one.',
  },

  // SEC007: Generic API Key
  {
    id: 'SEC007',
    name: 'Generic API Key',
    regex: /(api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9]{20,}['"]/gi,
    severity: 'medium',
    message: 'Possible API key detected. Verify and rotate if this is a real credential.',
  },

  // SEC008: Generic Secret
  {
    id: 'SEC008',
    name: 'Generic Secret',
    regex: /(secret|password|passwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    severity: 'medium',
    message:
      'Possible secret or password detected. Verify and rotate if this is a real credential.',
  },

  // SEC009: Slack Token
  {
    id: 'SEC009',
    name: 'Slack Token',
    regex: /xox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}/g,
    severity: 'high',
    message: 'Slack token detected. Revoke and regenerate this token.',
  },

  // SEC010: Stripe Key
  {
    id: 'SEC010',
    name: 'Stripe Live Key',
    regex: /sk_live_[A-Za-z0-9]{24}/g,
    severity: 'high',
    message: 'Stripe live secret key detected. Rotate this key immediately.',
  },
] as const;

/**
 * Get a pattern by its ID.
 *
 * @param id - Pattern ID (e.g., 'SEC001')
 * @returns The pattern or undefined if not found
 */
export function getPatternById(id: string): SecretPattern | undefined {
  return SECRET_PATTERNS.find((p) => p.id === id);
}

/**
 * Get all patterns of a specific severity.
 *
 * @param severity - Severity level to filter by
 * @returns Array of patterns matching the severity
 */
export function getPatternsBySeverity(severity: Severity): SecretPattern[] {
  return SECRET_PATTERNS.filter((p) => p.severity === severity);
}
