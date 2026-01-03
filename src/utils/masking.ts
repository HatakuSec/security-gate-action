/**
 * Secret masking utilities
 *
 * Provides functions for safely masking secret values in logs and outputs.
 * Never exposes full secret values; always truncates and masks.
 *
 * @module utils/masking
 */

import * as core from '@actions/core';

/** Default maximum length for masked snippets */
const DEFAULT_MAX_SNIPPET_LENGTH = 120;

/** Minimum length before we attempt partial reveal */
const MIN_REVEAL_LENGTH = 8;

/**
 * Mask a secret value, keeping first 4 and last 2 characters visible.
 * For short secrets, masks the entire value.
 *
 * @param value - The secret value to mask
 * @returns Masked string with asterisks
 *
 * @example
 * maskSecret('AKIAIOSFODNN7EXAMPLE') // 'AKIA************LE'
 * maskSecret('short') // '*****'
 */
export function maskSecret(value: string): string {
  if (!value || value.length === 0) {
    return '';
  }

  // For short secrets, mask entirely to avoid revealing too much
  if (value.length < MIN_REVEAL_LENGTH) {
    return '*'.repeat(value.length);
  }

  // Keep first 4 and last 2 characters, mask the rest
  const visibleStart = 4;
  const visibleEnd = 2;
  const maskLength = value.length - visibleStart - visibleEnd;

  if (maskLength <= 0) {
    return '*'.repeat(value.length);
  }

  return (
    value.substring(0, visibleStart) +
    '*'.repeat(maskLength) +
    value.substring(value.length - visibleEnd)
  );
}

/**
 * Register secrets with GitHub Actions to prevent them from appearing in logs.
 * Filters out empty and duplicate values.
 *
 * @param values - Array of secret values to register
 */
export function registerSecrets(values: string[]): void {
  const uniqueSecrets = new Set<string>();

  for (const value of values) {
    // Skip empty or whitespace-only values
    if (!value || value.trim().length === 0) {
      continue;
    }

    // Avoid registering duplicates
    if (uniqueSecrets.has(value)) {
      continue;
    }

    uniqueSecrets.add(value);
    core.setSecret(value);
  }
}

/**
 * Mask a matched secret within a line of code, producing a safe snippet.
 * Truncates to maximum length if needed.
 *
 * @param line - The full line of code
 * @param match - The matched secret value within the line
 * @param maxLength - Maximum length of the returned snippet (default: 120)
 * @returns Truncated and masked snippet
 *
 * @example
 * maskSnippet('const key = "AKIAIOSFODNN7EXAMPLE";', 'AKIAIOSFODNN7EXAMPLE')
 * // 'const key = "AKIA************LE";'
 */
export function maskSnippet(
  line: string,
  match: string,
  maxLength: number = DEFAULT_MAX_SNIPPET_LENGTH
): string {
  if (!line || !match) {
    return line?.substring(0, maxLength) ?? '';
  }

  // Replace the match with its masked version
  const masked = maskSecret(match);
  let result = line.replace(match, masked);

  // Truncate if too long, adding ellipsis
  if (result.length > maxLength) {
    result = result.substring(0, maxLength - 3) + '...';
  }

  return result;
}
