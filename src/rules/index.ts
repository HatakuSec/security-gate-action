/**
 * Custom Rules Engine
 *
 * Parses, validates, and compiles custom secret detection rules.
 * Includes ReDoS protection and safety validation.
 *
 * @module rules
 */

import { type CustomRule, type Severity, RULE_LIMITS } from '../config/schema';

/**
 * A compiled custom rule ready for use in scanning.
 */
export interface CompiledRule {
  /** Unique rule identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Optional description */
  description?: string;
  /** Severity level */
  severity: Severity;
  /** Compiled regex */
  regex: RegExp;
  /** File globs to match (undefined = all files) */
  fileGlobs?: string[];
  /** Inline allowlist patterns */
  allowlist?: string[];
  /** Whether this is a custom rule (vs built-in) */
  isCustom: boolean;
}

/**
 * Error thrown when a rule fails validation.
 */
export class RuleValidationError extends Error {
  constructor(
    message: string,
    public readonly ruleId: string,
    public readonly reason: string
  ) {
    super(message);
    this.name = 'RuleValidationError';
  }
}

/**
 * Error thrown when a regex is detected as potentially unsafe (ReDoS).
 */
export class UnsafeRegexError extends RuleValidationError {
  constructor(ruleId: string, reason: string) {
    super(`Rule '${ruleId}' contains an unsafe regex pattern: ${reason}`, ruleId, reason);
    this.name = 'UnsafeRegexError';
  }
}

// =============================================================================
// ReDoS Protection
// =============================================================================

/**
 * Known dangerous patterns that can cause catastrophic backtracking.
 * Each pattern is checked against the regex source.
 */
const DANGEROUS_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  // Nested quantifiers: (a+)+ or (a*)*
  {
    pattern: /\([^)]*[+*][^)]*\)[+*]/,
    description: 'nested quantifiers (e.g., (a+)+)',
  },
  // Overlapping alternations with quantifiers: (a|a)+
  {
    pattern: /\([^)]*\|[^)]*\)[+*]/,
    description: 'alternation with quantifier may cause backtracking',
  },
  // Greedy quantifier followed by same pattern: .*.*
  {
    pattern: /\.\*\.\*/,
    description: 'multiple greedy wildcards (.*.*)',
  },
  // Quantified groups with internal quantifiers: (a{1,100}){1,100}
  {
    pattern: /\{[0-9]+,[0-9]+\}[^}]*\{[0-9]+,[0-9]+\}/,
    description: 'nested range quantifiers',
  },
  // Repeated character classes with +: [a-z]+[a-z]+
  {
    pattern: /\[[^\]]+\][+*]\[[^\]]+\][+*]/,
    description: 'adjacent quantified character classes',
  },
  // Exponential backtracking: (.*a){x}
  {
    pattern: /\(\.\*[^)]+\)\{/,
    description: 'greedy wildcard in quantified group',
  },
];

/**
 * Additional heuristic checks for regex complexity.
 */
const COMPLEXITY_LIMITS = {
  /** Maximum number of quantifiers in a single regex */
  MAX_QUANTIFIERS: 10,
  /** Maximum number of alternations */
  MAX_ALTERNATIONS: 15,
  /** Maximum nesting depth of groups */
  MAX_NESTING_DEPTH: 5,
  /** Maximum number of capturing groups */
  MAX_GROUPS: 10,
};

/**
 * Count occurrences of a pattern in a string.
 */
function countOccurrences(str: string, pattern: RegExp): number {
  const matches = str.match(pattern);
  return matches ? matches.length : 0;
}

/**
 * Calculate the maximum nesting depth of parentheses.
 */
function calculateNestingDepth(pattern: string): number {
  let maxDepth = 0;
  let currentDepth = 0;
  let escaped = false;
  let inCharClass = false;

  for (const char of pattern) {
    if (escaped) {
      escaped = false;
      continue;
    }

    if (char === '\\') {
      escaped = true;
      continue;
    }

    if (char === '[' && !inCharClass) {
      inCharClass = true;
      continue;
    }

    if (char === ']' && inCharClass) {
      inCharClass = false;
      continue;
    }

    if (inCharClass) {
      continue;
    }

    if (char === '(') {
      currentDepth++;
      maxDepth = Math.max(maxDepth, currentDepth);
    } else if (char === ')') {
      currentDepth = Math.max(0, currentDepth - 1);
    }
  }

  return maxDepth;
}

/**
 * Validate a regex pattern for ReDoS safety.
 *
 * @param pattern - The regex pattern string
 * @param ruleId - Rule ID for error messages
 * @throws UnsafeRegexError if the pattern is deemed unsafe
 */
export function validateRegexSafety(pattern: string, ruleId: string): void {
  // Check pattern length
  if (pattern.length > RULE_LIMITS.MAX_REGEX_LENGTH) {
    throw new UnsafeRegexError(
      ruleId,
      `Pattern exceeds maximum length of ${RULE_LIMITS.MAX_REGEX_LENGTH} characters`
    );
  }

  // Check against known dangerous patterns
  for (const { pattern: dangerousPattern, description } of DANGEROUS_PATTERNS) {
    if (dangerousPattern.test(pattern)) {
      throw new UnsafeRegexError(ruleId, description);
    }
  }

  // Check complexity limits
  const quantifierCount = countOccurrences(pattern, /[+*?]|\{\d+,?\d*\}/g);
  if (quantifierCount > COMPLEXITY_LIMITS.MAX_QUANTIFIERS) {
    throw new UnsafeRegexError(
      ruleId,
      `Too many quantifiers (${quantifierCount} > ${COMPLEXITY_LIMITS.MAX_QUANTIFIERS})`
    );
  }

  const alternationCount = countOccurrences(pattern, /\|/g);
  if (alternationCount > COMPLEXITY_LIMITS.MAX_ALTERNATIONS) {
    throw new UnsafeRegexError(
      ruleId,
      `Too many alternations (${alternationCount} > ${COMPLEXITY_LIMITS.MAX_ALTERNATIONS})`
    );
  }

  const nestingDepth = calculateNestingDepth(pattern);
  if (nestingDepth > COMPLEXITY_LIMITS.MAX_NESTING_DEPTH) {
    throw new UnsafeRegexError(
      ruleId,
      `Nesting too deep (${nestingDepth} > ${COMPLEXITY_LIMITS.MAX_NESTING_DEPTH})`
    );
  }

  const groupCount = countOccurrences(pattern, /\(/g);
  if (groupCount > COMPLEXITY_LIMITS.MAX_GROUPS) {
    throw new UnsafeRegexError(
      ruleId,
      `Too many groups (${groupCount} > ${COMPLEXITY_LIMITS.MAX_GROUPS})`
    );
  }
}

// =============================================================================
// Rule Compilation
// =============================================================================

/**
 * Compile a single custom rule into a usable form.
 *
 * @param rule - The custom rule from config
 * @returns Compiled rule ready for scanning
 * @throws RuleValidationError if the rule is invalid
 * @throws UnsafeRegexError if the regex is unsafe
 */
export function compileRule(rule: CustomRule): CompiledRule {
  // Validate regex safety first
  validateRegexSafety(rule.regex, rule.id);

  // Attempt to compile the regex
  let regex: RegExp;
  try {
    regex = new RegExp(rule.regex, rule.flags);
  } catch (err) {
    throw new RuleValidationError(
      `Rule '${rule.id}' has invalid regex: ${err instanceof Error ? err.message : 'Unknown error'}`,
      rule.id,
      'Invalid regex syntax'
    );
  }

  // Extract allowlist patterns
  const allowlist = rule.allowlist?.map((entry) => entry.pattern);

  return {
    id: rule.id,
    name: rule.name,
    description: rule.description,
    severity: rule.severity,
    regex,
    fileGlobs: rule.file_globs,
    allowlist,
    isCustom: true,
  };
}

/**
 * Compile and validate an array of custom rules.
 *
 * @param rules - Array of custom rules from config
 * @returns Array of compiled rules
 * @throws RuleValidationError if any rule is invalid
 */
export function compileRules(rules: CustomRule[]): CompiledRule[] {
  // Check total count
  if (rules.length > RULE_LIMITS.MAX_RULES) {
    throw new RuleValidationError(
      `Too many custom rules: ${rules.length} exceeds maximum of ${RULE_LIMITS.MAX_RULES}`,
      'N/A',
      'Too many rules'
    );
  }

  // Check for duplicate IDs
  const seenIds = new Set<string>();
  for (const rule of rules) {
    if (seenIds.has(rule.id)) {
      throw new RuleValidationError(
        `Duplicate rule ID: '${rule.id}'`,
        rule.id,
        'Duplicate rule ID'
      );
    }
    seenIds.add(rule.id);
  }

  // Compile each rule
  const compiled: CompiledRule[] = [];
  for (const rule of rules) {
    compiled.push(compileRule(rule));
  }

  return compiled;
}

/**
 * Check if a file path matches any of the rule's file globs.
 *
 * @param filePath - Relative file path to check
 * @param globs - Glob patterns to match against
 * @returns True if the file matches (or no globs specified)
 */
export function fileMatchesGlobs(filePath: string, globs?: string[]): boolean {
  // No globs = match all files
  if (!globs || globs.length === 0) {
    return true;
  }

  // Simple glob matching (supports * and **)
  for (const glob of globs) {
    if (simpleGlobMatch(filePath, glob)) {
      return true;
    }
  }

  return false;
}

/**
 * Simple glob matching implementation.
 * Supports * (any characters except /) and ** (any characters including /).
 *
 * @param path - Path to test
 * @param glob - Glob pattern
 * @returns True if path matches glob
 */
function simpleGlobMatch(path: string, glob: string): boolean {
  // Escape regex special characters except * and **
  let regexPattern = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '{{GLOBSTAR}}')
    .replace(/\*/g, '[^/]*')
    .replace(/\{\{GLOBSTAR\}\}/g, '.*');

  // Anchor the pattern
  regexPattern = `^${regexPattern}$`;

  try {
    const regex = new RegExp(regexPattern);
    return regex.test(path);
  } catch {
    return false;
  }
}

/**
 * Check if a match should be allowed (suppressed) by the rule's inline allowlist.
 *
 * @param matchValue - The matched secret value
 * @param allowlist - Allowlist patterns
 * @returns True if the match should be suppressed
 */
export function isMatchAllowlisted(matchValue: string, allowlist?: string[]): boolean {
  if (!allowlist || allowlist.length === 0) {
    return false;
  }

  for (const pattern of allowlist) {
    // Simple pattern matching (exact or contains)
    if (pattern === matchValue || matchValue.includes(pattern)) {
      return true;
    }

    // Try glob-style matching
    if (simpleGlobMatch(matchValue, pattern)) {
      return true;
    }
  }

  return false;
}
