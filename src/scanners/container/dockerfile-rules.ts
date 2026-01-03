/**
 * Dockerfile Security Rules
 *
 * Implements DOCK001-DOCK008 rules for Dockerfile security validation.
 * Each rule checks for specific security misconfigurations in Dockerfiles.
 *
 * @module scanners/container/dockerfile-rules
 */

import type { Severity } from '../types';

/**
 * A parsed Dockerfile instruction with line information.
 */
export interface DockerfileInstruction {
  /** Instruction type (FROM, RUN, COPY, etc.) */
  instruction: string;
  /** The full original line(s) including arguments */
  content: string;
  /** Original line number (1-indexed) */
  lineNumber: number;
  /** End line number for multi-line instructions */
  endLineNumber: number;
  /** The arguments after the instruction */
  arguments: string;
}

/**
 * A finding from a Dockerfile rule check.
 */
export interface DockerfileRuleFinding {
  /** Rule ID (e.g., DOCK001) */
  ruleId: string;
  /** Line number where the issue was found */
  lineNumber: number;
  /** End line number (for multi-line issues) */
  endLineNumber?: number;
  /** Description of the issue */
  message: string;
  /** Code snippet for context */
  snippet?: string;
}

/**
 * A Dockerfile security rule.
 */
export interface DockerfileRule {
  /** Rule identifier (DOCK001-DOCK008) */
  id: string;
  /** Short description of what the rule checks */
  description: string;
  /** Severity level */
  severity: Severity;
  /** Check function that returns findings */
  check: (
    instructions: DockerfileInstruction[],
    context: DockerfileRuleContext
  ) => DockerfileRuleFinding[];
}

/**
 * Context provided to rule check functions.
 */
export interface DockerfileRuleContext {
  /** Path to the Dockerfile being checked */
  dockerfilePath: string;
  /** Whether a .dockerignore file exists */
  hasDockerignore: boolean;
  /** Raw Dockerfile content */
  content: string;
}

/**
 * DOCK001: Using `latest` tag for base image
 *
 * Using the `latest` tag can lead to unpredictable builds as the
 * base image may change unexpectedly.
 */
const DOCK001: DockerfileRule = {
  id: 'DOCK001',
  description: 'Using `latest` tag for base image',
  severity: 'medium',
  check: (instructions) => {
    const findings: DockerfileRuleFinding[] = [];

    for (const inst of instructions) {
      if (inst.instruction !== 'FROM') {
        continue;
      }

      const args = inst.arguments.trim();
      // Handle FROM image:latest, FROM image (implicit latest), FROM image AS stage
      // Skip --platform= prefix if present
      const imagePart = args.replace(/^--platform=\S+\s+/, '').split(/\s+/)[0];

      if (!imagePart) {
        continue;
      }

      // Check for explicit :latest tag
      if (imagePart.endsWith(':latest')) {
        findings.push({
          ruleId: 'DOCK001',
          lineNumber: inst.lineNumber,
          endLineNumber: inst.endLineNumber,
          message: `Base image uses \`latest\` tag: ${imagePart}. Pin to a specific version for reproducible builds.`,
          snippet: inst.content.trim(),
        });
        continue;
      }

      // Check for implicit latest (no tag specified, not a digest)
      // image@sha256:... is fine, image:tag is fine, just "image" is not
      if (!imagePart.includes(':') && !imagePart.includes('@')) {
        // Skip "scratch" which is a special case
        if (imagePart.toLowerCase() === 'scratch') {
          continue;
        }

        findings.push({
          ruleId: 'DOCK001',
          lineNumber: inst.lineNumber,
          endLineNumber: inst.endLineNumber,
          message: `Base image has no tag (implicit \`latest\`): ${imagePart}. Pin to a specific version for reproducible builds.`,
          snippet: inst.content.trim(),
        });
      }
    }

    return findings;
  },
};

/**
 * DOCK002: Missing `USER` instruction (running as root)
 *
 * Running containers as root is a security risk. A USER instruction
 * should be present to switch to a non-root user.
 */
const DOCK002: DockerfileRule = {
  id: 'DOCK002',
  description: 'Missing `USER` instruction (running as root)',
  severity: 'medium',
  check: (instructions) => {
    // Check if there's a USER instruction that sets a non-root user
    const hasNonRootUser = instructions.some((inst) => {
      if (inst.instruction !== 'USER') {
        return false;
      }
      const userPart = inst.arguments.trim().split(':')[0];
      const user = userPart?.toLowerCase() ?? '';
      // root user is typically "root" or uid 0
      return user !== 'root' && user !== '0' && user !== '';
    });

    if (!hasNonRootUser && instructions.length > 0) {
      // Find the last FROM instruction to report the line
      const lastFrom = [...instructions].reverse().find((i) => i.instruction === 'FROM');
      const lastInstruction = instructions[instructions.length - 1];

      return [
        {
          ruleId: 'DOCK002',
          lineNumber: lastFrom?.lineNumber ?? 1,
          endLineNumber: lastInstruction?.endLineNumber,
          message:
            'Dockerfile does not specify a non-root USER. Containers will run as root by default.',
        },
      ];
    }

    return [];
  },
};

/**
 * DOCK003: Missing `HEALTHCHECK` instruction
 *
 * A HEALTHCHECK instruction helps orchestrators determine if the
 * container is healthy and functioning correctly.
 */
const DOCK003: DockerfileRule = {
  id: 'DOCK003',
  description: 'Missing `HEALTHCHECK` instruction',
  severity: 'low',
  check: (instructions) => {
    const hasHealthcheck = instructions.some((inst) => inst.instruction === 'HEALTHCHECK');
    const lastInstruction = instructions[instructions.length - 1];

    if (!hasHealthcheck && lastInstruction) {
      return [
        {
          ruleId: 'DOCK003',
          lineNumber: lastInstruction.lineNumber,
          message:
            'Dockerfile does not include a HEALTHCHECK instruction. Consider adding one for better orchestration support.',
        },
      ];
    }

    return [];
  },
};

/**
 * DOCK004: `sudo` usage in RUN commands
 *
 * Using sudo in a Dockerfile is typically unnecessary and indicates
 * potential misconfiguration. The build process already runs as root.
 */
const DOCK004: DockerfileRule = {
  id: 'DOCK004',
  description: 'sudo usage in RUN commands',
  severity: 'high',
  check: (instructions) => {
    const findings: DockerfileRuleFinding[] = [];

    for (const inst of instructions) {
      if (inst.instruction !== 'RUN') {
        continue;
      }

      // Check for sudo usage - match word boundary to avoid false positives
      // like "pseudorandom" or file paths containing "sudo"
      const sudoPattern = /\bsudo\s+/i;
      if (sudoPattern.test(inst.arguments)) {
        findings.push({
          ruleId: 'DOCK004',
          lineNumber: inst.lineNumber,
          endLineNumber: inst.endLineNumber,
          message:
            '`sudo` usage detected in RUN command. This is unnecessary as Docker builds run as root and may indicate privilege escalation issues.',
          snippet: inst.content.trim(),
        });
      }
    }

    return findings;
  },
};

/**
 * DOCK005: `ADD` used instead of `COPY` for local files
 *
 * COPY is preferred for copying local files as ADD has additional
 * features (URL fetching, auto-extraction) that can be surprising.
 */
const DOCK005: DockerfileRule = {
  id: 'DOCK005',
  description: 'ADD used instead of COPY for local files',
  severity: 'medium',
  check: (instructions) => {
    const findings: DockerfileRuleFinding[] = [];

    for (const inst of instructions) {
      if (inst.instruction !== 'ADD') {
        continue;
      }

      const args = inst.arguments.trim();

      // Check if it's a URL (http://, https://, ftp://) - ADD is appropriate for these
      if (/^(https?|ftp):\/\//i.test(args)) {
        continue;
      }

      // Check if source looks like a tar/archive for auto-extraction
      // ADD is appropriate for local archives that should be extracted
      const sourceFile = args.split(/\s+/)[0] ?? '';
      if (/\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz|zip)$/i.test(sourceFile)) {
        // This is likely intentional use of ADD for extraction
        continue;
      }

      findings.push({
        ruleId: 'DOCK005',
        lineNumber: inst.lineNumber,
        endLineNumber: inst.endLineNumber,
        message:
          '`ADD` used for local files. Use `COPY` instead unless you need ADD-specific features (URL fetching, archive extraction).',
        snippet: inst.content.trim(),
      });
    }

    return findings;
  },
};

/**
 * DOCK006: Missing `.dockerignore` file
 *
 * A .dockerignore file helps exclude unnecessary files from the build
 * context, improving build performance and security.
 */
const DOCK006: DockerfileRule = {
  id: 'DOCK006',
  description: 'Missing .dockerignore file',
  severity: 'low',
  check: (instructions, context) => {
    if (!context.hasDockerignore && instructions.length > 0) {
      return [
        {
          ruleId: 'DOCK006',
          lineNumber: 1,
          message:
            'No .dockerignore file found. Consider adding one to exclude unnecessary files from the build context.',
        },
      ];
    }

    return [];
  },
};

/**
 * DOCK007: Secrets passed via `ARG`
 *
 * Passing secrets via ARG is insecure as they are visible in the image
 * history. Use build secrets or environment variables at runtime instead.
 */
const DOCK007: DockerfileRule = {
  id: 'DOCK007',
  description: 'Secrets passed via ARG',
  severity: 'medium',
  check: (instructions) => {
    const findings: DockerfileRuleFinding[] = [];

    // Common secret-related keywords in ARG names
    // Use underscore/hyphen boundaries as well as word boundaries
    const secretPatterns =
      /(^|[_-])(password|passwd|secret|token|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key)($|[_-])/i;

    for (const inst of instructions) {
      if (inst.instruction !== 'ARG') {
        continue;
      }

      const args = inst.arguments.trim();
      // ARG can be "ARG NAME" or "ARG NAME=default"
      const argName = args.split('=')[0]?.trim() ?? '';

      if (secretPatterns.test(argName)) {
        findings.push({
          ruleId: 'DOCK007',
          lineNumber: inst.lineNumber,
          endLineNumber: inst.endLineNumber,
          message: `ARG \`${argName}\` appears to contain a secret. Build arguments are visible in image history. Use build secrets (--secret) or runtime environment variables instead.`,
          snippet: inst.content.trim(),
        });
      }
    }

    return findings;
  },
};

/**
 * DOCK008: `curl | sh` pattern detected
 *
 * Piping curl (or wget) output directly to a shell is dangerous as it
 * executes untrusted code without verification.
 */
const DOCK008: DockerfileRule = {
  id: 'DOCK008',
  description: 'curl | sh pattern detected',
  severity: 'high',
  check: (instructions) => {
    const findings: DockerfileRuleFinding[] = [];

    // Pattern matches:
    // - curl ... | sh/bash/zsh/ash
    // - wget ... | sh/bash/zsh/ash
    // - curl ... | /bin/sh, etc.
    const pipeToShellPattern = /\b(curl|wget)\b[^|]*\|\s*(sh|bash|zsh|ash|\/bin\/sh|\/bin\/bash)/i;

    for (const inst of instructions) {
      if (inst.instruction !== 'RUN') {
        continue;
      }

      if (pipeToShellPattern.test(inst.arguments)) {
        findings.push({
          ruleId: 'DOCK008',
          lineNumber: inst.lineNumber,
          endLineNumber: inst.endLineNumber,
          message:
            'Detected `curl | sh` or similar pattern. Piping downloaded scripts directly to a shell is dangerous. Download the script, verify it, then execute.',
          snippet: inst.content.trim(),
        });
      }
    }

    return findings;
  },
};

/**
 * All Dockerfile rules in order.
 */
export const DOCKERFILE_RULES: readonly DockerfileRule[] = [
  DOCK001,
  DOCK002,
  DOCK003,
  DOCK004,
  DOCK005,
  DOCK006,
  DOCK007,
  DOCK008,
];

/**
 * Get a rule by its ID.
 *
 * @param id - Rule ID (e.g., 'DOCK001')
 * @returns The rule or undefined if not found
 */
export function getRuleById(id: string): DockerfileRule | undefined {
  return DOCKERFILE_RULES.find((rule) => rule.id === id);
}

/**
 * Parse a Dockerfile into a list of instructions.
 *
 * Handles:
 * - Comments (lines starting with #)
 * - Blank lines
 * - Multi-line instructions (lines ending with \)
 * - Parser directives (# directive=value)
 *
 * @param content - Raw Dockerfile content
 * @returns Parsed instructions with line numbers
 */
export function parseDockerfile(content: string): DockerfileInstruction[] {
  const lines = content.split('\n');
  const instructions: DockerfileInstruction[] = [];

  let currentInstruction = '';
  let startLineNumber = 0;
  let inMultiline = false;

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1; // 1-indexed
    const rawLine = lines[i] ?? '';
    const line = rawLine.trimEnd();

    // Skip empty lines when not in multiline
    if (!inMultiline && line.trim() === '') {
      continue;
    }

    // Skip comments when not in multiline
    // Note: Parser directives (# directive=value) are only at the very start
    if (!inMultiline && line.trim().startsWith('#')) {
      continue;
    }

    // Start of a new instruction
    if (!inMultiline) {
      startLineNumber = lineNumber;
      currentInstruction = line;
    } else {
      // Continuation of multiline instruction
      currentInstruction += '\n' + line;
    }

    // Check if line ends with backslash (continuation)
    if (line.endsWith('\\')) {
      inMultiline = true;
      continue;
    }

    // End of instruction - parse it
    inMultiline = false;

    // Extract instruction type and arguments
    // Remove leading/trailing whitespace and normalize
    const trimmedContent = currentInstruction.replace(/\\\n/g, ' ').trim();
    const match = trimmedContent.match(/^(\w+)\s*(.*)/s);

    if (match?.[1]) {
      const instructionType = match[1].toUpperCase();
      const args = match[2] ?? '';

      instructions.push({
        instruction: instructionType,
        content: currentInstruction,
        lineNumber: startLineNumber,
        endLineNumber: lineNumber,
        arguments: args,
      });
    }

    currentInstruction = '';
  }

  // Handle case where file ends with a continuation line
  if (inMultiline && currentInstruction.trim()) {
    const trimmedContent = currentInstruction.replace(/\\\n/g, ' ').trim();
    const match = trimmedContent.match(/^(\w+)\s*(.*)/s);

    if (match?.[1]) {
      instructions.push({
        instruction: match[1].toUpperCase(),
        content: currentInstruction,
        lineNumber: startLineNumber,
        endLineNumber: lines.length,
        arguments: match[2] ?? '',
      });
    }
  }

  return instructions;
}

/**
 * Run all Dockerfile rules against parsed instructions.
 *
 * @param instructions - Parsed Dockerfile instructions
 * @param context - Rule check context
 * @returns All findings from all rules
 */
export function runDockerfileRules(
  instructions: DockerfileInstruction[],
  context: DockerfileRuleContext
): { findings: DockerfileRuleFinding[]; rulesRun: number } {
  const findings: DockerfileRuleFinding[] = [];

  for (const rule of DOCKERFILE_RULES) {
    const ruleFindings = rule.check(instructions, context);
    findings.push(...ruleFindings);
  }

  return {
    findings,
    rulesRun: DOCKERFILE_RULES.length,
  };
}
