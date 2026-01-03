/**
 * Dockerfile Rules Unit Tests
 *
 * Tests for the Dockerfile security rules (DOCK001-DOCK008)
 * and the Dockerfile parser.
 *
 * @module tests/unit/scanners/container/dockerfile-rules
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

import {
  parseDockerfile,
  runDockerfileRules,
  DOCKERFILE_RULES,
  getRuleById,
  type DockerfileRuleContext,
} from '../../../../src/scanners/container/dockerfile-rules';

// Path to test fixtures
const FIXTURES_DIR = path.join(__dirname, '../../../fixtures/container');

describe('Dockerfile Rules', () => {
  describe('parseDockerfile', () => {
    it('should parse simple instructions', () => {
      const content = `FROM node:18
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "index.js"]`;

      const instructions = parseDockerfile(content);

      expect(instructions).toHaveLength(5);
      expect(instructions[0].instruction).toBe('FROM');
      expect(instructions[0].arguments).toBe('node:18');
      expect(instructions[0].lineNumber).toBe(1);
      expect(instructions[4].instruction).toBe('CMD');
    });

    it('should handle multi-line instructions', () => {
      const content = `FROM node:18
RUN apt-get update && \\
    apt-get install -y curl && \\
    apt-get clean
COPY . .`;

      const instructions = parseDockerfile(content);

      expect(instructions).toHaveLength(3);
      expect(instructions[1].instruction).toBe('RUN');
      expect(instructions[1].lineNumber).toBe(2);
      expect(instructions[1].endLineNumber).toBe(4);
      expect(instructions[1].arguments).toContain('apt-get update');
    });

    it('should skip comments', () => {
      const content = `# This is a comment
FROM node:18
# Another comment
COPY . .`;

      const instructions = parseDockerfile(content);

      expect(instructions).toHaveLength(2);
      expect(instructions[0].instruction).toBe('FROM');
      expect(instructions[1].instruction).toBe('COPY');
    });

    it('should skip blank lines', () => {
      const content = `FROM node:18

WORKDIR /app

COPY . .`;

      const instructions = parseDockerfile(content);

      expect(instructions).toHaveLength(3);
    });

    it('should preserve line numbers correctly', () => {
      const content = `# Comment
FROM node:18

# Another comment
WORKDIR /app`;

      const instructions = parseDockerfile(content);

      expect(instructions[0].lineNumber).toBe(2); // FROM
      expect(instructions[1].lineNumber).toBe(5); // WORKDIR
    });

    it('should handle empty content', () => {
      const instructions = parseDockerfile('');
      expect(instructions).toHaveLength(0);
    });

    it('should handle content with only comments', () => {
      const content = `# Just comments
# More comments`;

      const instructions = parseDockerfile(content);
      expect(instructions).toHaveLength(0);
    });
  });

  describe('DOCK001: latest tag usage', () => {
    const rule = getRuleById('DOCK001')!;

    it('should detect explicit :latest tag', () => {
      const instructions = parseDockerfile('FROM node:latest');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('DOCK001');
      expect(findings[0].lineNumber).toBe(1);
    });

    it('should detect implicit latest (no tag)', () => {
      const instructions = parseDockerfile('FROM node');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('DOCK001');
      expect(findings[0].message).toContain('implicit');
    });

    it('should not flag pinned versions', () => {
      const instructions = parseDockerfile('FROM node:18.19.0');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });

    it('should not flag digest references', () => {
      const instructions = parseDockerfile('FROM node@sha256:abc123');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });

    it('should not flag scratch image', () => {
      const instructions = parseDockerfile('FROM scratch');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });

    it('should handle --platform flag', () => {
      const instructions = parseDockerfile('FROM --platform=linux/amd64 node:latest');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
    });
  });

  describe('DOCK002: missing USER', () => {
    const rule = getRuleById('DOCK002')!;

    it('should detect missing USER instruction', () => {
      const instructions = parseDockerfile(`FROM node:18
COPY . .
CMD ["node", "index.js"]`);
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('DOCK002');
    });

    it('should not flag when USER is present', () => {
      const instructions = parseDockerfile(`FROM node:18
USER node
CMD ["node", "index.js"]`);
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });

    it('should flag when USER is root', () => {
      const instructions = parseDockerfile(`FROM node:18
USER root
CMD ["node", "index.js"]`);
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
    });

    it('should flag when USER is 0', () => {
      const instructions = parseDockerfile(`FROM node:18
USER 0
CMD ["node", "index.js"]`);
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
    });
  });

  describe('DOCK003: missing HEALTHCHECK', () => {
    const rule = getRuleById('DOCK003')!;

    it('should detect missing HEALTHCHECK', () => {
      const instructions = parseDockerfile(`FROM node:18
CMD ["node", "index.js"]`);
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('DOCK003');
    });

    it('should not flag when HEALTHCHECK is present', () => {
      const instructions = parseDockerfile(`FROM node:18
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["node", "index.js"]`);
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });
  });

  describe('DOCK004: sudo usage', () => {
    const rule = getRuleById('DOCK004')!;

    it('should detect sudo in RUN command', () => {
      const instructions = parseDockerfile('RUN sudo apt-get update');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('DOCK004');
    });

    it('should not flag RUN without sudo', () => {
      const instructions = parseDockerfile('RUN apt-get update');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });

    it('should not false positive on pseudoword', () => {
      const instructions = parseDockerfile('RUN echo "pseudorandom"');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });
  });

  describe('DOCK005: ADD instead of COPY', () => {
    const rule = getRuleById('DOCK005')!;

    it('should detect ADD for local files', () => {
      const instructions = parseDockerfile('ADD package.json /app/');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('DOCK005');
    });

    it('should not flag ADD for URLs', () => {
      const instructions = parseDockerfile('ADD https://example.com/file.txt /app/');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });

    it('should not flag ADD for archives', () => {
      const instructions = parseDockerfile('ADD app.tar.gz /app/');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });

    it('should not flag COPY', () => {
      const instructions = parseDockerfile('COPY package.json /app/');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });
  });

  describe('DOCK006: missing .dockerignore', () => {
    const rule = getRuleById('DOCK006')!;

    it('should detect missing .dockerignore', () => {
      const instructions = parseDockerfile('FROM node:18');
      const context = createContext({ hasDockerignore: false });
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('DOCK006');
    });

    it('should not flag when .dockerignore exists', () => {
      const instructions = parseDockerfile('FROM node:18');
      const context = createContext({ hasDockerignore: true });
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });
  });

  describe('DOCK007: secrets via ARG', () => {
    const rule = getRuleById('DOCK007')!;

    it('should detect secret-like ARG names', () => {
      const instructions = parseDockerfile('ARG API_KEY');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('DOCK007');
    });

    it('should detect PASSWORD ARG', () => {
      const instructions = parseDockerfile('ARG DATABASE_PASSWORD=default');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
    });

    it('should detect TOKEN ARG', () => {
      const instructions = parseDockerfile('ARG GITHUB_TOKEN');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
    });

    it('should not flag non-secret ARGs', () => {
      const instructions = parseDockerfile('ARG NODE_VERSION=18');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });
  });

  describe('DOCK008: curl | sh pattern', () => {
    const rule = getRuleById('DOCK008')!;

    it('should detect curl | sh', () => {
      const instructions = parseDockerfile('RUN curl -sSL https://example.com/install.sh | sh');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('DOCK008');
    });

    it('should detect curl | bash', () => {
      const instructions = parseDockerfile('RUN curl https://example.com/install.sh | bash');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
    });

    it('should detect wget | sh', () => {
      const instructions = parseDockerfile('RUN wget -O - https://example.com/install.sh | sh');
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(1);
    });

    it('should not flag curl without pipe', () => {
      const instructions = parseDockerfile(
        'RUN curl -o script.sh https://example.com/script.sh && sh script.sh'
      );
      const context = createContext();
      const findings = rule.check(instructions, context);

      expect(findings).toHaveLength(0);
    });
  });

  describe('runDockerfileRules', () => {
    it('should run all rules', () => {
      const instructions = parseDockerfile('FROM node:latest');
      const context = createContext({ hasDockerignore: false });
      const { findings, rulesRun } = runDockerfileRules(instructions, context);

      expect(rulesRun).toBe(8);
      // Should find: DOCK001 (latest), DOCK002 (no USER), DOCK003 (no HEALTHCHECK), DOCK006 (no .dockerignore)
      expect(findings.length).toBeGreaterThanOrEqual(4);
    });
  });

  describe('fixture files', () => {
    it('should find multiple issues in Dockerfile.bad', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'Dockerfile.bad'), 'utf-8');
      const instructions = parseDockerfile(content);
      const context: DockerfileRuleContext = {
        dockerfilePath: 'Dockerfile.bad',
        hasDockerignore: false, // Simulate no .dockerignore
        content,
      };

      const { findings } = runDockerfileRules(instructions, context);

      // Should find multiple issues
      expect(findings.length).toBeGreaterThanOrEqual(5);

      // Check specific rule IDs are present
      const ruleIds = findings.map((f) => f.ruleId);
      expect(ruleIds).toContain('DOCK001'); // latest tag
      expect(ruleIds).toContain('DOCK002'); // no USER
      expect(ruleIds).toContain('DOCK003'); // no HEALTHCHECK
      expect(ruleIds).toContain('DOCK004'); // sudo
      expect(ruleIds).toContain('DOCK005'); // ADD
      expect(ruleIds).toContain('DOCK007'); // secret ARG
      expect(ruleIds).toContain('DOCK008'); // curl | sh
    });

    it('should find no issues in Dockerfile.good', () => {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, 'Dockerfile.good'), 'utf-8');
      const instructions = parseDockerfile(content);
      const context: DockerfileRuleContext = {
        dockerfilePath: 'Dockerfile.good',
        hasDockerignore: true, // .dockerignore exists in fixtures
        content,
      };

      const { findings } = runDockerfileRules(instructions, context);

      // Should find no issues
      expect(findings).toHaveLength(0);
    });
  });

  describe('getRuleById', () => {
    it('should return rule by ID', () => {
      const rule = getRuleById('DOCK001');
      expect(rule).toBeDefined();
      expect(rule?.id).toBe('DOCK001');
    });

    it('should return undefined for unknown ID', () => {
      const rule = getRuleById('UNKNOWN');
      expect(rule).toBeUndefined();
    });
  });

  describe('DOCKERFILE_RULES', () => {
    it('should have 8 rules', () => {
      expect(DOCKERFILE_RULES).toHaveLength(8);
    });

    it('should have all expected rule IDs', () => {
      const ruleIds = DOCKERFILE_RULES.map((r) => r.id);
      expect(ruleIds).toContain('DOCK001');
      expect(ruleIds).toContain('DOCK002');
      expect(ruleIds).toContain('DOCK003');
      expect(ruleIds).toContain('DOCK004');
      expect(ruleIds).toContain('DOCK005');
      expect(ruleIds).toContain('DOCK006');
      expect(ruleIds).toContain('DOCK007');
      expect(ruleIds).toContain('DOCK008');
    });
  });
});

// Helper function to create test context
function createContext(overrides: Partial<DockerfileRuleContext> = {}): DockerfileRuleContext {
  return {
    dockerfilePath: 'Dockerfile',
    hasDockerignore: true,
    content: '',
    ...overrides,
  };
}
