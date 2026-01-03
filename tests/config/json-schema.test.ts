/**
 * Tests for JSON Schema generation from Zod config.
 */

import { describe, it, expect } from 'vitest';
import Ajv from 'ajv';
import {
  generateJsonSchema,
  generateJsonSchemaString,
  getYamlSchemaDirective,
} from '../../src/config/json-schema.js';

describe('JSON Schema Generation', () => {
  describe('generateJsonSchema', () => {
    it('should generate a valid JSON Schema draft-07', () => {
      const schema = generateJsonSchema();

      expect(schema.$schema).toBe('http://json-schema.org/draft-07/schema#');
      expect(schema.$id).toBeDefined();
      expect(schema.title).toBe('Security Gate Configuration');
      expect(schema.description).toContain('Security Gate');
    });

    it('should include all required top-level properties', () => {
      const schema = generateJsonSchema();
      const properties = schema.properties as Record<string, unknown>;

      expect(properties).toBeDefined();
      expect(properties.version).toBeDefined();
      expect(properties.fail_on).toBeDefined();
      expect(properties.mode).toBeDefined();
      expect(properties.scanners).toBeDefined();
      expect(properties.exclude_paths).toBeDefined();
      expect(properties.rules).toBeDefined();
      expect(properties.ignore).toBeDefined();
      expect(properties.allowlist).toBeDefined();
    });

    it('should include severity enum values', () => {
      const schema = generateJsonSchema();
      const properties = schema.properties as Record<string, unknown>;
      const failOn = properties?.fail_on as Record<string, unknown>;

      expect(failOn.enum).toEqual(['high', 'medium', 'low']);
    });

    it('should include mode enum values', () => {
      const schema = generateJsonSchema();
      const properties = schema.properties as Record<string, unknown>;
      const mode = properties?.mode as Record<string, unknown>;

      expect(mode.enum).toEqual(['auto', 'explicit']);
    });

    it('should include scanner types', () => {
      const schema = generateJsonSchema();
      const properties = schema.properties as Record<string, unknown>;
      const scanners = properties?.scanners as Record<string, unknown>;
      const scannerProps = scanners?.properties as Record<string, unknown>;

      expect(scannerProps.secrets).toBeDefined();
      expect(scannerProps.dependencies).toBeDefined();
      expect(scannerProps.iac).toBeDefined();
      expect(scannerProps.container).toBeDefined();
    });

    it('should include custom rules schema with limits', () => {
      const schema = generateJsonSchema();
      const properties = schema.properties as Record<string, unknown>;
      const rules = properties?.rules as Record<string, unknown>;

      expect(rules.type).toBe('array');
      expect(rules.maxItems).toBe(50); // RULE_LIMITS.MAX_RULES
    });

    it('should include allowlist schema with limits', () => {
      const schema = generateJsonSchema();
      const properties = schema.properties as Record<string, unknown>;
      const allowlist = properties?.allowlist as Record<string, unknown>;

      expect(allowlist.type).toBe('array');
      expect(allowlist.maxItems).toBe(200); // Max allowlist entries
    });

    it('should produce deterministic output (sorted keys)', () => {
      const schema1 = generateJsonSchemaString();
      const schema2 = generateJsonSchemaString();

      expect(schema1).toBe(schema2);
    });
  });

  describe('generateJsonSchemaString', () => {
    it('should produce valid JSON', () => {
      const schemaString = generateJsonSchemaString();

      expect(() => JSON.parse(schemaString) as unknown).not.toThrow();
    });

    it('should be formatted with 2-space indentation', () => {
      const schemaString = generateJsonSchemaString();

      expect(schemaString).toContain('\n  "');
    });

    it('should end with a newline', () => {
      const schemaString = generateJsonSchemaString();

      expect(schemaString.endsWith('\n')).toBe(true);
    });
  });

  describe('getYamlSchemaDirective', () => {
    it('should return yaml-language-server directive with default URL', () => {
      const directive = getYamlSchemaDirective();

      expect(directive).toMatch(/^# yaml-language-server: \$schema=/);
      expect(directive).toContain('security-gate-action');
      expect(directive).toContain('config.schema.json');
    });

    it('should accept custom schema URL', () => {
      const customUrl = 'https://example.com/my-schema.json';
      const directive = getYamlSchemaDirective(customUrl);

      expect(directive).toBe(`# yaml-language-server: $schema=${customUrl}`);
    });

    it('should work with local file paths', () => {
      const localPath = './schema/config.schema.json';
      const directive = getYamlSchemaDirective(localPath);

      expect(directive).toBe(`# yaml-language-server: $schema=${localPath}`);
    });
  });

  describe('Schema Validation with Ajv', () => {
    it('should validate a minimal valid config', () => {
      const schema = generateJsonSchema();
      const ajv = new Ajv({ strict: false });
      const validate = ajv.compile(schema);

      const validConfig = {
        version: '1',
        fail_on: 'high',
      };

      const isValid = validate(validConfig);
      expect(isValid).toBe(true);
    });

    it('should validate a full config with all features', () => {
      const schema = generateJsonSchema();
      const ajv = new Ajv({ strict: false });
      const validate = ajv.compile(schema);

      const fullConfig = {
        version: '1',
        fail_on: 'medium',
        mode: 'auto',
        exclude_paths: ['**/node_modules/**', '**/vendor/**'],
        scanners: {
          secrets: { enabled: true },
          dependencies: { enabled: true, ignore_cves: ['CVE-2021-1234'] },
          iac: { enabled: true, skip_checks: ['CKV_AWS_1'] },
          container: { enabled: false },
        },
        rules: [
          {
            id: 'CUSTOM-001',
            name: 'My Custom Rule',
            description: 'Detects custom secrets',
            severity: 'high',
            type: 'secret',
            regex: 'my-secret-[a-z0-9]+',
            flags: 'gi',
            file_globs: ['*.ts', '*.js'],
          },
        ],
        ignore: {
          paths: ['**/test-fixtures/**'],
        },
        allowlist: [
          {
            id: 'allow-1',
            reason: 'Test data only',
            expires: '2026-12-31',
            match: {
              scanner: 'secrets',
              path_glob: '**/test/**',
            },
          },
        ],
      };

      const isValid = validate(fullConfig);
      if (!isValid) {
        console.error('Validation errors:', validate.errors);
      }
      expect(isValid).toBe(true);
    });

    it('should reject invalid severity value', () => {
      const schema = generateJsonSchema();
      const ajv = new Ajv({ strict: false });
      const validate = ajv.compile(schema);

      const invalidConfig = {
        version: '1',
        fail_on: 'invalid',
      };

      const isValid = validate(invalidConfig);
      expect(isValid).toBe(false);
      expect(validate.errors).toBeDefined();
    });

    it('should reject invalid mode value', () => {
      const schema = generateJsonSchema();
      const ajv = new Ajv({ strict: false });
      const validate = ajv.compile(schema);

      const invalidConfig = {
        version: '1',
        mode: 'invalid',
      };

      const isValid = validate(invalidConfig);
      expect(isValid).toBe(false);
    });

    it('should reject rules exceeding MAX_RULES limit', () => {
      const schema = generateJsonSchema();
      const ajv = new Ajv({ strict: false });
      const validate = ajv.compile(schema);

      const rules = Array.from({ length: 51 }, (_, i) => ({
        id: `RULE-${String(i).padStart(3, '0')}`,
        name: `Rule ${i}`,
        regex: `pattern-${i}`,
      }));

      const invalidConfig = {
        version: '1',
        rules,
      };

      const isValid = validate(invalidConfig);
      expect(isValid).toBe(false);
    });
  });
});
