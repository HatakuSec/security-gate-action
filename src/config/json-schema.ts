/**
 * JSON Schema generator for Security Gate configuration
 *
 * Converts Zod schemas to JSON Schema format for IDE validation,
 * documentation, and external tooling integration.
 *
 * @module config/json-schema
 */

import { zodToJsonSchema } from 'zod-to-json-schema';
import { RootConfigSchema } from './schema.js';

/**
 * JSON Schema metadata for Security Gate configuration.
 */
const SCHEMA_METADATA = {
  $id: 'https://github.com/owner/security-gate-action/schema/config.schema.json',
  title: 'Security Gate Configuration',
  description:
    'Configuration schema for Security Gate GitHub Action. Use this schema to validate .security-gate.yml files.',
} as const;

/**
 * Generate JSON Schema from the Zod configuration schema.
 *
 * Produces a deterministic JSON Schema with sorted keys for
 * consistent output across runs.
 *
 * @returns JSON Schema object
 */
export function generateJsonSchema(): Record<string, unknown> {
  const rawSchema = zodToJsonSchema(RootConfigSchema, {
    name: 'SecurityGateConfig',
    $refStrategy: 'none', // Inline all definitions for simpler schema
    target: 'jsonSchema7', // Use JSON Schema draft-07
  }) as Record<string, unknown>;

  // The schema comes with definitions wrapper, extract the actual config schema
  const definitions = rawSchema.definitions as Record<string, unknown> | undefined;
  const configSchema = definitions?.SecurityGateConfig as Record<string, unknown> | undefined;

  // Build the final schema with metadata and the config schema properties
  const result: Record<string, unknown> = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    ...SCHEMA_METADATA,
    type: 'object',
    ...(configSchema ?? {}),
  };

  return sortObjectKeys(result);
}

/**
 * Generate JSON Schema as a formatted string.
 *
 * @returns JSON Schema as a pretty-printed string
 */
export function generateJsonSchemaString(): string {
  const schema = generateJsonSchema();
  return JSON.stringify(schema, null, 2) + '\n';
}

/**
 * Recursively sort object keys for deterministic output.
 *
 * @param obj - Object to sort
 * @returns New object with sorted keys
 */
function sortObjectKeys<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(sortObjectKeys) as T;
  }

  const sortedKeys = Object.keys(obj).sort((a, b) => {
    // Keep $schema, $id, title, description at the top
    const priority = ['$schema', '$id', 'title', 'description', 'type', 'properties', 'required'];
    const aIndex = priority.indexOf(a);
    const bIndex = priority.indexOf(b);

    if (aIndex !== -1 && bIndex !== -1) {
      return aIndex - bIndex;
    }
    if (aIndex !== -1) {
      return -1;
    }
    if (bIndex !== -1) {
      return 1;
    }
    return a.localeCompare(b);
  });

  const result: Record<string, unknown> = {};
  for (const key of sortedKeys) {
    result[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
  }

  return result as T;
}

/**
 * Get the yaml-language-server directive for schema validation.
 *
 * Users can add this comment at the top of their .security-gate.yml
 * to enable schema validation in VS Code and other editors.
 *
 * @param schemaUrl - URL or path to the schema file
 * @returns The yaml-language-server directive comment
 */
export function getYamlSchemaDirective(
  schemaUrl = 'https://raw.githubusercontent.com/owner/security-gate-action/main/schema/config.schema.json'
): string {
  return `# yaml-language-server: $schema=${schemaUrl}`;
}
