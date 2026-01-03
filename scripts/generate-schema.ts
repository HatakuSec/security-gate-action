#!/usr/bin/env node
/**
 * Script to generate JSON Schema from Zod configuration.
 *
 * Usage: npx tsx scripts/generate-schema.ts
 *
 * This generates schema/config.schema.json for editor validation.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateJsonSchemaString } from '../src/config/json-schema.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const schemaDir = join(rootDir, 'schema');
const outputPath = join(schemaDir, 'config.schema.json');

// Ensure schema directory exists
mkdirSync(schemaDir, { recursive: true });

// Generate and write schema
const schemaContent = generateJsonSchemaString();
writeFileSync(outputPath, schemaContent, 'utf8');

console.log(`✓ Generated JSON Schema: ${outputPath}`);
console.log(`  Size: ${(schemaContent.length / 1024).toFixed(1)} KB`);
