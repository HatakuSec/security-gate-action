#!/usr/bin/env node

/**
 * Build script for security-gate-action
 *
 * Uses esbuild to bundle the TypeScript source into a single dist/index.js file.
 * This is required for GitHub Actions which expects a single entry point.
 */

import * as esbuild from 'esbuild';
import { existsSync, mkdirSync, rmSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const distDir = join(rootDir, 'dist');

// Parse command line arguments
const isWatch = process.argv.includes('--watch');

// Clean dist directory
if (existsSync(distDir)) {
  rmSync(distDir, { recursive: true });
}
mkdirSync(distDir, { recursive: true });

/** @type {esbuild.BuildOptions} */
const buildOptions = {
  entryPoints: [join(rootDir, 'src', 'index.ts')],
  bundle: true,
  platform: 'node',
  target: 'node20',
  outfile: join(distDir, 'index.js'),
  format: 'cjs', // GitHub Actions requires CommonJS
  sourcemap: false,
  minify: false, // Keep readable for debugging
  treeShaking: true,
  // Exclude node built-ins and mark as external if needed
  external: [],
  // Handle __dirname and __filename for ESM compatibility
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  banner: {
    js: `/**
 * Security Gate Action
 * 
 * This file is auto-generated. Do not edit directly.
 * Source: src/index.ts
 */
`,
  },
  logLevel: 'info',
};

async function build() {
  try {
    if (isWatch) {
      const ctx = await esbuild.context(buildOptions);
      await ctx.watch();
      console.log('👀 Watching for changes...');
    } else {
      const result = await esbuild.build(buildOptions);
      console.log('✅ Build complete!');

      if (result.errors.length > 0) {
        console.error('Build errors:', result.errors);
        process.exit(1);
      }

      if (result.warnings.length > 0) {
        console.warn('Build warnings:', result.warnings);
      }

      // Log output file info
      const { statSync } = await import('fs');
      const stats = statSync(join(distDir, 'index.js'));
      const sizeKB = (stats.size / 1024).toFixed(2);
      console.log(`📦 dist/index.js: ${sizeKB} KB`);
    }
  } catch (error) {
    console.error('Build failed:', error);
    process.exit(1);
  }
}

build();
