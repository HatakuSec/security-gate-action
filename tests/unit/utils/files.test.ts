/**
 * @file Files Utilities Tests
 * @description Unit tests for file system helpers.
 *
 * Coverage targets:
 * - findFiles(): 80%
 * - isBinaryFile(): 90%
 * - getFileExtension(): 100%
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  findFiles,
  isBinaryFile,
  getFileExtension,
  pathExists,
  readTextFile,
  getFileSize,
} from '../../../src/utils/files';

describe('files utilities', () => {
  let testDir: string;

  beforeEach(() => {
    // Create a temporary test directory
    testDir = join(tmpdir(), `security-gate-test-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    // Clean up test directory
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('findFiles', () => {
    it('finds files matching glob pattern', async () => {
      // Create test files
      writeFileSync(join(testDir, 'file1.ts'), 'content');
      writeFileSync(join(testDir, 'file2.ts'), 'content');
      writeFileSync(join(testDir, 'file3.js'), 'content');

      const files = await findFiles('*.ts', { cwd: testDir });

      expect(files).toHaveLength(2);
      expect(files.some((f) => f.endsWith('file1.ts'))).toBe(true);
      expect(files.some((f) => f.endsWith('file2.ts'))).toBe(true);
    });

    it('finds files in subdirectories with ** pattern', async () => {
      mkdirSync(join(testDir, 'sub'), { recursive: true });
      writeFileSync(join(testDir, 'root.ts'), 'content');
      writeFileSync(join(testDir, 'sub', 'nested.ts'), 'content');

      const files = await findFiles('**/*.ts', { cwd: testDir });

      expect(files).toHaveLength(2);
    });

    it('excludes node_modules by default', async () => {
      mkdirSync(join(testDir, 'node_modules', 'pkg'), { recursive: true });
      writeFileSync(join(testDir, 'src.ts'), 'content');
      writeFileSync(join(testDir, 'node_modules', 'pkg', 'index.ts'), 'content');

      const files = await findFiles('**/*.ts', { cwd: testDir });

      expect(files).toHaveLength(1);
      expect(files[0]).toContain('src.ts');
    });

    it('respects custom ignore patterns', async () => {
      mkdirSync(join(testDir, 'vendor'), { recursive: true });
      writeFileSync(join(testDir, 'src.ts'), 'content');
      writeFileSync(join(testDir, 'vendor', 'lib.ts'), 'content');

      const files = await findFiles('**/*.ts', {
        cwd: testDir,
        ignore: ['**/vendor/**'],
      });

      expect(files).toHaveLength(1);
    });

    it('limits results with maxFiles', async () => {
      for (let i = 0; i < 10; i++) {
        writeFileSync(join(testDir, `file${i}.ts`), 'content');
      }

      const files = await findFiles('*.ts', { cwd: testDir, maxFiles: 3 });

      expect(files).toHaveLength(3);
    });

    it('handles multiple patterns', async () => {
      writeFileSync(join(testDir, 'file.ts'), 'content');
      writeFileSync(join(testDir, 'file.js'), 'content');
      writeFileSync(join(testDir, 'file.py'), 'content');

      const files = await findFiles(['*.ts', '*.js'], { cwd: testDir });

      expect(files).toHaveLength(2);
    });

    it('returns absolute paths', async () => {
      writeFileSync(join(testDir, 'file.ts'), 'content');

      const files = await findFiles('*.ts', { cwd: testDir });

      expect(files[0]).toMatch(/^\//);
      expect(files[0]).toContain(testDir);
    });
  });

  describe('isBinaryFile', () => {
    it('detects binary files with null bytes', () => {
      const binaryPath = join(testDir, 'binary.bin');
      writeFileSync(binaryPath, Buffer.from([0x00, 0x01, 0x02, 0x00]));

      expect(isBinaryFile(binaryPath)).toBe(true);
    });

    it('returns false for text files', () => {
      const textPath = join(testDir, 'text.txt');
      writeFileSync(textPath, 'Hello, world!\nThis is text.');

      expect(isBinaryFile(textPath)).toBe(false);
    });

    it('returns false for non-existent files', () => {
      expect(isBinaryFile(join(testDir, 'nonexistent.txt'))).toBe(false);
    });

    it('handles empty files', () => {
      const emptyPath = join(testDir, 'empty.txt');
      writeFileSync(emptyPath, '');

      expect(isBinaryFile(emptyPath)).toBe(false);
    });

    it('detects binary in first 8KB', () => {
      const binaryPath = join(testDir, 'large-binary.bin');
      const buffer = Buffer.alloc(16384);
      buffer[100] = 0x00; // Null byte within first 8KB

      writeFileSync(binaryPath, buffer);

      expect(isBinaryFile(binaryPath)).toBe(true);
    });
  });

  describe('getFileExtension', () => {
    it('returns lowercase extension without dot', () => {
      expect(getFileExtension('file.ts')).toBe('ts');
      expect(getFileExtension('file.TypeScript')).toBe('typescript');
      expect(getFileExtension('file.JSON')).toBe('json');
    });

    it('handles files without extension', () => {
      expect(getFileExtension('Dockerfile')).toBe('');
      expect(getFileExtension('Makefile')).toBe('');
    });

    it('handles dotfiles', () => {
      // Node's extname treats .gitignore as having no extension (entire name is the "base")
      expect(getFileExtension('.gitignore')).toBe('gitignore');
      expect(getFileExtension('.env')).toBe('env');
    });

    it('handles multiple dots', () => {
      expect(getFileExtension('file.test.ts')).toBe('ts');
      expect(getFileExtension('archive.tar.gz')).toBe('gz');
    });

    it('handles paths with directories', () => {
      expect(getFileExtension('/path/to/file.ts')).toBe('ts');
      expect(getFileExtension('src/index.ts')).toBe('ts');
    });
  });

  describe('pathExists', () => {
    it('returns true for existing files', () => {
      const filePath = join(testDir, 'exists.txt');
      writeFileSync(filePath, 'content');

      expect(pathExists(filePath)).toBe(true);
    });

    it('returns true for existing directories', () => {
      expect(pathExists(testDir)).toBe(true);
    });

    it('returns false for non-existent paths', () => {
      expect(pathExists(join(testDir, 'nonexistent'))).toBe(false);
    });
  });

  describe('readTextFile', () => {
    it('reads file contents', () => {
      const filePath = join(testDir, 'text.txt');
      writeFileSync(filePath, 'Hello, world!');

      expect(readTextFile(filePath)).toBe('Hello, world!');
    });

    it('returns null for files exceeding maxSize', () => {
      const filePath = join(testDir, 'large.txt');
      writeFileSync(filePath, 'x'.repeat(1000));

      expect(readTextFile(filePath, 100)).toBeNull();
    });

    it('returns null for non-existent files', () => {
      expect(readTextFile(join(testDir, 'nonexistent.txt'))).toBeNull();
    });
  });

  describe('getFileSize', () => {
    it('returns file size in bytes', () => {
      const filePath = join(testDir, 'sized.txt');
      writeFileSync(filePath, 'Hello'); // 5 bytes

      expect(getFileSize(filePath)).toBe(5);
    });

    it('returns -1 for non-existent files', () => {
      expect(getFileSize(join(testDir, 'nonexistent.txt'))).toBe(-1);
    });
  });
});
