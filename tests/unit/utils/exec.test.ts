/**
 * @file Exec Utilities Tests
 * @description Unit tests for safe command execution wrapper.
 *
 * Coverage targets:
 * - safeExec(): 90%
 * - commandExists(): 90%
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as exec from '@actions/exec';
import { safeExec, commandExists } from '../../../src/utils/exec';

// Mock @actions/exec
vi.mock('@actions/exec', () => ({
  exec: vi.fn(),
}));

describe('exec utilities', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('safeExec', () => {
    it('executes command and captures stdout', async () => {
      vi.mocked(exec.exec).mockImplementation((_cmd, _args, options) => {
        options?.listeners?.stdout?.(Buffer.from('output text'));
        return Promise.resolve(0);
      });

      const result = await safeExec('echo', ['hello']);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe('output text');
      expect(result.stderr).toBe('');
    });

    it('captures stderr', async () => {
      vi.mocked(exec.exec).mockImplementation((_cmd, _args, options) => {
        options?.listeners?.stderr?.(Buffer.from('error output'));
        return Promise.resolve(0);
      });

      const result = await safeExec('command', [], { ignoreReturnCode: true });

      expect(result.stderr).toBe('error output');
    });

    it('throws on non-zero exit code by default', async () => {
      vi.mocked(exec.exec).mockImplementation((_cmd, _args, options) => {
        options?.listeners?.stderr?.(Buffer.from('command failed'));
        return Promise.resolve(1);
      });

      await expect(safeExec('failing-command', [])).rejects.toThrow('command failed');
    });

    it('returns result on non-zero exit when ignoreReturnCode is true', async () => {
      vi.mocked(exec.exec).mockResolvedValue(1);

      const result = await safeExec('command', [], { ignoreReturnCode: true });

      expect(result.exitCode).toBe(1);
    });

    it('passes cwd option to exec', async () => {
      vi.mocked(exec.exec).mockResolvedValue(0);

      await safeExec('command', [], { cwd: '/some/path' });

      expect(exec.exec).toHaveBeenCalledWith(
        'command',
        [],
        expect.objectContaining({ cwd: '/some/path' })
      );
    });

    it('passes env option to exec', async () => {
      vi.mocked(exec.exec).mockResolvedValue(0);

      await safeExec('command', [], { env: { FOO: 'bar' } });

      expect(exec.exec).toHaveBeenCalledWith(
        'command',
        [],
        expect.objectContaining({
          env: expect.objectContaining({ FOO: 'bar' }),
        })
      );
    });

    it('passes silent option to exec', async () => {
      vi.mocked(exec.exec).mockResolvedValue(0);

      await safeExec('command', [], { silent: true });

      expect(exec.exec).toHaveBeenCalledWith(
        'command',
        [],
        expect.objectContaining({ silent: true })
      );
    });

    it('times out long-running commands', async () => {
      vi.mocked(exec.exec).mockImplementation(
        () => new Promise((resolve) => setTimeout(resolve, 10000))
      );

      await expect(safeExec('slow-command', [], { timeout: 50 })).rejects.toThrow('timed out');
    });

    it('uses args array to prevent shell injection', async () => {
      vi.mocked(exec.exec).mockResolvedValue(0);

      await safeExec('command', ['arg with spaces', '--flag=value']);

      expect(exec.exec).toHaveBeenCalledWith(
        'command',
        ['arg with spaces', '--flag=value'],
        expect.any(Object)
      );
    });
  });

  describe('commandExists', () => {
    it('returns true when command is found', async () => {
      vi.mocked(exec.exec).mockResolvedValue(0);

      const result = await commandExists('node');

      expect(result).toBe(true);
    });

    it('returns false when command is not found', async () => {
      vi.mocked(exec.exec).mockResolvedValue(1);

      const result = await commandExists('nonexistent-command');

      expect(result).toBe(false);
    });

    it('returns false when which/where throws', async () => {
      vi.mocked(exec.exec).mockRejectedValue(new Error('Command not found'));

      const result = await commandExists('bad-command');

      expect(result).toBe(false);
    });
  });
});
