import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, chmodSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadOrCreateInstanceId } from '../src/instance.js';

const dirs: string[] = [];
function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), 'linux-ops-widget-iid-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  delete process.env.LINUX_OPS_WIDGET_INSTANCE_ID;
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe('loadOrCreateInstanceId', () => {
  it('reuses a non-empty id and tightens a loose file to 0600', () => {
    const dir = tempDir();
    const file = join(dir, 'instance-id');
    writeFileSync(file, 'linux-ops-widget-abc123\n');
    chmodSync(file, 0o644);
    expect(loadOrCreateInstanceId(dir)).toBe('linux-ops-widget-abc123');
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('generates a new id for a pre-existing blank 0644 file and ends at 0600', () => {
    const dir = tempDir();
    const file = join(dir, 'instance-id');
    writeFileSync(file, '   \n');
    chmodSync(file, 0o644);
    const id = loadOrCreateInstanceId(dir);
    expect(id).toMatch(/^linux-ops-widget-[0-9a-f]{8}$/);
    expect(readFileSync(file, 'utf8').trim()).toBe(id);
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('creates a new 0600 id file when none exists and is stable across calls', () => {
    const dir = tempDir();
    const id = loadOrCreateInstanceId(dir);
    expect(statSync(join(dir, 'instance-id')).mode & 0o777).toBe(0o600);
    expect(loadOrCreateInstanceId(dir)).toBe(id);
  });

  it('honors the env override without touching the file', () => {
    process.env.LINUX_OPS_WIDGET_INSTANCE_ID = 'env-instance';
    const dir = tempDir();
    expect(loadOrCreateInstanceId(dir)).toBe('env-instance');
  });
});
