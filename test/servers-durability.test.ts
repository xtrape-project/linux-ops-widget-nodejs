import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Post-rename durability failure (review 2312). The store's commit is
 * `fsync(temp) → rename → fsync(directory)`; the rename is the PUBLICATION
 * point, so a directory-sync failure after it must not be reported as
 * "nothing changed" — that leaves disk new and memory old (split brain: a
 * TOFU pin the process does not know it holds, an add the API called failed
 * that reappears after restart). The contract under test: memory follows the
 * published file, and the caller still gets a DISTINGUISHED error so a TOFU
 * caller refuses the connection.
 *
 * The fs mock fails `fsyncSync` only for descriptors opened read-only — the
 * shape commit() uses exclusively for the DIRECTORY — leaving the temp-file
 * fsync (write descriptor) untouched.
 */
const dirFds = new Set<number>();
let failDirFsync = false;
let failTempOpen = false;

vi.mock('node:fs', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs')>();
  return {
    ...real,
    openSync: (path: never, flags: never, mode?: never): number => {
      if (failTempOpen && (flags as unknown) === 'wx') throw new Error('EIO: simulated temp-file open failure');
      const fd = real.openSync(path, flags, mode);
      if ((flags as unknown) === 'r') dirFds.add(fd);
      return fd;
    },
    fsyncSync: (fd: number): void => {
      if (failDirFsync && dirFds.has(fd)) throw new Error('EIO: simulated directory sync failure');
      real.fsyncSync(fd);
    },
    // The OS reuses descriptor numbers: without this, a closed directory fd
    // re-issued for the next temp FILE would inherit the dir-failure flag
    // and fail the pre-publication fsync instead.
    closeSync: (fd: number): void => {
      dirFds.delete(fd);
      real.closeSync(fd);
    },
  };
});

// Imported AFTER the mock so the store sees the instrumented fs.
const { ServerStore } = await import('../src/servers.js');

const FP = 'SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4';

const dirs: string[] = [];
function tempFile(): string {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-durability-'));
  dirs.push(dir);
  return join(dir, 'servers.json');
}

beforeEach(() => {
  failDirFsync = false;
  failTempOpen = false;
  dirFds.clear();
});
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe('post-rename durability failure (review 2312)', () => {
  it('a failed directory sync throws the DISTINGUISHED error, with memory following the published file — no split brain', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    failDirFsync = true;
    expect(() => store.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' })).toThrow(
      /updated but its durability is NOT confirmed/,
    );
    // Disk holds the published change…
    expect((JSON.parse(readFileSync(file, 'utf8')) as Array<{ id: string }>).map((s) => s.id)).toEqual(['web-01']);
    // …and memory agrees (the old behaviour kept the old map — the caller
    // would retry, "already exists" on disk after restart, absent in RAM).
    expect(store.get('web-01')).toBeDefined();
    failDirFsync = false;
    const reopened = new ServerStore(file);
    expect(reopened.get('web-01')).toBeDefined();
  });

  it('a TOFU pin under the same failure refuses the caller but stays consistent: the pin is live in memory AND on disk', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    const snap = store.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' });
    failDirFsync = true;
    // The executor treats this throw as "refuse the connection" — fail-closed
    // for THIS handshake…
    expect(() => store.pinHostKey(snap, FP)).toThrow(/durability is NOT confirmed/);
    // …while the recorded state is consistent everywhere it can be read: the
    // process KNOWS it holds the pin (no silent un-pinned state), and the
    // published file carries it. A crash losing the unconfirmed entry merely
    // re-runs accept-new on the next boot — never worse than the baseline.
    expect(store.get('web-01')?.hostKeyFingerprint).toBe(FP);
    expect(store.get('web-01')?.hostKeyAdmittedBy).toBe('first-use');
    expect((JSON.parse(readFileSync(file, 'utf8')) as Array<{ hostKeyFingerprint?: string }>)[0]?.hostKeyFingerprint).toBe(FP);
    // A second pin attempt refuses on the already-recorded key, not on a
    // phantom "unknown" state.
    failDirFsync = false;
    expect(() => store.pinHostKey(store.get('web-01')!, FP)).toThrow(/already has an admitted host key/);
  });

  it('ensureDurable keeps an unconfirmed pin unusable until a directory sync truly succeeds (review 2313)', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    const snap = store.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' });
    failDirFsync = true;
    expect(() => store.pinHostKey(snap, FP)).toThrow(/durability is NOT confirmed/);
    // The state is mechanically visible: while the sync keeps failing,
    // ensureDurable throws — this is what the executor consults before
    // exercising an admitted fingerprint, so the unconfirmed pin cannot be
    // used to execute.
    expect(() => store.ensureDurable()).toThrow(/still NOT confirmed/);
    expect(() => store.ensureDurable()).toThrow(/still NOT confirmed/); // still failing — still refused
    // Durability heals: one successful directory sync settles the debt…
    failDirFsync = false;
    expect(() => store.ensureDurable()).not.toThrow();
    // …and the steady state is a cheap no-op even if syncing broke again.
    failDirFsync = true;
    expect(() => store.ensureDurable()).not.toThrow();
  });

  it('a RESTART does not launder an unconfirmed pin into confirmed (review 2314)', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    const snap = store.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' });
    failDirFsync = true;
    expect(() => store.pinHostKey(snap, FP)).toThrow(/durability is NOT confirmed/);
    // The Worker restarts while the durability fault persists. The new
    // process reads the published pin off servers.json — but a restart is
    // not durability evidence: the fresh store must NOT begin confirmed.
    const restarted = new ServerStore(file);
    expect(restarted.get('web-01')?.hostKeyFingerprint).toBe(FP); // the pin is visible…
    expect(() => restarted.ensureDurable()).toThrow(/still NOT confirmed/); // …but still not trusted
    // The fault heals: the next use re-performs the sync and only then
    // does the pin become usable.
    failDirFsync = false;
    expect(() => restarted.ensureDurable()).not.toThrow();
  });

  it('a restart over a HEALTHY filesystem confirms at startup — the startup sync is real evidence, not an assumption', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    const snap = store.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' });
    failDirFsync = true;
    expect(() => store.pinHostKey(snap, FP)).toThrow(/durability is NOT confirmed/);
    // This restart CAN sync the directory — the constructor does, settling
    // the debt with an actual fsync rather than a fresh flag.
    failDirFsync = false;
    const restarted = new ServerStore(file);
    expect(() => restarted.ensureDurable()).not.toThrow();
    expect(restarted.get('web-01')?.hostKeyAdmittedBy).toBe('first-use');
  });

  it('a later SUCCESSFUL commit also settles an earlier unconfirmed rename (one dir sync covers all prior renames)', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    failDirFsync = true;
    expect(() => store.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' })).toThrow(
      /durability is NOT confirmed/,
    );
    failDirFsync = false;
    store.add({ id: 'db-01', host: 'h', username: 'ops', environment: 'staging', authMethod: 'password', password: 'pw' });
    expect(() => store.ensureDurable()).not.toThrow(); // debt was settled by the commit's own sync
  });

  it('pre-publication failures still change NOTHING (the two failure classes stay distinct)', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    store.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' });
    const before = readFileSync(file, 'utf8');
    // Fail BEFORE the publication point (the temp file cannot even open):
    // the ordinary error, an unchanged file, an unchanged map.
    failTempOpen = true;
    expect(() => store.add({ id: 'db-01', host: 'h', username: 'ops', environment: 'staging', authMethod: 'password', password: 'pw' })).toThrow(
      /simulated temp-file open failure/,
    );
    expect(store.get('db-01')).toBeUndefined(); // memory unchanged — nothing was published
    expect(readFileSync(file, 'utf8')).toBe(before); // file unchanged
  });
});
