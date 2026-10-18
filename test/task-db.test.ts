import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { TaskDb } from '../src/task-db.js';
import { TASK_CHECKPOINT_SHAPE } from '../src/checkpoints.js';
import { HEADER_END_MARKER, parseTaskFile, renderTaskFile, splitTaskSource } from '../src/task-file.js';

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-taskdb-'));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const script = (id: string, body = 'echo demo', extra = ''): string => `#!/usr/bin/env bash
# xtrape-task: ${id}
# version: 1.0.0
# description: Demo task
# risk: low
# readonly: true
# servers: *
# approval: policy
${extra}${body}
`;

const openDb = (dir: string): TaskDb => new TaskDb(join(dir, 'tasks.db'));

describe('canonical render round-trip (the DB stores columns; the digest covers the render)', () => {
  it('split -> render preserves meaning for a fully-loaded task file', () => {
    const source = `#!/bin/sh
# xtrape-task: demo.full
# version: 2.1.0
# description: Everything declared
# risk: high
# readonly: false
# servers: web-*, db-*
# approval: always_human
# interpreter: sh
# timeout: 30
# maxBytes: 4096
# param: level required string Aggressiveness level
# param.level.enum: low|high
# param: retries optional integer How many times
# param.retries.minimum: 0
# redact: sess-[0-9a-f]+
set -eu
tune "$XOPS_level"
`;
    const original = parseTaskFile(source, 'full.sh');
    const rendered = renderTaskFile(splitTaskSource(source));
    const reparsed = parseTaskFile(rendered, 'full.rendered.sh');
    expect(reparsed).toMatchObject({
      id: original.id,
      version: original.version,
      description: original.description,
      riskLevel: original.riskLevel,
      readonly: original.readonly,
      serverScopes: original.serverScopes,
      approvalPolicy: original.approvalPolicy,
      interpreter: original.interpreter,
      timeoutSeconds: original.timeoutSeconds,
      params: original.params,
      outputPolicy: original.outputPolicy,
    });
    // Rendering is idempotent: the canonical text is its own canonical form.
    expect(renderTaskFile(splitTaskSource(rendered))).toBe(rendered);
    // The body — including its interior comments — survives verbatim.
    expect(rendered).toContain('set -eu\ntune "$XOPS_level"');
  });
});

describe('the explicit header/body boundary (review 2354)', () => {
  it('a body that BEGINS with declaration-shaped comments stays script, never metadata', () => {
    const evilBody = '# executor: evil\n# param: injected required string x\necho hi';
    const source = `#!/usr/bin/env bash\n# xtrape-task: demo.echo\n# version: 1.0.0\n# risk: low\n# readonly: true\n# servers: *\n# approval: policy\n${HEADER_END_MARKER}\n${evilBody}`;
    const def = parseTaskFile(source, 'sealed.sh');
    expect(def.executor).toBe('ssh'); // NOT 'evil'
    expect(Object.keys((def.params as { properties: Record<string, unknown> }).properties)).toEqual([]);
    const parts = splitTaskSource(source);
    expect(parts.body).toBe(evilBody);
    // Leading plain comments in the body survive the canonical render.
    expect(renderTaskFile(parts)).toContain(evilBody);
  });

  it('a plain "# ---" comment in a LEGACY header block is still just a comment — declarations after it are not truncated (review 2355)', () => {
    const legacy = `#!/usr/bin/env bash
# xtrape-task: demo.legacy
# version: 1.0.0
# risk: high
# ---
# readonly: false
# servers: *
# approval: always_human
# param: level required string L
echo hi
`;
    const def = parseTaskFile(legacy, 'legacy.sh');
    expect(def.approvalPolicy).toBe('always_human'); // NOT silently defaulted
    expect(def.readonly).toBe(false);
    expect(Object.keys((def.params as { properties: Record<string, unknown> }).properties)).toEqual(['level']);
  });

  it('a pre-#60 revision keeps its FROZEN identity: canonical bytes backfilled, digest untouched, approvals coherent (review 2355)', () => {
    const dir = tempDir();
    let db = openDb(dir);
    const content = script('demo.echo', 'echo v1');
    const v1 = db.saveDraft(content);
    db.enable('demo.echo', v1.definition.scriptDigest, { commandId: 'cmd_old' });
    db.close();
    // Rewind the row to its pre-#60 shape: no canonical column value, and a
    // digest computed over the marker-LESS render of that era.
    const legacyText = renderTaskFile(splitTaskSource(v1.definition.script), false);
    const legacyDigest = parseTaskFile(legacyText, 'legacy').scriptDigest;
    const raw = new Database(join(dir, 'tasks.db'));
    raw.prepare('UPDATE task_revisions SET canonical = NULL, digest = ?').run(legacyDigest);
    raw.prepare('UPDATE task_approvals SET digest = ?').run(legacyDigest);
    raw.close();
    db = openDb(dir); // migration backfills the frozen bytes
    const enabled = db.findEnabled('demo.echo')!;
    // Identity preserved: SAME digest as before the upgrade, bytes = the
    // render of ITS time — no silent re-canonicalization, and the approval
    // row still names exactly this revision's digest.
    expect(enabled.definition.scriptDigest).toBe(legacyDigest);
    expect(enabled.definition.script).toBe(legacyText);
    expect(db.approvals('demo.echo')).toMatchObject([{ digest: legacyDigest }]);
    // An UNTOUCHED structural resave of the legacy row is a no-op: the
    // digest would differ (new render format), but "unchanged" is judged on
    // STRUCTURE, and the STORED identity is what comes back (review 2356).
    const resave = db.saveDraft(enabled.definition.script);
    expect(resave).toMatchObject({ state: 'enabled', unchanged: true });
    expect(resave.definition.scriptDigest).toBe(legacyDigest);
    expect(db.history('demo.echo')).toHaveLength(1);
    // New CONTENT saves use the new canonical form without disturbing the old row.
    const v2 = db.saveDraft(script('demo.echo', 'echo v2'));
    expect(v2.definition.script).toContain('# xtrape-script:');
    db.close();
  });

  it('a legacy row whose stored digest NO known render reproduces refuses the open — a corrupt store must not serve', () => {
    const dir = tempDir();
    const db = openDb(dir);
    db.saveDraft(script('demo.echo'));
    db.close();
    const raw = new Database(join(dir, 'tasks.db'));
    raw.prepare("UPDATE task_revisions SET canonical = NULL, digest = 'sha256:" + '0'.repeat(64) + "'").run();
    raw.close();
    expect(() => openDb(dir)).toThrow(/refusing to serve/);
  });
});

describe('TaskDb — the DB-backed task library (#58)', () => {
  it('a saved draft is stored as metadata columns + body, listed as draft — never enabled', () => {
    const db = openDb(tempDir());
    const { definition: def, revisionId, state } = db.saveDraft(script('demo.echo'));
    expect(def.id).toBe('demo.echo');
    expect(def.scriptDigest).toMatch(/^sha256:/);
    expect(def.sourceFile).toBe(`task:demo.echo@r${revisionId}`);
    expect(state).toBe('draft');
    expect(db.listAll()).toMatchObject([{ state: 'draft', revisionId }]);
    expect(db.findEnabled('demo.echo')).toBeUndefined();
    expect(db.enabledDefinitions()).toEqual([]);
  });

  it('refuses content that does not parse or cannot register — nothing lands', () => {
    const db = openDb(tempDir());
    expect(() => db.saveDraft('#!/usr/bin/env bash\necho no header\n')).toThrow();
    const reserved = script('demo.echo', 'echo x', '# param: serverId required string collides\n');
    expect(() => db.saveDraft(reserved)).toThrow(/reserved/);
    expect(db.listAll()).toEqual([]);
    expect(db.history('demo.echo')).toEqual([]);
  });

  it('enable promotes the draft; the approval binds to bytes and lands provenance on the ledger', () => {
    const db = openDb(tempDir());
    const draft = db.saveDraft(script('demo.echo', 'echo v1')).definition;
    // No approver and no authoritative reference = no approval record can
    // land — the enable fails closed (review 2350).
    expect(() => db.enable('demo.echo', draft.scriptDigest, {})).toThrow(/attests no approval provenance/);
    expect(db.findEnabled('demo.echo')).toBeUndefined();
    expect(db.approvals('demo.echo')).toEqual([]);
    expect(() => db.enable('demo.echo', 'sha256:' + '0'.repeat(64), { commandId: 'cmd_t' })).toThrow(/changed since it was reviewed/);
    const { definition, replaced } = db.enable('demo.echo', draft.scriptDigest, { commandId: 'cmd_test1' });
    expect(definition.scriptDigest).toBe(draft.scriptDigest);
    expect(replaced).toBeUndefined();
    expect(db.findEnabled('demo.echo')?.definition.scriptDigest).toBe(draft.scriptDigest);
    expect(db.findDraft('demo.echo')).toBeUndefined();
    expect(db.approvals('demo.echo')).toMatchObject([{ digest: draft.scriptDigest, commandId: 'cmd_test1' }]);
  });

  it('a same-id draft REPLACES the enabled version on enable; history and ledger accumulate', () => {
    const db = openDb(tempDir());
    const v1 = db.saveDraft(script('demo.echo', 'echo v1')).definition;
    db.enable('demo.echo', v1.scriptDigest, { commandId: 'cmd_t' });
    const v2 = db.saveDraft(script('demo.echo', 'echo v2')).definition;
    expect(db.findEnabled('demo.echo')?.definition.scriptDigest).toBe(v1.scriptDigest);
    expect(db.findDraft('demo.echo')?.definition.scriptDigest).toBe(v2.scriptDigest);
    expect(db.listAll().map((t) => t.state)).toEqual(['draft', 'enabled']);
    const { replaced } = db.enable('demo.echo', v2.scriptDigest, { commandId: 'cmd_t' });
    expect(replaced).toBe(v1.scriptDigest);
    expect(db.approvals('demo.echo')).toMatchObject([
      { digest: v2.scriptDigest, replacedDigest: v1.scriptDigest },
      { digest: v1.scriptDigest },
    ]);
    expect(db.history('demo.echo')).toHaveLength(2);
  });

  it('byte-identical resubmits create nothing, and editing BACK to the enabled bytes cancels the pending draft (review 2349)', () => {
    const db = openDb(tempDir());
    const v1 = db.saveDraft(script('demo.echo', 'echo v1'));
    expect(db.saveDraft(script('demo.echo', 'echo v1'))).toMatchObject({ revisionId: v1.revisionId, state: 'draft', unchanged: true });
    db.enable('demo.echo', v1.definition.scriptDigest, { commandId: 'cmd_t' });
    // Identical to the enabled version, no draft pending: a pure no-op.
    expect(db.saveDraft(script('demo.echo', 'echo v1'))).toMatchObject({ state: 'enabled', unchanged: true });
    // Open a draft, then edit it back to the running bytes: the draft is
    // WITHDRAWN — not judged a fresh draft of identical content.
    const v2 = db.saveDraft(script('demo.echo', 'echo v2'));
    expect(v2.state).toBe('draft');
    const restored = db.saveDraft(script('demo.echo', 'echo v1'));
    expect(restored).toMatchObject({ state: 'enabled', unchanged: true, canceledDraftDigest: v2.definition.scriptDigest });
    expect(db.findDraft('demo.echo')).toBeUndefined();
    // History kept every distinct version, including the withdrawn one.
    expect(db.history('demo.echo')).toHaveLength(2);
  });

  it('the title is a metadata COLUMN: an untouched resave of a titled task is a no-op (#61 / review 2365)', () => {
    const db = openDb(tempDir());
    const titled = script('demo.echo').replace('# version: 1.0.0', '# title: 磁盘用量\n# version: 1.0.0');
    const v1 = db.saveDraft(titled);
    expect(v1.definition.title).toBe('磁盘用量');
    db.enable('demo.echo', v1.definition.scriptDigest, { commandId: 'cmd_t' });
    // Structural equality sees the title, so nothing new is minted…
    expect(db.saveDraft(titled)).toMatchObject({ state: 'enabled', unchanged: true });
    expect(db.history('demo.echo')).toHaveLength(1);
    // …and a real title change IS a change.
    const renamed = db.saveDraft(titled.replace('磁盘用量', '磁盘使用情况'));
    expect(renamed).toMatchObject({ state: 'draft', unchanged: false });
    // Editing back to the enabled bytes withdraws that draft.
    expect(db.saveDraft(titled)).toMatchObject({ state: 'enabled', unchanged: true, canceledDraftDigest: renamed.definition.scriptDigest });
  });

  it('disable demotes to draft (pointer move); a pending NEWER draft blocks it', () => {
    const db = openDb(tempDir());
    const v1 = db.saveDraft(script('demo.echo', 'echo v1')).definition;
    db.enable('demo.echo', v1.scriptDigest, { commandId: 'cmd_t' });
    expect(() => db.enable('demo.echo', v1.scriptDigest, { commandId: 'cmd_t' })).toThrow(/no draft/);
    db.saveDraft(script('demo.echo', 'echo v2'));
    expect(() => db.disable('demo.echo')).toThrow(/draft "demo.echo" already exists/);
    db.removeDraft('demo.echo');
    const { definition } = db.disable('demo.echo');
    expect(definition.id).toBe('demo.echo');
    expect(db.findEnabled('demo.echo')).toBeUndefined();
    expect(db.findDraft('demo.echo')?.definition.scriptDigest).toBe(v1.scriptDigest);
  });

  it('removeDraft and removeEnabled are POINTER clears: history and approval evidence survive (review 2349)', () => {
    const db = openDb(tempDir());
    const v1 = db.saveDraft(script('demo.echo', 'echo v1')).definition;
    db.enable('demo.echo', v1.scriptDigest, { commandId: 'cmd_t' });
    db.saveDraft(script('demo.echo', 'echo v2'));
    db.removeDraft('demo.echo');
    expect(db.findDraft('demo.echo')).toBeUndefined();
    expect(db.findEnabled('demo.echo')?.definition.scriptDigest).toBe(v1.scriptDigest);
    // The withdrawn draft is still HISTORY — nothing was deleted.
    expect(db.history('demo.echo')).toHaveLength(2);
    db.removeEnabled('demo.echo');
    // Retired from the library view…
    expect(db.listAll()).toEqual([]);
    expect(() => db.removeEnabled('demo.echo')).toThrow(/no enabled task/);
    // …but the record of what existed and what was approved REMAINS.
    expect(db.history('demo.echo')).toHaveLength(2);
    expect(db.approvals('demo.echo')).toHaveLength(1);
    // And the id can live again, with its history continuing.
    const v3 = db.saveDraft(script('demo.echo', 'echo v3'));
    expect(v3.state).toBe('draft');
    expect(db.history('demo.echo')).toHaveLength(3);
  });

  it('removeEnabled keeps a pending draft in place', () => {
    const db = openDb(tempDir());
    const v1 = db.saveDraft(script('demo.echo', 'echo v1')).definition;
    db.enable('demo.echo', v1.scriptDigest, { commandId: 'cmd_t' });
    db.saveDraft(script('demo.echo', 'echo v2'));
    db.removeEnabled('demo.echo');
    expect(db.findEnabled('demo.echo')).toBeUndefined();
    expect(db.findDraft('demo.echo')?.definition.script).toContain('echo v2');
  });

  it('state survives a restart — committed means durable (WAL, synchronous=FULL)', () => {
    const dir = tempDir();
    let db = openDb(dir);
    const v1 = db.saveDraft(script('demo.echo', 'echo v1')).definition;
    db.enable('demo.echo', v1.scriptDigest, { commandId: 'cmd_x' });
    db.saveDraft(script('demo.echo', 'echo v2'));
    db.close();
    db = openDb(dir);
    expect(db.findEnabled('demo.echo')?.definition.scriptDigest).toBe(v1.scriptDigest);
    expect(db.findDraft('demo.echo')?.definition.script).toContain('echo v2');
    expect(db.approvals('demo.echo')).toMatchObject([{ commandId: 'cmd_x' }]);
    db.close();
  });
});

describe('TaskDb.importDir — provisioned files are a one-time bootstrap channel (#58)', () => {
  it('imports tasks/ as enabled and drafts/ as drafts; re-import skips everything', () => {
    const dir = tempDir();
    const conf = join(dir, 'tasks');
    mkdirSync(join(conf, 'drafts'), { recursive: true });
    writeFileSync(join(conf, 'a.sh'), script('demo.echo'));
    writeFileSync(join(conf, 'drafts', 'b.sh'), script('other.task'));
    const db = openDb(dir);
    expect(db.importDir(conf)).toEqual({ imported: 2, skipped: 0 });
    expect(db.findEnabled('demo.echo')).toBeDefined();
    expect(db.findDraft('other.task')).toBeDefined();
    // A provisioned enable is not an online approval — the ledger stays empty.
    expect(db.approvals('demo.echo')).toEqual([]);
    expect(db.importDir(conf)).toEqual({ imported: 0, skipped: 2 });
    expect(db.listAll()).toHaveLength(2);
  });

  it('a pending replacement draft (tasks/v1 + drafts/v2, one id) imports WHOLE — the review is not dropped (review 2349)', () => {
    const dir = tempDir();
    const conf = join(dir, 'tasks');
    mkdirSync(join(conf, 'drafts'), { recursive: true });
    writeFileSync(join(conf, 'demo.echo.sh'), script('demo.echo', 'echo v1'));
    writeFileSync(join(conf, 'drafts', 'demo.echo.sh'), script('demo.echo', 'echo v2'));
    const db = openDb(dir);
    expect(db.importDir(conf)).toEqual({ imported: 2, skipped: 0 });
    expect(db.findEnabled('demo.echo')?.definition.script).toContain('echo v1');
    expect(db.findDraft('demo.echo')?.definition.script).toContain('echo v2');
    // The draft enables through the normal reviewed flow.
    const draft = db.findDraft('demo.echo')!;
    const { replaced } = db.enable('demo.echo', draft.definition.scriptDigest, { commandId: 'cmd_t' });
    expect(replaced).toBe(db.history('demo.echo').find((r) => r.revisionId !== draft.revisionId)!.digest);
  });

  it('a task already managed in the DB is never overwritten by a host file — the DB is the truth', () => {
    const dir = tempDir();
    const conf = join(dir, 'tasks');
    mkdirSync(conf, { recursive: true });
    const db = openDb(dir);
    const online = db.saveDraft(script('demo.echo', 'echo online')).definition;
    db.enable('demo.echo', online.scriptDigest, { commandId: 'cmd_t' });
    writeFileSync(join(conf, 'demo.echo.sh'), script('demo.echo', 'echo host-edit'));
    expect(db.importDir(conf)).toEqual({ imported: 0, skipped: 1 });
    expect(db.findEnabled('demo.echo')?.definition.script).toContain('echo online');
  });

  it('two provisioned files claiming one id in the SAME state refuse the import — no scan-order survivor (review 2350)', () => {
    const dir = tempDir();
    const conf = join(dir, 'tasks');
    mkdirSync(join(conf, 'drafts'), { recursive: true });
    writeFileSync(join(conf, 'a.sh'), script('demo.echo', 'echo v1'));
    writeFileSync(join(conf, 'b.sh'), script('demo.echo', 'echo v2'));
    const db = openDb(dir);
    expect(() => db.importDir(conf)).toThrow(/will not pick a survivor/);
    expect(db.listAll()).toEqual([]);
    // Same rule for two drafts of one id.
    rmSync(join(conf, 'b.sh'));
    writeFileSync(join(conf, 'drafts', 'c.sh'), script('demo.echo', 'echo v3'));
    writeFileSync(join(conf, 'drafts', 'd.sh'), script('demo.echo', 'echo v4'));
    expect(() => openDb(tempDir()).importDir(conf)).toThrow(/will not pick a survivor/);
  });

  it('a missing directory imports nothing; a broken provisioned file fails loudly', () => {
    const dir = tempDir();
    const db = openDb(dir);
    expect(db.importDir(join(dir, 'absent'))).toEqual({ imported: 0, skipped: 0 });
    const conf = join(dir, 'tasks');
    mkdirSync(conf, { recursive: true });
    writeFileSync(join(conf, 'broken.sh'), '#!/usr/bin/env bash\necho no header\n');
    expect(() => db.importDir(conf)).toThrow();
  });
});


describe('definition shape (linux-ops#94): a task enabled under an older Widget is not republished or exposed until re-versioned', () => {
  it('legacy rows (NULL shape) are shape 1 and need re-version; a fresh enable / import records the current shape', () => {
    const dir = tempDir();
    const db = openDb(dir);
    try {
      const draft = db.saveDraft(script('legacy.task', 'echo one'));
      db.enable('legacy.task', draft.definition.scriptDigest, { commandId: 'cmd_1' });
      // Simulate a library enabled by a pre-shape Widget: the column is NULL.
      (db as unknown as { db: { prepare: (s: string) => { run: (...a: unknown[]) => unknown } } }).db.prepare('UPDATE tasks SET checkpoint_shape = NULL WHERE id = ?').run('legacy.task');
      const legacy = db.findEnabled('legacy.task')!;
      expect(legacy).toMatchObject({ checkpointShape: 1, needsReversion: true });
      expect(db.enabledDefinitions().map((d) => d.id)).not.toContain('legacy.task');
      expect(db.needingReversion().map((t) => t.definition.id)).toEqual(['legacy.task']);
      // Re-version + enable again: published under the current shape, exposed again.
      const bumped = db.saveDraft(script('legacy.task', 'echo two').replace('# version: 1.0.0', '# version: 1.0.1'));
      db.enable('legacy.task', bumped.definition.scriptDigest, { commandId: 'cmd_2' });
      expect(db.findEnabled('legacy.task')).toMatchObject({ checkpointShape: TASK_CHECKPOINT_SHAPE, needsReversion: false });
      expect(db.enabledDefinitions().map((d) => d.id)).toContain('legacy.task');
      expect(db.needingReversion()).toEqual([]);
    } finally {
      db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
