import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildCeActions } from '../src/ce-actions.js';
import { buildCheckpointSet, definitionFingerprint } from '../src/checkpoints.js';
import { OpsService } from '../src/service.js';
import { ServerStore } from '../src/servers.js';
import { TaskDb } from '../src/task-db.js';
import { RedlineSet } from '../src/redlines.js';
import type { ActionDefinition } from '../src/types.js';
import { ParamGuardSet } from '../src/param-guards.js';
import { MemoryAuditLogger } from '../src/audit.js';
import { FakeExecutor, makeAction, makeRegistry, TEST_HOST_KEY_FINGERPRINT } from './helpers.js';
import { HostKeyMismatchError } from '../src/executors/ssh.js';
import type { CommandInvocation, CommandResult, ServerDefinition } from '../src/types.js';

/** A deployment that declares no redlines — spelled out, since the dep is required. */
const NO_REDLINES = new RedlineSet([]);
/** A deployment that declares no parameter guards — spelled out, since the dep is required. */
const NO_GUARDS = new ParamGuardSet([]);

const dirs: string[] = [];
function store(): ServerStore {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-ce-'));
  dirs.push(dir);
  return new ServerStore(join(dir, 'servers.json'));
}
function tstore(): TaskDb {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-tasks-'));
  dirs.push(dir);
  return new TaskDb(join(dir, 'tasks.db'));
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function setup() {
  const registry = makeRegistry(
    makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }),
    makeAction({ id: 'nginx.reload', readonly: false, riskLevel: 'medium', serverScopes: ['web-*'], script: 'systemctl reload nginx' }),
    makeAction({ id: 'db.drop', readonly: false, riskLevel: 'critical', serverScopes: ['*'], script: 'dropdb x' }),
  );
  const srv = store();
  srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
  srv.add({ id: 'db-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
  const executor = new FakeExecutor();
  const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
  const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probeHostKey: () => Promise.resolve('SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4'), probe: (s) => executor.run(s, { command: 'true' }) });
  const byName = new Map(actions.map((a) => [a.name, a]));
  return { actions, byName, srv, executor };
}

/**
 * The real Edit flow: prepare, change cells on what it prefilled, submit.
 * Since #61 the submit carries a sealed token naming the revision it was
 * prefilled from, so a payload cannot be reused across saves (review 2393).
 */
async function editTask(
  byName: () => Map<string, { prepare?: (i?: unknown) => Promise<{ initialPayload?: unknown }> | { initialPayload?: unknown }; execute: (i: unknown, c?: unknown) => Promise<unknown> }>,
  id: string,
  changes: Record<string, unknown>,
): Promise<unknown> {
  const prep = await byName().get('updateTask')!.prepare!({ id });
  const payload = prep.initialPayload as Record<string, unknown>;
  return byName().get('updateTask')!.execute({ ...payload, ...changes });
}

describe('buildCeActions', () => {
  it('registers each ops capability as its own visible entry action (no runOps)', () => {
    const { actions, byName } = setup();
    expect(actions.map((a) => a.name)).not.toContain('runOps');
    expect(byName.get('system.uptime')?.category).toBe('ops');
    expect(byName.get('nginx.reload')?.category).toBe('ops');
  });

  it('the task library grows online: draft -> review -> enable -> HOT catalog update -> disable (#55)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore, store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a])); // re-scan the SAME live array
    // The structured Add Task form (#58 part 2): fields, not header syntax.
    const form = {
      id: 'demo.disk',
      title: '磁盘用量',
      version: '1.0.0',
      description: 'Show disk usage',
      risk: 'low',
      serverScope: '*',
      body: 'df -h',
    };
    // 1) Add lands a DRAFT: not in the live catalog, not executable.
    const added = (await byName().get('addTask')!.execute(form)) as { data: { id: string; state: string; scriptDigest: string } };
    expect(added.data).toMatchObject({ id: 'demo.disk', state: 'draft' });
    expect(byName().get('demo.disk')).toBeUndefined();
    expect((await opsService.execute({ serverId: 'web-01', actionId: 'demo.disk', args: {}, reason: 'x' }, { surface: 'platform', controlPlaneAvailable: true })).status).toBe('denied');
    // A duplicate draft is refused.
    await expect(byName().get('addTask')!.execute(form)).rejects.toThrow(/already exists/);
    // 2) Enable's prepare IS the review: full text + digest, platform-rendered.
    const review = await byName().get('enableTask')!.prepare!({ id: 'demo.disk' });
    const card = (review.currentState as { detail: { data: Record<string, unknown> } }).detail;
    expect(card.data.script).toContain('df -h');
    expect(card.data.scriptDigest).toBe(added.data.scriptDigest);
    // 2b) The approval binds to bytes UNFORGEABLY (review 2331 item 1): the
    // prepare seeds an HMAC-sealed binding over the reviewed digest — a
    // caller cannot mint or alter it, so pasting a digest by hand approves
    // nothing. An absent/tampered binding refuses outright.
    const binding = (review.initialPayload as { reviewBinding?: string }).reviewBinding!;
    expect(binding).toBeTruthy();
    expect(binding).not.toContain(added.data.scriptDigest); // opaque, not the raw digest
    await expect(byName().get('enableTask')!.execute({ id: 'demo.disk', reviewBinding: `${binding}x` }, { commandId: 'cmd_lc' })).rejects.toThrow(/no valid review binding/);
    await expect(byName().get('enableTask')!.execute({ id: 'demo.disk', reviewBinding: added.data.scriptDigest }, { commandId: 'cmd_lc' })).rejects.toThrow(/no valid review binding/);
    // An ops run token must NOT double as an enable approval (domain
    // separation): system.uptime's prepare seals the same key over its own
    // digest, and presenting that here refuses at the unseal.
    const opsPrep = await byName().get('system.uptime')!.prepare!();
    const opsToken = (opsPrep.initialPayload as { reviewBinding?: string }).reviewBinding!;
    await expect(byName().get('enableTask')!.execute({ id: 'demo.disk', reviewBinding: opsToken }, { commandId: 'cmd_lc' })).rejects.toThrow(/no valid review binding/);
    // 2c) An edit between review and submit is a DIFFERENT object: the old
    // binding unseals fine but the digest CAS refuses.
    await editTask(byName as never, 'demo.disk', { body: 'df -h /var' });
    await expect(byName().get('enableTask')!.execute({ id: 'demo.disk', reviewBinding: binding }, { commandId: 'cmd_lc' })).rejects.toThrow(/changed since it was reviewed/);
    // Re-review the current draft; its binding enables.
    const review2 = await byName().get('enableTask')!.prepare!({ id: 'demo.disk' });
    const binding2 = (review2.initialPayload as { reviewBinding?: string }).reviewBinding!;
    // 3) Enable hot-swaps: the SAME actions array now carries the task.
    // The local callback path (no commandId) cannot land an approval — the
    // store fails it closed (review 2350).
    await expect(byName().get('enableTask')!.execute({ id: 'demo.disk', reviewBinding: binding2 })).rejects.toThrow(/attests no approval provenance/);
    const enabled = (await byName().get('enableTask')!.execute(
      { id: 'demo.disk', reviewBinding: binding2 },
      { commandId: 'cmd_lc', origin: { account: 'acct_owner' } },
    )) as { data: { state: string } };
    expect(enabled.data.state).toBe('enabled');
    // The ledger names the deciding Account the Platform DELIVERED with the
    // command (#256) beside the command itself — the seam that stayed empty
    // until the origin existed. Never a configured stand-in.
    expect(taskStore.approvals('demo.disk')[0]).toMatchObject({ commandId: 'cmd_lc', approvedBy: 'acct_owner' });
    expect(byName().get('demo.disk')?.category).toBe('ops');
    const run = await opsService.execute({ serverId: 'web-01', actionId: 'demo.disk', args: {}, reason: 'x' }, { surface: 'platform', controlPlaneAvailable: true });
    expect(run.status).toBe('executed');
    // Running the task through the CE surface writes the Account CONTEXT into
    // the execution evidence — `accountId` + trace, deliberately not
    // `originActor*` (the Account is who is responsible, not who was at the
    // keyboard) — and nothing at all when nothing was delivered, not a
    // substituted identity.
    const audit = (opsService as unknown as { opts: { audit: MemoryAuditLogger } }).opts.audit;
    const runPrep = await byName().get('demo.disk')!.prepare!({});
    const runBinding = (runPrep.initialPayload as { reviewBinding: string }).reviewBinding;
    const ran = (await byName().get('demo.disk')!.execute(
      { serverId: 'web-01', reason: 'x', reviewBinding: runBinding },
      { commandId: 'cmd_run1', origin: { account: 'acct_agent_1', traceId: 'tr_run1' } },
    )) as { success: boolean };
    expect(ran.success).toBe(true);
    expect(audit.entries.at(-1)).toMatchObject({ request: { accountId: 'acct_agent_1', traceId: 'tr_run1' } });
    expect((audit.entries.at(-1) as { request: { originActorType?: string } }).request.originActorType).toBeUndefined();
    await byName().get('demo.disk')!.execute({ serverId: 'web-01', reason: 'x', reviewBinding: runBinding }, { commandId: 'cmd_run2' });
    const last = (audit.entries.at(-1) as { request: { accountId?: string; originActorType?: string } }).request;
    expect(last.accountId).toBeUndefined();
    expect(last.originActorType).toBeUndefined();
    // 4) Disable removes it from the live catalog and execution again.
    await byName().get('disableTask')!.execute({ id: 'demo.disk' });
    expect(byName().get('demo.disk')).toBeUndefined();
    expect((await opsService.execute({ serverId: 'web-01', actionId: 'demo.disk', args: {}, reason: 'x' }, { surface: 'platform', controlPlaneAvailable: true })).status).toBe('denied');
    // 5) Single-line fields refuse embedded newlines — a raw-JSON value like
    // "x\n# risk: low" would otherwise smuggle a header the form never
    // showed. (Description is deliberately MULTI-line since #61, so the
    // guard is asserted on a single-line field.) A malformed declarations
    // line is refused rather than silently dropped as a comment.
    await expect(editTask(byName as never, 'demo.disk', { title: 'x\n# risk: critical' })).rejects.toThrow(/must be a single line/);
    await expect(editTask(byName as never, 'demo.disk', { params: [{ name: 'level', type: 'nope' }] })).rejects.toThrow(/type must be/);
    // 6) updateTask prepare prefills every FIELD from the stored version —
    // an edit is an edit, not a retype.
    const prep = await byName().get('updateTask')!.prepare!({ id: 'demo.disk' });
    expect(prep.initialPayload).toMatchObject({ id: 'demo.disk', title: '磁盘用量', risk: 'low', serverScope: '*', body: 'df -h /var' });
    // 7) A destructive sub-op refuses an unrecognized state outright — it
    // must never fall into the enabled branch (review 2329 item 7).
    await expect(byName().get('removeTask')!.execute({ id: 'demo.disk', state: 'bogus' })).rejects.toThrow(/state must be/);
    // 8) Registry-grade admission at the door (review 2329 item 2): a
    // declaration naming a RESERVED param parses but cannot register — it
    // must be refused at draft time, not at enable time.
    await expect(byName().get('addTask')!.execute({ ...form, id: 'demo.bad', params: [{ name: 'serverId', type: 'string', required: true }] })).rejects.toThrow(/reserved/);
  });

  it('the bounded profile filters the LIVE ops catalog through rebuildOps, not a startup snapshot (#81 review 2688 #2)', async () => {
    // Two enabled ops at build; the bounded predicate hides nginx.reload.
    const registry = makeRegistry(
      makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }),
      makeAction({ id: 'nginx.reload', readonly: false, riskLevel: 'medium', serverScopes: ['*'], script: 'systemctl reload nginx' }),
    );
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    // Expose everything EXCEPT task.nginx.reload and task.demo.secret.
    const hidden = new Set(['task.nginx.reload', 'task.demo.secret']);
    const actions = buildCeActions({
      paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore, store: srv, opsService,
      probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT),
      isCheckpointExposed: (id) => !hidden.has(id),
    });
    const byName = () => new Map(actions.map((a) => [a.name, a])); // re-scan the SAME live array
    // Initial catalog: the exposed ops is present, the hidden one filtered out.
    expect(byName().get('system.uptime')?.category).toBe('ops');
    expect(byName().get('nginx.reload')).toBeUndefined();

    // Drive a real enable so rebuildOps runs on the live array the Connector holds.
    const enable = async (form: Record<string, unknown>): Promise<void> => {
      await byName().get('addTask')!.execute(form);
      const review = await byName().get('enableTask')!.prepare!({ id: form.id });
      const binding = (review.initialPayload as { reviewBinding: string }).reviewBinding;
      await byName().get('enableTask')!.execute({ id: form.id, reviewBinding: binding }, { commandId: `cmd_${String(form.id)}`, origin: { account: 'acct_owner' } });
    };
    const base = { title: 't', version: '1.0.0', description: 'd', risk: 'low', serverScope: '*' };
    // An EXPOSED new task appears after rebuildOps...
    await enable({ ...base, id: 'demo.disk', body: 'df -h' });
    expect(byName().get('demo.disk')?.category).toBe('ops');
    // ...and the hidden build-time ops is STILL filtered (rebuild re-applied the
    // predicate rather than snapshotting or resurrecting it).
    expect(byName().get('nginx.reload')).toBeUndefined();
    // A newly-enabled task the predicate HIDES stays out of the live catalog
    // even though it is enabled and registered — the filter lives in rebuildOps.
    await enable({ ...base, id: 'demo.secret', body: 'cat /etc/shadow' });
    expect(byName().get('demo.secret')).toBeUndefined();
    // The exposed ops survived every rebuild.
    expect(byName().get('system.uptime')?.category).toBe('ops');
    expect(byName().get('demo.disk')?.category).toBe('ops');
  });

  it('Enable REPUBLISHES a drifted definition at a known id@version and fails BEFORE the pointer move (#81 review 2692)', async () => {
    const registry = makeRegistry();
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();

    // A stand-in for index.ts's publish path + the Platform's immutable-conflict
    // authority: it builds the Checkpoint the same way, dedupes by the FULL
    // definition fingerprint (NOT id@version), and rejects a same id@version
    // carrying a different definition — exactly a 409 CHECKPOINT_IMMUTABLE_CONFLICT.
    const platform = new Map<string, string>(); // id@version -> definitionJson (immutable store)
    const publishedFp = new Set<string>();
    const ensureTaskCheckpoints = async (tasks: ReadonlyArray<ActionDefinition>): Promise<void> => {
      const defs = buildCheckpointSet({ profileDigest: `sha256:${'a'.repeat(64)}`, inputSchemaFor: () => ({ type: 'object' }), tasks, staticRows: false, bounded: null }).definitions;
      const fresh = defs.filter((d) => !publishedFp.has(definitionFingerprint(d)));
      for (const d of fresh) {
        const key = `${d.id.checkpointId}@${d.id.checkpointVersion}`;
        const json = JSON.stringify(d);
        const existing = platform.get(key);
        if (existing !== undefined && existing !== json) throw new Error('checkpoint immutable conflict (409)');
        platform.set(key, json);
      }
      for (const d of fresh) publishedFp.add(definitionFingerprint(d));
    };

    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore, store: srv, opsService, ensureTaskCheckpoints, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    const enable = async (id: string): Promise<unknown> => {
      const review = await byName().get('enableTask')!.prepare!({ id });
      const binding = (review.initialPayload as { reviewBinding: string }).reviewBinding;
      return byName().get('enableTask')!.execute({ id, reviewBinding: binding }, { commandId: `cmd_${id}_${platform.size}`, origin: { account: 'acct_owner' } });
    };

    // 1) Add + enable demo.x@1.0.0 at risk LOW — publishes def_A, exposes it.
    // The registry is the EXPOSED/enabled truth (updated only after a successful
    // enable's durable pointer move); a pending draft never shows there.
    await byName().get('addTask')!.execute({ id: 'demo.x', title: 't', version: '1.0.0', description: 'd', risk: 'low', serverScope: '*', body: 'echo a' });
    await enable('demo.x');
    expect(byName().get('demo.x')?.category).toBe('ops');
    const exposedA = registry.list().find((a) => a.id === 'demo.x')!;
    expect(exposedA.riskLevel).toBe('low');
    const digestA = exposedA.scriptDigest;

    // 2) Edit to risk HIGH — a governance drift at the SAME id@version (1.0.0).
    const prep = await byName().get('updateTask')!.prepare!({ id: 'demo.x' });
    await byName().get('updateTask')!.execute({ ...(prep.initialPayload as Record<string, unknown>), risk: 'high', body: 'echo b' });

    // 3) Re-enable: the drifted definition is REPUBLISHED (not swallowed by an
    // id@version cache) and the Platform rejects it. Enable must throw...
    await expect(enable('demo.x')).rejects.toThrow(/immutable conflict/);
    // ...BEFORE the durable pointer move: the EXPOSED task is still def_A, so the
    // HIGH-risk bytes never rode the old READ_ONLY/low Checkpoint.
    const exposedAfter = registry.list().find((a) => a.id === 'demo.x')!;
    expect(exposedAfter.riskLevel).toBe('low');
    expect(exposedAfter.scriptDigest).toBe(digestA);
  });

  it('the structured task form binds a server, keeps custom scopes, and round-trips declarations (#58 part 2)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    // Add Task's PREPARE renders the server-binding choices from the fleet.
    const addPrep = await byName().get('addTask')!.prepare!();
    const scopeProp = ((addPrep.inputSchema as { properties: Record<string, { enum?: string[] }> }).properties)['serverScope']!;
    expect(scopeProp.enum).toEqual(['*', 'web-01', '(custom)']);
    // Bind to ONE admitted server: the assembled task scopes to exactly it.
    const bound = (await byName().get('addTask')!.execute({
      id: 'demo.bound', version: '1.0.0', risk: 'low',
      serverScope: 'web-01', body: 'echo hi',
      params: [{ name: 'level', label: '强度', type: 'string', required: true, enum: 'low|high', default: 'low', description: 'Aggressiveness' }],
      redact: ['sess-[0-9a-f]+'],
    })) as { data: { id: string } };
    expect(bound.data.id).toBe('demo.bound');
    // A custom scope glob passes through verbatim.
    await byName().get('addTask')!.execute({
      id: 'demo.custom', version: '1.0.0', risk: 'low',
      serverScope: '(custom)', customScope: 'web-*, db-01', body: 'echo hi',
    });
    // Edit prefill maps the stored version BACK into the same fields —
    // including the declarations textarea and the custom-scope split.
    const prepBound = await byName().get('updateTask')!.prepare!({ id: 'demo.bound' });
    expect(prepBound.initialPayload).toMatchObject({
      serverScope: 'web-01', risk: 'low',
      params: [{ name: 'level', label: '强度', type: 'string', required: true, enum: 'low|high', default: 'low', description: 'Aggressiveness' }],
      redact: ['sess-[0-9a-f]+'],
    });
    const prepCustom = await byName().get('updateTask')!.prepare!({ id: 'demo.custom' });
    expect(prepCustom.initialPayload).toMatchObject({ serverScope: '(custom)', customScope: 'web-*, db-01' });
  });

  it('Edit -> Save untouched is a byte-exact no-op, and executor round-trips (review 2354)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    // Minimal form: approval/executor/interpreter left to their defaults —
    // normalization materializes them ONCE at save, so the stored version is
    // explicit and a later untouched resave cannot mint a phantom digest.
    await byName().get('addTask')!.execute({ id: 'demo.rt', version: '1.0.0', risk: 'low', serverScope: '*', body: '# a leading body comment\necho rt' });
    const prep = await byName().get('updateTask')!.prepare!({ id: 'demo.rt' });
    const payload = prep.initialPayload as Record<string, unknown>;
    // A task authored under the risk-only model carries no retired headers
    // at all — nothing to pass through (#61).
    expect(payload['legacyHeaders']).toBeUndefined();
    expect(payload).toMatchObject({ id: 'demo.rt', risk: 'low', serverScope: '*' });
    // The body — leading comment included — round-trips verbatim.
    expect(payload['body']).toBe('# a leading body comment\necho rt');
    const resaved = (await byName().get('updateTask')!.execute(payload)) as { message: string };
    expect(resaved.message).toContain('no change');
  });

  it('an online task can choose its interpreter: the shebang is an EDITABLE field that reaches the command (#61 / review 2370)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore, store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    const prep = await byName().get('addTask')!.prepare!();
    const shebangProp = ((prep.inputSchema as { properties: Record<string, { format?: string; readOnly?: boolean; default?: string }> }).properties)['shebang']!;
    // Editable: no longer hidden/readOnly, and it carries a usable default.
    expect(shebangProp.format).toBeUndefined();
    expect(shebangProp.readOnly).toBeUndefined();
    expect(shebangProp.default).toBe('#!/usr/bin/env bash');
    await byName().get('addTask')!.execute({
      id: 'demo.sh', title: 'POSIX task', version: '1.0.0', risk: 'low', serverScope: '*',
      shebang: '#!/bin/sh -e', body: 'echo hi',
    });
    const stored = taskStore.findDraft('demo.sh')!.definition;
    expect(stored.interpreter).toBe('/bin/sh');
    expect(stored.interpreterArgs).toEqual(['-e']);
    // Edit round-trips the chosen shebang instead of resetting it to bash.
    const editPrep = await byName().get('updateTask')!.prepare!({ id: 'demo.sh' });
    expect((editPrep.initialPayload as { shebang?: string }).shebang).toBe('#!/bin/sh -e');
  });

  it('parameter ROWS round-trip, and bounds without a column are preserved (#61 C-8)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore, store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    // A stored task declaring a bound the row has NO column for.
    taskStore.saveDraft(`#!/usr/bin/env bash
# xtrape-task: demo.rows
# version: 1.0.0
# risk: low
# servers: *
# param: retries optional integer How many times
# param.retries.label: 重试次数
# param.retries.default: 2
# param.retries.minimum: 0
# param.retries.maximum: 9
# redact: sess-[0-9a-f]+
# xtrape-script:
echo hi
`);
    const prep = await byName().get('updateTask')!.prepare!({ id: 'demo.rows' });
    const payload = prep.initialPayload as Record<string, unknown>;
    // The row carries the columns; minimum/maximum ride the hidden carrier.
    expect(payload['params']).toEqual([
      // `originName` is the stable row identity (review 2389): not a form
      // column, but it rides the row so a rename keeps its hidden bounds.
      { name: 'retries', originName: 'retries', type: 'integer', required: false, description: 'How many times', label: '重试次数', default: '2' },
    ]);
    expect(payload['redact']).toEqual(['sess-[0-9a-f]+']);
    // The stored declarations are NOT in the payload (review 2393): the
    // submit reads them from the revision the sealed token names.
    expect(payload['paramOriginals']).toBeUndefined();
    expect(payload['baseRevision']).toBeTruthy();
    // Saving the prefilled form unchanged is a NO-OP: nothing was dropped or
    // reordered on the way through the rows.
    const resaved = (await byName().get('updateTask')!.execute(payload)) as { message: string };
    expect(resaved.message).toContain('no change');
    // Editing a row's label keeps the bounds it never showed.
    await editTask(byName as never, 'demo.rows', {
      params: [{ ...(payload['params'] as Record<string, unknown>[])[0], label: '次数' }],
    });
    const after = taskStore.findDraft('demo.rows')!.definition;
    const retries = (after.params as { properties: Record<string, Record<string, unknown>> }).properties['retries']!;
    expect(retries).toMatchObject({ type: 'integer', title: '次数', default: 2, minimum: 0, maximum: 9 });
  });

  it('the row round-trip is LOSSLESS: constraint order, spacing and an empty default all survive (review 2388)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore, store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    // Deliberately awkward: constraints in an order the form does not emit,
    // a bound interleaved between two columns, doubled spacing in the
    // declaration, and an EMPTY default.
    taskStore.saveDraft(`#!/usr/bin/env bash
# xtrape-task: demo.rt
# version: 1.0.0
# risk: low
# servers: *
# param: note  optional  string   free text
# param.note.default:
# param.note.maxLength: 20
# param.note.label: 备注
# xtrape-script:
echo hi
`);
    const prep = await byName().get('updateTask')!.prepare!({ id: 'demo.rt' });
    const payload = prep.initialPayload as Record<string, unknown>;
    // The empty default is visible as an empty cell…
    expect((payload['params'] as Record<string, unknown>[])[0]).toMatchObject({ name: 'note', default: '', label: '备注' });
    // …and an untouched resave changes nothing at all.
    const resaved = (await byName().get('updateTask')!.execute(payload)) as { message: string };
    expect(resaved.message).toContain('no change');
    expect(taskStore.history('demo.rt')).toHaveLength(1);
    // Editing one cell keeps every other declaration byte in place: the
    // empty default, the interleaved bound, and the original ordering.
    await byName().get('updateTask')!.execute({
      ...payload,
      params: [{ ...(payload['params'] as Record<string, unknown>[])[0], label: '注释' }],
    });
    const text = taskStore.findDraft('demo.rt')!.definition.script;
    expect(text).toContain('# param: note  optional  string   free text');
    expect(text).toContain('# param.note.default:');
    expect(text.indexOf('# param.note.default:')).toBeLessThan(text.indexOf('# param.note.maxLength: 20'));
    expect(text).toContain('# param.note.label: 注释');
    // Clearing a cell that HAD a value removes that declaration.
    await editTask(byName as never, 'demo.rt', {
      params: [{ ...(payload['params'] as Record<string, unknown>[])[0], label: '' }],
    });
    expect(taskStore.findDraft('demo.rt')!.definition.script).not.toContain('param.note.label');
  });

  it('RENAMING a parameter carries its hidden bounds with it, and an identity-stripped payload fails closed (review 2389)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore, store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    taskStore.saveDraft(`#!/usr/bin/env bash
# xtrape-task: demo.rename
# version: 1.0.0
# risk: low
# servers: *
# param: retries optional integer How many times
# param.retries.minimum: 0
# param.retries.maximum: 9
# xtrape-script:
echo hi
`);
    const prep = await byName().get('updateTask')!.prepare!({ id: 'demo.rename' });
    const payload = prep.initialPayload as Record<string, unknown>;
    const row = (payload['params'] as Record<string, unknown>[])[0]!;
    // Rename ONLY the name; the bounds have no column, so nothing on screen
    // says they exist — losing them here would be an invisible widening.
    await byName().get('updateTask')!.execute({ ...payload, params: [{ ...row, name: 'attempts' }] });
    // Everything below re-opens Edit first: a save moves the task to a new
    // revision, and a payload from before it is refused by the base-revision
    // CAS (review 2393) — which is itself asserted at the end.
    const after = taskStore.findDraft('demo.rename')!.definition;
    const attempts = (after.params as { properties: Record<string, Record<string, unknown>> }).properties['attempts']!;
    expect(attempts).toMatchObject({ type: 'integer', minimum: 0, maximum: 9 });
    expect((after.params as { properties: Record<string, unknown> }).properties['retries']).toBeUndefined();
    // A payload whose row identity was stripped by hand cannot be told from
    // a new parameter, so it is refused rather than silently dropping the
    // bounds — and the message names both candidates.
    const fresh = (await byName().get('updateTask')!.prepare!({ id: 'demo.rename' })).initialPayload as Record<string, unknown>;
    const freshRow = (fresh['params'] as Record<string, unknown>[])[0]!; // now named `attempts`
    const stripped = { ...freshRow, name: 'renamed' } as Record<string, unknown>;
    delete stripped['originName'];
    await expect(byName().get('updateTask')!.execute({ ...fresh, params: [stripped] })).rejects.toThrow(/cannot tell whether/);
    // The identity is CALLER-WRITABLE, so it is verified, not trusted
    // (review 2392). An identity naming no stored parameter used to slip
    // past the guard above and drop the bounds in silence.
    await expect(
      byName().get('updateTask')!.execute({ ...fresh, params: [{ ...freshRow, originName: 'ghost' }] }),
    ).rejects.toThrow(/unknown identity "ghost"/);
    // And one stored parameter cannot be claimed by two rows, which would
    // copy its hidden bounds onto a second parameter.
    await expect(
      byName().get('updateTask')!.execute({
        ...fresh,
        params: [freshRow, { ...freshRow, name: 'second', originName: 'attempts' }],
      }),
    ).rejects.toThrow(/two parameter rows claim/);
    // A payload from BEFORE the rename is stale: its hidden declarations
    // would overwrite whatever landed in between, so it is refused.
    await expect(
      byName().get('updateTask')!.execute({ ...payload, params: [row] }),
    ).rejects.toThrow(/changed after this form was opened/);
    // Neither refusal landed anything: the draft is still exactly what the
    // successful rename above left — bounds intact, under the new name.
    const untouched = taskStore.findDraft('demo.rename')!.definition;
    expect((untouched.params as { properties: Record<string, Record<string, unknown>> }).properties['attempts']).toMatchObject({ minimum: 0, maximum: 9 });
    expect(taskStore.history('demo.rename')).toHaveLength(2); // the seed and the rename, nothing else
  });

  it('the hidden declarations come from the SERVER, not the payload — a tampered or stale carrier changes nothing (review 2393)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore, store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    taskStore.saveDraft(`#!/usr/bin/env bash
# xtrape-task: demo.auth
# version: 1.0.0
# risk: low
# servers: *
# approval: always_human
# param: retries optional integer How many times
# param.retries.minimum: 0
# param.retries.maximum: 9
# xtrape-script:
echo hi
`);
    const prep = await byName().get('updateTask')!.prepare!({ id: 'demo.auth' });
    const payload = prep.initialPayload as Record<string, unknown>;
    // Emptying the carriers that USED to hold the authority now changes
    // nothing: the submit reads them from the stored revision.
    await byName().get('updateTask')!.execute({
      ...payload,
      paramOriginals: JSON.stringify({ retries: { declaration: 'retries optional integer', constraints: [] } }),
      legacyHeaders: JSON.stringify({}),
    });
    const after = taskStore.findDraft('demo.auth')!.definition;
    expect((after.params as { properties: Record<string, Record<string, unknown>> }).properties['retries']).toMatchObject({ minimum: 0, maximum: 9 });
    expect(after.approvalPolicy).toBe('always_human');

    // A STALE prepare cannot overwrite what landed after it: another edit
    // moves the task on, and the old payload is refused rather than
    // silently reinstating the declarations it was filled with.
    const stale = (await byName().get('updateTask')!.prepare!({ id: 'demo.auth' })).initialPayload as Record<string, unknown>;
    await editTask(byName as never, 'demo.auth', { body: 'echo moved on' });
    await expect(byName().get('updateTask')!.execute({ ...stale, body: 'echo from the stale form' }))
      .rejects.toThrow(/changed after this form was opened/);

    // And a base-revision token this Worker never issued is refused too.
    const current = (await byName().get('updateTask')!.prepare!({ id: 'demo.auth' })).initialPayload as Record<string, unknown>;
    await expect(byName().get('updateTask')!.execute({ ...current, baseRevision: 'rvb1.forged.forged' }))
      .rejects.toThrow(/no valid base-revision token/);
  });

  it('a parameter row is validated cell by cell — no smuggling through a value (#61 C-8)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    const base = { id: 'demo.p', version: '1.0.0', risk: 'low', serverScope: '*', body: 'echo hi' };
    const add = (params: unknown[]) => byName().get('addTask')!.execute({ ...base, params });
    // A newline in a cell would render as extra header lines.
    await expect(add([{ name: 'a', type: 'string', label: 'x\n# risk: critical' }])).rejects.toThrow(/single line/);
    // A name that is not an environment variable name, and a duplicate.
    await expect(add([{ name: '2bad', type: 'string' }])).rejects.toThrow(/usable environment variable name/);
    await expect(add([{ name: 'a', type: 'string' }, { name: 'a', type: 'integer' }])).rejects.toThrow(/declared twice/);
    // A blank row the operator added and left empty is simply ignored.
    const saved = (await add([{ name: 'a', type: 'string' }, { name: '' }])) as { data: { id: string } };
    expect(saved.data.id).toBe('demo.p');
  });

  it('retired headers ride through an edit untouched — an always_human task cannot become automatic (#61)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore, store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    // A legacy task, as a pre-#61 provisioned file would arrive.
    taskStore.saveDraft(`#!/usr/bin/env bash
# xtrape-task: demo.legacy
# version: 1.0.0
# risk: low
# readonly: false
# servers: *
# approval: always_human
# interpreter: sh
echo legacy
`);
    const prep = await byName().get('updateTask')!.prepare!({ id: 'demo.legacy' });
    const payload = prep.initialPayload as Record<string, unknown>;
    // The retired headers are NOT form fields, and they are NOT in the
    // payload either (review 2393): the submit reads them from the stored
    // revision, so emptying a carrier cannot drop an `always_human`.
    expect(payload['approval']).toBeUndefined();
    expect(payload['readonly']).toBeUndefined();
    expect(payload['legacyHeaders']).toBeUndefined();
    expect(payload['baseRevision']).toBeTruthy();
    // Editing the BODY keeps every retired declaration intact — the task
    // stays must-ask, and its interpreter is unchanged.
    await byName().get('updateTask')!.execute({ ...payload, body: 'echo edited' });
    const after = taskStore.findDraft('demo.legacy')!;
    expect(after.definition.approvalPolicy).toBe('always_human');
    expect(after.definition.interpreter).toBe('sh');
    expect(after.definition.script).toContain('echo edited');
  });

  it('the run card previews what THESE arguments will trigger, not just what the task could (#66)', async () => {
    // Review 2409: the card listed every applicable rule, so `/opt` and `/`
    // read identically and the caller learned the answer by being refused.
    const registry = makeRegistry(makeAction({
      id: 'system.clean',
      serverScopes: ['*'],
      script: 'rm -rf "$path"',
      params: { type: 'object', properties: { path: { type: 'string' } }, additionalProperties: false },
    }));
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const paramGuards = new ParamGuardSet([
      { id: 'no-root', when: { param: 'path', equals: '/' }, severity: 'hard', message: '不能清理根目录' },
      { id: 'prod-clean', when: { environment: 'production' }, severity: 'soft', message: '生产环境清理需审批' },
    ]);
    const actions = buildCeActions({ paramGuards, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const run = actions.find((a) => a.name === 'system.clean')!;
    const shown = async (input?: unknown): Promise<string> =>
      String(((await run.prepare!(input)).currentState as { detail: { data: Record<string, unknown> } }).detail.data['paramGuards'] ?? '');

    // No target yet: all that is knowable is which rules apply.
    const blank = await shown();
    expect(blank).toContain('no-root');
    expect(blank).toContain('prod-clean');
    expect(blank).not.toContain('将被拒绝');

    // These arguments will be refused, and the card says so.
    const refused = await shown({ serverId: 'web-01', path: '/' });
    expect(refused).toContain('将被拒绝');
    expect(refused).toContain('no-root');

    // The SAME task with a different argument only needs approval.
    const asks = await shown({ serverId: 'web-01', path: '/opt/cache' });
    expect(asks).toContain('将需要审批');
    // The hard rule did NOT fire for this path — it is not among the hits…
    const [fired, rest] = asks.split('其它可能触发的规则:');
    expect(fired).toContain('prod-clean');
    expect(fired).not.toContain('no-root');
    // …but it is still named below, so a caller can see which value would
    // change the answer.
    expect(rest).toContain('no-root');
  });

  it('Enable shows redline hits on the review card, refuses a HARD one, and records the verdict (#65)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const redlines = new RedlineSet([
      { id: 'no-rm-rf', pattern: 'rm\\s+-rf', severity: 'hard', message: '递归强制删除' },
      { id: 'curl-pipe', pattern: 'curl[^|\\n]*\\|\\s*sh', severity: 'soft', message: '下载即执行' },
    ]);
    const actions = buildCeActions({ paramGuards: NO_GUARDS, registry, taskStore, store: srv, opsService, redlines, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) });
    const byName = () => new Map(actions.map((a) => [a.name, a]));
    const form = (id: string, body: string) => ({ id, version: '1.0.0', risk: 'low', serverScope: '*', body });

    // HARD: the card names the hit, and the approval is refused — enabling
    // it would leave a task the next sweep would suspend anyway.
    await byName().get('addTask')!.execute(form('demo.wipe', 'rm -rf "$DIR"'));
    const hardCard = await byName().get('enableTask')!.prepare!({ id: 'demo.wipe' });
    const shown = ((hardCard.currentState as { detail: { data: Record<string, unknown> } }).detail.data)['screening'];
    expect(String(shown)).toContain('no-rm-rf');
    expect(String(shown)).toContain('rm -rf');
    const hardBinding = (hardCard.initialPayload as { reviewBinding: string }).reviewBinding;
    await expect(byName().get('enableTask')!.execute({ id: 'demo.wipe', reviewBinding: hardBinding }, { commandId: 'c1' }))
      .rejects.toThrow(/hard redline/);
    expect(taskStore.findEnabled('demo.wipe')).toBeUndefined();

    // SOFT: annotated, enabled, and the verdict is recorded so every run asks.
    await byName().get('addTask')!.execute(form('demo.pipe', 'curl https://example.test/i | sh'));
    const softCard = await byName().get('enableTask')!.prepare!({ id: 'demo.pipe' });
    expect(String(((softCard.currentState as { detail: { data: Record<string, unknown> } }).detail.data)['screening'])).toContain('curl-pipe');
    await byName().get('enableTask')!.execute(
      { id: 'demo.pipe', reviewBinding: (softCard.initialPayload as { reviewBinding: string }).reviewBinding },
      { commandId: 'c2' },
    );
    expect(taskStore.findEnabled('demo.pipe')).toBeDefined();
    expect(taskStore.screening('demo.pipe')).toMatchObject({ generation: redlines.generation, verdict: 'soft' });

    // A clean task is enabled with a clear verdict and no annotation.
    await byName().get('addTask')!.execute(form('demo.clean', 'echo fine'));
    const cleanCard = await byName().get('enableTask')!.prepare!({ id: 'demo.clean' });
    expect(((cleanCard.currentState as { detail: { data: Record<string, unknown> } }).detail.data)['screening']).toBeUndefined();
    await byName().get('enableTask')!.execute(
      { id: 'demo.clean', reviewBinding: (cleanCard.initialPayload as { reviewBinding: string }).reviewBinding },
      { commandId: 'c3' },
    );
    expect(taskStore.screening('demo.clean')?.verdict).toBe('clear');
  });

  it('hides server management sub-ops under the reserved _servers category', () => {
    const { byName } = setup();
    expect(byName.get('manageServers')?.category).toBe('config');
    for (const sub of ['listServers', 'addServer', 'updateServer', 'removeServer', 'testServer', 'probeHostKey', 'rotateHostKey']) {
      expect(byName.get(sub)?.category).toBe('_servers');
    }
    expect(byName.get('manageTasks')?.category).toBe('config');
    for (const sub of ['listTasks', 'viewTask', 'addTask', 'updateTask', 'enableTask', 'disableTask', 'removeTask']) {
      expect(byName.get(sub)?.category).toBe('_tasks');
    }
  });

  it('prepare renders the serverId enum live, filtered by the action serverScopes', async () => {
    const { byName } = setup();
    const uptime = await byName.get('system.uptime')!.prepare!();
    const enumIds = ((uptime.inputSchema as { properties: { serverId: { enum?: string[] } } }).properties.serverId.enum) ?? [];
    expect(enumIds.sort()).toEqual(['db-01', 'web-01']);

    const nginx = await byName.get('nginx.reload')!.prepare!();
    const nginxIds = ((nginx.inputSchema as { properties: { serverId: { enum?: string[] } } }).properties.serverId.enum) ?? [];
    expect(nginxIds).toEqual(['web-01']); // web-* scope only
  });

  it('the review binding is UNFORGEABLE and demanded on the Platform surface (reviews 2322/2324)', async () => {
    const { byName, executor } = setup();
    const prepared = await byName.get('system.uptime')!.prepare!();
    // The prepare issues a sealed token (not a bare digest) and requires it
    // on the live schema.
    const binding = (prepared.initialPayload as { reviewBinding?: string }).reviewBinding!;
    expect(binding).toMatch(/^rv1\./);
    expect((prepared.inputSchema as { required: string[] }).required).toContain('reviewBinding');
    const ctx = { commandId: 'cmd_t1' };
    // Valid binding + unchanged file -> runs.
    const ok = await byName.get('system.uptime')!.execute({ serverId: 'web-01', reason: 'check', reviewBinding: binding }, ctx);
    expect(ok).toMatchObject({ success: true, message: 'executed' });
    // DELETING the binding no longer skips the check (review 2324): on the
    // Platform surface (commandId present) a valid token is demanded.
    const before = executor.commands.length;
    const missing = await byName.get('system.uptime')!.execute({ serverId: 'web-01', reason: 'check' }, ctx);
    expect(missing).toMatchObject({ success: false, error: { code: 'REVIEW_BINDING_INVALID' } });
    // ALTERING it fails the MAC — pasting another Worker's digest included.
    const tampered = await byName.get('system.uptime')!.execute({ serverId: 'web-01', reason: 'check', reviewBinding: `${binding}x` }, ctx);
    expect(tampered).toMatchObject({ success: false, error: { code: 'REVIEW_BINDING_INVALID' } });
    expect(executor.commands.length).toBe(before);
    // The callback surface (no commandId) is the operator's own local trust
    // domain with no review card to bind.
    const local = await byName.get('system.uptime')!.execute({ serverId: 'web-01', reason: 'check' });
    expect(local).toMatchObject({ success: true });
  });

  it('a binding sealed by ANOTHER Worker incarnation refuses — Platform fallback is fail-closed (review 2324)', async () => {
    // Two builds = two incarnations = two keys, same Service shape.
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const mk = () => new Map(buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) }).map((a) => [a.name, a]));
    const workerA = mk();
    const workerB = mk();
    const prepared = await workerA.get('system.uptime')!.prepare!();
    const bindingFromA = (prepared.initialPayload as { reviewBinding: string }).reviewBinding;
    // The Platform falls back to Worker B: A's review does not transfer.
    const out = await workerB.get('system.uptime')!.execute({ serverId: 'web-01', reason: 'check', reviewBinding: bindingFromA }, { commandId: 'cmd_t2' });
    expect(out).toMatchObject({ success: false, error: { code: 'REVIEW_BINDING_INVALID' } });
    expect(executor.commands).toEqual([]);
  });

  it('a valid binding over a DIFFERENT script version refuses with SCRIPT_CHANGED (review 2322)', async () => {
    // Inject the incarnation key so the test can seal a stale digest the way
    // the same Worker would have before its task file changed.
    const { createHmac } = await import('node:crypto');
    const key = Buffer.alloc(32, 7);
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const byName = new Map(buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT), reviewKey: key }).map((a) => [a.name, a]));
    const stale = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';
    const mac = createHmac('sha256', key).update(`rv1.${stale}`).digest('base64url');
    const staleBinding = `rv1.${Buffer.from(stale, 'utf8').toString('base64url')}.${mac}`;
    const out = await byName.get('system.uptime')!.execute({ serverId: 'web-01', reason: 'check', reviewBinding: staleBinding }, { commandId: 'cmd_t3' });
    expect(out).toMatchObject({ success: false, error: { code: 'SCRIPT_CHANGED' } });
    expect(executor.commands).toEqual([]);
  });

  it('the run panel says WHAT runs, WHERE it may run, and under WHICH rules (#48)', async () => {
    const { byName } = setup();
    const prepared = await byName.get('system.uptime')!.prepare!();
    const detail = (prepared.currentState as { detail: { title: string; data: Record<string, unknown>; fields: Array<{ key: string; format?: string }> } }).detail;
    // WHAT: the script verbatim plus the digest the audit trail pins.
    expect(detail.data.script).toBe('uptime');
    expect(String(detail.data.scriptDigest)).toMatch(/^sha256:/);
    expect(detail.fields.find((f) => f.key === 'script')?.format).toBe('pre');
    // WHERE: declared scopes and the currently eligible fleet.
    expect(detail.data.serverScopes).toBe('*');
    expect(detail.data.eligibleServers).toBe('db-01, web-01');
    // The review card is headed by the display name when the task has one,
    // with the id kept beside it (review 2370).
    expect(String(detail.title)).toContain('system.uptime');
    // WHICH rules: the effective-risk consequence, in one line (#61).
    expect(String(detail.data.risk)).toContain('low');
    expect(String(detail.data.risk)).toContain('runs automatically');
    // reason is a multiline field now (display-only keyword).
    const schema = prepared.inputSchema as { properties: { reason: { format?: string } } };
    expect(schema.properties.reason.format).toBe('textarea');
  });

  it('an ops task whose scopes match NO admitted server says so instead of degrading to free text (#48)', async () => {
    const registry = makeRegistry(makeAction({ id: 'xtrape.deploy', readonly: false, riskLevel: 'high', serverScopes: ['xtrape-*'], script: 'deploy' }));
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const byName = new Map(buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) }).map((a) => [a.name, a]));
    const prepared = await byName.get('xtrape.deploy')!.prepare!();
    const serverId = (prepared.inputSchema as { properties: { serverId: { enum?: string[]; description: string } } }).properties.serverId;
    // An EMPTY selector, not a free-text field (#48): nothing to pick, next
    // to the description saying why — no false affordance for a value the
    // policy engine refuses regardless.
    expect(serverId.enum).toEqual([]);
    expect(serverId.description).toContain('NO admitted server currently matches');
    const detail = (prepared.currentState as { detail: { data: Record<string, unknown> } }).detail;
    expect(String(detail.data.eligibleServers)).toContain('none');
  });

  it('executes a readonly allow action and returns its result', async () => {
    const { byName } = setup();
    const out = await byName.get('system.uptime')!.execute({ serverId: 'web-01', reason: 'check' });
    expect(out).toMatchObject({ success: true, message: 'executed' });
  });

  it('returns a stable HUMAN_REVIEW_UNAVAILABLE failure (not executed) for a human_review action', async () => {
    const { byName, executor } = setup();
    const out = await byName.get('db.drop')!.execute({ serverId: 'db-01', reason: 'danger' });
    expect(out).toMatchObject({ success: false, error: { code: 'HUMAN_REVIEW_UNAVAILABLE' } });
    expect(executor.commands).toEqual([]);
  });

  it('returns POLICY_DENIED when an ops action is denied by policy (server outside scope)', async () => {
    const { byName, executor } = setup();
    // nginx.reload is scoped to web-*; targeting db-01 → server-scope deny
    const out = await byName.get('nginx.reload')!.execute({ serverId: 'db-01', reason: 'x' });
    expect(out).toMatchObject({ success: false, error: { code: 'POLICY_DENIED' } });
    expect(executor.commands).toEqual([]);
  });

  it('testServer redacts the stored private key content from a probe error', async () => {
    const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfakekeybody\n-----END OPENSSH PRIVATE KEY-----\n';
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'privateKey', privateKey: KEY });
    const opsService = new OpsService({ registry, servers: srv, executors: [new FakeExecutor()], audit: new MemoryAuditLogger() });
    const probe = async () => {
      // A lower layer echoing the credential itself is the unrecoverable case —
      // exact-match redaction must strip it, multiline and all.
      throw new Error(`cannot parse key: ${KEY} (bad format)`);
    };
    const byName = new Map(buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probe, probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) }).map((a) => [a.name, a]));
    const out = (await byName.get('testServer')!.execute({ id: 'web-01' })) as { data: { reachable: boolean; error: string } };
    expect(out.data.reachable).toBe(false);
    expect(out.data.error).not.toContain('AAAAfakekeybody');
    expect(out.data.error).toContain('[redacted-secret]');
  });

  it('testServer on a host key MISMATCH returns the two fingerprints as data plus a one-confirm rotation affordance (#46)', async () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const presented = 'SHA256:Ls6zgAoI+ZpTKLdiiZlRqmB83T2nk73T4Z04PDAvyC8';
    const probe = async () => {
      throw new HostKeyMismatchError('web-01', 'h', 22, TEST_HOST_KEY_FINGERPRINT, presented, srv.get('web-01')!.generation!);
    };
    const byName = new Map(buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService: new OpsService({ registry, servers: srv, executors: [new FakeExecutor()], audit: new MemoryAuditLogger() }), probe, probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) }).map((a) => [a.name, a]));
    const out = (await byName.get('testServer')!.execute({ id: 'web-01' })) as {
      data: { reachable: boolean; hostKeyChanged?: boolean; error?: string; list?: { data: Array<Record<string, unknown>>; rowActions: Array<{ action: string; payload: Record<string, unknown>; lockFields?: string[] }> } };
    };
    expect(out.data.reachable).toBe(false);
    expect(out.data.hostKeyChanged).toBe(true);
    // Both fingerprints ride as DATA, side by side — the judgement between
    // "rotated" and "impersonated" belongs to the operator's eyes.
    expect(out.data.list?.data[0]).toMatchObject({ id: 'web-01', admittedFingerprint: TEST_HOST_KEY_FINGERPRINT, presentedFingerprint: presented });
    // The affordance is ONE confirm away, never automatic — and it is the
    // dedicated fingerprint-only action carrying the FULL binding the
    // mismatch was observed against, all of it LOCKED (reviews 2321/2325):
    // host + effective port + admitted key + record generation.
    const admit = out.data.list?.rowActions[0];
    expect(admit).toMatchObject({ action: 'rotateHostKey', lockFields: ['id', 'expectedHost', 'expectedPort', 'expectedFingerprint', 'expectedGeneration'] });
    expect(admit?.payload).toEqual({ id: '$row.id', expectedHost: '$row.host', expectedPort: '$row.port', expectedFingerprint: '$row.admittedFingerprint', expectedGeneration: '$row.generation', newFingerprint: '$row.presentedFingerprint' });
    expect(out.data.list?.data[0]).toMatchObject({ port: 22 });
    expect(String((out.data.list?.data[0] as { generation?: string }).generation)).toMatch(/^[0-9a-f]{16}$/);
    // The prose message is still there for text-only surfaces.
    expect(out.data.error).toContain('host key verification failed');
    // A NON-mismatch failure keeps the plain sanitized-text shape.
    const plainProbe = async () => {
      throw new Error('connect ETIMEDOUT');
    };
    const byName2 = new Map(buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService: new OpsService({ registry, servers: srv, executors: [new FakeExecutor()], audit: new MemoryAuditLogger() }), probe: plainProbe, probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) }).map((a) => [a.name, a]));
    const out2 = (await byName2.get('testServer')!.execute({ id: 'web-01' })) as { data: { hostKeyChanged?: boolean; error: string } };
    expect(out2.data.hostKeyChanged).toBeUndefined();
    expect(out2.data.error).toContain('ETIMEDOUT');
  });

  it('updateServer prepare never prefills a secret; a blank update preserves the stored key (#42)', async () => {
    const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfakekeybody\n-----END OPENSSH PRIVATE KEY-----\n';
    const { byName, srv } = setup();
    srv.update({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'privateKey', privateKey: KEY });
    const prepared = await byName.get('updateServer')!.prepare!({ id: 'web-01' });
    expect(prepared.initialPayload).not.toHaveProperty('privateKey');
    expect(prepared.initialPayload).not.toHaveProperty('password');
    expect(prepared.initialPayload).not.toHaveProperty('passphrase');
    // The METHOD is prefilled — configuration, not a secret; the form needs it
    // to show the right secret fields.
    expect(prepared.initialPayload).toMatchObject({ authMethod: 'privateKey' });
    // an update that omits the secret keeps the stored key content
    await byName.get('updateServer')!.execute({ id: 'web-01', host: 'h2', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'privateKey' });
    expect(srv.get('web-01')?.privateKey).toBe(KEY);
    expect(srv.get('web-01')?.host).toBe('h2');
  });

  it('manageServers opens AS the server list (a READ, no prepare — linux-ops#93) with row and page affordances', async () => {
    const { byName } = setup();
    expect(byName.get('manageServers')!.prepare).toBeUndefined();
    expect(byName.get('manageTasks')!.prepare).toBeUndefined();
    const prepared = { currentState: (await byName.get('manageServers')!.execute({}, { commandId: 'c0' } as never) as { data: unknown }).data };
    const list = (prepared.currentState as { list: { rowActions: unknown[]; pageActions: unknown[]; data: unknown[] } }).list;
    expect(list.data).toHaveLength(2);
    expect((list.rowActions as Array<{ action: string }>).map((r) => r.action)).toEqual(['updateServer', 'testServer', 'probeHostKey', 'removeServer']);
    expect((list.pageActions as Array<{ action: string }>)[0]?.action).toBe('addServer');
  });

  it('addServer/removeServer mutate the store and never return secrets', async () => {
    const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfakekeybody\n-----END OPENSSH PRIVATE KEY-----\n';
    const { byName, srv } = setup();
    const added = await byName.get('addServer')!.execute({ id: 'cache-01', host: 'h', username: 'ops', environment: 'staging', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'privateKey', privateKey: KEY });
    expect(srv.get('cache-01')).toBeDefined();
    const server = (added as { data: { server: Record<string, unknown> } }).data.server;
    expect(server).toMatchObject({ id: 'cache-01', authMethod: 'privateKey', keyConfigured: true });
    expect(server).not.toHaveProperty('privateKey');

    await byName.get('removeServer')!.execute({ id: 'cache-01' });
    expect(srv.get('cache-01')).toBeUndefined();
  });

  it('accepts an encrypted key or a password, stores the secrets, and shows only presence — never the values', async () => {
    const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfakekeybody\n-----END OPENSSH PRIVATE KEY-----\n';
    const { byName, srv } = setup();
    const added = await byName.get('addServer')!.execute({
      id: 'enc-01', host: 'h', username: 'ops', environment: 'staging',
      hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'privateKeyWithPassphrase', privateKey: KEY, passphrase: 'kp',
    });
    // Stored raw…
    expect(srv.get('enc-01')?.privateKey).toBe(KEY);
    expect(srv.get('enc-01')?.passphrase).toBe('kp');
    // …but the returned projection carries only presence booleans, no values.
    const server = (added as { data: { server: Record<string, unknown> } }).data.server;
    expect(server).toMatchObject({ id: 'enc-01', authMethod: 'privateKeyWithPassphrase', keyConfigured: true, passphraseConfigured: true });
    expect(server).not.toHaveProperty('privateKey');
    expect(server).not.toHaveProperty('passphrase');
    // The list projection is the same: presence, never value — and the
    // password-auth rows from setup() hide their password the same way.
    const listed = (await byName.get('listServers')!.execute({})) as { data: { servers: Array<Record<string, unknown>> } };
    const row = listed.data.servers.find((r) => r.id === 'enc-01')!;
    expect(row).toMatchObject({ keyConfigured: true, passphraseConfigured: true });
    expect(JSON.stringify(listed.data.servers)).not.toContain('AAAAfakekeybody');
    expect(JSON.stringify(listed.data.servers)).not.toContain('kp');
    expect(JSON.stringify(listed.data.servers)).not.toContain('"pw"');
  });

  it('declares the secrets as SENSITIVE write-only fields behind the authMethod choice (RFC-0008, #42)', async () => {
    const { byName } = setup();
    const schema = byName.get('addServer')!.inputSchema as {
      required: string[];
      properties: Record<string, { format?: string; writeOnly?: boolean; 'x-xtrape-sensitive'?: boolean; enum?: string[]; showWhen?: { field: string; equals?: string; in?: string[] } } | undefined>;
    };
    for (const field of ['privateKey', 'password', 'passphrase'] as const) {
      const prop = schema.properties[field];
      expect(prop).toBeDefined();
      // The SECURITY semantics live on the two keywords: never durable on the
      // Platform, never echoed by any projection. `format` is display only —
      // `textarea` marks the multiline entry a pasted PEM key needs.
      expect(prop?.['x-xtrape-sensitive']).toBe(true);
      expect(prop?.writeOnly).toBe(true);
      expect(prop?.format).toBe(field === 'privateKey' ? 'textarea' : 'password');
      expect(schema.required).not.toContain(field);
      // Each secret declares which method it belongs to (the Panel's generic
      // showWhen convention drives the three-way form).
      expect(prop?.showWhen?.field).toBe('authMethod');
    }
    // The method itself is a REQUIRED ordinary enum — configuration, no secret.
    expect(schema.required).toContain('authMethod');
    expect(schema.properties.authMethod?.enum).toEqual(['privateKey', 'privateKeyWithPassphrase', 'password']);
    expect(schema.properties.authMethod?.['x-xtrape-sensitive']).toBeUndefined();
    // The old retirement flags are gone — switching authMethod IS the
    // retirement of the other method's secrets.
    expect(schema.properties).not.toHaveProperty('clearPassword');
    expect(schema.properties).not.toHaveProperty('clearPassphrase');
    expect(schema.properties).not.toHaveProperty('privateKeyPath');
  });

  it('updateServer prepare pre-fills the row values (path shown, no secret content)', async () => {
    const { byName } = setup();
    const prepared = await byName.get('updateServer')!.prepare!({ id: 'web-01' });
    expect(prepared.initialPayload).toMatchObject({ id: 'web-01', host: 'h', username: 'ops', environment: 'development' });
    // The admitted host key IS prefilled — it is public, and an operator editing
    // an unrelated field must not have to retype it.
    expect(prepared.initialPayload).toMatchObject({ hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT });
  });

  it('hostKeyFingerprint is optional at admission (#44): blank admits an accept-new entry, malformed still refuses', async () => {
    const { byName, srv } = setup();
    const schema = byName.get('addServer')!.inputSchema as { required: string[]; properties: Record<string, unknown> };
    expect(schema.required).not.toContain('hostKeyFingerprint');
    expect(schema.properties).toHaveProperty('hostKeyFingerprint');

    const added = await byName.get('addServer')!.execute({ id: 'cache-02', host: 'h', username: 'ops', environment: 'staging', authMethod: 'password', password: 'pw' });
    const server = (added as { data: { server: Record<string, unknown> } }).data.server;
    expect(server).toMatchObject({ id: 'cache-02', hostKeyAdmitted: false, hostKeyAdmittedBy: '' });
    expect(srv.get('cache-02')?.hostKeyFingerprint).toBeUndefined(); // pinned on first use, not invented here
    // Malformed is still refused — optional never means unvalidated.
    await expect(
      byName.get('addServer')!.execute({ id: 'cache-03', host: 'h', username: 'ops', environment: 'staging', authMethod: 'password', password: 'pw', hostKeyFingerprint: 'MD5:aa:bb' }),
    ).rejects.toThrow(/OpenSSH SHA-256 fingerprint/);
  });

  it('probeHostKey hands back the fingerprint the endpoint presents — credential-free, admitting nothing', async () => {
    const { byName, srv } = setup();
    const out = (await byName.get('probeHostKey')!.execute({ host: 'somewhere.local' })) as { data: Record<string, unknown> };
    expect(out.data).toMatchObject({ host: 'somewhere.local', port: 22, fingerprint: TEST_HOST_KEY_FINGERPRINT });
    // Probing changed no fleet state.
    expect(srv.list().map((s) => s.id)).toEqual(['db-01', 'web-01']);
  });

  it('lists the admitted host key so an operator can compare it against the host', async () => {
    const { byName } = setup();
    const prepared = { currentState: (await byName.get('manageServers')!.execute({}, { commandId: 'c0' } as never) as { data: unknown }).data };
    const list = (prepared.currentState as { list: { data: Array<Record<string, unknown>>; columns: Array<{ key: string }> } }).list;
    expect(list.columns.map((c) => c.key)).toContain('hostKeyFingerprint');
    expect(list.data[0]).toMatchObject({ hostKeyAdmitted: true, hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT });
  });
});

describe('what a caller is told when the output ceiling is reached (review 2159)', () => {
  it('never reports a fabricated exit status, and says the remote outcome is unknown', async () => {
    // The executor closes the channel at the ceiling, so nothing observed the
    // task finishing. Reporting `task exited -1` invented a status; a caller
    // deciding whether to retry has to be told the outcome is unknown and that
    // the task may still be running.
    const truncating = {
      name: 'ssh',
      run: (_server: ServerDefinition, invocation: CommandInvocation): Promise<CommandResult> =>
        Promise.resolve({
          command: invocation.command,
          stdout: 'x'.repeat(64),
          stderr: '',
          terminatedBy: 'output_limit' as const,
        }),
    };
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'flood\n' }));
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const opsService = new OpsService({ registry, servers: srv, executors: [truncating], audit: new MemoryAuditLogger() });
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probeHostKey: () => Promise.resolve('SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4'), probe: () => truncating.run(srv.list()[0]!, { command: 'true' }) });
    const action = new Map(actions.map((a) => [a.name, a])).get('system.uptime');

    const result = (await action!.execute({
      serverId: 'web-01',
      reason: 'ceiling',
    })) as { success: boolean; error?: { code: string }; message: string };

    expect(result.success).toBe(false);
    expect(result.error?.code).toBe('OUTPUT_LIMIT_EXCEEDED');
    expect(result.message).toContain('outcome is unknown');
    expect(result.message).not.toContain('exited');
  });
});

describe('what CE hands to the Platform (review 2165/2166)', () => {
  it('carries no argument value in the returned command', async () => {
    // CE forwards the Service's result verbatim, so this is the end of the
    // path a parameter value would take out of this process: caller → task →
    // result → CE → Platform record.
    const SECRET = 'hunter2-not-a-real-token';
    const recording = { commands: [] as string[] };
    const executor = {
      name: 'ssh',
      run: (_server: ServerDefinition, invocation: CommandInvocation): Promise<CommandResult> => {
        recording.commands.push(invocation.command);
        return Promise.resolve({ command: invocation.command, exitCode: 0, stdout: 'done\n', stderr: '' });
      },
    };
    const registry = makeRegistry(
      makeAction({
        id: 'app.deploy',
        readonly: false,
        riskLevel: 'medium',
        serverScopes: ['*'],
        params: { type: 'object', properties: { apiToken: { type: 'string' } }, required: ['apiToken'], additionalProperties: false },
        script: 'deploy --token "$XOPS_apiToken"\n',
      }),
    );
    const srv = store();
    srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const actions = buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probeHostKey: () => Promise.resolve('SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4'), probe: () => executor.run(srv.list()[0]!, { command: 'true' }) });

    const result = (await new Map(actions.map((a) => [a.name, a])).get('app.deploy')!.execute({
      serverId: 'web-01',
      reason: 'ship it',
      apiToken: SECRET,
    })) as { success: boolean; data?: { command?: string } };

    expect(result.success).toBe(true);
    // The executor really did receive the value — the masking is on the way
    // out, not a fixture that never carried it.
    expect(recording.commands[0]).toContain(SECRET);
    expect(result.data?.command).not.toContain(SECRET);
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });
});

describe('what a chooser is told before picking a task (the reminding obligation)', () => {
  it('says up front that a task needs a human, instead of only refusing later', () => {
    // A task an operator approved is not gated here — it is executed as
    // written. What this Widget owes is that whoever picks it can see what it
    // is: a task marked `always_human` used to be indistinguishable from any
    // other until you tried it and were refused.
    const registry = makeRegistry(
      makeAction({ id: 'xtrape.deploy', readonly: false, riskLevel: 'high', approvalPolicy: 'always_human', serverScopes: ['*'], script: 'deploy\n' }),
      makeAction({ id: 'system.uptime', readonly: true, riskLevel: 'low', serverScopes: ['*'], script: 'uptime\n' }),
    );
    const srv = store();
    const opsService = new OpsService({ registry, servers: srv, executors: [new FakeExecutor()], audit: new MemoryAuditLogger() });
    const byName = new Map(
      buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probeHostKey: () => Promise.resolve('SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4'), probe: () => Promise.resolve({ command: 'true', exitCode: 0, stdout: '', stderr: '' }) }).map((a) => [a.name, a]),
    );

    expect(byName.get('xtrape.deploy')?.description).toContain('requires human approval');
    expect(byName.get('xtrape.deploy')?.description).toContain('risk: high');
    // The retired readonly/mutating vocabulary is gone from the line (#61):
    // what a chooser needs is the risk and its consequence.
    expect(byName.get('xtrape.deploy')?.description).not.toContain('mutating');
    expect(byName.get('system.uptime')?.description).toContain('risk: low');
    expect(byName.get('system.uptime')?.description).not.toContain('approval');
  });
});

describe('the catalogue mirrors policy.ts, in policy.ts order (reviews 2167/2176)', () => {
  const catalogue = () => {
    const registry = makeRegistry(
      makeAction({ id: 'db.drop', readonly: false, riskLevel: 'critical', approvalPolicy: 'policy', serverScopes: ['*'], script: 'dropdb\n' }),
      makeAction({ id: 'app.restart', readonly: false, riskLevel: 'high', approvalPolicy: 'policy', serverScopes: ['*'], script: 'restart\n' }),
      makeAction({ id: 'nginx.reload', readonly: false, riskLevel: 'medium', approvalPolicy: 'policy', serverScopes: ['*'], script: 'reload\n' }),
      makeAction({ id: 'system.uptime', readonly: true, riskLevel: 'low', approvalPolicy: 'policy', serverScopes: ['*'], script: 'uptime\n' }),
      makeAction({ id: 'never.run', readonly: false, riskLevel: 'critical', approvalPolicy: 'forbidden', serverScopes: ['*'], script: 'no\n' }),
    );
    const srv = store();
    const opsService = new OpsService({ registry, servers: srv, executors: [new FakeExecutor()], audit: new MemoryAuditLogger() });
    return new Map(
      buildCeActions({ paramGuards: NO_GUARDS, redlines: NO_REDLINES, registry, taskStore: tstore(), store: srv, opsService, probeHostKey: () => Promise.resolve('SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4'), probe: () => Promise.resolve({ command: 'true', exitCode: 0, stdout: '', stderr: '' }) }).map((a) => [a.name, a]),
    );
  };

  it('warns unconditionally for the rules that hold unconditionally', () => {
    // policy.ts holds high/critical risk by the `risk-level` rule. A catalogue
    // that only warned on `always_human` under-warned exactly the tasks that
    // most need it.
    const byName = catalogue();
    expect(byName.get('db.drop')?.description).toContain('requires human approval');
    expect(byName.get('app.restart')?.description).toContain('requires human approval');
  });

  it('states the production hold as the condition it is, rather than staying silent', () => {
    // `production-write` also holds for a human, but only on a production
    // server — and the target is chosen per call while this line is one static
    // sentence per task. Silence would under-warn; an unconditional claim
    // would over-warn.
    const byName = catalogue();
    // medium risk: automatic here, raised a notch by production or MCP (#61).
    expect(byName.get('nginx.reload')?.description).toContain('requires human approval on a production server or over MCP');
    // A low-risk task is never held by that rule.
    expect(byName.get('system.uptime')?.description).not.toContain('requires human approval');
  });

  it('lets the higher-priority denial win: a forbidden task is not also "approvable"', () => {
    // `forbidden` is a hard DENY and comes first in policy.ts. Showing both
    // notices told a chooser to go find an approver for something nobody can
    // approve.
    const forbidden = catalogue().get('never.run')?.description ?? '';
    expect(forbidden).toContain('not runnable through this surface');
    expect(forbidden).not.toContain('requires human approval');
  });
});

/**
 * runtime-platform/13 v0.5 (linux-ops#94): under a governed REVIEW the prepare
 * handlers answer through the Connector's alias WITH `filterResources` — the
 * §4.3 candidate exchange — and shape `next.inputSchema` as a narrowing of the
 * ADMITTED record. The legacy /prepare door (no exchange) is unchanged.
 */
describe('governed review through the prepare alias (13 v0.5 §4.3 / §5.2; linux-ops#94)', () => {
  const filterTo = (admitted: string[]) => ({ filterResources: async (candidates: string[]) => candidates.filter((c) => admitted.includes(c)) });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  type Loose = Record<string, any>;
  type Prep = (i?: unknown, ctx?: unknown) => Promise<{ inputSchema?: Loose; initialPayload?: Record<string, unknown>; currentState?: Loose }> | { inputSchema?: Loose; initialPayload?: Record<string, unknown>; currentState?: Loose };

  it('a task run offers ONLY the servers the exchange returned, on the admitted projection (no rich keywords), and the card lists exactly those', async () => {
    const { byName } = setup();
    const prepare = byName.get('system.uptime')!.prepare as unknown as Prep;
    const next = await prepare({}, filterTo(['db-01']));
    expect(next.inputSchema!.properties.serverId.enum).toEqual(['db-01']);
    // The projection: type + title/description only — the rich keywords the admitted record does not carry never appear.
    for (const prop of Object.values(next.inputSchema!.properties as Record<string, Record<string, unknown>>)) {
      for (const k of Object.keys(prop)) expect(['type', 'title', 'description', 'enum', 'readOnly', 'default']).toContain(k);
    }
    // linux-ops#96 (13 §5.2 mutable keywords): the sealed binding stays locked, defaults ride along, `format` never does.
    expect(next.inputSchema!.properties.reviewBinding).toMatchObject({ readOnly: true });
    expect(next.inputSchema!.properties.reviewBinding.format).toBeUndefined();
    expect(next.inputSchema!.properties.dryRun.default).toBe(false);
    expect(next.inputSchema!.additionalProperties).toBe(false);
    expect(typeof next.initialPayload!.reviewBinding).toBe('string');
    expect(next.currentState!.detail.data.eligibleServers).toBe('db-01');
    // Legacy door: no exchange, the rich local schema as before.
    const legacy = await prepare({});
    expect([...legacy.inputSchema!.properties.serverId.enum].sort()).toEqual(['db-01', 'web-01']);
    expect(legacy.inputSchema!.properties.reviewBinding.format).toBe('hidden');
  });

  it('none authorized is an explicit refusal, never an empty picker (arch/16 §8.1)', async () => {
    const { byName } = setup();
    const prepare = byName.get('system.uptime')!.prepare as unknown as Prep;
    await expect(Promise.resolve(prepare({}, filterTo([])))).rejects.toThrow(/no admitted server is authorized/);
  });

  it('addTask / updateTask run NO exchange (serverScope is an expression, review 3209) and narrow without an enum; updateServer / enableTask narrow without an enum; the by-id reviews render a card', async () => {
    const { byName } = setup();
    let exchanged = 0;
    const spy = { filterResources: async (c: string[]) => { exchanged += 1; return c; } };
    const add = await (byName.get('addTask')!.prepare as unknown as Prep)({}, spy);
    expect(add.inputSchema!.properties.serverScope.enum).toBeUndefined();
    expect(add.inputSchema!.properties.customScope.showWhen).toBeUndefined();
    const server = await (byName.get('updateServer')!.prepare as unknown as Prep)({ id: 'web-01' }, spy);
    expect(server.inputSchema!.properties.authMethod.enum).toBeUndefined();
    expect(server.initialPayload).toMatchObject({ id: 'web-01' });
    // The server card: the public view, no secret material.
    expect(server.currentState!.detail.title).toContain('web-01');
    expect(JSON.stringify(server.currentState)).not.toContain('pw');
    expect(server.currentState!.detail.data).toMatchObject({ id: 'web-01', host: 'h', username: 'ops' });
    expect(exchanged).toBe(0);
    const enable = await (byName.get('enableTask')!.prepare as unknown as Prep)({ id: 'nothing.here' }, filterTo([]));
    expect(Object.keys(enable.inputSchema!.properties)).toEqual(['id', 'reviewBinding']);
    expect(enable.inputSchema!.properties.reviewBinding.format).toBeUndefined();
  });
});
