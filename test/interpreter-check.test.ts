import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { interpreterAvailability, interpreterName, interpreterNotices } from '../src/interpreter-check.js';
import { normalizeShells, probeTargetSnapshot, ServerStore } from '../src/servers.js';
import { OpsService } from '../src/service.js';
import { MemoryAuditLogger } from '../src/audit.js';
import { buildCeActions } from '../src/ce-actions.js';
import { TaskDb } from '../src/task-db.js';
import { RedlineSet } from '../src/redlines.js';
import { ParamGuardSet } from '../src/param-guards.js';
import { FakeExecutor, makeAction, makeRegistry, TEST_HOST_KEY_FINGERPRINT } from './helpers.js';

/**
 * #69 — the target's interpreters are a fact the server record can carry, so
 * "the task wants bash / the target has no bash" is said at REVIEW time and
 * refused BEFORE dispatch, with its own rule, instead of an exit 127 after a
 * person approved. Unknown is not "none": undeclared records never block.
 */

const dirs: string[] = [];
function store(): ServerStore {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-shells-'));
  dirs.push(dir);
  return new ServerStore(join(dir, 'servers.json'));
}
function tstore(): TaskDb {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-shells-tasks-'));
  dirs.push(dir);
  return new TaskDb(join(dir, 'tasks.db'));
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const base = { host: 'h', username: 'ops', environment: 'development' as const, hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' };

describe('interpreter availability (#69)', () => {
  it('compares the shebang command name against what the target has; unknown when nothing is recorded', () => {
    expect(interpreterName('/usr/bin/python3')).toBe('python3');
    expect(interpreterAvailability('bash', {})).toEqual({ state: 'unknown', interpreter: 'bash' });
    expect(interpreterAvailability('bash', { shells: ['sh', 'ash'], shellsSource: 'probed', shellsProbedAt: 't1' })).toMatchObject({ state: 'missing', interpreter: 'bash', known: ['sh', 'ash'], source: 'probed', probedAt: 't1' });
    expect(interpreterAvailability('/bin/sh', { shells: ['sh'] })).toEqual({ state: 'ok', interpreter: 'sh' });
    // An explicit EMPTY declaration is "none of them", not unknown.
    expect(interpreterAvailability('sh', { shells: [] })).toMatchObject({ state: 'missing', known: [] });
    const n = interpreterNotices('bash', [{ id: 'a', shells: ['sh'] }, { id: 'b' }, { id: 'c', shells: ['bash'] }]);
    expect(n.missing).toEqual(['a']);
    expect(n.unknown).toEqual(['b']);
    expect(n.lines[0]).toContain('NO bash');
    expect(n.lines[1]).toContain('not probed');
  });

  it('normalizeShells: trims, dedupes, keeps order, refuses non-names; empty input is unknown', () => {
    expect(normalizeShells(undefined)).toBeUndefined();
    expect(normalizeShells(['bash', ' sh ', 'bash', ''])).toEqual(['bash', 'sh']);
    expect(normalizeShells('sh, bash python3')).toEqual(['sh', 'bash', 'python3']);
    expect(() => normalizeShells(['/bin/sh'])).toThrow(/plain interpreter command name/);
  });

  it('the store: a declaration is kept on unrelated edits, a probe overrides it with provenance, both survive a reload', () => {
    const s = store();
    s.add({ id: 'web-01', ...base, shells: ['bash', 'sh'] });
    expect(s.get('web-01')).toMatchObject({ shells: ['bash', 'sh'], shellsSource: 'declared' });
    // Editing the port says nothing about interpreters: keeps them.
    s.update({ id: 'web-01', ...base, port: 2222 });
    expect(s.get('web-01')).toMatchObject({ port: 2222, shells: ['bash', 'sh'], shellsSource: 'declared' });
    // A CONFIRMED probe observation wins and is stamped — bound to the
    // ProbeTargetSnapshot it was made against (host, port, USER, admitted
    // host key, generation; reviews 2480/2481): anything that changes what
    // `command -v` sees or which host answers refuses the stale confirmation.
    const snap = () => probeTargetSnapshot(s.get('web-01')!);
    const obs = { shells: ['sh', 'ash'], probedAt: '2026-08-18T00:00:00.000Z' };
    expect(() => s.recordProbedShells('web-01', obs, { ...snap(), generation: 'stale-gen' })).toThrow(/changed since the interpreters were probed/);
    // REHOST between probe and confirmation: same generation, other host → refused.
    const t0 = snap();
    s.update({ id: 'web-01', ...base, host: 'other-host', port: 2222 });
    expect(s.get('web-01')!.generation).toBe(t0.generation);
    expect(() => s.recordProbedShells('web-01', obs, t0)).toThrow(/changed since/);
    // USER change between probe and confirmation (review 2481): what
    // `command -v` saw as `ops` says nothing about `restricted` → refused.
    const t1 = snap();
    s.update({ id: 'web-01', ...base, host: 'other-host', port: 2222, username: 'restricted' });
    expect(() => s.recordProbedShells('web-01', obs, t1)).toThrow(/changed since/);
    // Admitted host key change → refused too (a different endpoint answered).
    const t2 = snap();
    s.rotateHostKey('web-01', { host: 'other-host', port: 2222, fingerprint: TEST_HOST_KEY_FINGERPRINT, generation: t2.generation }, 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
    expect(() => s.recordProbedShells('web-01', obs, t2)).toThrow(/changed since/);
    expect(s.recordProbedShells('web-01', obs, snap())).toMatchObject({ shells: ['sh', 'ash'], shellsSource: 'probed', shellsProbedAt: '2026-08-18T00:00:00.000Z' });
    expect(() => s.recordProbedShells('nope', obs, snap())).toThrow(/unknown server/);
    // A declaration cannot override an observation (probe wins; no silent
    // probed → declared laundering) — editing something else still keeps it.
    expect(() => s.update({ id: 'web-01', ...base, host: 'other-host', port: 2222, username: 'restricted', shells: ['bash'] })).toThrow(/cannot override an observation/);
    s.update({ id: 'web-01', ...base, host: 'other-host', port: 2223, username: 'restricted' });
    expect(s.get('web-01')).toMatchObject({ port: 2223, shells: ['sh', 'ash'], shellsSource: 'probed' });
    // remove + re-add is a NEW record: an observation made against the old one refuses.
    const oldSnap = snap();
    s.remove('web-01');
    s.add({ id: 'web-01', ...base, host: 'other-host', port: 2223, username: 'restricted' });
    expect(() => s.recordProbedShells('web-01', obs, oldSnap)).toThrow(/changed since/);
    s.recordProbedShells('web-01', obs, snap());
    // Reload from disk keeps the probe provenance.
    const again = new ServerStore(join(dirs[dirs.length - 1]!, 'servers.json'));
    expect(again.get('web-01')).toMatchObject({ shells: ['sh', 'ash'], shellsSource: 'probed', shellsProbedAt: '2026-08-18T00:00:00.000Z' });
    // The public projection carries what a person needs to see.
    // (publicServer is exercised through manageServers below.)
  });

  it('OpsService refuses BEFORE dispatch with its own rule when the target is known to lack the interpreter; unknown does not block', async () => {
    const registry = makeRegistry(makeAction({ id: 'needs.bash', interpreter: 'bash', serverScopes: ['*'], script: 'echo hi' }));
    const srv = store();
    srv.add({ id: 'alpine', ...base, shells: ['sh', 'ash'] });
    srv.add({ id: 'unknown-box', ...base });
    srv.add({ id: 'debian', ...base, shells: ['sh', 'bash'] });
    const executor = new FakeExecutor();
    const audit = new MemoryAuditLogger();
    const ops = new OpsService({ registry, servers: srv, executors: [executor], audit });
    const ctx = { surface: 'platform' as const, controlPlaneAvailable: true };
    const denied = await ops.execute({ serverId: 'alpine', actionId: 'needs.bash', args: {}, reason: 'x' }, ctx);
    expect(denied).toMatchObject({ status: 'denied', rule: 'interpreter-unavailable' });
    expect((denied as { reason: string }).reason).toContain('no "bash"');
    expect(executor.commands).toHaveLength(0); // nothing left this process
    // The audit says WHY, distinguishably from a script's own 127.
    expect(audit.entries.at(-1)).toMatchObject({ event: 'decision', decision: 'deny', policyRule: 'interpreter-unavailable' });
    expect(await ops.execute({ serverId: 'unknown-box', actionId: 'needs.bash', args: {}, reason: 'x' }, ctx)).toMatchObject({ status: 'executed' });
    // Through the CE surface the refusal carries its OWN code — not policy.
    const acts = new Map(buildCeActions({ registry, store: srv, opsService: ops, taskStore: tstore(), redlines: new RedlineSet([]), paramGuards: new ParamGuardSet([]), probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT) }).map((a) => [a.name, a]));
    const viaCe = (await acts.get('needs.bash')!.execute({ serverId: 'alpine', reason: 'x' })) as { success: boolean; error: { code: string } };
    expect(viaCe).toMatchObject({ success: false, error: { code: 'NOT_EXECUTABLE' } });
    expect(await ops.execute({ serverId: 'debian', actionId: 'needs.bash', args: {}, reason: 'x' }, ctx)).toMatchObject({ status: 'executed' });
  });

  it('ONE Test on an accept-new (no host key) entry pins the key AND yields a recordable observation (review 2483)', async () => {
    const registry = makeRegistry(makeAction({ id: 'needs.bash', interpreter: 'bash', serverScopes: ['*'], script: 'echo hi' }));
    const srv = store();
    // No hostKeyFingerprint: first use pins whatever the endpoint presents.
    srv.add({ id: 'tofu', host: 'h', username: 'ops', environment: 'development', authMethod: 'password', password: 'pw' });
    expect(srv.get('tofu')!.hostKeyFingerprint).toBeUndefined();
    // An executor that behaves like SshExecutor on first use: with no
    // admitted key it PINS through the store's CAS (record identity), and it
    // refuses if handed a stale record object — the exact trap of 2483.
    const pinning = {
      run: async (server: import('../src/types.js').ServerDefinition, inv: { command: string }) => {
        if (!server.hostKeyFingerprint) srv.pinHostKey(server, TEST_HOST_KEY_FINGERPRINT); // throws on a stale snapshot
        return { command: inv.command, exitCode: 0, stdout: inv.command === 'true' ? '' : 'sh\nash\n', stderr: '' };
      },
    };
    const opsService = new OpsService({ registry, servers: srv, executors: [new FakeExecutor()], audit: new MemoryAuditLogger() });
    const actions = new Map(
      buildCeActions({
        registry, store: srv, opsService, taskStore: tstore(), redlines: new RedlineSet([]), paramGuards: new ParamGuardSet([]),
        probe: (s) => pinning.run(s, { command: 'true' }),
        probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT),
        probeShells: async (s) => (await pinning.run(s, { command: 'command -v …' })).stdout.split('\n').filter(Boolean),
      }).map((a) => [a.name, a]),
    );
    const tested = (await actions.get('testServer')!.execute({ id: 'tofu' })) as { data: Record<string, unknown> & { list?: { data: Array<Record<string, string>> } } };
    // Same call: reachable, key pinned, interpreters observed, binding offered.
    expect(tested.data).toMatchObject({ reachable: true, shells: ['sh', 'ash'] });
    expect(tested.data.shellsProbe).toBeUndefined();
    expect(srv.get('tofu')).toMatchObject({ hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, hostKeyAdmittedBy: 'first-use' });
    const row = tested.data.list!.data[0]!;
    // …and that binding confirms directly (it was sealed against the PINNED record).
    await actions.get('recordProbedShells')!.execute({ id: 'tofu', probeBinding: row.probeBinding });
    expect(srv.get('tofu')).toMatchObject({ shells: ['sh', 'ash'], shellsSource: 'probed' });
  });

  it('a record changed WHILE the interpreter probe was in flight cannot receive that observation (review 2484)', async () => {
    const registry = makeRegistry(makeAction({ id: 'needs.bash', interpreter: 'bash', serverScopes: ['*'], script: 'echo hi' }));
    const srv = store();
    srv.add({ id: 'racy', ...base });
    // Deterministic interleaving: the shells probe PAUSES on a promise; the
    // test rehosts + changes the SSH user meanwhile; then the probe resumes
    // and answers what it saw on the OLD target.
    let release!: () => void;
    const paused = new Promise<void>((r) => { release = r; });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const actions = new Map(
      buildCeActions({
        registry, store: srv, opsService, taskStore: tstore(), redlines: new RedlineSet([]), paramGuards: new ParamGuardSet([]),
        probe: (s) => executor.run(s, { command: 'true' }),
        probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT),
        probeShells: async () => { await paused; return ['sh', 'ash']; },
      }).map((a) => [a.name, a]),
    );
    const inFlight = actions.get('testServer')!.execute({ id: 'racy' }) as Promise<{ data: { list: { data: Array<Record<string, string>> } } }>;
    await new Promise((r) => setTimeout(r, 10)); // the probe is now waiting
    srv.update({ id: 'racy', ...base, host: 'other-host', username: 'restricted' });
    release();
    const tested = await inFlight;
    // The observation was sealed against the target it was MADE on (A)…
    const row = tested.data.list.data[0]!;
    expect(row.probeBinding).toMatch(/^prb1\./);
    // …so it cannot be recorded onto B: the store's CAS refuses.
    await expect(actions.get('recordProbedShells')!.execute({ id: 'racy', probeBinding: row.probeBinding })).rejects.toThrow(/changed since/);
    expect(srv.get('racy')!.shells).toBeUndefined();
  });

  it('testServer probes the interpreters on a reachable target and records them; the run card and the enable card name the mismatch', async () => {
    const registry = makeRegistry(makeAction({ id: 'needs.bash', interpreter: 'bash', serverScopes: ['*'], script: 'echo hi' }));
    const srv = store();
    srv.add({ id: 'alpine', ...base });
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const actions = new Map(
      buildCeActions({
        registry,
        store: srv,
        opsService,
        taskStore,
        redlines: new RedlineSet([]),
        paramGuards: new ParamGuardSet([]),
        probe: (s) => executor.run(s, { command: 'true' }),
        probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT),
        probeShells: () => Promise.resolve(['sh', 'ash']),
      }).map((a) => [a.name, a]),
    );
    // Before the probe: the run card says unprobed.
    const before = (await actions.get('needs.bash')!.prepare!({})) as { currentState: { detail: { data: Record<string, string> } } };
    expect(before.currentState.detail.data.interpreter).toContain('unprobed on alpine');
    expect(before.currentState.detail.data.interpreterAvailability).toContain('not probed');
    // Test OBSERVES and offers the confirmation; it writes nothing (review 2475).
    const tested = (await actions.get('testServer')!.execute({ id: 'alpine' })) as { data: Record<string, unknown> & { list: { rowActions: Array<{ action: string; lockFields: string[] }>; data: Array<Record<string, string>> } } };
    expect(tested.data).toMatchObject({ reachable: true, shells: ['sh', 'ash'] });
    expect(srv.get('alpine')!.shells).toBeUndefined();
    expect(tested.data.list.rowActions[0]).toMatchObject({ action: 'recordProbedShells', lockFields: ['id', 'probeBinding'] });
    const row = tested.data.list.data[0]!;
    expect(row.probeBinding).toMatch(/^prb1\./);
    // Nobody can mint "probed" without the seal, or with a tampered one.
    await expect(actions.get('recordProbedShells')!.execute({ id: 'alpine', probeBinding: 'prb1.forged.x' })).rejects.toThrow(/no valid probe binding/);
    await expect(actions.get('recordProbedShells')!.execute({ id: 'other', probeBinding: row.probeBinding })).rejects.toThrow(/observed on "alpine"/);
    // The person confirms — the sealed observation is recorded AS OBSERVED.
    await actions.get('recordProbedShells')!.execute({ id: row.id, probeBinding: row.probeBinding });
    expect(srv.get('alpine')).toMatchObject({ shells: ['sh', 'ash'], shellsSource: 'probed', shellsProbedAt: row.probedAt });
    // A stale confirmation is refused: rehosted, or a different SSH USER
    // (the probe ran as `ops`; `restricted` may see other interpreters).
    const again = (await actions.get('testServer')!.execute({ id: 'alpine' })) as { data: { list: { data: Array<Record<string, string>> } } };
    await actions.get('updateServer')!.execute({ id: 'alpine', host: 'h', username: 'restricted', environment: 'development', authMethod: 'password' });
    await expect(actions.get('recordProbedShells')!.execute({ id: 'alpine', probeBinding: again.data.list.data[0]!.probeBinding })).rejects.toThrow(/changed since/);
    const again2 = (await actions.get('testServer')!.execute({ id: 'alpine' })) as { data: { list: { data: Array<Record<string, string>> } } };
    await actions.get('updateServer')!.execute({ id: 'alpine', host: 'h2', username: 'restricted', environment: 'development', authMethod: 'password' });
    await expect(actions.get('recordProbedShells')!.execute({ id: 'alpine', probeBinding: again2.data.list.data[0]!.probeBinding })).rejects.toThrow(/changed since/);
    // After: the run card says MISSING, and the fleet table shows the probe.
    const after = (await actions.get('needs.bash')!.prepare!({})) as { currentState: { detail: { data: Record<string, string> } } };
    expect(after.currentState.detail.data.interpreter).toContain('MISSING on alpine');
    expect(after.currentState.detail.data.interpreterAvailability).toContain('alpine: NO bash');
    const fleet = (await actions.get('manageServers')!.execute({}, { commandId: 'c0' } as never)) as { data: { list: { data: Array<Record<string, unknown>> } } };
    expect(fleet.data.list.data[0]).toMatchObject({ id: 'alpine', shells: 'sh, ash', shellsSource: 'probed' });
    // The enable card for a draft that wants bash names it too.
    await actions.get('addTask')!.execute({ id: 'demo.bash', version: '1.0.0', risk: 'low', serverScope: '*', body: 'echo hi' }, { commandId: 'c1' });
    const enable = (await actions.get('enableTask')!.prepare!({ id: 'demo.bash' })) as { currentState: { detail: { data: Record<string, string> } } };
    expect(enable.currentState.detail.data.interpreterAvailability).toContain('alpine: NO bash');
    // A declared list cannot override the probe (probe wins) — but on a
    // fresh record a declaration is accepted and shown as declared.
    await expect(actions.get('updateServer')!.execute({ id: 'alpine', host: 'h2', username: 'ops', environment: 'development', authMethod: 'password', shells: ['sh', 'ash', 'bash'] })).rejects.toThrow(/cannot override an observation/);
    await actions.get('addServer')!.execute({ id: 'debian', host: 'd', username: 'ops', environment: 'development', authMethod: 'password', password: 'pw', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, shells: ['sh', 'bash'] });
    expect(srv.get('debian')).toMatchObject({ shells: ['sh', 'bash'], shellsSource: 'declared' });
    const ok = (await actions.get('needs.bash')!.prepare!({})) as { currentState: { detail: { data: Record<string, string> } } };
    expect(ok.currentState.detail.data.interpreterAvailability).toContain('debian: has bash');
    expect(ok.currentState.detail.data.interpreterAvailability).toContain('alpine: NO bash');
  });
});
