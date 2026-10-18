/**
 * Widget Design Conventions §5 (xtrape-docs products/service/01, owner
 * 2026-09-06; linux-ops#92): an AI host sees ONLY the admitted input schema
 * and a description; the Panel labels a field `title ?? key`. Every governed
 * Action — static catalog AND every schema a prepare hands back — carries a
 * root title + description and a title + description on every field.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildCeActions } from '../src/ce-actions.js';
import { STATIC_CHECKPOINT_ROWS, checkpointRefFor, MGMT_CHECKPOINT_VERSION } from '../src/checkpoints.js';
import { OpsService } from '../src/service.js';
import { ServerStore } from '../src/servers.js';
import { TaskDb } from '../src/task-db.js';
import { RedlineSet } from '../src/redlines.js';
import { ParamGuardSet } from '../src/param-guards.js';
import { MemoryAuditLogger } from '../src/audit.js';
import { registrationInputSchemaFor, withFieldTitles } from '../src/schema-titles.js';
import { FakeExecutor, makeAction, makeRegistry, TEST_HOST_KEY_FINGERPRINT } from './helpers.js';

const dirs: string[] = [];
afterEach(() => { while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true }); });

function undescribed(schema: Record<string, unknown>, path = ''): string[] {
  const out: string[] = [];
  const props = schema['properties'] as Record<string, Record<string, unknown>> | undefined;
  for (const [k, v] of Object.entries(props ?? {})) {
    if (typeof v['description'] !== 'string' || (v['description'] as string).trim() === '') out.push(`${path}${k} (no description)`);
    if (typeof v['title'] !== 'string' || (v['title'] as string).trim() === '') out.push(`${path}${k} (no title)`);
    if (v['type'] === 'object') out.push(...undescribed(v, `${path}${k}.`));
    const items = v['items'] as Record<string, unknown> | undefined;
    if (items && items['type'] === 'object') out.push(...undescribed(items, `${path}${k}[].`));
  }
  return out;
}
const rootDescribed = (schema: Record<string, unknown>): void => {
  expect(typeof schema['title']).toBe('string');
  expect(typeof schema['description']).toBe('string');
  expect((schema['description'] as string).trim()).not.toBe('');
  expect(undescribed(schema)).toEqual([]);
};

function setup() {
  const registry = makeRegistry(
    makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }),
    makeAction({ id: 'nginx.reload', readonly: false, riskLevel: 'medium', serverScopes: ['web-*'], script: 'systemctl reload nginx' }),
  );
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-desc-')); dirs.push(dir);
  const srv = new ServerStore(join(dir, 'servers.json'));
  srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
  const taskStore = new TaskDb(join(dir, 'tasks.db'));
  const executor = new FakeExecutor();
  const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
  const actions = buildCeActions({ paramGuards: new ParamGuardSet([]), redlines: new RedlineSet([]), registry, taskStore, store: srv, opsService, probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT), probe: (s) => executor.run(s, { command: 'true' }) });
  return { actions, byName: new Map(actions.map((a) => [a.name, a] as const)) };
}

describe('governed Actions are self-describing to an AI host (conventions §5)', () => {
  it('covers every static management row', () => {
    const { byName } = setup();
    expect(STATIC_CHECKPOINT_ROWS.map((r) => r.action).filter((n) => !byName.has(n))).toEqual([]);
  });

  it('every catalog Action: root title + description, every field titled and described (ops tasks included)', () => {
    const { actions } = setup();
    for (const a of actions) rootDescribed(a.inputSchema as Record<string, unknown>);
  });

  it('the schema a Checkpoint registers with is the described catalog entry — ops tasks included (found live: task rows registered bare opsInputSchema)', () => {
    const { actions } = setup();
    for (const name of ['system.uptime', 'nginx.reload', 'manageServers', 'listTasks']) {
      const s = registrationInputSchemaFor(actions, name);
      expect(s, name).toBeDefined();
      rootDescribed(s!);
    }
    expect(registrationInputSchemaFor(actions, 'no.such')).toBeUndefined();
  });

  it('every prepare-issued schema is described the same way (updateServer / addTask / updateTask / enableTask / ops prepare)', async () => {
    const { byName } = setup();
    for (const [name, input] of [['updateServer', { id: 'web-01' }], ['addTask', undefined], ['system.uptime', { serverId: 'web-01' }]] as const) {
      const r = await byName.get(name)!.prepare!(input as never);
      if (r.inputSchema) rootDescribed(r.inputSchema);
      else expect(name).toBe('addTask-without-schema-is-unexpected');
    }
  });

  it('fields the Panel showed as key abbreviations now carry full-word titles; existing titles are kept', () => {
    const s = withFieldTitles({ type: 'object', properties: { serverId: { type: 'string', description: 'x' }, shells: { type: 'array', title: '可用解释器', items: { type: 'string' } }, id: { type: 'string' } } }, 'server');
    const p = s['properties'] as Record<string, Record<string, unknown>>;
    expect(p['serverId']!['title']).toBe('Target server');
    expect(p['shells']!['title']).toBe('可用解释器');
    expect(p['id']!['title']).toBe('Server ID');
    expect(typeof p['id']!['description']).toBe('string');
  });

  it('an ambiguous key names the entity of ITS cluster (review 3177): `id` is "Server ID" on _servers and "Task ID" on _tasks — catalog, enableTask/updateTask prepare schemas, and the admitted registration schema alike', async () => {
    const { actions, byName } = setup();
    const idTitle = (s: Record<string, unknown> | undefined) => ((s?.['properties'] as Record<string, Record<string, unknown>>)['id']?.['title']);
    for (const n of ['removeServer', 'testServer', 'rotateHostKey', 'recordProbedShells', 'updateServer']) expect(idTitle(byName.get(n)!.inputSchema as never), n).toBe('Server ID');
    for (const n of ['viewTask', 'enableTask', 'disableTask', 'removeTask']) expect(idTitle(byName.get(n)!.inputSchema as never), n).toBe('Task ID');
    expect(idTitle(registrationInputSchemaFor(actions, 'enableTask'))).toBe('Task ID');
    expect(idTitle(registrationInputSchemaFor(actions, 'removeServer'))).toBe('Server ID');
    // prepare-built schemas: a draft exists → enableTask hands back its review schema; updateTask its form
    await byName.get('addTask')!.execute({ id: 'demo.echo', version: '1.0.0', risk: 'low', serverScope: '*', body: 'echo hi' }, { commandId: 'c1' } as never);
    const en = await byName.get('enableTask')!.prepare!({ id: 'demo.echo' });
    expect(en.inputSchema, 'enableTask prepare returns a schema').toBeDefined();
    expect(idTitle(en.inputSchema)).toBe('Task ID');
    rootDescribed(en.inputSchema!);
    const up = await byName.get('updateTask')!.prepare!({ id: 'demo.echo', state: 'draft' });
    expect(idTitle(up.inputSchema)).toBe('任务 ID'); // the form declares its own title; kept
    rootDescribed(up.inputSchema!);
    const us = await byName.get('updateServer')!.prepare!({ id: 'web-01' });
    expect(idTitle(us.inputSchema)).toBe('Server ID');
  });
});

describe('ops task parameters stay in the neutral domain (review 3178)', () => {
  it('an ops task declaring a plain `id` parameter without a title is NOT relabeled as the task identity, while _tasks management schemas stay "Task ID"', () => {
    const registry = makeRegistry(
      makeAction({ id: 'demo.lookup', readonly: true, serverScopes: ['*'], script: 'echo $XOPS_ID', params: { type: 'object', properties: { id: { type: 'string', description: 'The record to look up' } }, required: ['id'], additionalProperties: false } }),
    );
    const dir = mkdtempSync(join(tmpdir(), 'linux-ops-desc-ops-')); dirs.push(dir);
    const srv = new ServerStore(join(dir, 'servers.json'));
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const actions = buildCeActions({ paramGuards: new ParamGuardSet([]), redlines: new RedlineSet([]), registry, taskStore: new TaskDb(join(dir, 'tasks.db')), store: srv, opsService, probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT), probe: (s) => executor.run(s, { command: 'true' }) });
    const byName = new Map(actions.map((a) => [a.name, a] as const));
    const idOf = (s: Record<string, unknown> | undefined) => (s?.['properties'] as Record<string, Record<string, unknown>>)['id']!;
    const ops = idOf(byName.get('demo.lookup')!.inputSchema as never);
    expect(ops['title']).not.toBe('Task ID');
    expect(ops['title']).toBe('Id');
    expect(ops['description']).toBe('The record to look up');
    expect(idOf(registrationInputSchemaFor(actions, 'demo.lookup'))['title']).toBe('Id');
    expect(idOf(byName.get('viewTask')!.inputSchema as never)['title']).toBe('Task ID');
    expect(idOf(byName.get('removeServer')!.inputSchema as never)['title']).toBe('Server ID');
  });
});

describe('manage entries are READ_ONLY list openers (conventions §2, linux-ops#92)', () => {
  it('servers.manage / tasks.manage declare READ_ONLY / LOW / INTERNAL; the whole management surface publishes at MGMT_CHECKPOINT_VERSION = 1.0.2 (linux-ops#92/#94 bumped six rows, #100 the other eleven)', () => {
    for (const id of ['manageServers', 'manageTasks']) {
      const row = STATIC_CHECKPOINT_ROWS.find((r) => r.action === id)!;
      expect([row.sideEffect, row.risk, row.input]).toEqual(['READ_ONLY', 'LOW', 'INTERNAL']);
    }
    expect(MGMT_CHECKPOINT_VERSION).toBe('1.0.2');
    for (const r of STATIC_CHECKPOINT_ROWS) expect(checkpointRefFor(r.action).checkpointVersion).toBe(MGMT_CHECKPOINT_VERSION);
  });

  it('opening an entry needs no input and answers the list — a Panel/Exposure entry, not a form', async () => {
    const { byName } = setup();
    for (const id of ['manageServers', 'manageTasks']) {
      const a = byName.get(id)!;
      expect((a.inputSchema as { required: string[] }).required).toEqual([]);
      const r = (await a.execute!({}, {} as never)) as { success: boolean; data: { list: unknown } };
      expect(r.success).toBe(true);
      expect(r.data.list).toBeDefined();
    }
  });
});
