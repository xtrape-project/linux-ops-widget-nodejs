import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { serveCeService, type ServeCeServiceHandle } from '@xtrape/connector';
import { buildCeActions } from '../src/ce-actions.js';
import { buildCheckpointSet } from '../src/checkpoints.js';
import { RedlineSet } from '../src/redlines.js';
import { ParamGuardSet } from '../src/param-guards.js';
import { OpsService } from '../src/service.js';
import { ServerStore, type ServerInput } from '../src/servers.js';
import { TaskDb } from '../src/task-db.js';
import { ActionRegistry } from '../src/registry.js';
import { MemoryAuditLogger } from '../src/audit.js';
import { buildManifest } from '../src/manifest.js';
import { FakeExecutor, makeAction, makeRegistry } from './helpers.js';

// Outbound SDK calls (register/heartbeat) are stubbed so the real callback
// listener starts without a live Platform; inbound callback requests still hit
// the genuine listener, exercising its auth (#27, archived review).
const stubFetch = (async (url: string) => {
  const u = String(url);
  if (u.includes('/api/agents/register') || u.endsWith('/v1/instances')) {
    return new Response(JSON.stringify({ instanceId: 'linux-ops-widget-test', contractVersion: 1, accessToken: 'acc' }), { status: 200, headers: { 'content-type': 'application/json' } });
  }
  return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
}) as unknown as typeof fetch;

const dirs: string[] = [];
function tstore(): TaskDb {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-tasks-'));
  dirs.push(dir);
  return new TaskDb(join(dir, 'tasks.db'));
}
let handle: ServeCeServiceHandle | undefined;
afterEach(async () => {
  await handle?.close();
  handle = undefined;
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

async function start(callbackToken?: string, setup: { registry?: ActionRegistry; executor?: FakeExecutor; seedServer?: ServerInput } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-cb-'));
  dirs.push(dir);
  const store = new ServerStore(join(dir, 'servers.json'));
  const registry = setup.registry ?? makeRegistry();
  const executor = setup.executor ?? new FakeExecutor();
  if (setup.seedServer) store.add(setup.seedServer);
  const opsService = new OpsService({ registry, servers: store, executors: [executor], audit: new MemoryAuditLogger() });
  const ceActions = buildCeActions({ paramGuards: new ParamGuardSet([]), redlines: new RedlineSet([]), registry, taskStore: tstore(), store, opsService, probe: (s) => executor.run(s, { command: 'true' }), probeHostKey: () => Promise.resolve('SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4') });
  // #79: every action carries a Checkpoint binding, so the harness publishes
  // the matching definitions (listen-only = the plain array).
  const inputSchemaFor = (name: string) => ceActions.find((a) => a.name === name)?.inputSchema as Record<string, unknown> | undefined;
  const set = buildCheckpointSet({ profileDigest: `sha256:${'0'.repeat(64)}`, inputSchemaFor, tasks: registry.list() });
  handle = await serveCeService({
    serverUrl: 'http://stub.invalid',
    manifest: buildManifest(),
    handler: async () => ({ content: 'ok' }),
    actions: ceActions,
    checkpoints: set.definitions,
    schemaRecords: set.schemaRecords,
    instanceId: 'linux-ops-widget-test',
    port: 0,
    host: '127.0.0.1',
    ...(callbackToken ? { callbackToken } : {}),
    fetchImpl: stubFetch,
  });
  const base = handle.address.replace(/\/$/, '');
  return { base, store, executor };
}

const addBody = JSON.stringify({ id: 'x', host: 'h', username: 'u', environment: 'staging', hostKeyFingerprint: 'SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4', authMethod: 'password', password: 'pw' });
function execAddServer(base: string, token?: string) {
  return fetch(`${base}/actions/addServer/execute`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { 'x-xtrape-service-callback-token': token } : {}) },
    body: addBody,
  });
}

describe('callback listener authentication', () => {
  it('rejects a missing or wrong callback token with 401 and zero side effects', async () => {
    const { base, store } = await start('secret');
    for (const token of [undefined, 'wrong']) {
      const res = await execAddServer(base, token);
      expect(res.status).toBe(401);
    }
    expect(store.get('x')).toBeUndefined(); // no addServer effect on unauthorized calls
  });

  it('accepts the correct callback token and performs the action', async () => {
    const { base, store } = await start('secret');
    const res = await execAddServer(base, 'secret');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean };
    expect(body.success).toBe(true);
    expect(store.get('x')).toBeDefined();
  });

  it('a policy-denied ops action returns 200 { success:false, error.code:POLICY_DENIED } with zero executor calls', async () => {
    // The SDK sends the top-level { success:false, error:{ code } } envelope as
    // the 200 body; xtrape-platform-ce#104 reclassifies it to a FAILED command. This
    // locks the agent side of that cross-repo wire contract.
    const executor = new FakeExecutor();
    const { base } = await start('secret', {
      registry: makeRegistry(makeAction({ id: 'nginx.reload', readonly: false, riskLevel: 'medium', serverScopes: ['web-*'], script: 'reload' })),
      executor,
      seedServer: { id: 'db-01', host: 'h', username: 'u', environment: 'staging', hostKeyFingerprint: 'SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4', authMethod: 'password', password: 'pw' },
    });
    const res = await fetch(`${base}/actions/nginx.reload/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-xtrape-service-callback-token': 'secret' },
      body: JSON.stringify({ serverId: 'db-01', reason: 'wrong scope' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; error?: { code?: string } };
    expect(body.success).toBe(false);
    expect(body.error?.code).toBe('POLICY_DENIED');
    expect(executor.commands).toEqual([]);
  });
});
