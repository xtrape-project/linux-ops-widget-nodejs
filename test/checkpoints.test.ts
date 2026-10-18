import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CheckpointDefinitionSchema, checkpointVersionKey } from '@xtrape/contracts';
import { buildCeActions } from '../src/ce-actions.js';
import { registrationSchemaForTask } from '../src/ops-schema.js';
import { parseTaskFile } from '../src/task-file.js';
import {
  MGMT_ROOT_ARTIFACT_BYTES,
  MGMT_ROOT_ARTIFACT_DIGEST,
  SERVER_BY_ID_ARTIFACT_DIGEST,
  TASK_BY_ID_ARTIFACT_BYTES,
  TASK_BY_ID_ARTIFACT_DIGEST,
  TASK_CHECKPOINT_SHAPE,
  ALL_ARTIFACTS,
  REVIEWED_UPTIME_DIGEST,
  SERVER_TARGET_ARTIFACT_BYTES,
  SERVER_TARGET_ARTIFACT_DIGEST,
  STATIC_CHECKPOINT_ROWS,
  assertCandidateParameterDeclared,
  buildCheckpointSet,
  checkpointRefFor,
  enforceableInputSchema,
  EMPTY_INPUT_SCHEMA_BYTES,
  ID_INPUT_SCHEMA_BYTES,
  REVIEW_CARD_SCHEMA_BYTES,
  MGMT_CHECKPOINT_VERSION,
  definitionFingerprint,
  isCheckpointExposed,
  parseBoundedCheckpoints,
  taskCheckpointId,
} from '../src/checkpoints.js';
import { OpsService } from '../src/service.js';
import { ServerStore } from '../src/servers.js';
import { TaskDb } from '../src/task-db.js';
import { RedlineSet } from '../src/redlines.js';
import { ParamGuardSet } from '../src/param-guards.js';
import { MemoryAuditLogger } from '../src/audit.js';
import { FakeExecutor, makeAction, makeRegistry, TEST_HOST_KEY_FINGERPRINT } from './helpers.js';

/**
 * The governance flip (#79): every served action carries a Checkpoint binding,
 * the definitions parse under the 0.8.13 strict contract (Action edge
 * included), and the two extractor artifacts are canonical content.
 */

const dirs: string[] = [];
function tstore(): TaskDb {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-cp-'));
  dirs.push(dir);
  return new TaskDb(join(dir, 'tasks.db'));
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const PROFILE = `sha256:${'7'.repeat(64)}`;

function world() {
  const registry = makeRegistry(
    makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }),
    makeAction({ id: 'db.drop', readonly: false, riskLevel: 'critical', serverScopes: ['*'], script: 'dropdb x' }),
  );
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-cp-srv-'));
  dirs.push(dir);
  const srv = new ServerStore(join(dir, 'servers.json'));
  srv.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: TEST_HOST_KEY_FINGERPRINT, authMethod: 'password', password: 'pw' });
  const executor = new FakeExecutor();
  const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
  const actions = buildCeActions({
    paramGuards: new ParamGuardSet([]),
    redlines: new RedlineSet([]),
    registry,
    taskStore: tstore(),
    store: srv,
    opsService,
    probe: (s) => executor.run(s, { command: 'true' }),
    probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT),
  });
  return { registry, actions };
}

describe('the artifacts are canonical content-addressed documents', () => {
  it('bytes are sorted-key canonical and the digests match the bytes', () => {
    for (const [bytes, digest] of [
      [MGMT_ROOT_ARTIFACT_BYTES, MGMT_ROOT_ARTIFACT_DIGEST],
      [SERVER_TARGET_ARTIFACT_BYTES, SERVER_TARGET_ARTIFACT_DIGEST],
    ] as const) {
      expect(digest).toBe(`sha256:${createHash('sha256').update(bytes, 'utf8').digest('hex')}`);
      // canonical: parsing and re-serializing with sorted keys reproduces the bytes
      const reser = (v: unknown): string =>
        Array.isArray(v)
          ? `[${v.map(reser).join(',')}]`
          : v !== null && typeof v === 'object'
            ? `{${Object.entries(v as Record<string, unknown>)
                .sort(([a], [b]) => (a < b ? -1 : 1))
                .map(([k, x]) => `${JSON.stringify(k)}:${reser(x)}`)
                .join(',')}}`
            : JSON.stringify(v);
      expect(reser(JSON.parse(bytes))).toBe(bytes);
    }
    expect(SERVER_TARGET_ARTIFACT_BYTES).toContain('"/serverId"');
  });
});

describe('every served action carries a binding and every definition parses strictly (#79)', () => {
  it('actions ↔ definitions are one-to-one and 0.8.13-valid, tasks versioned by their declared semver', () => {
    const { registry, actions } = world();
    // every action entry is bound
    for (const entry of actions) {
      expect(entry.checkpoint, `action ${entry.name} has no Checkpoint binding`).toBeDefined();
    }
    const set = buildCheckpointSet({
      profileDigest: PROFILE,
      inputSchemaFor: (name) => actions.find((a) => a.name === name)?.inputSchema as Record<string, unknown> | undefined,
      tasks: registry.list(),
    });
    // 17 static + 2 tasks; each parses under the strict contract WITH its edge
    expect(set.definitions).toHaveLength(STATIC_CHECKPOINT_ROWS.length + 2);
    const byKey = new Map(set.definitions.map((d) => [checkpointVersionKey(d.id), d]));
    for (const definition of set.definitions) {
      const parsed = CheckpointDefinitionSchema.parse(definition);
      expect(parsed.action?.actionId).toBeDefined();
    }
    // the bindings the catalog serves point at definitions that exist, and the
    // edge agrees in both directions (arch/19 §3.1 rule 4)
    for (const entry of actions) {
      const ref = entry.checkpoint!;
      const definition = byKey.get(checkpointVersionKey(ref as never));
      expect(definition, `binding of ${entry.name} has no definition`).toBeDefined();
      expect(definition!.action?.actionId).toBe(entry.name);
    }
    // task versioning: the checkpoint version IS the task's declared semver
    const uptime = registry.list().find((t) => t.id === 'system.uptime')!;
    const ref = checkpointRefFor('system.uptime', uptime.version);
    expect(ref.checkpointId).toBe('task.system.uptime');
    expect(ref.checkpointVersion).toBe(uptime.version);
    // risk maps from the declaration
    const drop = byKey.get(checkpointVersionKey({ serviceId: 'linux-ops-widget-nodejs', checkpointId: 'task.db.drop', checkpointVersion: registry.list().find((t) => t.id === 'db.drop')!.version } as never))!;
    expect(drop.risk).toBe('CRITICAL');
    expect(drop.sideEffect).toBe('MUTATING');
  });

  it('every admitted input schema sits inside the Platform-enforceable subset (linux-ops#82)', () => {
    const { registry, actions } = world();
    const set = buildCheckpointSet({
      profileDigest: PROFILE,
      inputSchemaFor: (name) => actions.find((a) => a.name === name)?.inputSchema as Record<string, unknown> | undefined,
      tasks: registry.list(),
    });
    const byDigest = new Map(set.schemaRecords.map((r) => [r.digest, r]));
    // platform-ce#306: the subset admits the two annotation keywords at the top and on every property — they validate nothing, they are what an AI host reads (linux-ops#92).
    const ENFORCEABLE_TOP = new Set(['type', 'properties', 'required', 'additionalProperties', 'title', 'description']);
    const ANNOTATION = new Set(['title', 'description']);
    for (const definition of set.definitions) {
      const rec = byDigest.get(definition.inputSchema.schemaRecord);
      expect(rec, `definition ${definition.id.checkpointId} cites an unknown schema record`).toBeDefined();
      const schema = JSON.parse(rec!.bytesJson) as Record<string, unknown>;
      // top level: nothing outside the enforced keyword set, and the two
      // non-negotiables are explicit
      for (const key of Object.keys(schema)) {
        expect(ENFORCEABLE_TOP.has(key), `${definition.id.checkpointId}: top-level "${key}" is not enforceable`).toBe(true);
      }
      expect(schema['type']).toBe('object');
      expect(schema['additionalProperties'], `${definition.id.checkpointId}: additionalProperties must be an explicit false`).toBe(false);
      // property level: `type` ONLY — a keyword the Platform silently ignores
      // is a declaration nobody checks
      for (const [name, prop] of Object.entries((schema['properties'] ?? {}) as Record<string, Record<string, unknown>>)) {
        expect(Object.keys(prop).filter((k) => !ANNOTATION.has(k)), `${definition.id.checkpointId}.${name} carries validating keywords beyond "type"`).toEqual(['type']);
        expect(typeof prop['title'], `${definition.id.checkpointId}.${name} has no title`).toBe('string');
        expect(typeof prop['description'], `${definition.id.checkpointId}.${name} has no description`).toBe('string');
      }
    }
  });

  it('enforceableInputSchema strips rich keywords, keeps required, pins additionalProperties:false', () => {
    const projected = enforceableInputSchema({
      type: 'object',
      properties: {
        id: { type: 'string', minLength: 1, pattern: '^[a-z-]+$' },
        port: { type: 'number', minimum: 1, maximum: 65535 },
      },
      required: ['id'],
      additionalProperties: true,
    });
    expect(projected).toEqual({
      type: 'object',
      properties: { id: { type: 'string' }, port: { type: 'number' } },
      required: ['id'],
      additionalProperties: false,
    });
  });

  it('a property with no `type` fails CLOSED at projection time, not as an unenforceable published Checkpoint', () => {
    expect(() =>
      enforceableInputSchema({
        type: 'object',
        properties: { environment: { enum: ['production', 'staging'] } },
      }),
    ).toThrow(/declares no "type"/);
  });

  it('a `type` outside the Platform allowlist fails CLOSED too — Widget-green/Platform-503 stays impossible (review 2716)', () => {
    expect(() =>
      enforceableInputSchema({
        type: 'object',
        properties: { note: { type: 'null' } },
      }),
    ).toThrow(/does not execute/);
    // the six enforced types all project
    for (const type of ['string', 'integer', 'number', 'boolean', 'object', 'array']) {
      expect(enforceableInputSchema({ type: 'object', properties: { v: { type } } })).toEqual({
        type: 'object',
        properties: { v: { type } },
        additionalProperties: false,
      });
    }
  });

  it('the empty input schema is itself enforceable (explicit additionalProperties:false)', () => {
    const empty = JSON.parse(EMPTY_INPUT_SCHEMA_BYTES) as Record<string, unknown>;
    expect(empty['additionalProperties']).toBe(false);
    expect(empty['properties']).toEqual({});
  });

  it('management Checkpoints publish as 1.0.2 — every row, since #93 changed the admitted bytes of all of them (linux-ops#100)', () => {
    expect(MGMT_CHECKPOINT_VERSION).toBe('1.0.2');
    expect(checkpointRefFor('listServers').checkpointVersion).toBe('1.0.2');
    // One cohort: no row carries a version of its own (the field is gone; the type says so).
    for (const row of STATIC_CHECKPOINT_ROWS) expect('version' in row).toBe(false);
    const { registry, actions } = world();
    const set = buildCheckpointSet({
      profileDigest: PROFILE,
      inputSchemaFor: (name) => actions.find((a) => a.name === name)?.inputSchema as Record<string, unknown> | undefined,
      tasks: registry.list(),
    });
    for (const definition of set.definitions) {
      if (!definition.id.checkpointId.startsWith('task.')) expect(definition.id.checkpointVersion).toBe('1.0.2');
    }
  });

  it('the management definitions are SNAPSHOTTED per id@version: a changed definition is an explicit fixture diff (built ≠ pin), a new version needs its pin, a stale pin is refused — the review rule is never to edit an existing pin (linux-ops#100)', () => {
    const { registry, actions } = world();
    const set = buildCheckpointSet({
      profileDigest: PROFILE,
      inputSchemaFor: (name) => actions.find((a) => a.name === name)?.inputSchema as Record<string, unknown> | undefined,
      tasks: registry.list(),
    });
    const pinsPath = fileURLToPath(new URL('./frozen-management-definitions.json', import.meta.url));
    const pins = JSON.parse(readFileSync(pinsPath, 'utf8')) as Record<string, string>;
    const canonical = (v: unknown): string =>
      Array.isArray(v) ? `[${v.map(canonical).join(',')}]`
      : v !== null && typeof v === 'object' ? `{${Object.keys(v as Record<string, unknown>).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(',')}}`
      : JSON.stringify(v);
    const built = new Map<string, string>();
    for (const definition of set.definitions) {
      if (definition.id.checkpointId.startsWith('task.')) continue;
      built.set(`${definition.id.checkpointId}@${definition.id.checkpointVersion}`, `sha256:${createHash('sha256').update(canonical(definition)).digest('hex')}`);
    }
    for (const [key, digest] of built) {
      expect(pins[key], `${key} is built but not pinned in test/frozen-management-definitions.json — a new version is pinned WITH its definition`).toBeDefined();
      expect(digest, `${key} changed bytes under a pinned version — this is the snapshot diff that must NOT be absorbed by editing the pin: bump MGMT_CHECKPOINT_VERSION (a persistent Platform refuses the mutation with CHECKPOINT_IMMUTABLE_CONFLICT) and pin the new identities`).toBe(pins[key]);
    }
    for (const key of Object.keys(pins)) expect(built.has(key), `${key} is pinned but no longer built — retire the pin in the same change that retires the version`).toBe(true);
  });

  it('a dotted-kebab task id is a legal Checkpoint identity; anything else fails closed at publication', () => {
    expect(taskCheckpointId('system.uptime')).toBe('task.system.uptime');
    expect(() => taskCheckpointId('Nope_Bad')).toThrow(/Checkpoint identity/);
  });
});

describe('the review face of the two-phase Checkpoints (runtime-platform/13 v0.5 §4.2; linux-ops#94)', () => {
  it('every task run and the four two-phase management rows declare a review face; every other definition has none; all parse strictly under contracts 0.8.17', () => {
    const { registry, actions } = world();
    const set = buildCheckpointSet({ profileDigest: PROFILE, inputSchemaFor: (name) => actions.find((a) => a.name === name)?.inputSchema as Record<string, unknown> | undefined, tasks: registry.list() });
    const byId = new Map(set.definitions.map((d) => [d.id.checkpointId, d]));
    const records = new Map(set.schemaRecords.map((r) => [r.digest, r.bytesJson]));
    for (const definition of set.definitions) {
      CheckpointDefinitionSchema.parse(definition);
      const face = definition.review;
      if (definition.id.checkpointId.startsWith('task.')) {
        // An entry-level review: empty request, Service-rooted Resource, the card schema, the execution risk, sealed ⇒ INCARNATION, the target choice on serverId.
        expect(face).toBeDefined();
        expect(records.get(face!.inputSchema.schemaRecord)).toBe(EMPTY_INPUT_SCHEMA_BYTES);
        expect(records.get(face!.outputSchema.schemaRecord)).toBe(REVIEW_CARD_SCHEMA_BYTES);
        expect(face!.resource).toEqual({ kind: 'extractor-artifact', artifactDigest: MGMT_ROOT_ARTIFACT_DIGEST, executionProfileRecord: PROFILE });
        expect(face).toMatchObject({ risk: definition.risk, affinity: 'INCARNATION', candidateParameter: 'serverId' });
        // The candidate slot really is a declared top-level property of the execution schema (what Platform admission verifies).
        expect(Object.keys((JSON.parse(records.get(definition.inputSchema.schemaRecord)!) as { properties: Record<string, unknown> }).properties)).toContain('serverId');
      }
    }
    // §4.2: a review that NAMES its target is authorized against that target — the ordinary extractor over {id} (review 3209).
    const face = (id: string) => byId.get(id)!.review!;
    expect(face('servers.update')).toMatchObject({ affinity: 'NONE', resource: { artifactDigest: SERVER_BY_ID_ARTIFACT_DIGEST } });
    expect(records.get(face('servers.update').inputSchema.schemaRecord)).toBe(ID_INPUT_SCHEMA_BYTES);
    expect(face('servers.update').candidateParameter).toBeUndefined();
    expect(face('tasks.update')).toMatchObject({ affinity: 'INCARNATION', resource: { artifactDigest: TASK_BY_ID_ARTIFACT_DIGEST } });
    expect(records.get(face('tasks.update').inputSchema.schemaRecord)).toBe(ID_INPUT_SCHEMA_BYTES);
    expect(face('tasks.enable')).toMatchObject({ affinity: 'INCARNATION', resource: { artifactDigest: TASK_BY_ID_ARTIFACT_DIGEST } });
    // An entry-level review (no target yet) is Service-rooted.
    expect(face('tasks.add')).toMatchObject({ affinity: 'NONE', resource: { artifactDigest: MGMT_ROOT_ARTIFACT_DIGEST } });
    expect(records.get(face('tasks.add').inputSchema.schemaRecord)).toBe(EMPTY_INPUT_SCHEMA_BYTES);
    // No exchange on a scope EXPRESSION (review 3209): only the task runs' `serverId` is a candidate slot.
    for (const id of ['tasks.add', 'tasks.update', 'tasks.enable', 'servers.update']) expect(face(id).candidateParameter).toBeUndefined();
    for (const id of ['servers.manage', 'servers.list', 'servers.add', 'servers.remove', 'tasks.manage', 'tasks.disable', 'tasks.remove']) expect(byId.get(id)!.review).toBeUndefined();
    // The task-by-id extractor is a published, canonical artifact like the others.
    expect(ALL_ARTIFACTS.map((a) => a.digest)).toContain(TASK_BY_ID_ARTIFACT_DIGEST);
    expect(JSON.parse(TASK_BY_ID_ARTIFACT_BYTES).segments).toEqual([{ id: { kind: 'literal', value: 'linux-ops-widget-nodejs' }, type: 'service' }, { id: { kind: 'pointer', pointer: '/id' }, type: 'task' }]);
    expect(TASK_CHECKPOINT_SHAPE).toBe(2);
  });
});

describe('grow before expose (#79): enable publishes the Checkpoint BEFORE the catalog reports the binding', () => {
  it('ensureTaskCheckpoints runs before the ops rebuild, and its failure aborts the enable', async () => {
    const registry = makeRegistry();
    const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-cp-grow-'));
    dirs.push(dir);
    const srv = new ServerStore(join(dir, 'servers.json'));
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const calls: string[] = [];
    const actions = buildCeActions({
      ensureTaskCheckpoints: async (tasks) => {
        // at growth time the catalog must NOT yet serve the entry
        expect(actions.some((a) => a.name === tasks[0]!.id)).toBe(false);
        calls.push(tasks.map((t) => `${t.id}@${t.version}`).join(','));
      },
      paramGuards: new ParamGuardSet([]),
      redlines: new RedlineSet([]),
      registry,
      taskStore,
      store: srv,
      opsService,
      probe: (s) => executor.run(s, { command: 'true' }),
      probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT),
    });
    const add = actions.find((a) => a.name === 'addTask')!;
    const enable = actions.find((a) => a.name === 'enableTask')!;
    const draft = await add.execute!({ id: 'grow.probe', title: 'Grow probe', version: '1.0.0', description: 'probe', risk: 'low', serverScope: '*', body: 'uptime' }, undefined as never);
    expect((draft as { success?: boolean }).success).toBe(true);
    // Enable's prepare IS the review: it seals the binding the execute presents.
    const review = await enable.prepare!({ id: 'grow.probe' });
    const binding = ((review as { initialPayload?: { reviewBinding?: string } }).initialPayload ?? {}).reviewBinding!;
    const enabled = await enable.execute!({ id: 'grow.probe', reviewBinding: binding }, { commandId: 'cmd_grow' } as never);
    expect((enabled as { success?: boolean }).success).toBe(true);
    expect(calls).toEqual(['grow.probe@1.0.0']);
    // NOW the catalog serves it
    expect(actions.some((a) => a.name === 'grow.probe')).toBe(true);
  });
});

describe('atomicity: a failed Checkpoint publication commits NOTHING (review 2674 P1-1)', () => {
  it('enable aborts BEFORE the irreversible pointer move: the draft survives, nothing registers, nothing is exposed', async () => {
    const registry = makeRegistry();
    const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-cp-fail-'));
    dirs.push(dir);
    const srv = new ServerStore(join(dir, 'servers.json'));
    const executor = new FakeExecutor();
    const opsService = new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() });
    const taskStore = tstore();
    const actions = buildCeActions({
      ensureTaskCheckpoints: async () => {
        throw new Error('platform unreachable');
      },
      paramGuards: new ParamGuardSet([]),
      redlines: new RedlineSet([]),
      registry,
      taskStore,
      store: srv,
      opsService,
      probe: (s) => executor.run(s, { command: 'true' }),
      probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT),
    });
    const add = actions.find((a) => a.name === 'addTask')!;
    const enable = actions.find((a) => a.name === 'enableTask')!;
    await add.execute!({ id: 'grow.probe', title: 'Grow probe', version: '1.0.0', description: 'probe', risk: 'low', serverScope: '*', body: 'uptime' }, undefined as never);
    const review = await enable.prepare!({ id: 'grow.probe' });
    const binding = ((review as { initialPayload?: { reviewBinding?: string } }).initialPayload ?? {}).reviewBinding!;
    await expect(enable.execute!({ id: 'grow.probe', reviewBinding: binding }, { commandId: 'cmd_grow' } as never)).rejects.toThrow(/platform unreachable/);
    // The DRAFT is intact (not consumed by an enable that never happened)…
    expect(taskStore.findDraft('grow.probe')).toBeTruthy();
    // …nothing became runtime truth, nothing reached the live catalog.
    expect(registry.list().some((t) => t.id === 'grow.probe')).toBe(false);
    expect(actions.some((a) => a.name === 'grow.probe')).toBe(false);
    // And a retry with a WORKING publisher is exactly a fresh Enable.
    const review2 = await enable.prepare!({ id: 'grow.probe' });
    const binding2 = ((review2 as { initialPayload?: { reviewBinding?: string } }).initialPayload ?? {}).reviewBinding!;
    expect(binding2).toBeTruthy();
  });
});

describe('task identity grammar is unified at the AUTHORING boundary (review 2674 P1-3)', () => {
  it('what the registry admits, the Checkpoint identity accepts; what the old grammar tolerated is refused at write time', () => {
    // conforming: letter-start dot-separated kebab
    const ok = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    expect(() => taskCheckpointId(ok.list()[0]!.id)).not.toThrow();
    // digit-start segment and underscore — legal under the OLD grammar,
    // refused now at registration, so publication-time failure cannot exist.
    expect(() => makeRegistry(makeAction({ id: '2fa.reset_all', readonly: false, serverScopes: ['*'], script: 'true' }))).toThrow();
  });
});

describe('bounded reference profile MECHANISM (#77): a deployment exposes only a named Checkpoint subset', () => {
  it('parses the allowlist; ABSENT means the full surface, but PRESENT-EMPTY fails closed', () => {
    // absent (var unset) is the only "expose everything" signal
    expect(parseBoundedCheckpoints(undefined)).toBeNull();
    // present-but-names-nothing must NOT silently fall back to the full surface —
    // a bounded profile that narrows exposure degrading to deny-nothing is a fail-open (#81 review 2688 #1)
    expect(() => parseBoundedCheckpoints('')).toThrow(/must not fall back to the full surface/);
    expect(() => parseBoundedCheckpoints('  ,  ')).toThrow(/must not fall back to the full surface/);
    const b = parseBoundedCheckpoints('servers.list, task.service.restart');
    expect(b).not.toBeNull();
    expect(isCheckpointExposed('servers.list', b)).toBe(true);
    expect(isCheckpointExposed('task.service.restart', b)).toBe(true);
    expect(isCheckpointExposed('servers.manage', b)).toBe(false);
    // full surface: everything exposed
    expect(isCheckpointExposed('servers.manage', null)).toBe(true);
  });

  it('the mechanism narrows exposure to ANY named subset — demonstrated with two example tasks, which are library content, not built-in capabilities', () => {
    const registry = makeRegistry(
      // system.uptime carries the EXACT reviewed identity (id@1.0.0 + digest) so
      // it matches the reviewed READ_ONLY reference fact.
      makeAction({ id: 'system.uptime', version: '1.0.0', scriptDigest: REVIEWED_UPTIME_DIGEST, readonly: true, serverScopes: ['*'], script: 'uptime' }),
      makeAction({ id: 'service.restart', readonly: false, riskLevel: 'high', serverScopes: ['*'], script: 'systemctl restart -- "$XOPS_service"' }),
    );
    const bounded = parseBoundedCheckpoints('task.system.uptime,task.service.restart');
    const set = buildCheckpointSet({
      profileDigest: PROFILE,
      inputSchemaFor: () => ({ type: 'object' }),
      tasks: registry.list(),
      bounded,
    });
    const ids = set.definitions.map((d) => d.id.checkpointId).sort();
    // exactly the two exposed task Checkpoints — none of the 17 management rows
    expect(ids).toEqual(['task.service.restart', 'task.system.uptime']);
    // the write reference Checkpoint: HIGH risk AND MUTATING (the profile default).
    const write = set.definitions.find((d) => d.id.checkpointId === 'task.service.restart')!;
    expect(write.risk).toBe('HIGH');
    expect(write.sideEffect).toBe('MUTATING');
    // the read reference Checkpoint: LOW risk AND READ_ONLY. Its sideEffect is a
    // REVIEWED PROFILE FACT (REFERENCE_TASK_SIDE_EFFECTS), NOT derived from the
    // task's legacy `# readonly:` field — #61 retired that field for governance,
    // and sideEffect is a governance fact the Platform reads (#81 review 2690 P1).
    const read = set.definitions.find((d) => d.id.checkpointId === 'task.system.uptime')!;
    expect(read.risk).toBe('LOW');
    expect(read.sideEffect).toBe('READ_ONLY');
  });

  it('the retired `readonly` field does NOT drive Checkpoint.sideEffect (#81 review 2690 P1)', () => {
    // A task NOT in the reviewed reference profile that declares readonly:true
    // must still be MUTATING — the legacy field cannot route itself back into
    // the governance fact the Platform authorizes on. Only a reviewed profile
    // fact makes a task READ_ONLY.
    const registry = makeRegistry(
      makeAction({ id: 'some.legacy.read', readonly: true, serverScopes: ['*'], script: 'cat /proc/loadavg' }),
    );
    const set = buildCheckpointSet({ profileDigest: PROFILE, inputSchemaFor: () => ({ type: 'object' }), tasks: registry.list(), staticRows: false });
    const cp = set.definitions.find((d) => d.id.checkpointId === 'task.some.legacy.read')!;
    expect(cp.sideEffect).toBe('MUTATING'); // fail-safe default, readonly ignored
  });

  it('the reviewed READ_ONLY fact stays pinned to the exact bytes of the example file (drift guard)', () => {
    // If examples/tasks/system-uptime.sh is ever edited, its scriptDigest changes
    // and this fails loudly — forcing REVIEWED_UPTIME_DIGEST to be re-pinned and
    // the read re-reviewed, rather than silently keeping READ_ONLY.
    const exampleDir = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'examples', 'tasks');
    const parsed = parseTaskFile(readFileSync(join(exampleDir, 'system-uptime.sh'), 'utf8'), 'system-uptime.sh');
    expect(parsed.scriptDigest).toBe(REVIEWED_UPTIME_DIGEST);
  });

  it('READ_ONLY binds to EXACT content: reusing system.uptime@1.0.0 with different bytes is NOT READ_ONLY (#81 review 2691)', () => {
    // Same logical id AND version as the reviewed reference read, but a swapped,
    // side-effecting script — the TaskDb revision model allows this. It must NOT
    // inherit READ_ONLY on the name alone; the scriptDigest mismatch fails closed.
    const registry = makeRegistry(
      makeAction({
        id: 'system.uptime',
        version: '1.0.0',
        readonly: true, // even lying with the retired flag cannot help
        serverScopes: ['*'],
        script: 'rm -rf /var/tmp/x', // different bytes ⇒ different scriptDigest
      }),
    );
    const set = buildCheckpointSet({ profileDigest: PROFILE, inputSchemaFor: () => ({ type: 'object' }), tasks: registry.list(), staticRows: false });
    const cp = set.definitions.find((d) => d.id.checkpointId === 'task.system.uptime')!;
    expect(cp.id.checkpointVersion).toBe('1.0.0'); // same id@version...
    expect(cp.sideEffect).toBe('MUTATING'); // ...but NOT the reviewed bytes ⇒ fail closed
  });

  it('a drifted definition at the same id@version has a DIFFERENT fingerprint, so the publish cache cannot suppress it (#81 review 2692)', () => {
    // The reviewed READ_ONLY read...
    const reviewed = buildCheckpointSet({
      profileDigest: PROFILE, inputSchemaFor: () => ({ type: 'object' }), staticRows: false,
      tasks: [makeAction({ id: 'system.uptime', version: '1.0.0', scriptDigest: REVIEWED_UPTIME_DIGEST, script: 'uptime' })],
    }).definitions.find((d) => d.id.checkpointId === 'task.system.uptime')!;
    // ...and a revision reusing system.uptime@1.0.0 with different, side-effecting bytes.
    const drifted = buildCheckpointSet({
      profileDigest: PROFILE, inputSchemaFor: () => ({ type: 'object' }), staticRows: false,
      tasks: [makeAction({ id: 'system.uptime', version: '1.0.0', readonly: true, script: 'rm -rf /var/tmp/x' })],
    }).definitions.find((d) => d.id.checkpointId === 'task.system.uptime')!;
    expect(reviewed.sideEffect).toBe('READ_ONLY');
    expect(drifted.sideEffect).toBe('MUTATING');
    // Fingerprints differ ⇒ a cache seeded with the reviewed fingerprint does
    // NOT match the drifted definition, so it is republished and reaches the
    // Platform's immutable-conflict authority instead of being swallowed by an
    // id@version cache.
    expect(definitionFingerprint(reviewed)).not.toBe(definitionFingerprint(drifted));
    // And an identical rebuild is a true no-op (same fingerprint).
    const same = buildCheckpointSet({
      profileDigest: PROFILE, inputSchemaFor: () => ({ type: 'object' }), staticRows: false,
      tasks: [makeAction({ id: 'system.uptime', version: '1.0.0', scriptDigest: REVIEWED_UPTIME_DIGEST, script: 'uptime' })],
    }).definitions.find((d) => d.id.checkpointId === 'task.system.uptime')!;
    expect(definitionFingerprint(same)).toBe(definitionFingerprint(reviewed));
  });

  it('the full surface (no bounded env) still emits all 17 management rows + tasks (default #80 behaviour unchanged)', () => {
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const full = buildCheckpointSet({ profileDigest: PROFILE, inputSchemaFor: () => ({ type: 'object' }), tasks: registry.list() });
    expect(full.definitions.length).toBe(STATIC_CHECKPOINT_ROWS.length + 1);
  });
});

describe('a task row registers the schema of ITS definition, not a catalog lookup by name (linux-ops#98, found live on m1)', () => {
  it('a task the served catalog does not know yet (a new task; a held "re-version required" task) still registers serverId, so the candidate slot is declared', () => {
    // The growth paths (governed content poll, tasks.enable) publish BEFORE the
    // ops catalog is rebuilt with the incoming task: the lookup by name found
    // nothing, an EMPTY schema was registered, and the Platform refused the
    // definition (422 §4.2) on every tick — the library could never grow.
    const incoming = makeAction({ id: 'disk.usage', version: '1.0.1', serverScopes: ['*'], script: 'df -h', params: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'], additionalProperties: false } });
    const set = buildCheckpointSet({ profileDigest: PROFILE, inputSchemaFor: () => undefined, tasks: [incoming], staticRows: false });
    const [definition] = set.definitions;
    const records = new Map(set.schemaRecords.map((r) => [r.digest, r.bytesJson]));
    const schema = JSON.parse(records.get(definition!.inputSchema.schemaRecord)!) as { properties: Record<string, unknown>; required: string[] };
    expect(Object.keys(schema.properties)).toEqual(expect.arrayContaining(['serverId', 'reason', 'dryRun', 'reviewBinding', 'path']));
    expect(schema.required).toEqual(expect.arrayContaining(['serverId', 'reason', 'path']));
    expect(definition!.review?.candidateParameter).toBe('serverId');
    CheckpointDefinitionSchema.parse(definition);
  });

  it('one canonical rich source: the served catalog entry IS registrationSchemaForTask(task), and the Checkpoint schema record IS its enforceable projection (review 3218)', () => {
    const { registry, actions } = world();
    const set = buildCheckpointSet({ profileDigest: PROFILE, inputSchemaFor: () => undefined, tasks: registry.list(), staticRows: false });
    const records = new Map(set.schemaRecords.map((r) => [r.digest, r.bytesJson]));
    for (const task of registry.list()) {
      // Half one: no by-name lookup — the rich source the catalog serves is the one the registration starts from.
      const served = actions.find((a) => a.name === task.id)?.inputSchema as Record<string, unknown> | undefined;
      expect(served).toBeDefined();
      expect(registrationSchemaForTask(task)).toEqual(served);
      // Half two: the record the built Checkpoint cites is exactly the enforceable projection of that source — not the rich text (format / default / readOnly are projected away), and nothing else.
      const definition = set.definitions.find((d) => d.id.checkpointId === taskCheckpointId(task.id))!;
      const registered = JSON.parse(records.get(definition.inputSchema.schemaRecord)!) as Record<string, unknown>;
      expect(registered).toEqual(enforceableInputSchema(served!));
      expect(registered).not.toEqual(served);
      expect(Object.keys(registered['properties'] as Record<string, unknown>).sort()).toEqual(Object.keys(served!['properties'] as Record<string, unknown>).sort());
    }
  });

  it('a candidate slot the execution schema does not declare fails closed at build time, with the §4.2 sentence', () => {
    // The Widget-side mirror of the Platform's admission rule (what the
    // Platform answered with 422 on m1 for a task row registered with an EMPTY
    // schema): no definition with an undeclared candidateParameter can leave
    // this process.
    const id = { checkpointId: 'task.system.uptime', checkpointVersion: '1.0.1' };
    expect(() => assertCandidateParameterDeclared(id, 'serverId', EMPTY_INPUT_SCHEMA_BYTES)).toThrow(/task\.system\.uptime@1\.0\.1: review\.candidateParameter "serverId" is not a declared top-level property .*13 §4\.2/);
    expect(() => assertCandidateParameterDeclared(id, 'serverId', JSON.stringify({ type: 'object', properties: { serverId: { type: 'string' } } }))).not.toThrow();
    expect(() => assertCandidateParameterDeclared(id, undefined, EMPTY_INPUT_SCHEMA_BYTES)).not.toThrow();
    // …and the reference set really is built through it: every task row's schema declares `serverId`.
    const { registry } = world();
    expect(() => buildCheckpointSet({ profileDigest: PROFILE, inputSchemaFor: () => undefined, tasks: registry.list(), staticRows: false })).not.toThrow();
  });
});
