import { createHash } from 'node:crypto';
import type { CheckpointDefinition } from '@xtrape/contracts';
import type { ActionDefinition } from './types.js';
import { registrationSchemaForTask } from './ops-schema.js';

/**
 * The governance flip (linux-ops-widget-nodejs#79, owner plan A on #75): every
 * action this Widget serves — the 17 static management entries and every
 * enabled library task — is governed by an immutable Checkpoint, published
 * atomically with registration. The mapping table below is the one frozen on
 * #79 for review; changing a row is a reviewed change, not a local edit.
 *
 * Versioning: the management Checkpoints are ONE cohort pinned to
 * MGMT_CHECKPOINT_VERSION (its history sits beside the constant); a task Checkpoint's
 * version IS the task's declared semver `version` header — the platform's
 * byte-immutable registration then makes the model enforce itself: changing a
 * task's declared risk (or anything else that alters its definition) without
 * bumping its version is refused as an immutable-content conflict, and the
 * remedy is the version bump the form already requires.
 */

export const SERVICE_ID = 'linux-ops-widget-nodejs';
export const STATIC_EXTRACTOR_MEDIA_TYPE = 'application/vnd.xtrape.static-resource-extractor.v1+json';

/** JCS-equivalent canonical bytes for the simple ASCII documents built here (sorted keys, no whitespace). */
function canon(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canon).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${canon(v)}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

const sha256 = (bytes: string): string => `sha256:${createHash('sha256').update(bytes, 'utf8').digest('hex')}`;

/** Management surface: the Resource is this Widget itself. */
export const MGMT_ROOT_ARTIFACT_BYTES = canon({
  artifactKind: 'static-resource-extractor',
  contractVersion: 1,
  segments: [{ id: { kind: 'literal', value: SERVICE_ID }, type: 'service' }],
});
/**
 * Server-touching surfaces extract the EXACT field the action's real input
 * schema carries (review 2674 P1-2 — one artifact per field spelling, never
 * one spelling forced onto every action):
 * - library task runs name the target as `serverId`;
 * - the server-admin actions (testServer / recordProbedShells /
 *   rotateHostKey) name the admitted server as `id`;
 * - probeHostKey probes a HOST that need not be an admitted server at all —
 *   its Resource is the endpoint (`/host`), not a fabricated serverId.
 */
export const SERVER_TARGET_ARTIFACT_BYTES = canon({
  artifactKind: 'static-resource-extractor',
  contractVersion: 1,
  segments: [
    { id: { kind: 'literal', value: SERVICE_ID }, type: 'service' },
    { id: { kind: 'pointer', pointer: '/serverId' }, type: 'server' },
  ],
});
export const SERVER_BY_ID_ARTIFACT_BYTES = canon({
  artifactKind: 'static-resource-extractor',
  contractVersion: 1,
  segments: [
    { id: { kind: 'literal', value: SERVICE_ID }, type: 'service' },
    { id: { kind: 'pointer', pointer: '/id' }, type: 'server' },
  ],
});
/**
 * 13 v0.5 §4.2 (linux-ops#94, review 3209): a by-id TASK review (`enableTask
 * {id}` / `updateTask {id}`) is authorized against the task it names, not the
 * management root — the ordinary extractor over the review input.
 */
export const TASK_BY_ID_ARTIFACT_BYTES = canon({
  artifactKind: 'static-resource-extractor',
  contractVersion: 1,
  segments: [
    { id: { kind: 'literal', value: SERVICE_ID }, type: 'service' },
    { id: { kind: 'pointer', pointer: '/id' }, type: 'task' },
  ],
});
export const HOST_ENDPOINT_ARTIFACT_BYTES = canon({
  artifactKind: 'static-resource-extractor',
  contractVersion: 1,
  segments: [
    { id: { kind: 'literal', value: SERVICE_ID }, type: 'service' },
    { id: { kind: 'pointer', pointer: '/host' }, type: 'host' },
  ],
});
export const MGMT_ROOT_ARTIFACT_DIGEST = sha256(MGMT_ROOT_ARTIFACT_BYTES);
export const SERVER_TARGET_ARTIFACT_DIGEST = sha256(SERVER_TARGET_ARTIFACT_BYTES);
export const SERVER_BY_ID_ARTIFACT_DIGEST = sha256(SERVER_BY_ID_ARTIFACT_BYTES);
export const HOST_ENDPOINT_ARTIFACT_DIGEST = sha256(HOST_ENDPOINT_ARTIFACT_BYTES);
export const TASK_BY_ID_ARTIFACT_DIGEST = sha256(TASK_BY_ID_ARTIFACT_BYTES);

/** Every artifact this Widget publishes at bootstrap, digest-addressed. */
export const ALL_ARTIFACTS: ReadonlyArray<{ bytesJson: string; digest: string }> = [
  { bytesJson: MGMT_ROOT_ARTIFACT_BYTES, digest: MGMT_ROOT_ARTIFACT_DIGEST },
  { bytesJson: SERVER_TARGET_ARTIFACT_BYTES, digest: SERVER_TARGET_ARTIFACT_DIGEST },
  { bytesJson: SERVER_BY_ID_ARTIFACT_BYTES, digest: SERVER_BY_ID_ARTIFACT_DIGEST },
  { bytesJson: HOST_ENDPOINT_ARTIFACT_BYTES, digest: HOST_ENDPOINT_ARTIFACT_DIGEST },
  { bytesJson: TASK_BY_ID_ARTIFACT_BYTES, digest: TASK_BY_ID_ARTIFACT_DIGEST },
];

/**
 * The SHAPE of the projected task Checkpoint definition (linux-ops#94, review
 * 3209). A task Checkpoint versions with its task (`# version:`), so a Widget
 * release that changes what the projection DECLARES at a given task version —
 * shape 2 added the review face — cannot republish the same id@version with
 * different bytes (the Platform's immutable-conflict authority). The
 * migration contract is therefore explicit and non-destructive: an enabled
 * task records the shape it was published under; a task enabled under an
 * older shape is NOT republished or exposed by a newer Widget — it shows in
 * the library as "re-version required" until its `# version:` is bumped and
 * it is enabled again (which publishes the new definition at the new version).
 * Nothing is purged, nothing runs under a definition the Platform never admitted.
 */
export const TASK_CHECKPOINT_SHAPE = 2;

/**
 * Round-1 output schemas are a PERMISSIVE PLACEHOLDER, deliberately and
 * visibly: real per-action output schemas are the 0.8.7 completion item
 * (xtrape-exposure#30). Admitted INPUT schemas are the actions' real ones
 * PROJECTED onto the Platform-enforceable subset (below); the empty form
 * carries the same explicit `additionalProperties: false`, because a no-input
 * Checkpoint that admits arbitrary keys is not "empty".
 */
export const PLACEHOLDER_OUTPUT_SCHEMA_BYTES = '{"type":"object"}';
export const EMPTY_INPUT_SCHEMA_BYTES = '{"additionalProperties":false,"properties":{},"type":"object"}';
/** runtime-platform/13 v0.5 §4.2: the review request of a by-id review (`enableTask {id}`, `updateServer {id}`, `updateTask {id}`). */
export const ID_INPUT_SCHEMA_BYTES = '{"additionalProperties":false,"properties":{"id":{"type":"string"}},"required":["id"],"type":"object"}';
/**
 * 13 §4.2 / §5.4: the admitted shape of `next.currentState` — the review card
 * this Widget renders (`{ detail: { title, data, fields } }`, or nothing for
 * a review that shows no card). Classified under the Checkpoint's output
 * bound by the Platform; the shape is what it validates against.
 */
export const REVIEW_CARD_SCHEMA_BYTES = '{"additionalProperties":false,"properties":{"detail":{"type":"object"}},"type":"object"}';

/**
 * Project an Action's input schema onto the subset the Platform's execution
 * profile actually ENFORCES (linux-ops#82, the forgejo-ops#7/#9 discipline):
 * top-level `type` / `properties` / `required` / `additionalProperties:false`,
 * and property-level `type` ONLY. The M2a static profile fails CLOSED on
 * anything richer (503 EXECUTION_UNAVAILABLE, "only additionalProperties:false
 * is supported") — an admitted schema the enforcement build cannot enforce is
 * a declaration nobody checks. The richer constraints (enums, formats,
 * minima…) remain on the Widget's own Action surface and in its execute-time
 * validation: local narrowing, exactly where narrowing belongs.
 */
/**
 * The property types the Platform's enforcement build executes (#82 review
 * 2716 follow-up): mirrored from platform-ce `json-schema-subset.ts` as an
 * explicit ALLOWLIST, because "any string in `type`" recreates the failure
 * mode this projection exists to close — a `type: "null"` (or a typo) would
 * pass the Widget's own tests and answer 503 EXECUTION_UNAVAILABLE on the
 * Platform, exactly the Widget-green/Platform-503 split of the original bug.
 */
const ENFORCEABLE_PROPERTY_TYPES = new Set(['string', 'integer', 'number', 'boolean', 'object', 'array']);

const ANNOTATIONS = ['title', 'description'] as const;
function annotationsOf(node: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of ANNOTATIONS) if (typeof node[k] === 'string' && (node[k] as string).trim()) out[k] = node[k] as string;
  return out;
}

export function enforceableInputSchema(schema: Record<string, unknown>): Record<string, unknown> {
  const properties = (schema['properties'] ?? {}) as Record<string, Record<string, unknown>>;
  const projected: Record<string, unknown> = {};
  for (const [name, prop] of Object.entries(properties)) {
    // A property with no `type` — or one outside the enforced allowlist —
    // cannot be projected honestly: inventing or passing it through would
    // publish a Checkpoint the enforcement build refuses to run. Fail CLOSED
    // where the schema is built, so the defect is a build/test failure, not
    // a published Checkpoint nobody can invoke.
    if (typeof prop['type'] !== 'string') {
      throw new Error(`input schema property "${name}" declares no "type"; the enforceable projection cannot represent it`);
    }
    if (!ENFORCEABLE_PROPERTY_TYPES.has(prop['type'])) {
      throw new Error(
        `input schema property "${name}" declares type "${prop['type']}", which the Platform's enforcement build does not execute (allowed: ${[...ENFORCEABLE_PROPERTY_TYPES].join(', ')})`,
      );
    }
    // Annotations ride along (Widget Design Conventions §5, linux-ops#92):
    // the admitted record is ALL an AI host ever sees of this Action, and the
    // Platform's JSON-Schema subset admits `title` / `description` (platform-ce#306).
    projected[name] = { type: prop['type'], ...annotationsOf(prop) };
  }
  return {
    ...annotationsOf(schema),
    type: 'object',
    properties: projected,
    ...(Array.isArray(schema['required']) ? { required: schema['required'] } : {}),
    additionalProperties: false,
  };
}

type Target = 'mgmt' | 'server' | 'server-by-id' | 'host';
interface StaticRow {
  action: string;
  checkpointId: string;
  sideEffect: CheckpointDefinition['sideEffect'];
  risk: CheckpointDefinition['risk'];
  input: CheckpointDefinition['sensitivity']['inputUpperBound'];
  output: CheckpointDefinition['sensitivity']['outputUpperBound'];
  target: Target;
  /**
   * runtime-platform/13 v0.5 §4.2 (linux-ops#94): the two-phase rows declare
   * their review face. `input`: what the review request carries (`none` = an
   * entry-level review, `id` = the target is named up front); the review
   * Resource is Service-rooted either way (the management root — a review
   * reads, it never touches a server); `candidateParameter`: the execution
   * property whose choices go through the §4.3 candidate exchange;
   * `affinity`: `INCARNATION` when the review seals a binding under THIS
   * Worker's key (the execute must land on the same incarnation), `NONE` when
   * nothing sealed rides `next`.
   */
  review?: ReviewSpec;
}
interface ReviewSpec {
  input: 'none' | 'id';
  /** What the review is authorized against: the management root (an entry-level review), or the server / task the review input names (§4.2: "the ordinary extractor over review.inputSchema when the target is chosen"). */
  resource: 'mgmt' | 'server-by-id' | 'task-by-id';
  candidateParameter?: string;
  affinity: 'INCARNATION' | 'NONE';
}

/** The frozen #79 mapping table — one row per static management action. */
export const STATIC_CHECKPOINT_ROWS: readonly StaticRow[] = [
  // Widget Design Conventions §2 (linux-ops#92): the entry opens AS the list —
  // a read; every write is its own `_servers` / `_tasks` Checkpoint below.
  // The 17 rows are ONE version cohort at MGMT_CHECKPOINT_VERSION
  // (linux-ops#100): a change to ANY management definition bumps the cohort —
  // a published id@version is immutable, and one version per surface is the
  // discipline a persistent deployment can follow. No per-row override.
  { action: 'manageServers', checkpointId: 'servers.manage', sideEffect: 'READ_ONLY', risk: 'LOW', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'mgmt' },
  { action: 'listServers', checkpointId: 'servers.list', sideEffect: 'READ_ONLY', risk: 'LOW', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'mgmt' },
  { action: 'addServer', checkpointId: 'servers.add', sideEffect: 'MUTATING', risk: 'HIGH', input: 'SECRET', output: 'CONFIDENTIAL', target: 'mgmt' },
  // 13 v0.5 (linux-ops#94): the four two-phase management rows declare a review face.
  { action: 'updateServer', checkpointId: 'servers.update', sideEffect: 'MUTATING', risk: 'HIGH', input: 'SECRET', output: 'CONFIDENTIAL', target: 'mgmt', review: { input: 'id', resource: 'server-by-id', affinity: 'NONE' } },
  { action: 'removeServer', checkpointId: 'servers.remove', sideEffect: 'MUTATING', risk: 'HIGH', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'mgmt' },
  { action: 'testServer', checkpointId: 'servers.test', sideEffect: 'MUTATING', risk: 'MEDIUM', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'server-by-id' },
  { action: 'rotateHostKey', checkpointId: 'servers.rotate-host-key', sideEffect: 'MUTATING', risk: 'HIGH', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'server-by-id' },
  { action: 'recordProbedShells', checkpointId: 'servers.record-probed-shells', sideEffect: 'MUTATING', risk: 'MEDIUM', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'server-by-id' },
  { action: 'probeHostKey', checkpointId: 'servers.probe-host-key', sideEffect: 'MUTATING', risk: 'MEDIUM', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'host' },
  { action: 'manageTasks', checkpointId: 'tasks.manage', sideEffect: 'READ_ONLY', risk: 'LOW', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'mgmt' },
  { action: 'listTasks', checkpointId: 'tasks.list', sideEffect: 'READ_ONLY', risk: 'LOW', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'mgmt' },
  { action: 'viewTask', checkpointId: 'tasks.view', sideEffect: 'READ_ONLY', risk: 'LOW', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'mgmt' },
  // addTask / updateTask run NO candidate exchange (review 3209): `serverScope`
  // is a scope EXPRESSION ('*', an id, '(custom)'), not a Resource the
  // management-rooted execution extractor could normalize — the form keeps
  // its free choice, the Platform admits no enum on it.
  { action: 'addTask', checkpointId: 'tasks.add', sideEffect: 'MUTATING', risk: 'HIGH', input: 'CONFIDENTIAL', output: 'CONFIDENTIAL', target: 'mgmt', review: { input: 'none', resource: 'mgmt', affinity: 'NONE' } },
  { action: 'updateTask', checkpointId: 'tasks.update', sideEffect: 'MUTATING', risk: 'HIGH', input: 'CONFIDENTIAL', output: 'CONFIDENTIAL', target: 'mgmt', review: { input: 'id', resource: 'task-by-id', affinity: 'INCARNATION' } },
  { action: 'enableTask', checkpointId: 'tasks.enable', sideEffect: 'MUTATING', risk: 'HIGH', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'mgmt', review: { input: 'id', resource: 'task-by-id', affinity: 'INCARNATION' } },
  { action: 'disableTask', checkpointId: 'tasks.disable', sideEffect: 'MUTATING', risk: 'HIGH', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'mgmt' },
  { action: 'removeTask', checkpointId: 'tasks.remove', sideEffect: 'MUTATING', risk: 'HIGH', input: 'INTERNAL', output: 'CONFIDENTIAL', target: 'mgmt' },
];

const STATIC_BY_ACTION = new Map(STATIC_CHECKPOINT_ROWS.map((row) => [row.action, row]));

/**
 * Reviewed side-effect facts for the bounded reference profile's task
 * Checkpoints (linux-ops-widget-nodejs#81 review 2690 P1).
 *
 * A task is an opaque script — the framework cannot infer whether it changes
 * state — so `sideEffect` is a GOVERNANCE FACT the profile must DECLARE, not
 * something derived. It must NOT be derived from the legacy `# readonly:`
 * field: #61's owner ruling retired `readonly` as "parse-retained, authorization
 * IGNORED", and `sideEffect` is exactly a fact the Platform reads to choose
 * Approval / Confirmation / AUTO / DENY — so routing the retired field into
 * `sideEffect` would smuggle it back into the authorization decision.
 *
 * The 0.8.7 reference profile therefore names the two reviewed reference
 * Checkpoints' side effects here explicitly. Every other (dynamically grown)
 * task defaults to the fail-safe MUTATING: an un-reviewed task is assumed to
 * change state, which only ever TIGHTENS governance. A general, currently-valid
 * per-task side-effect declaration is the 0.9.x dynamic-governance concern
 * (linux-ops#78 / connector#98), deliberately deferred here under the Second
 * OSS scope-freeze (docs#270 c19644).
 *
 * The fact binds to EXACT reviewed-content identity — id + version +
 * scriptDigest — not to the logical name alone (linux-ops#81 review 2691).
 * `TaskDb` revisions allow the same `id@version` to hold different script
 * bytes; if the fact keyed on `task.system.uptime` alone, a revision that
 * swapped `uptime` for a side-effecting script would inherit READ_ONLY. So a
 * byte change that does not bump the version FAILS the match and falls to the
 * conservative MUTATING (and collides with the already-published immutable
 * READ_ONLY Checkpoint at that id@version — forcing a version bump + re-review),
 * exactly the exact-immutable-binding #77 requires.
 */
export const REVIEWED_UPTIME_DIGEST = 'sha256:f55a9132f540e3ddb2ebd7b62c3b97bef1207ba8aa5aac11c69a7a3af4916154';
interface ReferenceSideEffectFact {
  readonly version: string;
  readonly scriptDigest: string;
  readonly sideEffect: CheckpointDefinition['sideEffect'];
}
const REFERENCE_TASK_SIDE_EFFECTS: Readonly<Record<string, ReferenceSideEffectFact>> = {
  // The reviewed READ_ONLY read: the exact bytes of examples/tasks/system-uptime.sh
  // (a test pins REVIEWED_UPTIME_DIGEST to that file, failing loudly on any edit).
  'task.system.uptime': { version: '1.0.0', scriptDigest: REVIEWED_UPTIME_DIGEST, sideEffect: 'READ_ONLY' },
  // task.service.restart is the approval-gated write → MUTATING (the default).
};

/**
 * Bounded reference profile (linux-ops-widget-nodejs#77): a deployment may
 * expose only a NAMED SUBSET of this Widget's Checkpoints — the Second OSS
 * proof ships one real read + one approval-gated write, not the whole 17-Action
 * management surface. `LINUX_OPS_BOUNDED_CHECKPOINTS` is a comma-separated
 * allowlist of checkpointIds (management ids like `servers.list`, or task ids
 * like `task.service.restart`). When set, ONLY those Checkpoints are published
 * and only the Actions bound to them appear in the catalog; when ABSENT the
 * full surface is exposed (the #79/#80 default is unchanged). This is a
 * per-deployment exposure narrowing, NOT a partial-governed mode — every
 * exposed Action is still fully governed (docs#273 / #77: no partial-governed
 * semantic in Platform or Connector).
 */
export function parseBoundedCheckpoints(raw: string | undefined): ReadonlySet<string> | null {
  // ABSENT = the profile is off (full surface). PRESENT = the operator asked
  // to narrow — a present-but-empty/whitespace value is a MISCONFIGURED
  // security control, and a control that narrows exposure must NEVER degrade
  // into maximum exposure on misconfiguration (review 2688). Fail closed: the
  // caller (startup) refuses to run rather than exposing everything.
  if (raw === undefined) return null;
  const ids = raw.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
  if (ids.length === 0) {
    throw new Error(
      'LINUX_OPS_BOUNDED_CHECKPOINTS is set but names no Checkpoint — a bounded profile that narrows exposure must not fall back to the full surface. Unset it to expose everything, or name at least one checkpointId.',
    );
  }
  return new Set(ids);
}

/** True when `checkpointId` is exposed under the current bounded profile. */
export function isCheckpointExposed(checkpointId: string, bounded: ReadonlySet<string> | null): boolean {
  return bounded === null || bounded.has(checkpointId);
}

const KEBAB_ID = /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*$/; // dot-separated kebab, the checkpointId grammar itself
const TASK_VERSION = /^\d+\.\d+\.\d+$/;

export function taskCheckpointId(taskId: string): string {
  if (!KEBAB_ID.test(taskId)) {
    // Task ids are normalized kebab (#53's sealed enable binding); a
    // non-conforming id cannot become a Checkpoint identity and fails closed
    // HERE, at publication, not at the platform's parse.
    throw new Error(`task id "${taskId}" is not a dot-separated lowercase-kebab Checkpoint identity`);
  }
  return `task.${taskId}`;
}

/**
 * The version every management row publishes at. A PUBLISHED id@version is
 * immutable on every Platform that holds it; a definition that changes takes
 * a new version — never new bytes under the old one. History:
 *
 * - 1.0.1 (linux-ops#82): the admitted input schema moved onto the Platform's
 *   enforceable subset. 1.0.0 cited the richer Action schemas, whose extra
 *   keywords the enforcement build refuses (503 EXECUTION_UNAVAILABLE) — every
 *   management Checkpoint published but none could execute.
 * - 1.0.2 (linux-ops#100): #93 put every field's title / description into the
 *   admitted schema record and #92/#94 re-gated the entries and gave the four
 *   two-phase rows a review face. Six rows took 1.0.2 then; the other eleven kept
 *   publishing CHANGED bytes as 1.0.1 — invisible on m1-local, which is purged
 *   on every rebuild, and refused by the first persistent Platform to upgrade
 *   (host2, 2026-09-07: `CHECKPOINT_IMMUTABLE_CONFLICT servers.list@1.0.1`).
 *   So the whole surface is one cohort at 1.0.2. test/frozen-management-
 *   definitions.json snapshots each id@version's canonical bytes: a changed
 *   definition is an explicit snapshot diff in review, and the review rule
 *   (AGENTS.md) is that an existing pin is never edited — the cohort version
 *   bumps and the new identities are pinned beside it.
 *
 * Task Checkpoints version with their task (`# version:`) under the shape
 * contract above (TASK_CHECKPOINT_SHAPE): a task enabled under an older shape
 * is not republished — it waits for its own version bump.
 */
export const MGMT_CHECKPOINT_VERSION = '1.0.2';

/** The static binding an action entry carries in the live catalog. */
export function checkpointRefFor(actionName: string, taskVersion?: string): { serviceId: string; checkpointId: string; checkpointVersion: string } {
  const row = STATIC_BY_ACTION.get(actionName);
  if (row) return { serviceId: SERVICE_ID, checkpointId: row.checkpointId, checkpointVersion: MGMT_CHECKPOINT_VERSION };
  if (taskVersion === undefined) throw new Error(`action "${actionName}" is not a management action and no task version was given`);
  if (!TASK_VERSION.test(taskVersion)) throw new Error(`task "${actionName}" declares version "${taskVersion}", not core SemVer x.y.z`);
  return { serviceId: SERVICE_ID, checkpointId: taskCheckpointId(actionName), checkpointVersion: taskVersion };
}

const RISK_MAP: Record<string, CheckpointDefinition['risk']> = { low: 'LOW', medium: 'MEDIUM', high: 'HIGH', critical: 'CRITICAL' };

export interface BuiltCheckpointSet {
  definitions: CheckpointDefinition[];
  schemaRecords: { bytesJson: string; dialect: string; digest: string }[];
}

const SCHEMA_DIALECT = 'https://json-schema.org/draft/2020-12/schema';

/**
 * Build every definition of the current authority snapshot: the 17 static
 * rows plus one `task.<id>@<version>` per enabled task. Input schemas are the
 * actions' real ones (keyed by action name); outputs are the visible
 * placeholder above. All conservative axes are the legal fail-closed
 * combination: NON_IDEMPOTENT (reads: IDEMPOTENT) / AT_MOST_ONCE / NONE / SYNC.
 */
/**
 * runtime-platform/13 §4.2, mirrored on the Widget side so an undeclared
 * candidate slot fails at BUILD time with a sentence — not at the Platform with
 * a 422 on every poll tick (linux-ops#98, found live on m1): the parameter a
 * review's §4.3 exchange fills must be a declared top-level property of the
 * execution schema this very definition registers.
 */
export function assertCandidateParameterDeclared(
  id: { checkpointId: string; checkpointVersion: string },
  candidate: string | undefined,
  inputSchemaBytes: string,
): void {
  if (candidate === undefined) return;
  const properties = (JSON.parse(inputSchemaBytes) as { properties?: Record<string, unknown> }).properties ?? {};
  if (!Object.prototype.hasOwnProperty.call(properties, candidate)) {
    throw new Error(
      `checkpoint ${id.checkpointId}@${id.checkpointVersion}: review.candidateParameter "${candidate}" is not a declared top-level property of its execution inputSchema (runtime-platform/13 §4.2)`,
    );
  }
}

export function buildCheckpointSet(opts: {
  profileDigest: string;
  /** The management rows' schemas, by catalog entry name. Task rows derive theirs from the definition (ops-schema.ts). */
  inputSchemaFor: (actionName: string) => Record<string, unknown> | undefined;
  tasks: ReadonlyArray<ActionDefinition>;
  /** false = task definitions only (the online-growth path); default true. */
  staticRows?: boolean;
  /** #77 bounded profile: publish only these checkpointIds (null = full surface). */
  bounded?: ReadonlySet<string> | null;
}): BuiltCheckpointSet {
  const bounded = opts.bounded ?? null;
  const schemaRecords = new Map<string, { bytesJson: string; dialect: string; digest: string }>();
  const addSchema = (bytesJson: string): string => {
    const digest = sha256(bytesJson);
    if (!schemaRecords.has(digest)) schemaRecords.set(digest, { bytesJson, dialect: SCHEMA_DIALECT, digest });
    return digest;
  };
  const outputDigest = addSchema(PLACEHOLDER_OUTPUT_SCHEMA_BYTES);
  // 13 v0.5 §4.2: the review face of a two-phase Checkpoint — its own admitted
  // request schema, the Service-rooted review Resource (the management root:
  // a review reads configuration, it never reaches a server), the card
  // schema, the execution risk, the declared affinity and candidate slot.
  const reviewFace = (spec: ReviewSpec, risk: CheckpointDefinition['risk']): NonNullable<CheckpointDefinition['review']> => ({
    inputSchema: { schemaRecord: addSchema(spec.input === 'id' ? ID_INPUT_SCHEMA_BYTES : EMPTY_INPUT_SCHEMA_BYTES) },
    resource: {
      kind: 'extractor-artifact',
      artifactDigest: spec.resource === 'server-by-id' ? SERVER_BY_ID_ARTIFACT_DIGEST : spec.resource === 'task-by-id' ? TASK_BY_ID_ARTIFACT_DIGEST : MGMT_ROOT_ARTIFACT_DIGEST,
      executionProfileRecord: opts.profileDigest,
    },
    outputSchema: { schemaRecord: addSchema(REVIEW_CARD_SCHEMA_BYTES) },
    risk,
    affinity: spec.affinity,
    ...(spec.candidateParameter !== undefined ? { candidateParameter: spec.candidateParameter } : {}),
  });

  const definition = (
    id: { checkpointId: string; checkpointVersion: string },
    actionId: string,
    row: Pick<StaticRow, 'sideEffect' | 'risk' | 'input' | 'output' | 'target' | 'review'>,
    inputSchema: Record<string, unknown> | undefined,
  ): CheckpointDefinition => {
    const inputSchemaBytes = inputSchema ? canon(enforceableInputSchema(inputSchema)) : EMPTY_INPUT_SCHEMA_BYTES;
    assertCandidateParameterDeclared(id, row.review?.candidateParameter, inputSchemaBytes);
    return {
      contractVersion: 1,
      id: { serviceId: SERVICE_ID, ...id },
      inputSchema: { schemaRecord: addSchema(inputSchemaBytes) },
      outputSchema: { schemaRecord: outputDigest },
      resourceExtraction: {
        kind: 'extractor-artifact',
        artifactDigest:
          row.target === 'server'
            ? SERVER_TARGET_ARTIFACT_DIGEST
            : row.target === 'server-by-id'
              ? SERVER_BY_ID_ARTIFACT_DIGEST
              : row.target === 'host'
                ? HOST_ENDPOINT_ARTIFACT_DIGEST
                : MGMT_ROOT_ARTIFACT_DIGEST,
        executionProfileRecord: opts.profileDigest,
      },
      sideEffect: row.sideEffect,
      risk: row.risk,
      sensitivity: { inputUpperBound: row.input, outputUpperBound: row.output },
      idempotency: row.sideEffect === 'READ_ONLY' ? 'IDEMPOTENT' : 'NON_IDEMPOTENT',
      delivery: 'AT_MOST_ONCE',
      retry: 'NONE',
      execution: 'SYNC',
      action: { actionId },
      localPreconditions: [],
      ...(row.review ? { review: reviewFace(row.review, row.risk) } : {}),
    };
  };

  const definitions: CheckpointDefinition[] = (opts.staticRows === false ? [] : STATIC_CHECKPOINT_ROWS)
    .filter((row) => isCheckpointExposed(row.checkpointId, bounded))
    .map((row) =>
      definition({ checkpointId: row.checkpointId, checkpointVersion: MGMT_CHECKPOINT_VERSION }, row.action, row, opts.inputSchemaFor(row.action)),
    );
  for (const task of opts.tasks) {
    const risk = RISK_MAP[task.riskLevel];
    if (!risk) throw new Error(`task "${task.id}" declares unknown risk "${task.riskLevel}"`);
    const ref = checkpointRefFor(task.id, task.version);
    if (!isCheckpointExposed(ref.checkpointId, bounded)) continue;
    // sideEffect is a GOVERNANCE FACT the Platform reads to choose Approval /
    // Confirmation / AUTO / DENY, so it must be DECLARED, never derived from the
    // retired `# readonly:` field (#61: parse-retained, authorization ignored —
    // deriving here would route it straight back into the authz decision, review
    // 2690 P1). The reviewed reference profile names its reads explicitly, bound
    // to EXACT reviewed-content identity — id + version + scriptDigest (review
    // 2691): a revision that reused this id@version with different bytes does
    // NOT match and falls to the fail-safe MUTATING. Every other task defaults
    // to MUTATING too (an un-reviewed task is assumed to change state).
    const fact = REFERENCE_TASK_SIDE_EFFECTS[ref.checkpointId];
    const sideEffect =
      fact && fact.version === task.version && fact.scriptDigest === task.scriptDigest ? fact.sideEffect : 'MUTATING';
    definitions.push(
      definition(
        { checkpointId: ref.checkpointId, checkpointVersion: ref.checkpointVersion },
        task.id,
        {
          sideEffect,
          risk,
          input: 'CONFIDENTIAL',
          // Conservative output bound regardless of side effect: #61's "a
          // read-only task can read secrets" is honoured HERE, in sensitivity.
          output: 'CONFIDENTIAL',
          target: 'server',
          // 13 v0.5 (linux-ops#94): every task run is two-phase — an
          // entry-level review that renders the card, seals the reviewBinding
          // under THIS Worker's key (⇒ INCARNATION) and offers the target
          // choice through the §4.3 exchange on `serverId`.
          review: { input: 'none', resource: 'mgmt', candidateParameter: 'serverId', affinity: 'INCARNATION' },
        },
        // From the definition, NOT a catalog lookup by name (linux-ops#98): the
        // growth paths publish BEFORE the catalog is rebuilt with this task.
        registrationSchemaForTask(task),
      ),
    );
  }
  return { definitions, schemaRecords: [...schemaRecords.values()] };
}

/**
 * Fingerprint over the FULL Checkpoint definition (linux-ops#81 review 2692).
 * The local "already published" cache keys on this, NOT on `id@version`, so a
 * revision that reused a known id@version with a different definition (drifted
 * bytes flipping sideEffect, or changed risk / schema) produces a DIFFERENT
 * fingerprint, is not suppressed, and reaches the Platform's immutable-conflict
 * authority. Only a byte-for-byte identical definition is skipped.
 */
export function definitionFingerprint(d: CheckpointDefinition): string {
  return createHash('sha256').update(JSON.stringify(d), 'utf8').digest('hex');
}
