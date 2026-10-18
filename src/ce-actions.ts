import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { CeServiceActionDefinition, CeActionPrepareResult, CePrepareContext } from '@xtrape/connector';
import { CommandOriginSchema, type CommandOrigin } from '@xtrape/contracts';
import type { ActionDefinition, CommandResult, ServerDefinition } from './types.js';
import type { ActionRegistry } from './registry.js';
import { probeTargetSnapshot, type ProbeTargetSnapshot, type ServerStore, type ServerInput } from './servers.js';
import type { TaskDb } from './task-db.js';
import { renderTaskFile, splitTaskSource, type TaskParts } from './task-file.js';
import { checkpointRefFor, enforceableInputSchema } from './checkpoints.js';
import { describedAction } from './schema-titles.js';
import { opsEntryText, opsInputSchema, paramProps, policyNotice } from './ops-schema.js';
import { RedlineSet, verdictOf, type RedlineHit } from './redlines.js';
import type { ContentSource } from './content-source.js';
import { ParamGuardSet } from './param-guards.js';
import type { OpsService, OpsResponse } from './service.js';
import type { AuditLogger } from './audit.js';
import { sanitizeMessage } from './service.js';
import { HostKeyMismatchError } from './executors/ssh.js';
import { interpreterNotices } from './interpreter-check.js';

/**
 * Build the CE action catalog served to the Platform. Two kinds of visible entry
 * actions — each ops capability (independently registered, carrying its own
 * metadata; no `runOps` dispatcher) and `manageServers` — plus hidden server
 * management sub-ops (reserved `_servers` category the Panel filters out,
 * reachable from the manageServers list affordances).
 *
 * Action names, the `_servers` category, the `serverId` input key and the
 * failure codes below are frozen wire identifiers — the concept-correction pass
 * does not rewrite them. See xtrape-docs runtime-platform/10 for the entry
 * action + hidden sub-op + inline affordance model.
 */
export interface BuildCeActionsDeps {
  /**
   * GROW BEFORE EXPOSE (#79): durably publish the Checkpoints of these tasks
   * (idempotent per id+version) before their ops entries reach the live
   * catalog. Wired by the entrypoint once the serve handle exists; absent in
   * unit harnesses that never publish.
   */
  ensureTaskCheckpoints?: (tasks: ReadonlyArray<ActionDefinition>) => Promise<void>;
  /**
   * #77 bounded profile: is this Checkpoint exposed? Applied INSIDE the live
   * catalog build (management entries + every rebuildOps) so the array the
   * Connector holds by reference is bounded at all times — a startup-only
   * `.filter()` on the returned array would desync, because rebuildOps mutates
   * the original array in place (review 2688). Default: everything exposed.
   */
  isCheckpointExposed?: (checkpointId: string) => boolean;
  registry: ActionRegistry;
  store: ServerStore;
  opsService: OpsService;
  /** Read-only reachability probe for testServer (a trivial command over the executor). */
  probe: (server: ServerDefinition) => Promise<CommandResult>;
  /** Credential-free host key fetch for probeHostKey (#44) — key exchange only, admits nothing. */
  probeHostKey: (host: string, port?: number) => Promise<string>;
  /**
   * Which interpreters the target has (#69): the names `command -v` resolves
   * on the host, observed over the executor. Optional seam: without it,
   * testServer records nothing about interpreters and cards say "unprobed".
   */
  probeShells?: (server: ServerDefinition) => Promise<string[]>;
  /** Test seam only: the per-incarnation review-binding key (defaults to fresh random bytes). */
  reviewKey?: Buffer;
  /** The task library's two-state file store (#55). */
  taskStore: TaskDb;
  /** The redline set screened at review time (#65); absent = no screening. */
  /**
   * Required, even when empty (reviews 2403 / 2404): as optional deps these
   * defaulted to empty sets, so a composition root that forgot one screened
   * NOTHING while every card still said "screened". A deployment with no
   * rules now has to say so.
   */
  redlines: RedlineSet;
  /** Parameter guards, named on the run panel so a caller knows what will ask (#66). */
  paramGuards: ParamGuardSet;
  /**
   * The governed content source, when this library's authority lives at a
   * governance side rather than here (xtrape-docs#255). Present = this Widget
   * keeps only the latest effective version: edits become SUBMISSIONS, and
   * the lifecycle actions refuse and point at the review instead.
   */
  content?: {
    source: ContentSource;
    path: (taskId: string) => string;
  };
  /**
   * Handed this catalog's own rebuild so a change that did NOT come through
   * an action — a governed content version applied by the poll — can refresh
   * the published ops entries the same way an Enable does.
   */
  onRebuildAvailable?: (rebuild: () => void) => void;
  /** Local evidence log; task-library lifecycle events land here (review 2329). */
  audit?: AuditLogger;
}

/**
 * The review-to-execution binding, made UNFORGEABLE (review 2324): a plain
 * digest field is caller-writable — deletable to skip the check, replaceable
 * with another Worker's digest to convert a review of A into a run of B. So
 * the prepare seals the reviewed digest under an HMAC keyed by a secret this
 * WORKER INCARNATION minted at startup: no caller holds the key, so the token
 * cannot be minted or altered; a different Worker (Platform fallback) or a
 * restarted one holds a different key, so their executes fail CLOSED and the
 * operator re-opens the action against the live state — 'pin the original
 * Worker incarnation', per the review's own alternative.
 */
const REVIEW_BINDING_PREFIX = 'rv1';
// Domain separation: the SAME incarnation key also seals task-enable
// approvals (review 2331 item 1), and without a distinct prefix inside the
// MAC input, an ops run token for digest X would double as an enable
// approval for digest X. Different claim, different domain string.
const TASK_ENABLE_BINDING_PREFIX = 'rvt1';
/** Domain for the token naming the stored revision an Edit is based on (review 2393). */
const TASK_EDIT_BINDING_PREFIX = 'rvb1';
/** Domain of the sealed interpreter-probe observation (#69, review 2480): testServer seals, recordProbedShells verifies. */
const PROBE_BINDING_PREFIX = 'prb1';
function sealReviewBinding(key: Buffer, digest: string, domain: string = REVIEW_BINDING_PREFIX): string {
  const mac = createHmac('sha256', key).update(`${domain}.${digest}`).digest('base64url');
  return `${domain}.${Buffer.from(digest, 'utf8').toString('base64url')}.${mac}`;
}
function unsealReviewBinding(key: Buffer, token: string, domain: string = REVIEW_BINDING_PREFIX): string | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== domain) return null;
  let digest: string;
  try {
    digest = Buffer.from(parts[1]!, 'base64url').toString('utf8');
  } catch {
    return null;
  }
  const expected = createHmac('sha256', key).update(`${domain}.${digest}`).digest();
  let presented: Buffer;
  try {
    presented = Buffer.from(parts[2]!, 'base64url');
  } catch {
    return null;
  }
  if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) return null;
  return digest;
}

const asRecord = (input: unknown): Record<string, unknown> =>
  input && typeof input === 'object' && !Array.isArray(input) ? (input as Record<string, unknown>) : {};
const str = (v: unknown): string => (typeof v === 'string' ? v : '');
/**
 * What the run panel must answer before anyone dares press Execute (#48):
 * WHAT runs (the script, verbatim, plus the digest audit pins), WHERE it may
 * run (declared scopes and the servers currently eligible), and under WHICH
 * rules (risk, side effects, approval). The script is not a secret — caller
 * input never enters its body (parameters ride as environment variables) —
 * and reviewing it here is what makes the audit happen on the Platform
 * surface instead of on the Widget host's filesystem.
 */
/**
 * runtime-platform/13 v0.5 (linux-ops#94): a prepare handler answers on TWO
 * doors. The governed REVIEW (World A delivery, or the dial `/review` door)
 * reaches it through the Connector's prepare alias WITH `filterResources` —
 * there, `next.inputSchema` must be a §5.2 narrowing of the ADMITTED record
 * (the enforceable projection: type + title/description per property) and
 * an added `enum` may carry only what the §4.3 exchange returned. The legacy
 * `/prepare` door has no exchange and keeps the rich local schema.
 */
function governedReview(ctx: CePrepareContext | undefined): boolean {
  return typeof ctx?.filterResources === 'function';
}

/**
 * §4.3 / arch/16 §8.1: the candidates travel to the Platform, only what comes
 * back is offered — and NONE is an explicit refusal, never an empty picker
 * (an empty list reads as "nothing exists", not "nothing is permitted").
 */
async function admittedCandidates(ctx: CePrepareContext | undefined, candidates: string[], what: string): Promise<string[]> {
  if (!governedReview(ctx)) return candidates;
  const admitted = await ctx!.filterResources!(candidates);
  if (admitted.length === 0) {
    throw new Error(`no ${what} is authorized for this session (runtime-platform/13 §4.3): ${candidates.length === 0 ? 'nothing is admitted — admit one via manageServers' : 'the session\'s authorization covers none of the admitted candidates'}`);
  }
  return admitted;
}

/** The admitted projection of `schema`, with the exchange's answer as the ONLY added enum (13 §5.2). */
function reviewNextSchema(schema: Record<string, unknown>, narrowed?: { property: string; values: string[] }): Record<string, unknown> {
  const projected = enforceableInputSchema(schema);
  const props = projected['properties'] as Record<string, Record<string, unknown>>;
  // 13 §5.2 lets a review ADD or CHANGE `title` / `description` / `default` /
  // `readOnly` on a property (linux-ops#96): the rich schema's `readOnly`
  // (the sealed reviewBinding / baseRevision) and `default` ride the
  // narrowing, so the consumer renders them as the author meant — locked,
  // prefilled — without any keyword the admitted record does not carry.
  const rich = (schema['properties'] ?? {}) as Record<string, Record<string, unknown>>;
  for (const [name, prop] of Object.entries(rich)) {
    if (!props[name]) continue;
    if (prop['readOnly'] === true) props[name] = { ...props[name], readOnly: true };
    if (prop['default'] !== undefined) props[name] = { ...props[name], default: prop['default'] };
  }
  if (narrowed) props[narrowed.property] = { ...props[narrowed.property], enum: narrowed.values };
  return projected;
}

function opsPrepareDetail(action: ActionDefinition, eligible: string[], paramGuards: string[] = [], servers: ServerDefinition[] = []): Record<string, unknown> {
  // Executability (#69): the shebang's interpreter against what each eligible
  // target is known to have — said HERE, on the card, not as an exit 127.
  const avail = interpreterNotices(action.interpreter, servers.filter((sv) => eligible.includes(sv.id)));
  const interpreterLine = `${action.interpreter} (executor: ${action.executor})${avail.missing.length ? ` — MISSING on ${avail.missing.join(', ')}` : ''}${avail.unknown.length ? ` — unprobed on ${avail.unknown.join(', ')}` : ''}`;
  return {
    detail: {
      // The display name a reviewer reads, with the id kept beside it — the
      // id is the wire name, the title is what a person recognizes (#61 /
      // review 2370).
      title: `${action.title ? `${action.title} (${action.id})` : action.id} — what this will run`,
      data: {
        description: action.description ?? '',
        risk: `${action.riskLevel}${policyNotice(action).length > 0 ? ` — ${policyNotice(action).join('; ')}` : ' — runs automatically'}`,
        serverScopes: action.serverScopes.join(', '),
        eligibleServers: eligible.length ? eligible.join(', ') : '(none — no admitted server matches; admit one via manageServers)',
        // What the ARGUMENTS can trigger (#66): named up front, because a
        // caller should know which values will stop and ask before they
        // type them, not after.
        ...(paramGuards.length > 0 ? { paramGuards: paramGuards.join('\n') } : {}),
        interpreter: interpreterLine,
        ...(avail.lines.length > 0 ? { interpreterAvailability: avail.lines.join('\n') } : {}),
        sourceFile: action.sourceFile,
        scriptDigest: action.scriptDigest,
        script: action.script,
      },
      fields: [
        { key: 'description', label: 'What it does' },
        { key: 'risk', label: 'Risk & approval' },
        { key: 'serverScopes', label: 'Server scopes' },
        { key: 'eligibleServers', label: 'Eligible servers (now)' },
        ...(paramGuards.length > 0 ? [{ key: 'paramGuards', label: '参数风控', format: 'pre' }] : []),
        { key: 'interpreter', label: 'Runs via' },
        ...(avail.lines.length > 0 ? [{ key: 'interpreterAvailability', label: 'Interpreter on targets (#69)', format: 'pre' }] : []),
        { key: 'sourceFile', label: 'Task file', format: 'code' },
        // The digest is the same value the audit trail pins, so what you
        // reviewed and what ran are mechanically the same bytes.
        { key: 'scriptDigest', label: 'Script digest', format: 'code', copyable: true },
        { key: 'script', label: 'Script (exactly what runs)', format: 'pre' },
      ],
    },
  };
}

/**
 * Map an OpsResponse to a CE execute result. Non-executed / failed outcomes
 * RETURN `{ success: false, error: { code } }` rather than throwing: the SDK
 * forwards a returned structured error verbatim (thrown errors collapse to a
 * generic ACTION_FAILED), so distinct codes reach Platform and operators
 * (#27, archived review). Every failure code is a stable non-executed/failed
 * signal.
 */
function fail(code: string, message: string, data?: Record<string, unknown>): Record<string, unknown> {
  return { success: false, message, error: { code, message }, ...(data ? { data } : {}) };
}

function mapOps(response: OpsResponse): Record<string, unknown> {
  switch (response.status) {
    case 'executed':
      // The execution result rides FLAT in `data` (owner design intent,
      // 2026-08-20): the Panel tabulates data's entries, and a caller reads
      // `data.exitCode`, not `data.result.exitCode` — the extra `result`
      // level carried no information.
      return { success: true, message: 'executed', data: { ...response.result } };
    case 'dry_run':
      return { success: true, message: 'dry run (not executed)', data: { command: response.command, scriptDigest: response.scriptDigest } };
    case 'denied': {
      // Input/validation-class denials carry a distinct code from policy denials.
      const validationRules = new Set(['unknown-action', 'unknown-server', 'args-schema', 'missing-reason', 'unknown-executor']);
      // The mcp-readonly rule (and its MCP_READ_ONLY code) retired with the
      // hard-read-only model (#53 P1.5): the graded surface escalates instead
      // of denying, so no deny carries that rule anymore.
      // Executability (#69) is not policy: the target is KNOWN to lack the
      // interpreter, so the run cannot happen there — its own code, so a
      // caller can tell "not runnable here" from "not allowed" (and from
      // the script's own exit 127).
      if (response.rule === 'interpreter-unavailable') return fail('NOT_EXECUTABLE', `not executable (${response.rule}): ${response.reason}`);
      const code = validationRules.has(response.rule) ? 'VALIDATION_FAILED' : 'POLICY_DENIED';
      return fail(code, `denied (${response.rule}): ${response.reason}`);
    }
    case 'requires_approval':
      return fail('HUMAN_REVIEW_UNAVAILABLE', `requires human approval (${response.rule}): ${response.reason} — no way to put the question to a person is configured, so the task is stopped rather than run`);
    case 'confirmation_refused':
      // Not a policy denial: policy allowed the question to be put, and a
      // person answered no. Saying POLICY_DENIED would misname who decided.
      return fail(
        'CONFIRMATION_REFUSED',
        `a person declined this run (${response.rule})${response.answeredBy === undefined ? '' : ` — answered by ${response.answeredBy}`}`,
      );
    case 'command_failed':
      // `exitCode` is optional because an executor may not have observed one.
      // Where that happens for a known reason it is its own status above; here
      // it can only mean an executor reported neither, so say that rather than
      // print "exited undefined".
      return fail(
        'COMMAND_FAILED',
        response.result.exitCode === undefined
          ? 'task failed and no exit status was reported'
          : `task exited ${String(response.result.exitCode)}`,
        { ...response.result },
      );
    case 'output_limit':
      // Deliberately not phrased as an exit status. The channel was closed at
      // the output ceiling, so nothing observed the task finishing and the
      // remote command may still be running — a caller deciding whether to
      // retry needs to be told that, not handed a number that was made up.
      return fail(
        'OUTPUT_LIMIT_EXCEEDED',
        'output limit reached; the channel was closed and the remote outcome is unknown — the task may still be running on the target',
        { ...response.result },
      );
    case 'error':
      return fail('ACTION_ERROR', response.message);
  }
}

/** The review card of a server edit (linux-ops#94): the public view, field by field, no secret. */
function serverDetailDisplay(s: ServerDefinition): Record<string, unknown> {
  const pub = publicServer(s);
  return {
    detail: {
      title: `Edit server ${s.id} — current configuration`,
      data: Object.fromEntries(Object.entries(pub).map(([k, v]) => [k, v === undefined || v === null ? '' : String(v)])),
      fields: Object.keys(pub).map((key) => ({ key, label: key })),
    },
  };
}

function publicServer(s: ServerDefinition): Record<string, unknown> {
  // hostKeyFingerprint is a digest of a public key: it is shown, not hidden —
  // the operator has to be able to compare it against the host.
  return {
    id: s.id,
    host: s.host,
    port: s.port ?? 22,
    username: s.username,
    environment: s.environment,
    // The method is configuration, not a secret; blank = a legacy entry with
    // no usable credential (inert until reconfigured).
    authMethod: s.authMethod ?? '',
    // Secrets are shown ONLY as presence booleans — the values (private key,
    // password, key passphrase) are write-only and never leave the store.
    keyConfigured: Boolean(s.privateKey),
    passwordConfigured: Boolean(s.password),
    passphraseConfigured: Boolean(s.passphrase),
    hostKeyFingerprint: s.hostKeyFingerprint ?? '',
    hostKeyAdmitted: Boolean(s.hostKeyFingerprint),
    // `operator` vs `first-use` is worth a column (#44): a first-use pin
    // protects against later substitution, not an impostor already answering
    // at first contact — the operator should see which trust they hold.
    hostKeyAdmittedBy: s.hostKeyAdmittedBy ?? '',
    // What the target can run (#69): known interpreters, and whether that
    // knowledge is a probe's observation or an operator's declaration.
    shells: s.shells === undefined ? '' : s.shells.join(', '),
    shellsSource: s.shells === undefined ? 'unprobed' : (s.shellsSource ?? 'declared'),
    shellsProbedAt: s.shellsProbedAt ?? '',
  };
}

function serversListDisplay(servers: ServerDefinition[]): Record<string, unknown> {
  return {
    title: 'Managed Servers',
    data: servers.map(publicServer),
    columns: [
      { key: 'id', label: 'Server', format: 'code', copyable: true },
      { key: 'host', label: 'Host' },
      { key: 'port', label: 'Port' },
      { key: 'username', label: 'User' },
      { key: 'environment', label: 'Env', format: 'status' },
      { key: 'authMethod', label: 'Auth', format: 'code' },
      { key: 'keyConfigured', label: 'Key', format: 'boolean' },
      { key: 'passwordConfigured', label: 'Password', format: 'boolean' },
      { key: 'hostKeyAdmitted', label: 'Host key', format: 'boolean' },
      { key: 'hostKeyAdmittedBy', label: 'Admitted by', format: 'code' },
      { key: 'hostKeyFingerprint', label: 'Host key fingerprint', format: 'code', copyable: true },
      { key: 'shells', label: 'Interpreters (probed by Test)' },
    ],
    rowActions: [
      { label: 'Edit', action: 'updateServer', submitLabel: 'Save', lockFields: ['id'], payload: { id: '$row.id' } },
      { label: 'Test', action: 'testServer', submitLabel: 'Test', lockFields: ['id'], payload: { id: '$row.id' } },
      { label: 'Probe Key', action: 'probeHostKey', submitLabel: 'Probe', payload: { host: '$row.host', port: '$row.port' } },
      { label: 'Remove', action: 'removeServer', submitLabel: 'Remove', lockFields: ['id'], payload: { id: '$row.id' }, danger: true, confirm: true },
    ],
    pageActions: [
      { label: 'Add Server', action: 'addServer', submitLabel: 'Add', payload: {}, variant: 'primary' },
      // Hands the operator the SHA256:… value to paste into Add/Edit — the
      // probe itself admits nothing (#44).
      { label: 'Probe Host Key', action: 'probeHostKey', submitLabel: 'Probe', payload: {} },
    ],
  };
}

const SERVER_FIELDS_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string', description: 'Server id ([a-z0-9._-])' },
    host: { type: 'string', description: 'Hostname or IP' },
    port: { type: 'integer', minimum: 1, maximum: 65535, description: 'SSH port (default 22)' },
    username: { type: 'string', description: 'Least-privilege SSH user' },
    // The auth method is an explicit three-way choice (#42); each secret below
    // is applicable only under its own method and declares that with the
    // Panel's generic `showWhen` convention — the form shows exactly the
    // fields the chosen method uses, and drops hidden ones on submit. The
    // Widget still validates the combination itself (UI filtering is UX, not
    // a security boundary): a secret outside the chosen method is refused.
    authMethod: {
      type: 'string',
      enum: ['privateKey', 'privateKeyWithPassphrase', 'password'],
      enumLabels: ['Private key', 'Encrypted private key + passphrase', 'Password'],
      description: "How this Widget authenticates to the target. Switching methods retires the other method's stored secrets.",
    },
    // Sensitive Action Input (RFC-0008 / docs/09 §6.2): `x-xtrape-sensitive`
    // keeps the value out of Platform durable state (split → ephemeral →
    // overlay), `writeOnly` keeps every projection from echoing it, and
    // `format` is display-only (`textarea` = the Panel's newline-preserving
    // masked entry — a private key is a multiline PEM).
    privateKey: { type: 'string', format: 'textarea', writeOnly: true, 'x-xtrape-sensitive': true, showWhen: { field: 'authMethod', in: ['privateKey', 'privateKeyWithPassphrase'] }, description: 'The private key CONTENT (OpenSSH/PEM, pasted whole). Rides the Platform only ephemerally; stored in this Widget (0600) and never shown again; leave blank on edit to keep the current one.' },
    passphrase: { type: 'string', format: 'password', writeOnly: true, 'x-xtrape-sensitive': true, showWhen: { field: 'authMethod', equals: 'privateKeyWithPassphrase' }, description: 'Passphrase that decrypts the private key. Rides the Platform only ephemerally; stored in this Widget and never shown again; leave blank on edit to keep the current one.' },
    password: { type: 'string', format: 'password', writeOnly: true, 'x-xtrape-sensitive': true, showWhen: { field: 'authMethod', equals: 'password' }, description: 'SSH password. Rides the Platform only ephemerally; stored in this Widget (0600) and never shown again; leave blank on edit to keep the current one.' },
    hostKeyFingerprint: {
      type: 'string',
      description: 'Admitted SSH host key fingerprint, SHA256:… as printed by `ssh-keygen -lf <hostkey>.pub` (probeHostKey fetches it for you). Leave blank to pin the key the endpoint presents on FIRST use (accept-new) — later mismatches still refuse. An explicit value also protects the first connection and is the stronger posture.',
    },
    environment: { type: 'string', enum: ['production', 'staging', 'development'] },
    shells: {
      type: 'array',
      title: '可用解释器',
      items: { type: 'string' },
      description: '目标主机上有哪些解释器(command -v 的名字:sh, bash, python3 …)。testServer 会探测并回填,探测结果优先于这里的声明。留空 = 未知:不阻断,只在审阅卡上标「未探测」。任务的 shebang 解释器不在此列表 → 审阅期明说、执行前拒绝(#69)。',
    },
  },
  required: ['id', 'host', 'username', 'authMethod', 'environment'],
  additionalProperties: false,
} as const;

function serverInputFrom(input: unknown): ServerInput {
  const rec = asRecord(input);
  return {
    id: str(rec.id),
    host: str(rec.host),
    username: str(rec.username),
    environment: str(rec.environment) as ServerInput['environment'],
    ...(rec.port !== undefined ? { port: Number(rec.port) } : {}),
    ...(rec.authMethod !== undefined ? { authMethod: str(rec.authMethod) } : {}),
    ...(rec.privateKey !== undefined ? { privateKey: str(rec.privateKey) } : {}),
    ...(rec.password !== undefined ? { password: str(rec.password) } : {}),
    ...(rec.passphrase !== undefined ? { passphrase: str(rec.passphrase) } : {}),
    ...(rec.hostKeyFingerprint !== undefined ? { hostKeyFingerprint: str(rec.hostKeyFingerprint) } : {}),
    ...(rec.shells !== undefined ? { shells: (Array.isArray(rec.shells) ? rec.shells : String(rec.shells).split(/[,\s]+/)).map((x) => String(x)).filter((x) => x !== '') } : {}),
  };
}

// Server management sub-ops (listServers/addServer/updateServer/removeServer/
// testServer) are hidden from the Panel catalog via the reserved `_servers`
// category and reached only from the manageServers list affordances.

/**
 * The task library as a managed list (#55): one row per FILE in either
 * state. Scripts are the operator's configuration, not secrets — the review
 * flows show them verbatim; what must stay honest is the STATE column
 * (drafts are not executable) and the digest (what an approval binds to).
 */
function tasksListDisplay(tasks: ReturnType<TaskDb['listAll']>): Record<string, unknown> {
  return {
    title: 'Task Library',
    data: tasks.map((t) => ({
      id: t.definition.id,
      title: t.definition.title ?? '',
      // linux-ops#94: enabled under an older definition shape — not published,
      // not runnable — until `# version:` is bumped and it is enabled again.
      state: t.needsReversion ? 'enabled — re-version required' : t.state,
      version: t.definition.version,
      risk: t.definition.riskLevel,
      serverScopes: t.definition.serverScopes.join(', '),
      scriptDigest: t.definition.scriptDigest,
      revision: t.revisionId,
    })),
    columns: [
      { key: 'id', label: 'Task', format: 'code', copyable: true },
      { key: 'title', label: 'Title' },
      { key: 'state', label: 'State', format: 'status' },
      { key: 'version', label: 'Version' },
      { key: 'risk', label: 'Risk', format: 'status' },
      { key: 'serverScopes', label: 'Scopes', format: 'code' },
      { key: 'scriptDigest', label: 'Digest', format: 'code', copyable: true },
    ],
    rowActions: [
      { label: 'View', action: 'viewTask', submitLabel: 'View', lockFields: ['id', 'state'], payload: { id: '$row.id', state: '$row.state' }, showResult: true },
      { label: 'Edit', action: 'updateTask', submitLabel: 'Save Draft', lockFields: ['id'], payload: { id: '$row.id' } },
      // Enable/Disable are state transitions, offered only where they apply
      // (row-action showWhen — the same convention as field visibility).
      { label: 'Enable', action: 'enableTask', submitLabel: 'Approve & Enable', lockFields: ['id'], payload: { id: '$row.id' }, showWhen: { field: 'state', equals: 'draft' } },
      { label: 'Disable', action: 'disableTask', submitLabel: 'Disable', lockFields: ['id'], payload: { id: '$row.id' }, showWhen: { field: 'state', equals: 'enabled' }, danger: true },
      { label: 'Remove', action: 'removeTask', submitLabel: 'Remove', lockFields: ['id', 'state'], payload: { id: '$row.id', state: '$row.state' }, danger: true },
    ],
    pageActions: [{ label: 'Add Task', action: 'addTask', submitLabel: 'Save Draft', payload: {}, variant: 'primary' }],
  };
}


/** Structured Add/Edit Task form (#58 part 2) — fields map 1:1 to the task DB's metadata columns. */
const TASK_RISKS = ['low', 'medium', 'high', 'critical'];
const RISK_LABELS = [
  'low — 自动执行',
  'medium — 自动执行(生产或 AI 面升为需审批)',
  'high — 需人工审批',
  'critical — 需人工审批(最高)',
];
/**
 * Headers retired from authoring (#61) but preserved verbatim when a stored
 * task carries them: dropping them on an edit would silently change the
 * task's authorization (an `always_human` task becoming automatic).
 */
const RETIRED_HEADERS = new Set(['readonly', 'approval', 'executor', 'interpreter', 'maxBytes']);

/** Sentinel option: the operator types a scope glob instead of picking an admitted server. */
const CUSTOM_SCOPE = '(custom)';

function taskFormSchema(opts: { forAdd: boolean; serverIds?: string[] }): Record<string, unknown> {
  const scopeChoices = ['*', ...(opts.serverIds ?? []), CUSTOM_SCOPE];
  return {
    type: 'object',
    properties: {
      id: {
        type: 'string',
        title: '任务 ID',
        ...(opts.forAdd ? { pattern: '^[a-z0-9]+(\\.[a-z0-9_-]+)+$' } : {}),
        description: opts.forAdd
          ? '任务的永久身份,例如 system.uptime(小写、点分)。它是命令寻址、审批台账与修订历史的挂靠键,创建后不可更改——显示名请用「标题」。'
          : '这次编辑的目标任务(身份不可更改)',
        ...(opts.forAdd ? {} : { readOnly: true }),
      },
      title: { type: 'string', title: '标题', description: '人类可读的显示名,可随时修改(与不可变的任务 ID 相对)' },
      version: { type: 'string', title: '版本', pattern: '^\\d+\\.\\d+\\.\\d+$', default: '1.0.0', description: 'MAJOR.MINOR.PATCH' },
      description: { type: 'string', title: '说明', format: 'textarea', description: '这个任务做什么 —— 展示给选择它的人或 AI。可多行。' },
      risk: {
        type: 'string',
        title: '风险等级',
        enum: TASK_RISKS,
        enumLabels: RISK_LABELS,
        description: '这个任务的爆炸半径,也是唯一的授权轴:有效风险 ≥ high 需人工审批。目标为生产服务器 +1 档,经 MCP(AI 设备)调用 +1 档。如实声明是作者的义务。',
      },
      serverScope: {
        type: 'string',
        title: '服务器绑定',
        ...(opts.serverIds !== undefined ? { enum: scopeChoices } : {}),
        description: '这个任务可以在哪里运行:选一台已准入服务器 = 绑定到它;「*」= 运行时再选;「(custom)」= 自己写范围表达式',
      },
      customScope: {
        type: 'string',
        title: '自定义范围',
        description: '逗号分隔的服务器范围,例如 "web-*, db-01" —— 运行时与已准入服务器 id 匹配',
        showWhen: { field: 'serverScope', equals: CUSTOM_SCOPE },
      },
      timeoutSeconds: { type: 'integer', title: '超时(秒)', minimum: 1, description: '可选。不填 = 不设期限(有些任务本就要跑数小时);请优先在脚本里用 timeout 约束真正的工作' },
      // Structured rows, not hand-typed declaration text (#61 C-8): a
      // parameter is a name AND a label AND a type AND a default, and
      // spelling that as syntax is where mistakes came from. Rendered by the
      // Panel's generic object-array row editor (panel-ce#157).
      params: {
        type: 'array',
        title: '参数',
        description: '调用方要填的参数。到目标机是 XOPS_<名称> 环境变量。',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string', title: '名称', description: '环境变量名' },
            label: { type: 'string', title: '标签' },
            type: { type: 'string', title: '类型', enum: ['string', 'integer', 'number', 'boolean'] },
            required: { type: 'boolean', title: '必填' },
            default: { type: 'string', title: '默认值' },
            pattern: { type: 'string', title: '正则约束' },
            enum: { type: 'string', title: '可选值', description: '用 | 分隔' },
            description: { type: 'string', title: '说明' },
          },
          required: ['name', 'type'],
        },
      },
      redact: {
        type: 'array',
        title: '输出脱敏',
        items: { type: 'string' },
        description: '额外的脱敏正则,匹配到的内容不会进入结果与本地证据',
      },

      body: { type: 'string', title: '脚本', format: 'textarea', description: '运维人员自己的脚本 —— 在目标机上逐字执行(参数以 XOPS_<名称> 环境变量送达)' },
      // EDITABLE (review 2370): the shebang is the interpreter authority —
      // the Widget reads it locally and runs that command with its own
      // arguments, so the script still never lands on the target. Hiding it
      // meant an online task could not choose anything but bash.
      shebang: {
        type: 'string',
        title: '解释器指令行(Shebang)',
        default: '#!/usr/bin/env bash',
        description: '决定用什么解释这段脚本,例如 "#!/bin/sh"、"#!/usr/bin/env python3"、"#!/bin/sh -e"(其中的参数会被忠实传递)。脚本经标准输入送达,不会落到目标机上。',
      },
      // What the edit is BASED on: a sealed token naming the exact stored
      // revision this form was prefilled from (review 2393). Everything the
      // form does not show — retired headers, parameter bounds with no
      // column — is read from THAT revision on the server at submit time.
      // Carrying those values in the payload made the caller the authority
      // over them: emptying the carrier silently dropped an `always_human`
      // declaration or a `minimum`, and a stale carrier could overwrite a
      // newer revision's hidden declarations.
      baseRevision: { type: 'string', format: 'hidden', readOnly: true, description: 'Issued by prepare; opaque. Names the stored revision this edit is based on — do not edit.' },
    },
    required: ['id', 'version', 'risk', 'serverScope', 'body'],
    additionalProperties: false,
  };
}

/**
 * Build TaskParts DIRECTLY from the form's fields (review 2354: the form
 * operates on the DB's columns; no header-text detour, so the body can
 * never fall back into the header parser — it is stored verbatim, and the
 * canonical render seals it behind the explicit boundary marker).
 * Single-line fields refuse embedded newlines OUTRIGHT: a value like
 * "desc\n# interpreter: sh" typed into the raw JSON editor would otherwise
 * smuggle a header the form never showed. The declarations textarea is
 * checked line by line against the three legal shapes — a malformed line is
 * refused, never silently dropped.
 */
function taskPartsFromForm(
  rec: Record<string, unknown>,
  /**
   * The stored revision this edit is based on, read on the SERVER (review
   * 2393). Everything the form does not show comes from here — never from
   * the payload, which the caller writes.
   */
  base: { legacy: Record<string, string>; originals: Record<string, { declaration: string; constraints: Array<{ key: string; value: string }> }> },
): TaskParts {
  const single = (key: string, required = false): string | undefined => {
    const v = rec[key];
    if (v === undefined || v === null || v === '') {
      if (required) throw new Error(`"${key}" is required`);
      return undefined;
    }
    const s = String(v).trim();
    if (s.includes('\n')) throw new Error(`"${key}" must be a single line`);
    return s;
  };
  const scope = single('serverScope', true)!;
  const servers = scope === CUSTOM_SCOPE ? single('customScope', true)! : scope;
  const headers: Record<string, string> = {
    'xtrape-task': single('id', true)!,
    version: single('version', true)!,
    risk: single('risk', true)!,
    servers,
  };
  const title = single('title');
  if (title) headers['title'] = title;
  // Description is the one MULTI-line header (#61): stored as consecutive
  // `# description:` lines, joined back on read.
  const rawDescription = String(rec.description ?? '').trim();
  if (rawDescription) headers['description'] = rawDescription;
  if (rec.timeoutSeconds !== undefined && rec.timeoutSeconds !== null && rec.timeoutSeconds !== '') headers['timeout'] = String(Number(rec.timeoutSeconds));
  // Retired headers the stored version still carries ride through unchanged
  // — read from the stored revision, not from the payload (review 2393).
  for (const [k, v] of Object.entries(base.legacy)) {
    if (RETIRED_HEADERS.has(k) && typeof v === 'string') headers[k] = v;
  }

  // Parameter ROWS -> declarations (#61 C-8). Every cell is checked here so
  // a raw-JSON payload cannot smuggle a second declaration through a value:
  // a name that is not an environment-variable name, a type outside the
  // declared set, or any newline is refused rather than rendered into the
  // header block as extra lines.
  const params: TaskParts['params'] = [];
  // The stored declarations, verbatim (review 2388): the rows are EDITS
  // applied onto them, not a re-derivation. Re-emitting from columns alone
  // reordered constraints and normalized spacing, so an untouched Edit ->
  // Save produced different canonical bytes — a phantom draft.
  const originals = base.originals;
  const seen = new Set<string>();
  const claimed = new Set<string>();
  const unidentified: string[] = [];
  for (const row of Array.isArray(rec.params) ? rec.params : []) {
    const cell = asRecord(row);
    const oneLine = (key: string): string => {
      const v = cell[key];
      if (v === undefined || v === null) return '';
      const s = String(v).trim();
      if (s.includes('\n')) throw new Error(`parameter field "${key}" must be a single line`);
      return s;
    };
    const name = oneLine('name');
    if (name === '') continue; // an empty row the operator added and left blank
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(`parameter "${name}" is not a usable environment variable name`);
    if (seen.has(name)) throw new Error(`parameter "${name}" declared twice`);
    seen.add(name);
    const type = oneLine('type');
    if (!['string', 'integer', 'number', 'boolean'].includes(type)) {
      throw new Error(`parameter "${name}": type must be string, integer, number or boolean (got "${type}")`);
    }
    const description = oneLine('description');
    // Follow the row's identity, not its current name, so a rename carries
    // its hidden bounds with it (review 2389). The identity is CALLER-
    // WRITABLE, so it is verified rather than trusted (review 2392): an
    // identity naming no stored parameter used to slip past the ambiguity
    // guard and silently drop that parameter's hidden bounds, and two rows
    // claiming one identity could copy one parameter's bounds onto another.
    const originName = oneLine('originName');
    let original: { declaration: string; constraints: Array<{ key: string; value: string }> } | undefined;
    if (originName !== '') {
      original = originals[originName];
      if (original === undefined) {
        throw new Error(`parameter row for "${name}" carries an unknown identity "${originName}" — re-open Edit rather than hand-editing the payload`);
      }
      if (claimed.has(originName)) {
        throw new Error(`two parameter rows claim the stored parameter "${originName}"; each stored parameter belongs to at most one row`);
      }
      claimed.add(originName);
    } else if (originals[name] !== undefined) {
      if (claimed.has(name)) {
        throw new Error(`two parameter rows claim the stored parameter "${name}"; each stored parameter belongs to at most one row`);
      }
      original = originals[name];
      claimed.add(name);
    } else {
      unidentified.push(name);
    }
    const rebuilt = `${name} ${cell.required === true ? 'required' : 'optional'} ${type}${description ? ` ${description}` : ''}`;
    // Keep the stored declaration byte-for-byte while it still SAYS the same
    // thing: rebuilding normalizes spacing, which would change the canonical
    // text without changing its meaning.
    const declaration = original !== undefined && sameDeclaration(original.declaration, name, cell.required === true, type, description)
      ? original.declaration
      : rebuilt;
    // A rename re-keys the carried constraints too (review 2389): their key
    // names the parameter, and leaving the old name behind would declare a
    // constraint for a parameter that no longer exists.
    const constraints = (original?.constraints ?? []).map((c) => {
      const suffix = c.key.split('.')[2] ?? '';
      return { key: `param.${name}.${suffix}`, value: c.value };
    });
    const upsert = (suffix: string, value: string | undefined): void => {
      const key = `param.${name}.${suffix}`;
      const at = constraints.findIndex((c) => c.key === key);
      if (value === undefined) {
        // The operator cleared a cell that had a value: remove it. A cell
        // that is empty because the STORED value was empty is left alone by
        // the caller passing `undefined` only for a real clearing.
        if (at !== -1) constraints.splice(at, 1);
        return;
      }
      if (at === -1) constraints.push({ key, value });
      else (constraints[at] as { value: string }).value = value; // in place: order preserved
    };
    for (const suffix of ['label', 'pattern', 'enum', 'default'] as const) {
      const cellValue = cell[suffix];
      const stored = constraints.find((c) => c.key === `param.${name}.${suffix}`)?.value;
      if (cellValue === undefined || cellValue === null) {
        // Absent cell: a stored EMPTY value renders as an empty cell, so an
        // absent cell over an empty stored value is "unchanged", not
        // "cleared" (review 2388: an empty-string default was being lost).
        upsert(suffix, stored === '' ? '' : undefined);
        continue;
      }
      const text = String(cellValue);
      if (text.includes('\n')) throw new Error(`parameter field "${suffix}" must be a single line`);
      const trimmed = text.trim();
      if (trimmed === '' && stored !== '') upsert(suffix, undefined);
      else upsert(suffix, trimmed === '' ? '' : trimmed);
    }
    params.push({ declaration, constraints });
  }
  // A row carrying no identity whose name matches no stored parameter is
  // either a NEW parameter or a rename whose identity was stripped by hand.
  // Those are indistinguishable, and guessing "new" would silently drop the
  // renamed parameter's hidden bounds — a widening. Refuse instead, naming
  // both sides so the operator can say which it is (review 2389).
  const orphaned = Object.keys(originals).filter(
    (key) => !claimed.has(key) && (originals[key]?.constraints ?? []).some((c) => !COLUMN_SUFFIXES.has(c.key.split('.')[2] ?? '')),
  );
  if (unidentified.length > 0 && orphaned.length > 0) {
    throw new Error(
      `cannot tell whether parameter(s) ${unidentified.map((n) => `"${n}"`).join(', ')} are new or a rename of ${orphaned.map((n) => `"${n}"`).join(', ')}, which declare bounds the form does not show; re-open Edit rather than hand-editing the payload`,
    );
  }
  const redact = (Array.isArray(rec.redact) ? rec.redact : [])
    .map((entry) => String(entry).trim())
    .filter((entry) => entry !== '');
  for (const entry of redact) {
    if (entry.includes('\n')) throw new Error('a redaction pattern must be a single line');
  }
  return {
    shebang: single('shebang') ?? '#!/usr/bin/env bash',
    headers,
    params,
    redact,
    body: String(rec.body ?? ''),
  };
}

/** Constraint suffixes the form has a column for; the rest ride the carrier. */
const COLUMN_SUFFIXES = new Set(['label', 'pattern', 'enum', 'default']);

/**
 * Whether a stored `# param:` declaration still says exactly what the row
 * says. Compared field by field so spacing differences do not count as an
 * edit (review 2388): the stored bytes are kept whenever the meaning is
 * unchanged.
 */
function sameDeclaration(declaration: string, name: string, required: boolean, type: string, description: string): boolean {
  const [storedName = '', storedRequired = '', storedType = '', ...rest] = declaration.trim().split(/\s+/);
  return storedName === name && (storedRequired === 'required') === required && storedType === type && rest.join(' ') === description;
}

/** Map a stored task back into form fields for the Edit prefill. */
function taskFormPayloadFrom(parts: TaskParts, serverIds: string[]): Record<string, unknown> {
  const servers = (parts.headers['servers'] ?? '').trim();
  const bound = servers !== '*' && !servers.includes(',') && serverIds.includes(servers);
  // Declarations -> parameter ROWS, with the bounds that have no column
  // preserved in the hidden carrier so an edit cannot drop them.
  const paramRows = parts.params.map((p) => {
    const [name = '', requiredWord = 'optional', type = 'string', ...rest] = p.declaration.trim().split(/\s+/);
    const row: Record<string, unknown> = { name, type, required: requiredWord === 'required' };
    const description = rest.join(' ');
    if (description) row['description'] = description;
    for (const c of p.constraints) {
      const key = c.key.split('.')[2] ?? '';
      if (COLUMN_SUFFIXES.has(key)) row[key] = c.value;
    }
    // Stable row identity (review 2389): `name` is EDITABLE, so matching a
    // row to its stored parameter by name alone loses a renamed one's
    // hidden bounds. Not a form column — the row editor renders only
    // declared properties — but it rides the row object through edits, and
    // the submit path resolves it against the SERVER's copy of the stored
    // revision (review 2393).
    row['originName'] = name;
    return row;
  });
  return {
    id: parts.headers['xtrape-task'] ?? '',
    ...(parts.headers['title'] !== undefined ? { title: parts.headers['title'] } : {}),
    version: parts.headers['version'] ?? '',
    ...(parts.headers['description'] !== undefined ? { description: parts.headers['description'] } : {}),
    risk: parts.headers['risk'] ?? '',
    serverScope: servers === '*' ? '*' : bound ? servers : CUSTOM_SCOPE,
    ...(servers !== '*' && !bound ? { customScope: servers } : {}),
    ...(parts.headers['timeout'] !== undefined ? { timeoutSeconds: Number(parts.headers['timeout']) } : {}),
    ...(paramRows.length > 0 ? { params: paramRows } : {}),
    ...(parts.redact.length > 0 ? { redact: parts.redact } : {}),
    body: parts.body,
    shebang: parts.shebang,
  };
}

/** Review card for a stored task — the same what/where/rules shape as the run panel (#48). */
function taskDetailDisplay(title: string, def: ActionDefinition, content: string, state: string, screening?: string, interpreterAvailability?: string): Record<string, unknown> {
  return {
    detail: {
      title,
      data: {
        id: def.id,
        name: def.title ?? '',
        ...(screening !== undefined ? { screening } : {}),
        state,
        description: def.description ?? '',
        risk: `${def.riskLevel}${policyNotice(def).length > 0 ? ` — ${policyNotice(def).join('; ')}` : ' — runs automatically'}`,
        serverScopes: def.serverScopes.join(', '),
        interpreter: `${def.interpreter} (executor: ${def.executor})`,
        ...(interpreterAvailability !== undefined ? { interpreterAvailability } : {}),
        scriptDigest: def.scriptDigest,
        script: content,
      },
      fields: [
        { key: 'id', label: 'Task', format: 'code' },
        { key: 'name', label: 'Title' },
        ...(screening !== undefined ? [{ key: 'screening', label: '红线筛查', format: 'pre' }] : []),
        { key: 'state', label: 'State', format: 'status' },
        { key: 'description', label: 'What it does' },
        { key: 'risk', label: 'Risk & approval' },
        { key: 'serverScopes', label: 'Server scopes' },
        { key: 'interpreter', label: 'Runs via' },
        ...(interpreterAvailability !== undefined ? [{ key: 'interpreterAvailability', label: 'Interpreter on targets (#69)', format: 'pre' }] : []),
        { key: 'scriptDigest', label: 'Script digest', format: 'code', copyable: true },
        { key: 'script', label: 'Script (full text)', format: 'pre' },
      ],
    },
  };
}

/**
 * What a CE execute handler receives that this surface reads. `origin` is
 * the authenticated Account context the Platform delivered with the command
 * (xtrape-docs runtime-platform/12, #256): the canonical Account id when the
 * Platform could map the subject to one, and a trace id — no class field,
 * and NOT the actual originator. It is a FACT for attribution and
 * forwarding — never taken from the action's input, never a substitute for
 * the Platform's own authorization, never a policy-branch input, and never
 * filled in from a static deployment identity when it is missing.
 */
interface ExecuteContext {
  commandId?: string;
  signal?: AbortSignal;
  origin?: CommandOrigin;
}

/** The fail-closed reading of a missing or malformed delivered origin. */
const UNKNOWN_ORIGIN: CommandOrigin = {};

/** The delivered origin, re-validated so this module has exactly one reading of it. */
export function originOf(context?: { origin?: unknown }): CommandOrigin {
  const parsed = CommandOriginSchema.safeParse(context?.origin);
  return parsed.success ? parsed.data : UNKNOWN_ORIGIN;
}

export function buildCeActions(deps: BuildCeActionsDeps): CeServiceActionDefinition[] {
  const { registry, store, opsService, probe, probeHostKey, probeShells, taskStore } = deps;
  const redlines = deps.redlines;
  const paramGuards = deps.paramGuards;
  const content = deps.content;
  /**
   * In a governed library nothing becomes effective here. An edit is a
   * proposal, and what comes back is where it is being reviewed — saying
   * "saved" would be a lie, and saying nothing would leave the caller (human
   * or AI) with no way to follow it.
   */
  const submitGoverned = async (parts: TaskParts, message: string, context?: ExecuteContext): Promise<{ success: boolean; message: string; data: Record<string, unknown> }> => {
    const id = parts.headers['xtrape-task'] ?? '(unnamed)';
    const bytes = renderTaskFile(parts);
    // The proposal's author is the Account the Platform delivered with this
    // command, forwarded as received. The Curator refuses to approve a
    // proposal without an attributed author (distinctness from the approver
    // cannot be shown), so an edit that arrives without one is refused HERE,
    // with the reason, instead of parking an unapprovable proposal on the
    // review side. A static deployment identity is not a fallback: it would
    // be a false author (12-command-origin §6.1).
    const origin = originOf(context);
    if (origin.account === undefined) {
      throw new Error(
        'this edit carries no caller Account from the Platform, so its proposal could never be approved — ' +
          'a governed library needs a Platform that delivers the command origin (features.commandOrigin) and a caller with a registered Account',
      );
    }
    const commandId = context?.commandId;
    const result = await content!.source.submit({
      path: content!.path(id),
      bytes,
      message,
      origin,
      // The command reference is delivery evidence in the detail text — an
      // audit fact about the path, separate from the identity on purpose.
      detail: `Task ${id}, proposed through the Widget's task library${commandId !== undefined ? ` (delivered by Platform command ${commandId})` : ''}.`,
    });
    auditTask('task_submitted', id, { after: result.submissionId });
    return {
      success: true,
      message: `submitted for review — it becomes effective here only after the review side approves it (${result.url})`,
      data: { id, state: 'submitted', submissionId: result.submissionId, reviewUrl: result.url },
    };
  };
  /** What a person needs to see on a governed library's panel: where it comes from. */
  const governedBanner = (): Record<string, unknown> =>
    content === undefined
      ? {}
      : {
        governed: {
          effectiveVersion: taskStore.lastContentVersion()?.versionId ?? '(nothing applied yet)',
          reviewUrl: content.source.reviewUrl(),
          note: '这个任务库由评审侧治理:编辑会作为提案提交,合并后才在此生效。历史与评审在评审侧。',
        },
      };

  /**
   * The Panel renders `data.list` and ignores its siblings, so the governed
   * marker has to ride ON the list to be seen at all. The structured
   * `governed` block stays for API callers.
   */
  const governedListTitle = (list: Record<string, unknown>): Record<string, unknown> =>
    content === undefined
      ? list
      : { ...list, title: `${String(list.title ?? 'Task Library')} — 由评审侧治理(生效版本 ${taskStore.lastContentVersion()?.versionId.slice(0, 12) ?? '未应用'})` };

  /** Refuse a lifecycle action a governed library does not decide locally. */
  const governedElsewhere = (verb: string): { success: boolean; message: string; data: Record<string, unknown> } => ({
    success: false,
    message: `this task library is governed: ${verb} is decided at the review side, not here — see ${content!.source.reviewUrl()}`,
    data: { reviewUrl: content!.source.reviewUrl() },
  });
  /** Hits rendered for a person: what was matched, and what it means. */
  const hitLines = (hits: RedlineHit[]): string =>
    hits.map((h) => `${h.severity === 'hard' ? '禁止' : '需审批'} · ${h.id}: ${h.message} (匹配到 "${h.excerpt}")`).join('\n');
  // The library's growth is evidence (review 2329 item 6): every lifecycle
  // step records WHICH bytes entered or left the executable surface. The
  // request block is shaped for the shared evidence file; the values name
  // the library operation rather than a fleet call.
  const auditTask = (event: 'task_draft_saved' | 'task_enabled' | 'task_disabled' | 'task_removed' | 'task_submitted', id: string, task: { before?: string; after?: string; state?: string }): void => {
    deps.audit?.write({
      timestamp: new Date().toISOString(),
      event,
      request: { serverId: '(task-library)', actionId: id, argsKeys: [], reason: '(manageTasks)', dryRun: false, surface: 'platform' },
      task: { id, ...task },
    });
  };
  // One key per Worker INCARNATION (buildCeActions runs once at startup):
  // what makes the review binding unforgeable and fallback/restart
  // fail-closed — see sealReviewBinding.
  const reviewKey = deps.reviewKey ?? randomBytes(32);

  /**
   * Everything an edit must preserve but the form does not show, read from
   * the STORED revision (review 2393): the retired headers and each
   * parameter's declaration with its full constraint list. The payload
   * carries none of it — a caller-supplied carrier made the caller the
   * authority over declarations they cannot see.
   */
  const baseOf = (parts: TaskParts): { legacy: Record<string, string>; originals: Record<string, { declaration: string; constraints: Array<{ key: string; value: string }> }> } => {
    const legacy = Object.fromEntries(Object.entries(parts.headers).filter(([k]) => RETIRED_HEADERS.has(k))) as Record<string, string>;
    const originals: Record<string, { declaration: string; constraints: Array<{ key: string; value: string }> }> = {};
    for (const p of parts.params) {
      const name = p.declaration.trim().split(/\s+/)[0] ?? '';
      originals[name] = { declaration: p.declaration, constraints: p.constraints.map((c) => ({ ...c })) };
    }
    return { legacy, originals };
  };
  const EMPTY_BASE = { legacy: {}, originals: {} };

  /**
   * What the guards say about THESE arguments, for the review card (#66,
   * review 2409).
   *
   * The card used to list every rule that could ever fire for the task, so
   * `/opt` and `/` — or development and production — read identically and a
   * caller learned the actual answer only by being refused. When the tentative
   * input already names an admitted server, this evaluates the guards against
   * those arguments and says what will happen; otherwise it falls back to
   * listing the applicable rules, which is all that is knowable yet.
   *
   * It is a PREVIEW, never authority: `execute` re-evaluates against the
   * arguments it is actually given and remains the only thing that decides.
   */
  const guardPreview = (action: ActionDefinition, input?: unknown): string[] => {
    const rec = input === undefined ? {} : asRecord(input);
    const serverId = str(rec.serverId);
    const server = serverId === '' ? undefined : store.list().find((s) => s.id === serverId);
    const applicable = paramGuards.rulesFor(action.id);
    const rule = (severity: string, id: string, message: string): string => `${severity === 'hard' ? '禁止' : '需审批'} · ${id}: ${message}`;
    if (!server) return applicable.map((g) => rule(g.severity, g.id, g.message));
    const args = Object.fromEntries(Object.keys(paramProps(action)).filter((k) => k in rec).map((k) => [k, rec[k]]));
    const hits = paramGuards.evaluate({
      taskId: action.id,
      args,
      serverId: server.id,
      environment: server.environment,
      // The Panel/Platform surface is the one a prepare card is drawn for; the
      // MCP surface has no prepare step, so previewing it here would be a
      // guess. `execute` uses the real surface.
      surface: 'platform',
    });
    const verdict =
      hits.some((h) => h.severity === 'hard')
        ? `这组参数将被拒绝(目标 ${server.id} · ${server.environment})`
        : hits.length > 0
          ? `这组参数将需要审批(目标 ${server.id} · ${server.environment})`
          : `这组参数当前不触发参数风控(目标 ${server.id} · ${server.environment})`;
    const lines = [`${verdict};执行时以实际参数重新判定。`, ...hits.map((h) => rule(h.severity, h.id, h.message))];
    // Still worth naming what else exists, so a caller can see which values
    // would change the answer.
    const others = applicable.filter((g) => !hits.some((h) => h.id === g.id));
    if (others.length > 0) lines.push('其它可能触发的规则:', ...others.map((g) => rule(g.severity, g.id, g.message)));
    return lines;
  };

  const buildOpsAction = (action: ActionDefinition): CeServiceActionDefinition => ({
    // name / label / description / category are ONE text with the schema the
    // task's Checkpoint registers (ops-schema.ts, linux-ops#98): the catalog
    // entry and the admitted record must never drift apart.
    ...opsEntryText(action),
    // The governed edge (#79): the ops entry binds the task's own immutable
    // Checkpoint, versioned by the task's declared semver.
    checkpoint: checkpointRefFor(action.id, action.version),
    inputSchema: opsInputSchema(action),
    prepare: async (input?: unknown, ctx?: CePrepareContext): Promise<CeActionPrepareResult> => {
      // Render the serverId enum live from the configured fleet at execution
      // time, and put WHAT/WHERE/UNDER-WHICH-RULES on the dialog itself (#48).
      // Under a governed REVIEW the fleet goes through the §4.3 exchange
      // first: only the servers the SESSION is authorized for are offered.
      const eligible = await admittedCandidates(ctx, store.listMatching(action.serverScopes).map((s) => s.id), 'admitted server');
      return {
        inputSchema: governedReview(ctx) ? reviewNextSchema(opsInputSchema(action, eligible), { property: 'serverId', values: eligible }) : opsInputSchema(action, eligible),
        // Sealed over the digest of the version this prepare's review card
        // SHOWS (reviews 2322/2324): the executing Worker holds the run to
        // the reviewed bytes, and nobody without this incarnation's key can
        // mint or alter the claim.
        initialPayload: { reviewBinding: sealReviewBinding(reviewKey, action.scriptDigest) },
        currentState: opsPrepareDetail(action, eligible, guardPreview(action, input), store.listMatching(action.serverScopes)),
      };
    },
    execute: async (input: unknown, context?: ExecuteContext) => {
      const rec = asRecord(input);
      // Hold the run to the REVIEWED bytes (reviews 2322/2324). A
      // Platform-delivered execute always carries a commandId (uniformly
      // async transport since connector 0.8.1) and, for these
      // prepare-declaring actions, always followed a prepare — so on that
      // surface a VALID sealed binding is demanded, not merely honored:
      // deleting the field, blanking it, or pasting another Worker's digest
      // all refuse. The callback listener (no commandId) is the operator's
      // own token-authed local surface with no review card to bind — it
      // keeps its own trust domain. dryRun is gated too: rendering B while
      // the card showed A is the same confusion.
      if (context?.commandId !== undefined) {
        const reviewed = unsealReviewBinding(reviewKey, str(rec.reviewBinding));
        if (reviewed === null) {
          return fail(
            'REVIEW_BINDING_INVALID',
            'this execute carries no valid review binding from THIS Worker incarnation — a Platform fallback to another Worker, a Worker restart, or an altered payload; re-open the action to review the current script',
          );
        }
        if (reviewed !== action.scriptDigest) {
          return fail(
            'SCRIPT_CHANGED',
            `the task file on this Worker (${action.scriptDigest}) is not the version the review showed (${reviewed}); re-open the action to review the current script`,
          );
        }
      }
      const args = Object.fromEntries(Object.keys(paramProps(action)).filter((k) => k in rec).map((k) => [k, rec[k]]));
      // The delivery context was being dropped on the floor: `commandId` is
      // what makes a repeated delivery answerable without running the task
      // again, and `signal` is how a Platform-side cancel reaches a task that
      // has no deadline of its own.
      // The Account context goes into the execution's evidence
      // (12-command-origin §6.1) AS Account context: `account` + trace. Not
      // `originActor` — the Account is who is responsible for the command,
      // not who was at the keyboard (review 2455); the originator seam stays
      // empty until an Invocation Envelope really carries it.
      const origin = originOf(context);
      const response = await opsService.execute(
        {
          serverId: str(rec.serverId),
          actionId: action.id,
          args,
          reason: str(rec.reason),
          dryRun: rec.dryRun === true,
          ...(origin.account !== undefined ? { account: origin.account } : {}),
          ...(origin.traceId !== undefined ? { traceId: origin.traceId } : {}),
        },
        {
          surface: 'platform',
          controlPlaneAvailable: true,
          ...(context?.commandId !== undefined ? { commandId: context.commandId } : {}),
          ...(context?.signal !== undefined ? { signal: context.signal } : {}),
        },
      );
      return mapOps(response);
    },
  });

  // The LIVE catalog (#55): serveCeService keeps this array by reference and
  // the Platform re-fetches GET /actions on every catalog read, so replacing
  // the ops entries in place IS the hot update — no re-registration, no
  // restart. Management entries are constant; ops entries mirror the runtime
  // registry and are rebuilt whenever the task library changes.
  const actions: CeServiceActionDefinition[] = [];
  const exposed = (entry: CeServiceActionDefinition): boolean =>
    deps.isCheckpointExposed === undefined || entry.checkpoint === undefined || deps.isCheckpointExposed(entry.checkpoint.checkpointId);
  const rebuildOps = (): void => {
    for (let i = actions.length - 1; i >= 0; i -= 1) {
      if (actions[i]!.category === 'ops') actions.splice(i, 1);
    }
    // Bounded profile applied IN the rebuild, so enable/disable/remove keep the
    // live array (held by the Connector) correct — not a one-time snapshot.
    actions.unshift(...registry.list().map(buildOpsAction).map(describedAction).filter(exposed));
  };

  const manage: CeServiceActionDefinition[] = [
    {
      name: 'manageServers',
      label: 'Manage Servers',
      description: "This Service's target server fleet as a list: host, port, user, environment, admitted host key, probed interpreters. Opening it only reads; Add from the page, Edit / Test / Remove / Admit New Host Key from the row.",
      category: 'config',
      // No prepare ON PURPOSE (linux-ops#93, found live): an entry that
      // declares one makes a zero-shot governed execute 409
      // ACTION_REQUIRES_PREPARE — the Panel's open-as-list READ and the AI
      // host's tools/call both take exactly that path. The list IS the answer.
      inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
      execute: async () => ({ success: true, data: { list: serversListDisplay(store.list()) } }),
    },
    {
      name: 'listServers',
      label: 'List Servers',
      category: '_servers',
      execute: async () => ({ success: true, data: { servers: store.list().map(publicServer), list: serversListDisplay(store.list()) } }),
    },
    {
      name: 'addServer',
      label: 'Add Server',
      category: '_servers',
      inputSchema: SERVER_FIELDS_SCHEMA,
      execute: async (input: unknown) => ({ success: true, message: 'server added', data: { server: publicServer(store.add(serverInputFrom(input))) } }),
    },
    {
      name: 'updateServer',
      label: 'Edit Server',
      category: '_servers',
      inputSchema: SERVER_FIELDS_SCHEMA,
      prepare: (input?: unknown, ctx?: CePrepareContext): CeActionPrepareResult => {
        const id = str(asRecord(input).id);
        const existing = id ? store.get(id) : undefined;
        // Secrets are never prefilled — a blank submit preserves the stored
        // values (see ServerStore.update). The auth METHOD is prefilled: it is
        // configuration, and the form needs it to show the right secret fields.
        return {
          inputSchema: governedReview(ctx) ? reviewNextSchema(SERVER_FIELDS_SCHEMA as unknown as Record<string, unknown>) : (SERVER_FIELDS_SCHEMA as unknown as Record<string, unknown>),
          initialPayload: existing
            ? {
                id: existing.id,
                host: existing.host,
                port: existing.port ?? 22,
                username: existing.username,
                ...(existing.authMethod ? { authMethod: existing.authMethod } : {}),
                environment: existing.environment,
                // Prefilled, unlike the credential reference: a fingerprint is
                // public, and an operator editing an unrelated field must not
                // have to retype it — while deliberately replacing it is how a
                // rotated host key is re-admitted.
                hostKeyFingerprint: existing.hostKeyFingerprint ?? '',
              }
            : {},
          // The review card (#94): the current NON-sensitive configuration —
          // `publicServer` never carries a password, key or passphrase.
          ...(existing ? { currentState: serverDetailDisplay(existing) } : {}),
        };
      },
      execute: async (input: unknown) => ({ success: true, message: 'server updated', data: { server: publicServer(store.update(serverInputFrom(input))) } }),
    },
    {
      name: 'removeServer',
      label: 'Remove Server',
      category: '_servers',
      inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false },
      execute: async (input: unknown) => {
        const id = str(asRecord(input).id);
        store.remove(id);
        return { success: true, message: 'server removed', data: { removed: id, list: serversListDisplay(store.list()) } };
      },
    },
    {
      name: 'testServer',
      label: 'Test Server',
      category: '_servers',
      inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false },
      execute: async (input: unknown) => {
        const id = str(asRecord(input).id);
        const server = store.get(id);
        if (!server) throw new Error(`unknown server "${id}"`);
        try {
          const result = await probe(server);
          // A probe cut off at its output ceiling saw no exit status, so it
          // proves nothing about reachability — a host flooding a command that
          // prints nothing is not a host this Widget should call reachable.
          const reachable = result.terminatedBy === undefined && result.exitCode === 0;
          // Reachable → also learn what the target can RUN (#69): the
          // interpreters `command -v` resolves, recorded as an observation
          // (with its time) so "task wants bash / target has no bash" is
          // said at review time, not discovered as exit 127 after dispatch.
          // Best-effort: a probe that fails leaves the record as it was.
          // A Test is a READ (review 2475): the observation is shown, and a
          // person records it through `recordProbedShells`. What travels to
          // that confirmation is a SEALED observation (review 2480, same
          // discipline as the review bindings): {id, target snapshot, shells,
          // probedAt} under this incarnation's key — nobody can mint a
          // "probed" record the target never answered, edit the observed
          // list and still call it probed, or replay it against an entry
          // whose endpoint or execution identity changed (the store
          // CAS-checks the whole ProbeTargetSnapshot: host, port, user,
          // admitted host key, generation — review 2481).
          let shells: string[] | undefined;
          let shellsError: string | undefined;
          const probedAt = new Date().toISOString();
          // The reachability probe may have CHANGED the record (review 2483):
          // on an accept-new entry the executor pins the host key at the
          // first key exchange, and the store's pin CAS is on record
          // identity — running the second probe against the object read
          // BEFORE the first would try to pin again and be refused. So the
          // second probe, and the snapshot the observation is sealed with,
          // use the record as it is NOW (pinned key included): one Test on a
          // TOFU entry both admits the key and yields a recordable
          // observation.
          const live = store.get(id) ?? server;
          // The snapshot is FIXED before the shells probe runs (review 2484):
          // the observation must be sealed with the target it was made
          // against, not with whatever the record says when the probe
          // returns — a rehost during the network wait would otherwise seal
          // "target = new host, interpreters = old host", and the
          // confirmation's CAS would pass on the new one. Sealed against
          // `shellTarget`, that confirmation refuses instead.
          const shellTarget = probeTargetSnapshot(live);
          if (reachable && probeShells) {
            try {
              shells = await probeShells(live);
            } catch (probeErr) {
              shellsError = probeErr instanceof Error ? probeErr.message : String(probeErr);
            }
          }
          const known = store.get(id) ?? live;
          const changed = shells !== undefined && known?.shells !== undefined && (known.shells.length !== shells.length || known.shells.some((x, i) => x !== shells![i]));
          const observation = shells === undefined ? undefined : { id, target: shellTarget, shells, probedAt };
          const probeBinding = observation === undefined ? undefined : sealReviewBinding(reviewKey, JSON.stringify(observation), PROBE_BINDING_PREFIX);
          return {
            success: true,
            data: {
              id,
              reachable,
              exitCode: result.exitCode,
              ...(result.terminatedBy ? { terminatedBy: result.terminatedBy } : {}),
              ...(shells !== undefined ? { shells, shellsProbedAt: probedAt } : {}),
              ...(shellsError !== undefined ? { shellsProbe: `failed: ${shellsError}` } : {}),
              ...(observation !== undefined && probeBinding !== undefined
                ? {
                    list: {
                      title: known?.shells === undefined
                        ? 'Interpreters observed on the target — record them to use at review time'
                        : changed
                          ? `Interpreters observed on the target DIFFER from the record (${known.shellsSource ?? 'declared'}: ${known.shells.join(', ') || '(none)'}) — record the observation`
                          : 'Interpreters observed on the target — same as recorded',
                      data: [{ id, shells: shells!.join(', '), recorded: known?.shells?.join(', ') ?? '(unknown)', probedAt, probeBinding }],
                      columns: [
                        { key: 'id', label: 'Server', format: 'code' },
                        { key: 'shells', label: 'Observed now' },
                        { key: 'recorded', label: 'Recorded' },
                        { key: 'probedAt', label: 'Probed at' },
                      ],
                      // Submitting the form IS the confirmation. Nothing on it
                      // is editable: the sealed observation is recorded AS
                      // OBSERVED or not at all — a person who wants a
                      // different list declares one (updateServer, `declared`).
                      rowActions: [
                        {
                          label: 'Record Interpreters',
                          action: 'recordProbedShells',
                          submitLabel: 'Record',
                          lockFields: ['id', 'probeBinding'],
                          payload: { id: '$row.id', probeBinding: '$row.probeBinding' },
                        },
                      ],
                    },
                  }
                : {}),
            },
          };
        } catch (err) {
          // A host key MISMATCH is the one failure the operator can act on
          // right here (#46): the endpoint answering for this host is not the
          // one that was admitted. Surface the two fingerprints as DATA, side
          // by side, plus a one-confirm rotation affordance — updateServer
          // with the id locked and the PRESENTED key prefilled (editable, so
          // an operator can paste an out-of-band-verified value instead).
          // Never auto-accepted: admitting the new key stays a human decision,
          // because a mismatch reads the same whether the host was rebuilt or
          // impersonated — the operator is the one who knows which happened.
          if (err instanceof HostKeyMismatchError) {
            return {
              success: true,
              data: {
                id,
                reachable: false,
                hostKeyChanged: true,
                error: err.message,
                list: {
                  title: 'Host key changed — this endpoint is not the one that was admitted',
                  // port and generation ride the row for the affordance's CAS
                  // payload (review 2325); generation is a random record
                  // handle, not a credential.
                  data: [{ id, host: err.host, port: err.port, generation: err.generation, admittedFingerprint: err.admitted, presentedFingerprint: err.presented }],
                  columns: [
                    { key: 'id', label: 'Server', format: 'code' },
                    { key: 'host', label: 'Host' },
                    { key: 'port', label: 'Port' },
                    { key: 'admittedFingerprint', label: 'Admitted (old)', format: 'code', copyable: true },
                    { key: 'presentedFingerprint', label: 'Presented (new)', format: 'code', copyable: true },
                  ],
                  // A dedicated fingerprint-only action, not the generic Edit
                  // (review 2321): the observation crosses a command round-trip
                  // before a human confirms, so the rotation carries the
                  // BINDING it was observed against (host + admitted key) and
                  // the store CAS-refuses if the entry changed in the window —
                  // a rehost, a remove+re-add, or someone else's rotation wins
                  // over a stale observation. The expected-binding fields are
                  // LOCKED (an editable CAS basis is no CAS at all); the new
                  // fingerprint stays editable for pasting an out-of-band-
                  // verified value. Submitting the form IS the explicit human
                  // confirmation — deliberately no `confirm` flag: the Panel
                  // does not consume one today, and claiming a second popup
                  // that does not exist would be a paper control.
                  rowActions: [
                    {
                      label: 'Admit New Host Key',
                      action: 'rotateHostKey',
                      submitLabel: 'Admit',
                      lockFields: ['id', 'expectedHost', 'expectedPort', 'expectedFingerprint', 'expectedGeneration'],
                      payload: { id: '$row.id', expectedHost: '$row.host', expectedPort: '$row.port', expectedFingerprint: '$row.admittedFingerprint', expectedGeneration: '$row.generation', newFingerprint: '$row.presentedFingerprint' },
                    },
                  ],
                },
              },
            };
          }
          // Redact the probe error with the SAME sanitizer as executor errors —
          // strip this server's stored secrets by exact match, then redact
          // secret-looking values (#27, archived review).
          return { success: true, data: { id, reachable: false, error: sanitizeMessage(err instanceof Error ? err.message : String(err), undefined, [server.password, server.passphrase, server.privateKey]) } };
        }
      },
    },
    {
      name: 'rotateHostKey',
      label: 'Admit New Host Key',
      category: '_servers',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'Server id ([a-z0-9._-])' },
          expectedHost: { type: 'string', description: 'The host the mismatch was observed against — the rotation refuses if the entry was rehosted since' },
          expectedPort: { type: 'integer', minimum: 1, maximum: 65535, description: 'The effective port the mismatch was observed on — the same host on another port is another endpoint' },
          expectedFingerprint: { type: 'string', description: 'The fingerprint admitted when the mismatch was observed — the rotation refuses if someone already rotated it' },
          expectedGeneration: { type: 'string', description: 'The record generation the mismatch was observed against — a removed-and-re-added lookalike is a NEW trust record and refuses' },
          newFingerprint: { type: 'string', description: 'The fingerprint to admit (SHA256:…). Prefilled with what the endpoint presented; replace it with an out-of-band-verified value if you prefer.' },
        },
        required: ['id', 'expectedHost', 'expectedPort', 'expectedFingerprint', 'expectedGeneration', 'newFingerprint'],
        additionalProperties: false,
      },
      // Fingerprint-only by design (review 2321): the generic updateServer
      // writes a whole snapshot, so confirming a stale mismatch through it
      // could overwrite changes made while the operator was deciding. This
      // action changes EXACTLY the admitted key, and only when the record
      // still matches the state the mismatch was observed against.
      execute: async (input: unknown) => {
        const rec = asRecord(input);
        const port = Number(rec.expectedPort);
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('expectedPort must be an integer in 1..65535');
        const rotated = store.rotateHostKey(
          str(rec.id),
          { host: str(rec.expectedHost), port, fingerprint: str(rec.expectedFingerprint), generation: str(rec.expectedGeneration) },
          str(rec.newFingerprint),
        );
        return { success: true, message: 'host key rotated', data: { server: publicServer(rotated), list: serversListDisplay(store.list()) } };
      },
    },
    {
      name: 'recordProbedShells',
      label: 'Record Interpreters',
      category: '_servers',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'Server id ([a-z0-9._-])' },
          probeBinding: { type: 'string', description: 'The sealed observation testServer produced (server binding + interpreters + time). Recorded exactly as observed, or refused.' },
        },
        required: ['id', 'probeBinding'],
        additionalProperties: false,
      },
      // The explicit confirmation of a probe (#69, reviews 2475/2480): a Test
      // is a read; THIS writes — only what THIS Worker incarnation sealed
      // when it observed the target, and only while the record still matches
      // the observation's binding. Same posture as rotateHostKey, plus the
      // seal: `probed` can only ever mean "the target answered this".
      execute: async (input: unknown) => {
        const rec = asRecord(input);
        const opened = unsealReviewBinding(reviewKey, str(rec.probeBinding), PROBE_BINDING_PREFIX);
        if (opened === null) throw new Error('this record carries no valid probe binding from THIS Worker incarnation — run Test again and record from its result');
        let observation: { id: string; target: ProbeTargetSnapshot; shells: string[]; probedAt: string };
        try {
          observation = JSON.parse(opened) as typeof observation;
        } catch {
          throw new Error('probe binding is unreadable; run Test again');
        }
        if (observation.id !== str(rec.id)) throw new Error(`probe binding was observed on "${observation.id}", not "${str(rec.id)}"`);
        const recorded = store.recordProbedShells(observation.id, { shells: observation.shells, probedAt: observation.probedAt }, observation.target);
        return { success: true, message: `recorded interpreters for ${recorded.id}: ${observation.shells.join(', ') || '(none)'} (probed ${observation.probedAt})`, data: { server: publicServer(recorded), list: serversListDisplay(store.list()) } };
      },
    },
    {
      name: 'probeHostKey',
      label: 'Probe Host Key',
      category: '_servers',
      inputSchema: {
        type: 'object',
        properties: {
          host: { type: 'string', description: 'Hostname or IP to probe' },
          port: { type: 'integer', minimum: 1, maximum: 65535, description: 'SSH port (default 22)' },
        },
        required: ['host'],
        additionalProperties: false,
      },
      execute: async (input: unknown) => {
        const rec = asRecord(input);
        const host = str(rec.host).trim();
        if (!host) throw new Error('host is required');
        const port = rec.port !== undefined ? Number(rec.port) : 22;
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('port must be an integer in 1..65535');
        // Key exchange happens BEFORE authentication, so this needs no
        // credential and admits nothing (#44): it hands the operator the
        // SHA256:… value to confirm into addServer/updateServer.
        try {
          const fingerprint = await probeHostKey(host, port);
          return {
            success: true,
            message: 'host key probed',
            data: {
              host,
              port,
              fingerprint,
              detail: {
                title: `Host key of ${host}:${port}`,
                data: { host, port, fingerprint },
                fields: [
                  { key: 'host', label: 'Host' },
                  { key: 'port', label: 'Port' },
                  { key: 'fingerprint', label: 'SHA-256 fingerprint', format: 'code', copyable: true },
                ],
              },
            },
          };
        } catch (err) {
          // No credential is in play, so the raw message is safe — but it is
          // still bounded by the standard sanitizer for shape consistency.
          return { success: true, data: { host, port, error: sanitizeMessage(err instanceof Error ? err.message : String(err), undefined, []) } };
        }
      },
    },
    {
      name: 'manageTasks',
      label: 'Manage Tasks',
      description: "Grow this Service's task library online (#53): add and edit land as DRAFTS — not executable, not in the catalog — and a task runs only after a person approves its full script text via Enable.",
      category: 'config',
      inputSchema: { type: 'object', properties: {}, required: [], additionalProperties: false },
      // A governed library says so on the panel a person actually opens
      // (xtrape-docs#255): what is effective here, which version it came
      // from, and where the review lives. Without this the refusals from
      // Enable/Disable/Remove would look like a broken build.
      // No prepare — same reason as manageServers: the READ answers the list.
      execute: async () => ({ success: true, data: { ...governedBanner(), list: governedListTitle(tasksListDisplay(taskStore.listAll())) } }),
    },
    {
      name: 'listTasks',
      label: 'List Tasks',
      category: '_tasks',
      execute: async () => ({ success: true, data: { list: tasksListDisplay(taskStore.listAll()) } }),
    },
    {
      name: 'viewTask',
      label: 'View Task',
      category: '_tasks',
      inputSchema: {
        type: 'object',
        properties: { id: { type: 'string' }, state: { type: 'string', enum: ['enabled', 'draft'] } },
        required: ['id', 'state'],
        additionalProperties: false,
      },
      execute: async (input: unknown) => {
        const rec = asRecord(input);
        const state = str(rec.state);
        if (state !== 'draft' && state !== 'enabled') throw new Error(`state must be "draft" or "enabled", got "${state}"`);
        const stored = state === 'draft' ? taskStore.findDraft(str(rec.id)) : taskStore.findEnabled(str(rec.id));
        if (!stored) throw new Error(`no ${str(rec.state)} task "${str(rec.id)}"`);
        return { success: true, data: taskDetailDisplay(`${stored.definition.id} — ${stored.state}`, stored.definition, taskStore.content(stored), stored.state) };
      },
    },
    {
      name: 'addTask',
      label: 'Add Task',
      category: '_tasks',
      // Structured fields, 1:1 with the task DB's metadata columns (#58 part
      // 2): risk, approval, and the server binding are choices, not header
      // syntax to memorize. The catalog-time schema has no live fleet read;
      // prepare renders the serverScope choices from the admitted fleet.
      inputSchema: taskFormSchema({ forAdd: true }),
      prepare: (_input?: unknown, ctx?: CePrepareContext): CeActionPrepareResult => {
        const rich = taskFormSchema({ forAdd: true, serverIds: store.list().map((s) => s.id) });
        // No candidate exchange (review 3209): `serverScope` is a scope
        // EXPRESSION, not a Resource — under a governed review the form keeps
        // it free (the description lists the choices), no enum is added.
        return { inputSchema: governedReview(ctx) ? reviewNextSchema(rich) : rich };
      },
      execute: async (input: unknown, context?: ExecuteContext) => {
        const rec = asRecord(input);
        // A new task has nothing stored to preserve.
        const parts = taskPartsFromForm(rec, EMPTY_BASE);
        if (content) return submitGoverned(parts, `add task ${parts.headers['xtrape-task']}`, context);
        if (taskStore.findDraft(parts.headers['xtrape-task']!)) throw new Error(`a draft "${parts.headers['xtrape-task']}" already exists; edit it instead`);
        const saved = taskStore.saveDraftFromParts(parts);
        if (saved.state === 'enabled') {
          // Byte-identical to the running version (review 2349 P2): nothing
          // was saved and no review is pending — reporting "draft saved"
          // would send the operator hunting for a draft that does not exist.
          return { success: true, message: 'no change — the content is identical to the enabled version', data: { id: saved.definition.id, state: 'enabled', scriptDigest: saved.definition.scriptDigest, list: tasksListDisplay(taskStore.listAll()) } };
        }
        if (!saved.unchanged) auditTask('task_draft_saved', saved.definition.id, { after: saved.definition.scriptDigest });
        return { success: true, message: saved.unchanged ? 'no change — identical to the pending draft' : 'draft saved (not executable until enabled)', data: { id: saved.definition.id, state: 'draft', scriptDigest: saved.definition.scriptDigest, list: tasksListDisplay(taskStore.listAll()) } };
      },
    },
    {
      name: 'updateTask',
      label: 'Edit Task',
      category: '_tasks',
      inputSchema: taskFormSchema({ forAdd: false }),
      prepare: (input?: unknown, ctx?: CePrepareContext): CeActionPrepareResult => {
        const id = str(asRecord(input).id);
        const stored = taskStore.findDraft(id) ?? taskStore.findEnabled(id);
        const serverIds = store.list().map((s) => s.id);
        const rich = taskFormSchema({ forAdd: false, serverIds });
        return {
          // No candidate exchange on `serverScope` (review 3209): a scope expression, not a Resource.
          inputSchema: governedReview(ctx) ? reviewNextSchema(rich) : rich,
          // The review card (#94): what is stored NOW — the text the edit starts from.
          ...(stored ? { currentState: taskDetailDisplay(`Edit ${id} — ${stored.state} r${stored.revisionId}`, stored.definition, taskStore.content(stored), stored.state) } : {}),
          // A task's configuration is not a secret: prefill every field from
          // the stored version — the canonical text split back into the same
          // columns the form edits — so an edit is an edit, not a retype.
          initialPayload: {
            id,
            ...(stored ? taskFormPayloadFrom(splitTaskSource(taskStore.content(stored)), serverIds) : {}),
            // Which stored revision this form was filled from. Sealed under
            // this Worker incarnation's key, so it cannot be minted or
            // altered, and checked against the live revision at submit —
            // a stale prepare must not overwrite a newer revision's hidden
            // declarations (review 2393).
            ...(stored ? { baseRevision: sealReviewBinding(reviewKey, `${id}@r${stored.revisionId}`, TASK_EDIT_BINDING_PREFIX) } : {}),
          },
        };
      },
      execute: async (input: unknown, context?: ExecuteContext) => {
        const rec = asRecord(input);
        const id = str(rec.id);
        // The edit applies to the revision the form was filled from, and to
        // no other (review 2393). The token is sealed, so it names a
        // revision this Worker really issued; the CAS then refuses a stale
        // prepare, whose hidden declarations would otherwise overwrite
        // whatever landed in between.
        const stored = taskStore.findDraft(id) ?? taskStore.findEnabled(id);
        const sealedBase = unsealReviewBinding(reviewKey, str(rec.baseRevision), TASK_EDIT_BINDING_PREFIX);
        if (sealedBase === null) {
          throw new Error('this edit carries no valid base-revision token from THIS Worker incarnation — re-open Edit and submit again');
        }
        if (!stored) throw new Error(`no task "${id}" to edit — it was removed after this form was opened`);
        if (sealedBase !== `${id}@r${stored.revisionId}`) {
          throw new Error(`task "${id}" changed after this form was opened (${sealedBase} is no longer current); re-open Edit so the change you did not see is not overwritten`);
        }
        const parts = taskPartsFromForm(rec, baseOf(splitTaskSource(taskStore.content(stored))));
        // The locked row identity must match the form's id field — the id is
        // readOnly on this surface, so a mismatch is a tampered payload.
        if (parts.headers['xtrape-task'] !== id) throw new Error(`the form declares id "${parts.headers['xtrape-task']}" but this edit targets "${id}" — use Add Task for a new task`);
        if (content) return submitGoverned(parts, `edit task ${id}`, context);
        const before = taskStore.findDraft(id)?.definition.scriptDigest;
        const saved = taskStore.saveDraftFromParts(parts);
        if (saved.state === 'enabled') {
          // Byte-identical to the running version: nothing was saved and no
          // review is pending. When this RESTORED the enabled bytes over a
          // pending draft, that draft is withdrawn — say so, and record the
          // withdrawal (review 2349: editing back to the running version is
          // a cancel, not a new draft).
          if (saved.canceledDraftDigest) {
            auditTask('task_removed', id, { before: saved.canceledDraftDigest, state: 'draft' });
            return { success: true, message: 'pending draft withdrawn — the content now matches the enabled version', data: { id, state: 'enabled', scriptDigest: saved.definition.scriptDigest, list: tasksListDisplay(taskStore.listAll()) } };
          }
          return { success: true, message: 'no change — the content is identical to the enabled version', data: { id, state: 'enabled', scriptDigest: saved.definition.scriptDigest, list: tasksListDisplay(taskStore.listAll()) } };
        }
        if (!saved.unchanged) auditTask('task_draft_saved', saved.definition.id, { after: saved.definition.scriptDigest, ...(before ? { before } : {}) });
        return { success: true, message: saved.unchanged ? 'no change — identical to the pending draft' : 'draft saved (not executable until enabled)', data: { id: saved.definition.id, state: 'draft', scriptDigest: saved.definition.scriptDigest, list: tasksListDisplay(taskStore.listAll()) } };
      },
    },
    {
      name: 'enableTask',
      label: 'Enable Task',
      category: '_tasks',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          reviewBinding: { type: 'string', description: 'Issued by prepare; opaque. Binds this approval to the exact draft bytes the review card showed AND to the Worker incarnation that showed them — do not edit.' },
        },
        required: ['id', 'reviewBinding'],
        additionalProperties: false,
      },
      // The approval step (#53): prepare IS the review — the full draft text
      // and its digest, platform-rendered — and submitting the form is the
      // explicit human decision (the same confirmation semantics as
      // rotateHostKey). Never reachable without that review on the Panel
      // surface; the MCP surface cannot reach _tasks sub-ops at all before
      // #53 P2, where enable stays Panel-only by the default evidence scale.
      prepare: (input?: unknown, ctx?: CePrepareContext): CeActionPrepareResult => {
        const id = str(asRecord(input).id);
        const draft = taskStore.findDraft(id);
        const replacing = taskStore.findEnabled(id);
        const richSchema = {
          type: 'object',
          properties: {
            id: { type: 'string' },
            reviewBinding: { type: 'string', description: 'Issued by prepare; opaque — do not edit.' },
          },
          required: ['id', 'reviewBinding'],
          additionalProperties: false,
        };
        const schema = governedReview(ctx) ? reviewNextSchema(richSchema) : richSchema;
        if (!draft) {
          return { inputSchema: schema, initialPayload: { id } };
        }
        // Screening is REVIEW-TIME help (#65): the hits are put in front of
        // the person about to approve, because a sixty-line script is where
        // an `rm -rf $DIR` hides. A hard hit refuses at submit; a soft one
        // is recorded and makes every later run ask.
        const hits = redlines.screen(draft.definition.script);
        // Executability (#69): the shebang's interpreter against every
        // admitted server this task's scope matches — on the card the
        // approver reads, where "the target has no bash" belongs.
        const avail = interpreterNotices(draft.definition.interpreter, store.listMatching(draft.definition.serverScopes));
        const card = taskDetailDisplay(
          replacing
            ? `Approve & enable ${id} — REPLACES the running version (${replacing.definition.scriptDigest})`
            : `Approve & enable ${id}`,
          draft.definition,
          taskStore.content(draft),
          'draft',
          hits.length > 0 ? hitLines(hits) : undefined,
          avail.lines.length > 0 ? avail.lines.join('\n') : undefined,
        );
        return {
          inputSchema: schema,
          // The approval binds to the digest the review card SHOWS — sealed
          // under the incarnation key (review 2331 item 1): a plain digest
          // field was CALLER-writable, so anyone could copy a current digest
          // into it and "approve" bytes no card ever showed. The sealed token
          // can only have been minted by THIS Worker's prepare, i.e. by a
          // flow that actually rendered the script.
          initialPayload: { id, reviewBinding: sealReviewBinding(reviewKey, draft.definition.scriptDigest, TASK_ENABLE_BINDING_PREFIX) },
          currentState: card,
        };
      },
      execute: async (input: unknown, context?: ExecuteContext) => {
        const rec = asRecord(input);
        const id = str(rec.id);
        if (content) return governedElsewhere('enabling a task');
        const approvedDigest = unsealReviewBinding(reviewKey, str(rec.reviewBinding), TASK_ENABLE_BINDING_PREFIX);
        if (approvedDigest === null) {
          throw new Error('this enable carries no valid review binding from THIS Worker incarnation — a Platform fallback to another Worker, a Worker restart, or an altered payload; re-open Enable and review the current draft');
        }
        // Approval provenance (reviews 2349/2350): the ledger records what
        // this surface can attest — the Platform command that delivered the
        // approved execute and, since #256, the deciding Account the
        // Platform delivered with it (`approvedBy` = the canonical Account
        // id; unset when the origin carries none — never a stand-in).
        // Absent BOTH a commandId and a deciding Account (the operator's
        // local callback path), the store fails the enable closed rather
        // than landing an approval record that names nobody.
        // A HARD redline is a refusal, not a warning: approving it here
        // would leave a task enabled that the next rule-set sweep would
        // suspend anyway (#65).
        const draftNow = taskStore.findDraft(id);
        const hits = draftNow ? redlines.screen(draftNow.definition.script) : [];
        if (verdictOf(hits) === 'hard') {
          throw new Error(`task "${id}" cannot be enabled: it hits a hard redline —\n${hitLines(hits.filter((h) => h.severity === 'hard'))}`);
        }
        // The verdict rides INTO the same transaction as the pointer move
        // (review 2403): recorded afterwards, a crash in between left the
        // new revision wearing the previous one's verdict.
        // GROW BEFORE EXPOSE, atomically against the durable state (review
        // 2674 P1-1): the Checkpoint is durably published from the DRAFT's
        // definition BEFORE taskStore.enable() commits the irreversible
        // pointer move (the draft is consumed in that transaction). A publish
        // failure aborts HERE — the draft, its approval and the enable
        // pointer are all untouched, and re-running Enable retries the
        // publication (idempotent per FULL definition, not per id@version — a
        // drifted definition at a known id@version is republished and hits the
        // Platform's 409 CHECKPOINT_IMMUTABLE_CONFLICT here, before the pointer
        // move, review 2692). A published Checkpoint whose enable then fails is
        // harmless: immutable, unbound, never exposed.
        if (draftNow) await deps.ensureTaskCheckpoints?.([draftNow.definition]);
        const approver = originOf(context);
        const { definition, replaced } = taskStore.enable(
          id,
          approvedDigest,
          {
            ...(context?.commandId !== undefined ? { commandId: context.commandId } : {}),
            ...(approver.account !== undefined ? { approvedBy: approver.account } : {}),
          },
          { generation: redlines.generation, verdict: verdictOf(hits) },
        );
        // Hot swap: the runtime registry mirrors the file truth, and the live
        // actions array follows — the Platform's next catalog fetch sees it.
        registry.unregister(id);
        registry.register(definition);
        rebuildOps();
        auditTask('task_enabled', id, { after: definition.scriptDigest, ...(replaced ? { before: replaced } : {}) });
        return {
          success: true,
          message: replaced ? 'task enabled — replaced the previous version' : 'task enabled',
          data: { id, state: 'enabled', scriptDigest: definition.scriptDigest, ...(replaced ? { replacedDigest: replaced } : {}), list: tasksListDisplay(taskStore.listAll()) },
        };
      },
    },
    {
      name: 'disableTask',
      label: 'Disable Task',
      category: '_tasks',
      inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false },
      execute: async (input: unknown) => {
        const id = str(asRecord(input).id);
        if (content) return governedElsewhere('disabling a task');
        const { definition: def } = taskStore.disable(id);
        registry.unregister(id);
        rebuildOps();
        auditTask('task_disabled', id, { before: def.scriptDigest });
        return { success: true, message: 'task disabled (back to draft)', data: { id, state: 'draft', scriptDigest: def.scriptDigest, list: tasksListDisplay(taskStore.listAll()) } };
      },
    },
    {
      name: 'removeTask',
      label: 'Remove Task',
      category: '_tasks',
      inputSchema: {
        type: 'object',
        properties: { id: { type: 'string' }, state: { type: 'string', enum: ['enabled', 'draft'] } },
        required: ['id', 'state'],
        additionalProperties: false,
      },
      execute: async (input: unknown) => {
        const rec = asRecord(input);
        const id = str(rec.id);
        const state = str(rec.state);
        if (content) return governedElsewhere('removing a task');
        // Strict discriminator (review 2329 item 7): a destructive action
        // must never let an unrecognized state fall into the enabled branch.
        if (state !== 'draft' && state !== 'enabled') throw new Error(`state must be "draft" or "enabled", got "${state}"`);
        if (state === 'draft') {
          const before = taskStore.findDraft(id)?.definition.scriptDigest;
          taskStore.removeDraft(id);
          auditTask('task_removed', id, { ...(before ? { before } : {}), state: 'draft' });
        } else {
          const removed = taskStore.removeEnabled(id);
          registry.unregister(id);
          rebuildOps();
          auditTask('task_removed', id, { before: removed.definition.scriptDigest, state: 'enabled' });
        }
        return { success: true, message: 'task removed', data: { removed: id, list: tasksListDisplay(taskStore.listAll()) } };
      },
    },
  ];

  // Every management entry carries its frozen Checkpoint binding (#79) — one
  // mapping site, so the table in checkpoints.ts stays the single authority.
  actions.push(...manage.map((entry) => describedAction({ ...entry, checkpoint: checkpointRefFor(entry.name) })).filter(exposed));
  rebuildOps();
  // The caller can now refresh this catalog itself — used by the governed
  // content poll, whose changes do not arrive through any action here.
  deps.onRebuildAvailable?.(rebuildOps);
  return actions;
}
