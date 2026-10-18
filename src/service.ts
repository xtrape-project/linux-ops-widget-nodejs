import { createHash, randomUUID } from 'node:crypto';
import type { CommandResult, Executor, OpsRequest, OutputPolicy, ServerDefinition, Surface } from './types.js';
import type { ActionRegistry } from './registry.js';
import type { ServerResolver } from './servers.js';
import type { AuditLogger } from './audit.js';
import { evaluate } from './policy.js';
import { guardVerdict, ParamGuardSet } from './param-guards.js';
import { buildTaskCommand, maskedTaskCommand } from './shell.js';
import { DEFAULT_MAX_OUTPUT_BYTES, redactOutput } from './redact.js';
import { describeRequest, type ConfirmationChannel, type ConfirmationRequest } from './confirmation.js';
import { interpreterAvailability } from './interpreter-check.js';

export type OpsResponse =
  | { status: 'denied'; rule: string; reason: string }
  | { status: 'requires_approval'; rule: string; reason: string }
  /** A person was asked and said no. Distinct from a policy denial: policy allowed the question to be put. */
  | { status: 'confirmation_refused'; rule: string; reason: string; answeredBy?: string | undefined }
  | { status: 'dry_run'; command: string; scriptDigest: string }
  | { status: 'executed'; result: CommandResult }
  | { status: 'command_failed'; result: CommandResult }
  /**
   * An executor had to stop the command and no exit status was observed, so
   * the remote outcome is unknown. Since #61 B the RECORDING ceiling no
   * longer does this — output beyond it is read and dropped while the task
   * runs to completion — so this status is reserved for a genuine forced
   * termination.
   */
  | { status: 'output_limit'; result: CommandResult }
  | { status: 'error'; message: string };

/**
 * What is known about an execution at the point a record is written.
 *
 * It widens as the request is resolved — task version and script digest as
 * soon as the task is found, the execution hash once the arguments are
 * validated — and every record from that point carries what was known. A
 * record that dropped it could not be attributed to its own execution.
 */
interface ExecutionBinding {
  actionVersion?: string;
  scriptDigest?: string;
  executionHash?: string;
  /** Governed content version the executing revision came from (xtrape-docs#255). */
  sourceVersion?: string;
  /**
   * The task's declared blast radius, recorded so a reviewer reading the log
   * sees it there rather than having to go and open the task file — which by
   * then may have been edited. The Widget does not act on it beyond policy;
   * carrying it is part of the same obligation as recording the digest.
   */
  riskLevel?: string;
}

/** Upper bound on remembered command outcomes; see `remember`. */
const MAX_REMEMBERED_COMMANDS = 1_024;

export interface OpsServiceOptions {
  registry: ActionRegistry;
  servers: ServerResolver;
  executors: Executor[];
  audit: AuditLogger;
  /**
   * How this Widget puts a question to a person. Since the 0.8.1 bump the
   * runtime wiring configures this from the pinned SDK's `ask()`; absent — an
   * SDK without the method, a caller that passes none — leaves the
   * fail-closed path: a task needing a human is stopped and nobody is asked.
   */
  confirmation?: ConfirmationChannel;
  /**
   * How much task output this DEPLOYMENT records, across stdout and stderr
   * together (#61 B, owner ruling: a task generates what its business needs;
   * what can be recorded is the deployment's call, not the task author's).
   * Beyond it, output is read and dropped — the task still runs to
   * completion. A stored task's retired `# maxBytes:` still applies when it
   * asks for LESS, so an upgrade never records more than an author allowed.
   */
  maxRecordedOutputBytes?: number;
  /**
   * The standing redline verdict for a task, when the deployment screens
   * scripts (#65). Read per execution so a sweep's verdict takes effect
   * without a restart.
   */
  screening?: (actionId: string) => 'soft' | 'hard' | undefined;
  /**
   * Parameter risk control (#66), evaluated per invocation because a
   * parameter's value does not exist until somebody calls. Absent = no
   * guards.
   */
  paramGuards?: ParamGuardSet;
}

export interface ExecuteContext {
  surface: Surface;
  /**
   * Whether the Xtrape Platform (the control plane) is reachable. Drives the
   * fail-safe: a non-readonly action is denied when the Platform is down. The
   * Platform command path is inherently reachable (the Platform is invoking);
   * an Exposure-originated path passes its live connection state.
   */
  controlPlaneAvailable: boolean;
  /**
   * The Platform command this execution settles, when there is one. Used to
   * answer a repeated delivery with the first execution's outcome instead of
   * running the task again.
   */
  commandId?: string;
  /** Aborted when the Platform delivers a cancel for that command. */
  signal?: AbortSignal;
}

/** Deterministic JSON with recursively sorted object keys (order-independent). */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

/**
 * Stable per-invocation hash binding server + task version + SCRIPT + args.
 *
 * The script digest is part of it because a task id and version name a file
 * whose contents can be edited in place. Without it, two runs of
 * `xtrape.deploy@1.0.0` with identical arguments are indistinguishable in
 * evidence even when the operator replaced the script between them — and the
 * same hash is what a future approval binds to, so an approval would carry
 * over to a script nobody approved (review 2165).
 */
export function executionHashOf(
  serverId: string,
  actionId: string,
  version: string,
  scriptDigest: string,
  args: Record<string, unknown>,
): string {
  return createHash('sha256').update(stableStringify({ serverId, actionId, version, scriptDigest, args })).digest('hex');
}

/*
 * A task's script never contains caller input, and the command line carries
 * parameter values only inside quoted environment assignments — a shape this
 * code produces and can therefore project exactly. So the audit projection
 * (`maskedTaskCommand` in `./shell.ts`) is that command with the parameter
 * VALUES masked: which parameters were supplied, never what they were. The
 * exact values stay pinned by `executionHash` and held authoritatively by the
 * Platform.
 */

/**
 * Sanitize an exception message before it reaches local audit or the wire: an
 * executor error can echo secret-looking values. Strip every stored raw
 * secret by exact match first, then apply output redaction (#27, archived
 * review). (The retired `privateKeyPath` reference is gone (#42) — the key
 * CONTENT is a stored secret like the others and rides this same list; exact
 * match works on a multiline PEM too.)
 */
export function sanitizeMessage(raw: string, outputPolicy?: OutputPolicy, secrets?: (string | undefined)[]): string {
  // ssh2's auth errors do not carry the value, but a leak here is
  // unrecoverable, so each secret is removed by exact match BEFORE the
  // pattern-based redaction. Empty secrets are skipped — `split('')` would
  // shatter the message into characters.
  const withoutSecrets = (secrets ?? []).reduce<string>(
    (acc, secret) => (secret ? acc.split(secret).join('[redacted-secret]') : acc),
    raw,
  );
  return redactOutput(withoutSecrets, outputPolicy);
}

/**
 * Orchestrates request validation, local policy, and execution + local
 * evidence.
 *
 * Deciding that a task needs a person is this Widget's job — only it knows
 * which of its own tasks are dangerous — and putting the question is too; the
 * Platform relays. `deny` and `human_review` are both settled before the
 * command is built or the executor is reached, on BOTH surfaces, so nothing
 * runs while a person is deciding and a refusal costs no execution. With no
 * channel to ask through, `human_review` stays fail-closed: the task stops and
 * nobody is asked. The MCP surface is GRADED, not read-only (#53 P1.5):
 * read-only tasks flow as policy allows; mutating work escalates to a human
 * approval whose grant must echo the script digest.
 */
export class OpsService {
  private readonly executors: Map<string, Executor>;
  private confirmation: ConfirmationChannel | undefined;

  constructor(private readonly opts: OpsServiceOptions) {
    this.executors = new Map(opts.executors.map((e) => [e.name, e]));
    this.confirmation = opts.confirmation;
  }

  /**
   * Attach the way to reach a person, once it exists.
   *
   * The channel rides the Connector, which only exists after
   * this Service's actions — which need this OpsService — are registered; a
   * constructor argument cannot express that order. One-time on purpose: a
   * second attach would silently reroute questions mid-flight.
   */
  attachConfirmation(channel: ConfirmationChannel | undefined): void {
    if (this.confirmation !== undefined) throw new Error('a confirmation channel is already attached');
    this.confirmation = channel;
  }

  listActions(surface: Surface = 'platform'): Array<{ id: string; version: string; description?: string; riskLevel: string }> {
    // Both surfaces list everything (#53 P1.5): the MCP caller is a person
    // acting through an AI device, and every task is EXECUTABLE there —
    // gated by the effective risk, not hidden. `surface` stays a parameter
    // so audit/callers keep naming who asked.
    void surface;
    return this.opts.registry
      .list()
      .map(({ id, version, description, riskLevel }) => ({
        id,
        version,
        ...(description !== undefined ? { description } : {}),
        riskLevel,
      }));
  }

  async execute(request: OpsRequest, ctx: ExecuteContext): Promise<OpsResponse> {
    // Collapse a REPEATED DELIVERY of the same command, best effort.
    //
    // This Widget does not retry, but that says nothing about being ASKED
    // twice: a retried push or a reconnect can deliver the same commandId
    // again, and re-running a task with side effects would be an effect nobody
    // requested. A repeat is therefore answered with the first execution's
    // outcome.
    //
    // What this is NOT is "one command, one execution" as a durable
    // guarantee, and the difference matters for a task with side effects
    // (review 2172). The memory is in-process and bounded: past
    // MAX_REMEMBERED_COMMANDS, or across a Worker restart, the same commandId
    // runs again. It also only engages where the transport hands over a
    // commandId — World A does, and so does registered World B since
    // connector 0.8.1 (the push carries x-xtrape-command-id into the
    // execute context); a transport without one leaves the collapse
    // inapplicable. A durable, transport-independent guarantee needs
    // persisted command outcomes (#39). Until then, write tasks with side
    // effects to be re-runnable — the same property the SSH timeout note asks
    // for, for the same reason.
    const commandId = ctx.commandId;
    if (commandId !== undefined) {
      const inFlight = this.settled.get(commandId);
      if (inFlight !== undefined) return inFlight;
      const run = this.run(request, ctx);
      this.remember(commandId, run);
      return run;
    }
    return this.run(request, ctx);
  }

  /** Bounded so a long-lived Worker cannot grow one entry per command forever. */
  private readonly settled = new Map<string, Promise<OpsResponse>>();

  private remember(commandId: string, run: Promise<OpsResponse>): void {
    if (this.settled.size >= MAX_REMEMBERED_COMMANDS) {
      const oldest = this.settled.keys().next().value;
      if (oldest !== undefined) this.settled.delete(oldest);
    }
    this.settled.set(commandId, run);
  }

  private async run(request: OpsRequest, ctx: ExecuteContext): Promise<OpsResponse> {
    const started = Date.now();
    // Data-minimized at construction, so BOTH the durable and the in-memory
    // logger see the same minimized record. Argument names are kept (they are
    // already public in the action's params schema); values are represented
    // only by `executionHash`.
    //
    // The scope of that is the REQUEST and the COMMAND, and no wider. A task's
    // stdout and stderr are also recorded, and they are the script's output —
    // a script that echoes `$XOPS_release` writes that value into evidence.
    // `redactOutput` is pattern-based (`token`, `password`, `secret`, …) and
    // cannot know an arbitrary argument value, so it does not close that and
    // is not claimed to. A task handling something sensitive keeps it out of
    // its own output, or declares `# redact:` for it.
    const auditRequest = {
      serverId: request.serverId,
      actionId: request.actionId,
      argsKeys: Object.keys(request.args ?? {}).sort(),
      reason: request.reason,
      dryRun: request.dryRun ?? false,
      surface: ctx.surface,
      ...(request.traceId !== undefined ? { traceId: request.traceId } : {}),
      ...(request.originActor !== undefined
        ? { originActorType: request.originActor.type, originActorId: request.originActor.id }
        : {}),
      ...(request.account !== undefined ? { accountId: request.account } : {}),
    };

    const action = this.opts.registry.get(request.actionId);
    // Nothing is bound yet: there is no task, so no version, script or hash.
    if (!action) return this.deny(auditRequest, 'unknown-action', `unknown action "${request.actionId}"`);

    // From here the task is resolved, so every record says WHICH task — id and
    // version name a file whose contents can be edited in place, and the digest
    // is what distinguishes one edit from another.
    const resolved: ExecutionBinding = {
      actionVersion: action.version,
      scriptDigest: action.scriptDigest,
      riskLevel: action.riskLevel,
      // Every execution record names the reviewed version it ran from
      // (review 2433 blocker 3) — the approval ledger alone cannot answer
      // "which governed version was live for THIS run".
      ...(action.sourceVersion !== undefined ? { sourceVersion: action.sourceVersion } : {}),
    };

    // Reason is a first-class request requirement, enforced BEFORE server
    // resolution / policy / command / executor — not left to the advertised
    // schema (which the SDK/server do not enforce). Zero side effects.
    if (!request.reason || request.reason.trim().length === 0) {
      return this.deny(auditRequest, 'missing-reason', 'a human-readable reason is required for every action', resolved);
    }

    const server = this.opts.servers.get(request.serverId);
    if (!server) return this.deny(auditRequest, 'unknown-server', `unknown server "${request.serverId}"`, resolved);

    const argsCheck = this.opts.registry.validateArgs(action.id, request.args);
    if (!argsCheck.ok) return this.deny(auditRequest, 'args-schema', argsCheck.errors, resolved);

    // Executability pre-check (#69), fail closed: when the target's
    // interpreters are KNOWN (declared or probed) and the shebang's is not
    // among them, refuse HERE — with its own rule, so it can never be
    // mistaken for the script's own exit 127 — before policy, before any
    // command leaves. UNKNOWN never blocks: an unprobed record keeps
    // working exactly as before, and the review cards say it is unprobed.
    // Not a control layer: this changes no risk and relaxes nothing.
    const avail = interpreterAvailability(action.interpreter, server);
    if (avail.state === 'missing') {
      return this.deny(
        auditRequest,
        'interpreter-unavailable',
        `target "${server.id}" has no "${avail.interpreter}" (${avail.source === 'probed' ? `probed${avail.probedAt ? ` at ${avail.probedAt}` : ''}` : 'declared'}: ${avail.known.length ? avail.known.join(', ') : 'none'}); the task's shebang names it — change the task's interpreter or pick a target that has it`,
        resolved,
      );
    }

    // ONE authorization axis (#61, owner ruling 2026-08-13): the surface is
    // an input to the EFFECTIVE risk (`effectiveRisk`, a notch for MCP, a
    // notch for a production target), not a separate grading pass. The old
    // `mcp-mutating` escalation is gone with the `readonly` flag it read —
    // "read-only" was never a safety property, and a label must not open a
    // door. The MCP surface still carries a stricter EVIDENCE grade: a
    // human-review grant there must echo the script digest (below).
    const screening = this.opts.screening?.(action.id);
    // Judged HERE, on the arguments that will actually run (#66): a preview
    // at prepare time cannot bind, because the caller may submit others.
    const guardHits =
      this.opts.paramGuards?.evaluate({
        taskId: action.id,
        args: request.args,
        serverId: server.id,
        environment: server.environment,
        surface: ctx.surface,
      }) ?? [];
    const guard = guardVerdict(guardHits);
    const policy = evaluate(action, server, request, {
      controlPlaneAvailable: ctx.controlPlaneAvailable,
      surface: ctx.surface,
      ...(screening !== undefined ? { screening } : {}),
      ...(guard !== 'clear' ? { paramGuard: guard, paramGuardReasons: guardHits.map((h) => `${h.id}: ${h.message}`) } : {}),
    });
    const executionHash = executionHashOf(server.id, action.id, action.version, action.scriptDigest, request.args);
    // Everything from here — including the error path — carries the SAME hash
    // the decision record carried, so a terminal record can be attributed to
    // the execution it belongs to.
    const bound: ExecutionBinding = { ...resolved, executionHash };

    this.audit({
      timestamp: new Date().toISOString(),
      event: 'decision',
      request: auditRequest,
      ...bound,
      decision: policy.decision,
      policyRule: policy.rule,
    });

    if (policy.decision === 'deny') {
      return { status: 'denied', rule: policy.rule, reason: policy.reason };
    }

    // A human_review verdict puts the question to a person and waits for the
    // answer. It is decided BEFORE the command is built or the executor is
    // reached, on both surfaces — so nothing runs while a person is deciding,
    // and a refusal costs no execution.
    //
    // With no channel configured it stays fail-closed instead: the task stops
    // and nobody is asked. (This used to describe a Platform preflight that
    // held the invocation before dispatch — a model the owner corrected: the
    // Platform keeps no management information about a task and cannot gate a
    // run, so asking is this Widget's job and the Platform relays.)
    if (policy.decision === 'human_review') {
      // A dry run never pages anyone. A preview that woke somebody up would
      // make previewing a thing people avoid.
      if (request.dryRun || this.confirmation === undefined) {
        return { status: 'requires_approval', rule: policy.rule, reason: policy.reason };
      }

      const question: ConfirmationRequest = {
        executionHash,
        serverId: server.id,
        taskId: action.id,
        taskVersion: action.version,
        scriptDigest: action.scriptDigest,
        riskLevel: action.riskLevel,
        rule: policy.rule,
        reason: request.reason,
        question: `Run ${action.id} on ${server.id}?`,
        // The conversation identity: the commandId when the Platform gave one,
        // otherwise a fresh nonce. NOT executionHash — that is content, shared
        // by any run of the same task+args, and would collide two runs into one
        // thread (review 2172).
        interactionId: ctx.commandId ?? `int_${randomUUID().slice(0, 12)}`,
        ...(request.originActor !== undefined ? { originActor: request.originActor } : {}),
        ...(request.account !== undefined ? { account: request.account } : {}),
        ...(ctx.commandId !== undefined ? { commandId: ctx.commandId } : {}),
      };
      this.audit({
        timestamp: new Date().toISOString(),
        event: 'approval_requested',
        request: auditRequest,
        ...bound,
        policyRule: policy.rule,
        results: { question: describeRequest(question) },
      });

      let outcome;
      try {
        // No deadline of its own: a person may take hours, and this Worker
        // imposes no clock on a task. A cancelled command ends the wait.
        outcome = await this.confirmation.ask(question, ctx.signal);
      } catch (err) {
        return this.error(auditRequest, err, bound, server, action.outputPolicy);
      }

      // MCP-level evidence is digest-anchored (#53, reviews 2328/2330): the
      // question DISCLOSING the digest is not binding — only an answer that
      // repeats it proves the approval was made about THIS script version
      // and not a stale or paraphrased rendition. The requirement is a
      // property of the SURFACE, not of one rule: EVERY grant that would
      // authorize execution over MCP — mcp-mutating, risk-level,
      // approval-policy, production-write alike — must carry the echo, or
      // the surface's evidence grade would depend on which rule happened to
      // fire first. Grants on the Platform surface keep their existing
      // shape: their approver answers on a platform-rendered surface.
      const echoRequired = ctx.surface === 'mcp';
      // The anchor is the EXECUTION, not the script (#66): `executionHash`
      // binds server + task + version + script digest + ARGUMENTS, so an
      // echo of it proves the person approved these arguments and not
      // merely this file. Echoing the script digest alone left the argument
      // set to whatever the AI relaying the question chose to describe.
      const echoValid = !echoRequired || outcome.approvedDigest === executionHash;
      const effectiveGranted = outcome.granted && echoValid;

      // ONE answer record, carrying the EFFECTIVE verdict (review 2330): a
      // record saying granted followed by a correction saying refused is
      // contradictory evidence — a reader stopping at the first entry would
      // believe an approval this Widget refused to honor.
      this.audit({
        timestamp: new Date().toISOString(),
        event: 'approval_answered',
        request: auditRequest,
        ...bound,
        policyRule: policy.rule,
        granted: effectiveGranted,
        ...(outcome.answeredBy !== undefined ? { answeredBy: outcome.answeredBy } : {}),
        // Which, never what — the same rule arguments follow.
        supplementaryInformationSupplied: outcome.supplementaryInformation !== undefined,
        ...(outcome.granted && !echoValid
          ? { error: `approval lacked the execution anchor: expected ${executionHash}, answer carried ${outcome.approvedDigest ?? '(none)'}` }
          : {}),
      });

      if (outcome.granted && !echoValid) {
        return {
          status: 'confirmation_refused',
          rule: policy.rule,
          reason: 'the approval did not echo the execution anchor — MCP-level evidence binds to the exact reviewed bytes AND the arguments they run with (#53/#66); re-approve naming the executionHash the question carried',
          ...(outcome.answeredBy !== undefined ? { answeredBy: outcome.answeredBy } : {}),
        };
      }
      if (!outcome.granted) {
        return {
          status: 'confirmation_refused',
          rule: policy.rule,
          reason: 'a person was asked and declined',
          ...(outcome.answeredBy !== undefined ? { answeredBy: outcome.answeredBy } : {}),
        };
      }
    }

    const maskedCommand = maskedTaskCommand(action.interpreter, request.args, action.interpreterArgs ?? [], action.interpreterStdinArg ?? '-s');

    // A dry run is a side-effect-free preview. It names the exact script by
    // digest and shows which parameters would be set, but never the values —
    // the preview is also an audit record, and the script body is operator
    // configuration, not something a caller is entitled to read back.
    if (request.dryRun) {
      return { status: 'dry_run', command: maskedCommand, scriptDigest: action.scriptDigest };
    }

    const executor = this.executors.get(action.executor);
    if (!executor) {
      // The hash exists by now, so the record carries it: this refusal belongs
      // to one specific execution, not merely to this task.
      return this.deny(auditRequest, 'unknown-executor', `executor "${action.executor}" is not configured`, bound);
    }

    try {
      // The command is masked HERE, not on the way into audit, so there is
      // exactly one command string in existence past this point.
      //
      // Masking only the audit copy left the real one — parameter values and
      // all — in `OpsResponse.result.command`, which CE hands to the Platform
      // and the Platform records. A value this Service went to the trouble of
      // keeping out of its own local evidence was leaving in the answer
      // (review 2165). The caller supplied the arguments and does not need
      // them read back; what it needs to know is WHICH task ran, and
      // `scriptDigest` says that exactly.
      const redact = (r: CommandResult): CommandResult => ({
        ...r,
        command: maskedCommand,
        stdout: redactOutput(r.stdout, action.outputPolicy),
        stderr: redactOutput(r.stderr, action.outputPolicy),
      });

      const finish = (response: OpsResponse): OpsResponse => {
        this.audit({
          timestamp: new Date().toISOString(),
          event: 'execution',
          request: auditRequest,
          ...bound,
          results: response,
          durationMs: Date.now() - started,
        });
        return response;
      };

      // The operator's script goes to the interpreter's standard input; the
      // caller's parameters go beside it as environment assignments. Whatever
      // sequencing a task needs — validate before reload, verify afterwards —
      // the operator writes into the script, where they can see it run under
      // one exit status instead of three separate remote commands.
      const result = redact(
        await executor.run(server, {
          command: buildTaskCommand(action.interpreter, request.args, undefined, action.interpreterArgs ?? [], action.interpreterStdinArg ?? '-s'),
          stdin: action.script,
          // The same ceiling the output policy states, enforced where it costs
          // something: at the wire, not on a result already in memory.
          maxOutputBytes: Math.min(
            this.opts.maxRecordedOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
            action.outputPolicy?.maxBytes ?? Number.POSITIVE_INFINITY,
          ),
          // Only what the task declared. No default: a task that may run for
          // hours does not declare one, and nothing here invents a clock for it.
          ...(action.timeoutSeconds !== undefined ? { timeoutMs: action.timeoutSeconds * 1000 } : {}),
          // A cancel delivered by the Platform is the only thing that stops an
          // unbounded task from this side.
          ...(ctx.signal !== undefined ? { signal: ctx.signal } : {}),
        }),
      );
      // The recording ceiling no longer ends a command (#61 B): the task runs
      // to completion, its exit status is its own, and how much output was
      // dropped rides on the result. `output_limit` remains a possible status
      // for an executor that genuinely had to stop a command.
      if (result.terminatedBy === 'output_limit') return finish({ status: 'output_limit', result });
      // A non-zero exit is a failed task, not a completed one — but the
      // redacted output is kept as diagnostic evidence.
      if (result.exitCode !== 0) return finish({ status: 'command_failed', result });

      return finish({ status: 'executed', result });
    } catch (err) {
      return this.error(auditRequest, err, bound, server, action.outputPolicy);
    }
  }

  /** Append-only local evidence (the Platform audits the command centrally in the command lifecycle). */
  private audit(entry: Parameters<AuditLogger['write']>[0]): void {
    this.opts.audit.write(entry);
  }

  private deny(
    request: Parameters<AuditLogger['write']>[0]['request'],
    rule: string,
    reason: string,
    binding: ExecutionBinding = {},
  ): OpsResponse {
    this.audit({
      timestamp: new Date().toISOString(),
      event: 'decision',
      request,
      ...binding,
      decision: 'deny',
      policyRule: rule,
    });
    return { status: 'denied', rule, reason };
  }

  private error(
    request: Parameters<AuditLogger['write']>[0]['request'],
    err: unknown,
    binding: ExecutionBinding,
    server?: ServerDefinition,
    outputPolicy?: OutputPolicy,
  ): OpsResponse {
    // Sanitize before it reaches the local audit or the wire: a raw executor
    // exception can echo secret-looking values (#27, archived review).
    const message = sanitizeMessage(err instanceof Error ? err.message : String(err), outputPolicy, [server?.password, server?.passphrase, server?.privateKey]);
    // Carries the same binding the decision record carried. Without it, two
    // concurrent calls differing only in ARGUMENT VALUES — which are never
    // recorded — produced error records identical but for the timestamp, so
    // neither could be attributed to its own decision (review 2166).
    this.audit({ timestamp: new Date().toISOString(), event: 'error', request, ...binding, error: message });
    return { status: 'error', message };
  }
}
