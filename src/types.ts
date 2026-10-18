export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type ApprovalPolicy = 'policy' | 'always_human' | 'forbidden';
export type Decision = 'allow' | 'human_review' | 'deny';
export type Environment = 'production' | 'staging' | 'development';

export interface OutputPolicy {
  redact?: string[];
  maxBytes?: number;
}

export interface ActionDefinition {
  id: string;
  /** Human-readable display name (#61). The id is the immutable identity; this is what people read. */
  title?: string;
  version: string;
  description?: string;
  executor: string;
  riskLevel: RiskLevel;
  readonly: boolean;
  serverScopes: string[];
  approvalPolicy: ApprovalPolicy;
  params: Record<string, unknown>;
  /** Command reading the script from stdin, e.g. `bash`. */
  interpreter: string;
  /** Arguments the shebang asked for, kept verbatim (e.g. `-e` from `#!/bin/sh -e`). */
  interpreterArgs?: string[];
  /**
   * The argument that delivers the program on standard input, decided when
   * the task was parsed: `-s` for a shell (and for every task stored with
   * the retired `# interpreter:` header, whose invocation is frozen), `-`
   * for python/perl/ruby.
   */
  interpreterStdinArg?: string;
  /** The task file verbatim — this is what the interpreter executes. */
  script: string;
  /** `sha256:<hex>` over the script bytes; names the exact text in audit. */
  scriptDigest: string;
  /** File the task was loaded from, for operator-facing diagnostics. */
  sourceFile: string;
  /**
   * The governed content version (xtrape-docs#255) this revision came from,
   * when the library is governed. Rides the definition so every EXECUTION
   * record can name it (review 2433 blocker 3) — the approval ledger knows
   * it, but audit must answer "which reviewed version ran" per run.
   */
  sourceVersion?: string;
  /**
   * Deadline the task declared for itself, in seconds. Absent means none —
   * a long-running task is a task, not a fault.
   */
  timeoutSeconds?: number;
  outputPolicy?: OutputPolicy;
}

/**
 * How this Widget authenticates to a target, chosen explicitly by the operator
 * (#42): a plain private key, an encrypted private key with its passphrase, or
 * a password. Methods are EXCLUSIVE — the chosen method is the authority, and
 * switching it retires the other method's stored secrets. `undefined` exists
 * only for entries loaded from an older store that carried no usable
 * credential; such an entry is inert until reconfigured.
 */
export type AuthMethod = 'privateKey' | 'privateKeyWithPassphrase' | 'password';

export interface ServerDefinition {
  id: string;
  host: string;
  port?: number;
  username: string;
  /**
   * Identity of THIS trust record (#46, review 2325): a random handle minted
   * when the entry is admitted and kept for the record's whole life. Values
   * (id/host/port/fingerprint) can all collide across a remove + re-add —
   * only the generation proves an observation was made against the SAME
   * record and not a lookalike successor. Not a credential, safe to show.
   */
  generation?: string;
  authMethod?: AuthMethod;
  /**
   * Raw SSH secrets under the chosen `authMethod`. `privateKey` is the key
   * CONTENT (PEM/OpenSSH) — the retired `privateKeyPath` referenced a file on
   * the executor host, which tied a fleet entry to that host's filesystem;
   * the content lives in this Service's own 0600 store instead — the
   * transitional posture until a dedicated vault-widget holds widget secrets
   * centrally. All three are write-only from the Panel's side: never
   * projected by `publicServer`, never in evidence, never returned.
   */
  privateKey?: string;
  password?: string;
  passphrase?: string;
  environment: Environment;
  /**
   * The admitted SSH host key, in OpenSSH fingerprint form
   * (`SHA256:<43 base64 chars>`, exactly what `ssh-keygen -lf` prints).
   *
   * This is the target-admission binding: without it, `server.host` names
   * whatever endpoint currently answers for that name, not the host the
   * operator admitted. Since #44 it is OPTIONAL at admission: an entry
   * without one is pinned on first use (accept-new) — `SshExecutor` records
   * the key the endpoint presents at the first key exchange and refuses any
   * later mismatch. An explicit operator-supplied fingerprint remains the
   * stronger posture (it also protects the FIRST connection) and is never
   * overwritten by a pin. It is public data — a digest of a public key —
   * and safe to display and persist.
   */
  hostKeyFingerprint?: string;
  /**
   * How the fingerprint above got here (#44): `operator` = supplied through
   * manageServers; `first-use` = pinned by the executor at the first key
   * exchange. The difference is worth showing — a first-use pin protects
   * against later substitution, not against an impostor already answering at
   * first contact. Absent when no fingerprint is recorded.
   */
  hostKeyAdmittedBy?: 'operator' | 'first-use';
  /**
   * Interpreters known to be on the target (#69): command names as
   * `command -v` resolves them (`sh`, `bash`, `python3`, …). A task's
   * interpreter comes from its shebang; whether the TARGET has it is a fact
   * this record can carry, so "the target has no bash" is said at review
   * time and refused before dispatch — instead of an `exit 127` after a
   * person approved and the command left. Absent = UNKNOWN, which is not
   * "none": an undeclared record is never blocked on this, only marked as
   * unprobed on the cards.
   */
  shells?: string[];
  /**
   * How `shells` got here: `declared` through manageServers, `probed` by
   * testServer's `command -v` sweep. A probe is an observation of the live
   * host and wins over a declaration (declarations drift; probes do not).
   */
  shellsSource?: 'declared' | 'probed';
  /** When the last probe observed `shells` (ISO); absent for declarations. */
  shellsProbedAt?: string;
}

/** Who originated the request (the AI agent / user / Service acting through this Widget). */
export interface OriginActor {
  type: string;
  id: string;
}

export interface OpsRequest {
  serverId: string;
  actionId: string;
  args: Record<string, unknown>;
  reason: string;
  dryRun?: boolean;
  /** Cross-hop trace id propagated into audit records (0.7 provenance hook). */
  traceId?: string;
  /** Who dispatched this request; propagated into audit (0.7 provenance hook). */
  originActor?: OriginActor;
  /**
   * The canonical Account the Platform delivered the carrying command under
   * (xtrape-docs runtime-platform/12, #256) — the RESPONSIBILITY context of
   * the call, not the actual originator (a Panel may be driven by an AI;
   * that is what `originActor` is reserved for and nothing here fills it).
   * Recorded as Account context in evidence; absent when the Platform could
   * not map the subject to an Account — never a stand-in.
   */
  account?: string;
}

export interface PolicyResult {
  decision: Decision;
  /** Identifier of the rule that produced the decision. */
  rule: string;
  reason: string;
  /** Hard results (deny / forced human_review) can never be loosened. */
  hard: boolean;
}

export interface CommandResult {
  command: string;
  /**
   * The exit status the remote command reported, or `undefined` when this
   * Worker cut the command off before one was observed. An invented number
   * would be a claim about an outcome nobody saw.
   */
  exitCode?: number | undefined;
  stdout: string;
  stderr: string;
  /**
   * Why this Worker stopped the command, when it did. Carried as a FIELD
   * rather than appended to `stderr`, so output redaction cannot truncate the
   * explanation of a truncation. Reserved for causes that really do end a
   * command early — the output ceiling no longer does (#61 B).
   */
  terminatedBy?: 'output_limit' | undefined;
  /**
   * How much output this Worker RECORDED and how much it read and dropped
   * (#61 B). Present only when something was dropped. The task itself ran to
   * completion and `exitCode` is its own — recording less never changes an
   * outcome.
   */
  outputTruncated?: { recordedBytes: number; discardedBytes: number } | undefined;
}

/**
 * What the executor is asked to run: a command line, plus the bytes written to
 * that command's standard input. A task supplies its script through `stdin`,
 * which is what keeps caller parameters out of the OPERATOR'S SCRIPT. They are
 * still part of the command line, as quoted environment assignments — see
 * `../shell.ts` for what that does and does not guarantee.
 */
export interface CommandInvocation {
  command: string;
  stdin?: string;
  /**
   * Ceiling on the bytes this Worker RECORDS from the remote command, across
   * stdout and stderr together. Beyond it the output is read and DISCARDED:
   * this process's memory stays bounded while the task runs to completion and
   * reports its own exit status (#61 B — the ceiling is a recording decision,
   * not a licence to kill the task).
   *
   * Enforced at the wire, while the bytes arrive, rather than on a result
   * already accumulated in full (review 2157). `redactOutput` still applies
   * afterwards, but the memory cost was already bounded here.
   */
  maxOutputBytes?: number;
  /**
   * Deadline for the whole remote operation, or `undefined` for none.
   *
   * There is deliberately no default. A task may legitimately run for hours,
   * and a Worker-side clock that cut it off would be this Widget deciding
   * something the task's author did not ask for. A task that wants a bound
   * declares one.
   */
  timeoutMs?: number;
  /** Aborted when the Platform delivers a cancel for this command. */
  signal?: AbortSignal;
}

export interface Executor {
  readonly name: string;
  run(server: ServerDefinition, invocation: CommandInvocation): Promise<CommandResult>;
}

/**
 * Which surface invoked this Service. The Platform command path (Panel /
 * Platform CE, over the Connector callback listener) may run `allow` mutations
 * within the Platform command lifecycle.
 *
 * `mcp` is the Xtrape Exposure protocol projection. This Widget does not
 * implement MCP transport — that authority belongs to `xtrape/xtrape-exposure`
 * — and the surface is GRADED, not read-only (#53 P1.5): the MCP caller is a
 * person acting through an AI device, so read-only actions flow as policy
 * allows while anything with side effects is ESCALATED to a human answer
 * through the confirmation loop. EVERY human-review grant that authorizes
 * execution over this surface — whichever rule produced it — must echo the
 * script digest: the evidence obligation is a property of the surface, not
 * of one rule (review 2330). Local policy may only narrow or deny
 * Platform authority, never broaden it — escalation is a narrowing.
 */
export type Surface = 'platform' | 'mcp';
