import { closeSync, fchmodSync, mkdirSync, openSync, writeSync } from 'node:fs';
import { join } from 'node:path';

export interface AuditEntry {
  timestamp: string;
  event:
    | 'decision'
    | 'execution'
    | 'approval_requested'
    | 'approval_answered'
    | 'error'
    // Task-library lifecycle (#55, review 2329 item 6): who grew/shrank the
    // executable surface, with the before/after script digests.
    | 'task_draft_saved'
    | 'task_enabled'
    | 'task_disabled'
    | 'task_removed'
    // A governed library's edits leave here as proposals (xtrape-docs#255):
    // the local record is that something was SENT for review, not that it
    // became executable — that fact arrives later, with a content version.
    | 'task_submitted';
  request: {
    serverId: string;
    actionId: string;
    /**
     * Argument NAMES only — never values. Action parameters are a generic
     * extension surface: any action may declare a param carrying a token, a
     * credential or a path, and this record is durable. What ran is pinned by
     * `executionHash` (a digest over server + task + version + script digest +
     * the exact arguments, so a claimed value can be
     * verified against the record) plus the action id and version, which name
     * the parameter schema. The values themselves belong to the Platform's
     * authoritative command record, not to this local evidence file.
     */
    argsKeys: string[];
    reason: string;
    dryRun: boolean;
    /** Which surface invoked the call ('platform' command path or 'mcp' consumer). */
    surface?: string;
    /** Cross-hop trace id; propagated into forwarded control-plane audit events. */
    traceId?: string;
    /** Origin provenance; propagated into forwarded control-plane audit events. */
    originActorType?: string;
    originActorId?: string;
    /**
     * The canonical Account the Platform delivered the carrying command
     * under (#256): Account CONTEXT, deliberately not `originActor*` — the
     * Account says who is responsible, not who was at the keyboard.
     */
    accountId?: string;
  };
  actionVersion?: string;
  /** Governed content version this task's revision came from (xtrape-docs#255). */
  sourceVersion?: string;
  executionHash?: string;
  /** `sha256:…` over the exact task script that ran. */
  scriptDigest?: string;
  /** The task's declared blast radius at the time it ran. */
  riskLevel?: string;
  decision?: string;
  policyRule?: string;
  /** Whether the person allowed the task to proceed. */
  granted?: boolean;
  /** Who answered, as the Platform identified them. */
  answeredBy?: string;
  /**
   * Whether the person supplied anything beyond the decision — not what they
   * supplied. Same rule as arguments: the record says which, never what.
   */
  supplementaryInformationSupplied?: boolean;
  /** Task-library lifecycle detail: digests before/after, and which state a removal hit. */
  task?: { id: string; before?: string; after?: string; state?: string };
  results?: unknown;
  durationMs?: number;
  error?: string;
}

export interface AuditLogger {
  write(entry: AuditEntry): void;
}

/**
 * Append-only local JSONL audit log. This Widget has no code path to modify or
 * delete existing entries; retention is managed outside the Service.
 *
 * This is *local evidence only*. The authoritative command-level audit belongs
 * to the Platform, in the command lifecycle — this file is not a second audit
 * authority and must never be treated as one.
 *
 * The file mode is enforced at 0600, not left to the process umask: this record
 * names every target, action and operator reason, and a default umask on a
 * shared host publishes that at 0644 to anyone with a login. The entries
 * themselves are data-minimized upstream (`OpsService`), so a mode slip is not
 * a secret disclosure — but the two together are the property the README
 * claims.
 *
 * The log DIRECTORY is created 0700, but an existing directory is deliberately
 * left as the operator made it: `LINUX_OPS_WIDGET_LOG_DIR` is an operator-
 * supplied path (a bind mount, by convention `./logs`) that this Service does
 * not own and may share with other files. Confidentiality of the records is
 * carried by the file mode, which is enforced below on every append; the
 * directory mode only governs who can list the name `audit.jsonl`.
 */
export class FileAuditLogger implements AuditLogger {
  private readonly file: string;

  constructor(dir: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.file = join(dir, 'audit.jsonl');
  }

  write(entry: AuditEntry): void {
    // The mode argument to open() applies to CREATION only, so it does not
    // help a file that already exists at 0644. Tighten explicitly before every
    // append, and do it with fchmod on the descriptor already opened for the
    // append rather than chmod on the path:
    //
    //  - fchmod acts on the same object the append lands in. A chmod by path
    //    can hit a different file if the path is replaced between open and
    //    chmod, which would both leave the record world-readable and re-mode
    //    something this Service does not own.
    //  - every write, not once per logger: a one-shot flag assumes nothing
    //    loosens or replaces the file afterwards, and a long-lived Worker holds
    //    this logger for its whole life. One extra syscall per audit record is
    //    not a cost worth trading that assumption for.
    //  - before the append, not after: otherwise the first new record — target,
    //    action, operator reason, provenance, policy decision, execution
    //    evidence — is readable to every local user for the duration of the
    //    write.
    const fd = openSync(this.file, 'a', 0o600);
    try {
      fchmodSync(fd, 0o600);
      writeSync(fd, `${JSON.stringify(entry)}\n`, null, 'utf8');
    } finally {
      closeSync(fd);
    }
  }
}

export class MemoryAuditLogger implements AuditLogger {
  readonly entries: AuditEntry[] = [];
  write(entry: AuditEntry): void {
    this.entries.push(entry);
  }
}
