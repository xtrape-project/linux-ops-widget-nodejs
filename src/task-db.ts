import { mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import Database from 'better-sqlite3';
import type { ActionDefinition } from './types.js';
import { normalizeTaskParts, parseTaskFile, renderTaskFile, splitTaskSource, type TaskParts } from './task-file.js';
import { TASK_CHECKPOINT_SHAPE } from './checkpoints.js';
import { ActionRegistry } from './registry.js';
import type { Verdict } from './redlines.js';

/**
 * Registry-grade admission (review 2329 item 2): `parseTaskFile` alone is
 * WEAKER than what `ActionRegistry.register` enforces (meta schema, reserved
 * param names, env-safe names, scalar types), and discovering the gap at
 * enable time — after the store committed — would leave store and runtime
 * split. A scratch registry runs the FULL admission with zero side effects,
 * so a revision that cannot register never lands, and an enable that reaches
 * the commit cannot fail the register that follows.
 */
function assertRegistryAdmission(def: ActionDefinition): void {
  new ActionRegistry().register(def);
}

/**
 * Order-independent structural fingerprint of normalized TaskParts. The
 * UNCHANGED check compares STRUCTURE, not canonical digests (review 2356):
 * a pre-#60 revision's frozen bytes render in an older format, so an
 * untouched Edit → Save would produce a different digest for identical
 * business content — and a phantom draft with it.
 */
function partsKey(parts: TaskParts): string {
  return JSON.stringify({
    shebang: parts.shebang,
    headers: Object.entries(parts.headers).sort(([a], [b]) => a.localeCompare(b)),
    params: parts.params,
    redact: parts.redact,
    body: parts.body,
  });
}

export interface StoredTask {
  definition: ActionDefinition;
  state: 'enabled' | 'draft';
  /** The revision carrying this state — stable, monotonic per store. */
  revisionId: number;
  createdAt: string;
  /**
   * Enabled rows only (linux-ops#94): the projected-definition shape this
   * task was published under. `1` = enabled before the review face existed.
   * A task whose shape is older than TASK_CHECKPOINT_SHAPE is enabled in the
   * library but NOT published or exposed until it is re-versioned and enabled
   * again (see `needsReversion`).
   */
  checkpointShape?: number;
  needsReversion?: boolean;
}

export interface SaveDraftResult {
  definition: ActionDefinition;
  revisionId: number;
  /** Where the submitted bytes now stand: a pending draft, or the enabled version itself. */
  state: 'draft' | 'enabled';
  /** True when no new revision was created (byte-identical resubmit or a cancel). */
  unchanged: boolean;
  /** Set when this save CANCELED a pending draft by restoring the enabled bytes. */
  canceledDraftDigest?: string;
}

/** Provenance of an online Enable — what the delivery surface can attest today. */
export interface ApprovalProvenance {
  /**
   * The deciding Account / Responsibility Owner, WHEN the interaction
   * contract delivers it. Today's Platform→Widget execute context carries no
   * Account identity (commandId/signal/timeoutSeconds only), so this stays
   * unset until that plumbing exists — the column and parameter are the
   * ready seam, per platform-ce AGENTS.md's 0.8 approval-identity rule.
   */
  approvedBy?: string;
  /** The Platform command that delivered the approved execute. */
  commandId?: string;
  /**
   * The governed content version these bytes came from (xtrape-docs#255).
   * In a governed library the approval happened at the governance side; what
   * this Widget can attest is WHICH effective version it applied, so that is
   * what the ledger records rather than a local approver it never saw.
   */
  sourceVersion?: string;
}

interface RevisionRow {
  revision_id: number;
  task_id: string;
  digest: string;
  shebang: string;
  title: string | null;
  version: string;
  description: string | null;
  executor: string | null;
  risk: string;
  readonly: string;
  servers: string;
  approval: string | null;
  interpreter: string | null;
  timeout_seconds: string | null;
  max_bytes: string | null;
  params: string;
  redact: string;
  body: string;
  canonical: string | null;
  created_at: string;
}

/**
 * The task library, DB-backed (#58, owner decisions 2026-08-13): tasks live
 * in SQLite so that edits become an append-only REVISION HISTORY and
 * approvals become queryable first-class records.
 *
 * The model separates three concerns (review 2349):
 *
 * - **History** — `task_revisions` is APPEND-ONLY: metadata columns + script
 *   body, one row per distinct saved version. No workflow operation deletes
 *   a revision or an approval; history and approval evidence outlive drafts,
 *   disables, and removals.
 * - **Current workflow state** — two pointers on `tasks`:
 *   `enabled_revision` (what executes) and `draft_revision` (what awaits
 *   review). State changes move pointers, never rows. A task with neither
 *   pointer is retired from the library view; its history remains.
 * - **Approvals** — `task_approvals` records every online Enable: which
 *   revision, which digest, what it replaced, when, and the provenance the
 *   surface can attest (commandId today; the deciding Account when the
 *   interaction contract delivers it).
 *
 * Metadata lives in COLUMNS (risk, servers, approval, params, …) with the
 * script body beside them — the structured form (#58 part b) binds these
 * fields directly. The header-comment file format is only the IMPORT/EXPORT
 * serialization: `renderTaskFile` produces the canonical text, and that text
 * is what the digest covers, what the review card shows, and what the
 * interpreter is fed — so an approval still binds metadata + body as one
 * byte stream, and a provisioned `.sh` file round-trips.
 *
 * Durability is the transaction's (WAL + synchronous=FULL): a committed
 * mutation survives a crash, which retires the file-era fsync/reconcile
 * state machine (reviews 2329/2331/2333) wholesale.
 *
 * Nothing in this store touches the runtime registry — enabling is the
 * CALLER's transaction (ce-actions), because it is the step a human approves.
 */
export class TaskDb {
  private readonly db: Database.Database;

  constructor(dbPath: string) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    // FULL, not NORMAL: an enable/disable is a safety decision, and "committed"
    // must mean "survives a power cut", the same bar the file era's fsync
    // discipline was held to.
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = FULL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        enabled_revision INTEGER,
        draft_revision INTEGER,
        screened_generation TEXT,
        screen_verdict TEXT,
        screened_revision INTEGER
      );
      CREATE TABLE IF NOT EXISTS task_revisions (
        revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL,
        digest TEXT NOT NULL,
        shebang TEXT NOT NULL,
        title TEXT,
        version TEXT NOT NULL,
        description TEXT,
        executor TEXT,
        risk TEXT NOT NULL,
        readonly TEXT NOT NULL,
        servers TEXT NOT NULL,
        approval TEXT,
        interpreter TEXT,
        timeout_seconds TEXT,
        max_bytes TEXT,
        params TEXT NOT NULL,
        redact TEXT NOT NULL,
        body TEXT NOT NULL,
        canonical TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS task_revisions_by_task ON task_revisions(task_id, revision_id);
      CREATE TABLE IF NOT EXISTS task_approvals (
        approval_id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL,
        revision_id INTEGER NOT NULL,
        digest TEXT NOT NULL,
        replaced_digest TEXT,
        approved_by TEXT,
        command_id TEXT,
        redline_generation TEXT,
        redline_verdict TEXT,
        source_version TEXT,
        approved_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS content_versions (
        version_id TEXT PRIMARY KEY,
        sequence INTEGER NOT NULL,
        redline_generation TEXT,
        applied_at TEXT NOT NULL
      );
    `);
    this.migrate();
  }

  /**
   * A revision's IDENTITY is frozen at write time (review 2355): the
   * `canonical` column holds the exact bytes its digest covers, so a later
   * change to the render rules can never rewrite history — approvals keep
   * pointing at the digest of the bytes that were actually approved, and an
   * enabled task keeps executing the bytes it was enabled as, no silent
   * re-canonicalization. This migration backfills the column for rows
   * written before it existed by reconstructing the render OF THEIR TIME
   * and verifying it reproduces the STORED digest byte-exactly; a row whose
   * digest no reconstruction reproduces fails the open loudly — a corrupt
   * store must not serve.
   */
  private migrate(): void {
    const cols = (this.db.pragma("table_info('task_revisions')") as Array<{ name: string }>).map((c) => c.name);
    if (!cols.includes('canonical')) this.db.exec('ALTER TABLE task_revisions ADD COLUMN canonical TEXT');
    // The display name is a metadata COLUMN like every other header (#61 /
    // review 2365): keeping it only inside the canonical bytes would leave
    // the structural comparison blind to it, so an untouched Edit → Save of
    // a titled task would mint a phantom revision.
    if (!cols.includes('title')) this.db.exec('ALTER TABLE task_revisions ADD COLUMN title TEXT');
    const taskCols = (this.db.pragma("table_info('tasks')") as Array<{ name: string }>).map((c) => c.name);
    if (!taskCols.includes('screened_generation')) this.db.exec('ALTER TABLE tasks ADD COLUMN screened_generation TEXT');
    if (!taskCols.includes('screen_verdict')) this.db.exec('ALTER TABLE tasks ADD COLUMN screen_verdict TEXT');
    if (!taskCols.includes('screened_revision')) this.db.exec('ALTER TABLE tasks ADD COLUMN screened_revision INTEGER');
    // linux-ops#94: the projected-definition shape an enabled task was
    // published under (NULL = enabled before shapes existed = shape 1).
    if (!taskCols.includes('checkpoint_shape')) this.db.exec('ALTER TABLE tasks ADD COLUMN checkpoint_shape INTEGER');
    // Which rules an approval was granted under (#65 / review 2403): a
    // historical approval must be able to say so.
    const approvalCols = (this.db.pragma("table_info('task_approvals')") as Array<{ name: string }>).map((c) => c.name);
    if (!approvalCols.includes('redline_generation')) this.db.exec('ALTER TABLE task_approvals ADD COLUMN redline_generation TEXT');
    if (!approvalCols.includes('redline_verdict')) this.db.exec('ALTER TABLE task_approvals ADD COLUMN redline_verdict TEXT');
    if (!approvalCols.includes('source_version')) this.db.exec('ALTER TABLE task_approvals ADD COLUMN source_version TEXT');
    // Which governed content versions this library has already applied
    // (xtrape-docs#255). A version that was applied once is never applied
    // again: a replayed or cached read of an older effective version would
    // otherwise roll the library backwards without anyone deciding to.
    this.db.exec('CREATE TABLE IF NOT EXISTS content_versions (version_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, applied_at TEXT NOT NULL)');
    const cvCols = (this.db.pragma("table_info('content_versions')") as Array<{ name: string }>).map((c) => c.name);
    if (!cvCols.includes('sequence')) this.db.exec('ALTER TABLE content_versions ADD COLUMN sequence INTEGER NOT NULL DEFAULT 0');
    if (!cvCols.includes('redline_generation')) this.db.exec('ALTER TABLE content_versions ADD COLUMN redline_generation TEXT');
    const run = this.db.transaction(() => {
      const rows = this.db.prepare('SELECT * FROM task_revisions WHERE canonical IS NULL').all() as RevisionRow[];
      for (const row of rows) {
        const parts = this.partsOf(row);
        // The only real pre-upgrade shape is the released #59 line: digested
        // over the marker-LESS render. Databases written by unmerged interim
        // builds of THIS PR (a '# ---' marker render) are explicitly
        // UNSUPPORTED — they never shipped, and pretending to migrate them
        // would paper over genuine corruption (review 2356).
        const text = renderTaskFile(parts, false);
        if (parseTaskFile(text, `task:${row.task_id}@r${row.revision_id}`).scriptDigest !== row.digest) {
          throw new Error(`task revision ${row.revision_id} (task "${row.task_id}"): the render of its era does not reproduce its stored digest — an unsupported interim-build database or a corrupt store; refusing to serve`);
        }
        this.db.prepare('UPDATE task_revisions SET canonical = ? WHERE revision_id = ?').run(text, row.revision_id);
      }
      if (rows.length > 0) console.warn(`[tasks] backfilled the frozen canonical bytes of ${rows.length} pre-existing revision(s); digests unchanged`);
    });
    run();
  }

  close(): void {
    this.db.close();
  }

  /**
   * Seed the store from a provisioned directory of `*.sh` task files (the
   * file era's `conf/tasks/` plus its `drafts/`). Idempotent by task id: a
   * task the store already knows is SKIPPED entirely — once a task is
   * managed online, the DB is the truth and host files stop being an edit
   * channel. For a NEW id, the file-era state imports whole: a `tasks/` file
   * arrives enabled AND a same-id `drafts/` file arrives as its pending
   * replacement draft (review 2349 item 1 — an upgrade must not drop a
   * pending review). An unparseable or inadmissible file fails the import
   * loudly — a broken provisioned task is a configuration error, not
   * something to skip silently.
   */
  importDir(dir: string): { imported: number; skipped: number } {
    let imported = 0;
    let skipped = 0;
    const byId = new Map<string, { enabled?: { def: ActionDefinition; parts: TaskParts; file: string }; draft?: { def: ActionDefinition; parts: TaskParts; file: string }; files: number }>();
    for (const { file, path, enabled } of this.scanDir(dir)) {
      const source = readFileSync(path, 'utf8');
      const def = parseTaskFile(source, file);
      assertRegistryAdmission(def);
      const parts = splitTaskSource(source);
      const entry = byId.get(def.id) ?? { files: 0 };
      // Two files claiming one id IN THE SAME STATE have no survivor rule
      // (review 2350): the file era failed closed on this, and a migration
      // must not let scan order pick which version becomes the library.
      // enabled + draft for one id IS the legal pending-replacement shape.
      if (enabled) {
        if (entry.enabled) throw new Error(`import refused: both "${entry.enabled.file}" and "${file}" declare enabled task "${def.id}" — remove one; the import will not pick a survivor`);
        entry.enabled = { def, parts, file };
      } else {
        if (entry.draft) throw new Error(`import refused: both "${entry.draft.file}" and "${file}" declare a draft of task "${def.id}" — remove one; the import will not pick a survivor`);
        entry.draft = { def, parts, file };
      }
      entry.files += 1;
      byId.set(def.id, entry);
    }
    const importOne = this.db.transaction((id: string, entry: { enabled?: { parts: TaskParts }; draft?: { parts: TaskParts } }) => {
      let enabledRev: number | null = null;
      let draftRev: number | null = null;
      if (entry.enabled) {
        const parts = normalizeTaskParts(entry.enabled.parts);
        const { canonical, def } = this.canonicalize(parts, `(import ${id})`);
        enabledRev = this.insertRevision(id, parts, def.scriptDigest, canonical);
      }
      if (entry.draft) {
        const parts = normalizeTaskParts(entry.draft.parts);
        const { canonical, def } = this.canonicalize(parts, `(import ${id} draft)`);
        draftRev = this.insertRevision(id, parts, def.scriptDigest, canonical);
      }
      this.db.prepare('INSERT INTO tasks (id, enabled_revision, draft_revision, checkpoint_shape) VALUES (?, ?, ?, ?)').run(id, enabledRev, draftRev, enabledRev === null ? null : TASK_CHECKPOINT_SHAPE);
    });
    for (const [id, entry] of byId) {
      if (this.db.prepare('SELECT 1 FROM tasks WHERE id = ?').get(id)) {
        skipped += entry.files;
        continue;
      }
      importOne(id, entry);
      imported += entry.files;
    }
    return { imported, skipped };
  }

  private scanDir(dir: string): Array<{ file: string; path: string; enabled: boolean }> {
    const out: Array<{ file: string; path: string; enabled: boolean }> = [];
    for (const [d, enabled] of [
      [dir, true],
      [join(dir, 'drafts'), false],
    ] as const) {
      let files: string[];
      try {
        files = readdirSync(d);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
        throw error;
      }
      for (const file of files.filter((f) => f.endsWith('.sh')).sort()) {
        out.push({ file, path: join(d, file), enabled });
      }
    }
    return out;
  }

  /**
   * Every enabled task's definition — what the runtime registry loads at
   * startup. A task enabled under an OLDER definition shape is left out
   * (linux-ops#94): its Checkpoint at that id@version cannot be republished
   * with the current bytes, so it must not be exposed as a governed Action
   * until it is re-versioned and enabled again.
   */
  enabledDefinitions(): ActionDefinition[] {
    return this.listAll()
      .filter((t) => t.state === 'enabled' && !t.needsReversion)
      .map((t) => t.definition);
  }

  /** The enabled tasks a newer Widget cannot publish: re-version (`# version:`) and enable again. */
  needingReversion(): StoredTask[] {
    return this.listAll().filter((t) => t.state === 'enabled' && t.needsReversion === true);
  }

  /** One row per task per state, from the two pointers. */
  listAll(): StoredTask[] {
    const tasks = this.db.prepare('SELECT id, enabled_revision, draft_revision, checkpoint_shape FROM tasks').all() as Array<{
      id: string;
      enabled_revision: number | null;
      draft_revision: number | null;
      checkpoint_shape: number | null;
    }>;
    const out: StoredTask[] = [];
    for (const t of tasks) {
      if (t.enabled_revision !== null) {
        const shape = t.checkpoint_shape ?? 1;
        out.push({ ...this.stored(t.enabled_revision, 'enabled'), checkpointShape: shape, needsReversion: shape < TASK_CHECKPOINT_SHAPE });
      }
      if (t.draft_revision !== null) out.push(this.stored(t.draft_revision, 'draft'));
    }
    return out.sort((a, b) => a.definition.id.localeCompare(b.definition.id) || a.state.localeCompare(b.state));
  }

  findEnabled(id: string): StoredTask | undefined {
    const t = this.pointers(id);
    if (t?.enabled_revision == null) return undefined;
    const shape = t.checkpoint_shape ?? 1;
    return { ...this.stored(t.enabled_revision, 'enabled'), checkpointShape: shape, needsReversion: shape < TASK_CHECKPOINT_SHAPE };
  }

  findDraft(id: string): StoredTask | undefined {
    const t = this.pointers(id);
    return t?.draft_revision != null ? this.stored(t.draft_revision, 'draft') : undefined;
  }

  /** A stored task's full canonical text (the bytes its digest covers). */
  content(task: StoredTask): string {
    return task.definition.script;
  }

  /**
   * Land CONTENT as the pending draft. A draft may coexist with an ENABLED
   * version — that is the replacement flow. Byte-identical resubmits create
   * nothing; and a save whose canonical bytes EQUAL the enabled version is
   * the operator restoring the running state — it clears any pending draft
   * (review 2349 item 2: "edited back to v1" is a cancel, not a new draft)
   * and reports `state: 'enabled'` so no caller invents a phantom review.
   */
  saveDraft(content: string): SaveDraftResult {
    // Validate the submitted TEXT first (import shape), then store its parts.
    const submitted = parseTaskFile(content, '(draft submission)');
    assertRegistryAdmission(submitted);
    return this.saveDraftFromParts(splitTaskSource(content));
  }

  /**
   * The primary write path (#58 part 2, review 2354): structured parts —
   * the form's fields — go straight to columns. Defaults are materialized
   * here (normalizeTaskParts) so a stored revision is always explicit and
   * an untouched Edit → Save round-trips byte-exact. The single render →
   * re-parse inside canonicalize() is the digest definition and the full
   * validation, not a format adapter.
   */
  saveDraftFromParts(rawParts: TaskParts): SaveDraftResult {
    const parts = normalizeTaskParts(rawParts);
    const { canonical, def } = this.canonicalize(parts, '(draft submission)');
    assertRegistryAdmission(def);
    const key = partsKey(parts);
    // Structural equality against a stored revision: its columns, normalized
    // the same way. A pre-#60 revision's frozen canonical renders in an
    // older format, so digests differ for identical content — the STRUCTURE
    // is what "unchanged" means (review 2356). On equality the STORED
    // revision's identity is returned, never the freshly rendered one.
    const sameAs = (row: RevisionRow): boolean => partsKey(normalizeTaskParts(this.partsOf(row))) === key;
    const run = this.db.transaction((): SaveDraftResult => {
      const t = this.pointers(def.id);
      const enabled = t?.enabled_revision != null ? this.revision(t.enabled_revision) : undefined;
      const draft = t?.draft_revision != null ? this.revision(t.draft_revision) : undefined;
      if (enabled && sameAs(enabled)) {
        const stored = this.decorate(this.definitionOf(enabled), enabled.revision_id);
        if (draft) {
          this.db.prepare('UPDATE tasks SET draft_revision = NULL WHERE id = ?').run(def.id);
          return { definition: stored, revisionId: enabled.revision_id, state: 'enabled', unchanged: true, canceledDraftDigest: draft.digest };
        }
        return { definition: stored, revisionId: enabled.revision_id, state: 'enabled', unchanged: true };
      }
      if (draft && sameAs(draft)) {
        return { definition: this.decorate(this.definitionOf(draft), draft.revision_id), revisionId: draft.revision_id, state: 'draft', unchanged: true };
      }
      if (!t) this.db.prepare('INSERT INTO tasks (id, enabled_revision, draft_revision) VALUES (?, NULL, NULL)').run(def.id);
      const rev = this.insertRevision(def.id, parts, def.scriptDigest, canonical);
      this.db.prepare('UPDATE tasks SET draft_revision = ? WHERE id = ?').run(rev, def.id);
      return { definition: this.decorate(def, rev), revisionId: rev, state: 'draft', unchanged: false };
    });
    return run();
  }

  /**
   * Promote the pending draft to enabled. The approval binds to BYTES
   * (review 2329 item 1): `approvedDigest` — unsealed by the caller from the
   * prepare-issued review binding — must match the draft revision, or the
   * draft changed between review and submit and the enable refuses. Every
   * online enable lands a `task_approvals` record, and it MUST carry
   * provenance — the deciding Account or the delivering Platform command —
   * or the enable fails closed (reviews 2349/2350).
   */
  enable(
    id: string,
    approvedDigest: string,
    provenance: ApprovalProvenance,
    /**
     * The redline verdict for the bytes being approved (#65). Written in the
     * SAME transaction as the pointer move (review 2403): two statements
     * left a crash window in which a new revision kept the previous one's
     * verdict, and the ledger could not say which rules an approval was
     * granted under.
     */
    screening?: { generation: string; verdict: Verdict },
  ): { definition: ActionDefinition; replaced?: string } {
    // An approval record with NEITHER an approver nor an authoritative
    // reference is evidence of nothing (review 2350): the ledger's storage
    // boundary refuses it. The accepted authoritative references are the
    // Platform commandId and — for a governed library — the effective content
    // version this Widget applied (xtrape-docs#255), which is exactly what it
    // can attest when the approval happened at the governance side. The
    // deciding Account joins when the interaction contract carries it. A
    // surface that attests none of the three — the operator's local callback
    // path — cannot land an online enable.
    if (!provenance.approvedBy && !provenance.commandId && !provenance.sourceVersion) {
      throw new Error(`enable "${id}" refused: this surface attests no approval provenance (no deciding Account, no Platform command); run Enable through the Platform surface`);
    }
    const run = this.db.transaction(() => {
      const t = this.pointers(id);
      if (!t || t.draft_revision === null) throw new Error(`no draft "${id}" to enable`);
      const draft = this.revision(t.draft_revision);
      if (draft.digest !== approvedDigest) {
        throw new Error(
          `draft "${id}" changed since it was reviewed (${draft.digest} != approved ${approvedDigest}); re-open Enable and review the current text`,
        );
      }
      const def = this.definitionOf(draft);
      // Before the commit point: the register that follows must be unable to fail.
      assertRegistryAdmission(def);
      const replaced = t.enabled_revision !== null ? this.revision(t.enabled_revision).digest : undefined;
      // The shape this publication declares (linux-ops#94): the enable that
      // follows a re-version publishes the CURRENT projection.
      this.db.prepare('UPDATE tasks SET enabled_revision = ?, draft_revision = NULL, checkpoint_shape = ? WHERE id = ?').run(draft.revision_id, TASK_CHECKPOINT_SHAPE, id);
      if (screening) {
        this.db
          .prepare('UPDATE tasks SET screened_generation = ?, screen_verdict = ?, screened_revision = ? WHERE id = ?')
          .run(screening.generation, screening.verdict, draft.revision_id, id);
      }
      this.db
        .prepare(
          'INSERT INTO task_approvals (task_id, revision_id, digest, replaced_digest, approved_by, command_id, redline_generation, redline_verdict, source_version, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        )
        .run(
          id,
          draft.revision_id,
          draft.digest,
          replaced ?? null,
          provenance.approvedBy ?? null,
          provenance.commandId ?? null,
          screening?.generation ?? null,
          screening?.verdict ?? null,
          provenance.sourceVersion ?? null,
          new Date().toISOString(),
        );
      return { def: this.decorate(def, draft.revision_id), replaced };
    });
    const { def, replaced } = run();
    return { definition: def, ...(replaced ? { replaced } : {}) };
  }

  /**
   * Demote an enabled task: the enabled revision becomes the pending draft
   * (pointer move — the file era's observable). Refused while a NEWER draft
   * is pending: an Enable after such a disable would promote the pending
   * edit, not restore what was running, and the operator must resolve that
   * draft explicitly first.
   */
  disable(id: string): { definition: ActionDefinition } {
    const run = this.db.transaction(() => {
      const t = this.pointers(id);
      if (!t || t.enabled_revision === null) throw new Error(`no enabled task "${id}"`);
      if (t.draft_revision !== null) {
        throw new Error(`a draft "${id}" already exists; enable or remove it before disabling the running version`);
      }
      const enabled = this.stored(t.enabled_revision, 'enabled');
      this.db.prepare('UPDATE tasks SET enabled_revision = NULL, draft_revision = ? WHERE id = ?').run(t.enabled_revision, id);
      return enabled.definition;
    });
    return { definition: run() };
  }

  /**
   * Withdraw the pending draft — a POINTER clear, never a delete: the
   * revision stays in the history and any approval evidence is untouched
   * (review 2349 item 2 — workflow state must not consume history).
   */
  removeDraft(id: string): void {
    const run = this.db.transaction(() => {
      const t = this.pointers(id);
      if (!t || t.draft_revision === null) throw new Error(`no draft "${id}"`);
      this.db.prepare('UPDATE tasks SET draft_revision = NULL WHERE id = ?').run(id);
    });
    run();
  }

  /**
   * Retire the enabled version — a POINTER clear. A pending draft survives.
   * With neither pointer left the task disappears from the library view;
   * its revisions and approval ledger REMAIN as history.
   */
  removeEnabled(id: string): { definition: ActionDefinition } {
    const run = this.db.transaction(() => {
      const t = this.pointers(id);
      if (!t || t.enabled_revision === null) throw new Error(`no enabled task "${id}"`);
      const enabled = this.stored(t.enabled_revision, 'enabled');
      this.db.prepare('UPDATE tasks SET enabled_revision = NULL WHERE id = ?').run(id);
      return enabled.definition;
    });
    return { definition: run() };
  }

  /**
   * The redline verdict recorded for a task's ENABLED revision, and the rule
   * generation it was made under (#65). `undefined` means never screened.
   */
  screening(id: string): { generation: string; verdict: Verdict; revisionId: number } | undefined {
    const row = this.db
      .prepare('SELECT enabled_revision, screened_generation, screen_verdict, screened_revision FROM tasks WHERE id = ?')
      .get(id) as
      | { enabled_revision: number | null; screened_generation: string | null; screen_verdict: string | null; screened_revision: number | null }
      | undefined;
    if (!row || row.screened_generation === null || row.screen_verdict === null || row.screened_revision === null) return undefined;
    // A verdict belongs to the REVISION it was made about (review 2403):
    // generation alone let a newly enabled revision inherit the previous
    // one's `clear`. A mismatch is no verdict at all, and the sweep will
    // make one.
    if (row.enabled_revision !== row.screened_revision) return undefined;
    return { generation: row.screened_generation, verdict: row.screen_verdict as Verdict, revisionId: row.screened_revision };
  }

  /**
   * Take a task out of service because it hit a HARD redline added after it
   * was approved (#65). The revision itself is untouched: the enabled
   * pointer is cleared, and the revision becomes the pending draft when
   * nothing newer is already waiting — so re-approving it is a review, not
   * a retype.
   */
  suspendEnabled(id: string): { definition: ActionDefinition } | undefined {
    const run = this.db.transaction(() => {
      const t = this.pointers(id);
      if (!t || t.enabled_revision === null) return undefined;
      const enabled = this.stored(t.enabled_revision, 'enabled');
      if (t.draft_revision === null) {
        this.db.prepare('UPDATE tasks SET enabled_revision = NULL, draft_revision = ? WHERE id = ?').run(t.enabled_revision, id);
      } else {
        this.db.prepare('UPDATE tasks SET enabled_revision = NULL WHERE id = ?').run(id);
      }
      return { definition: enabled.definition };
    });
    return run();
  }

  /**
   * Write a sweep's verdict and, for a HARD hit, take the task out of service
   * — in ONE transaction (review 2408).
   *
   * These used to be two statements. A crash between them left the verdict
   * recorded at the current generation while the task was still enabled, and
   * the next sweep skipped it as already screened: the "hard redline suspends
   * an approved task" invariant (#65) was permanently broken for that task.
   * Execution stayed fail-closed on the recorded verdict, but the state was
   * wrong and nothing would ever correct it.
   */
  applyScreening(id: string, generation: string, verdict: Verdict): { suspended: boolean } {
    const run = this.db.transaction(() => {
      const t = this.pointers(id);
      if (!t || t.enabled_revision === null) return { suspended: false };
      const judged = t.enabled_revision;
      this.db
        .prepare('UPDATE tasks SET screened_generation = ?, screen_verdict = ?, screened_revision = ? WHERE id = ?')
        .run(generation, verdict, judged, id);
      if (verdict !== 'hard') return { suspended: false };
      if (t.draft_revision === null) {
        this.db.prepare('UPDATE tasks SET enabled_revision = NULL, draft_revision = ? WHERE id = ?').run(judged, id);
      } else {
        this.db.prepare('UPDATE tasks SET enabled_revision = NULL WHERE id = ?').run(id);
      }
      return { suspended: true };
    });
    return run();
  }

  /**
   * The most recently APPLIED governed content version — id and sequence
   * (review 2427 blocker 2). Monotonicity is enforced on the sequence: a
   * "seen versions" set would only stop exact replays, while an older
   * version never seen here (applied v1 -> v3, then v2 arrives) would still
   * roll the library backwards.
   */
  lastContentVersion(): { versionId: string; sequence: number; redlineGeneration?: string } | undefined {
    const row = this.db.prepare('SELECT version_id, sequence, redline_generation FROM content_versions ORDER BY sequence DESC, rowid DESC LIMIT 1').get() as
      | { version_id: string; sequence: number; redline_generation: string | null }
      | undefined;
    return row
      ? { versionId: row.version_id, sequence: row.sequence, ...(row.redline_generation ? { redlineGeneration: row.redline_generation } : {}) }
      : undefined;
  }

  /**
   * Attach governed provenance to an ALREADY-ENABLED revision whose bytes
   * matched the effective content exactly (review 2435 blocker 3): the first
   * switch to governed mode finds local tasks byte-identical to the Curator's
   * set, nothing needs enabling — but every execution from then on must still
   * name the governed version it ran under. Recorded as an approval row (no
   * pointer move) so `decorate()` finds it like any other.
   */
  attachSourceVersion(id: string, sourceVersion: string): boolean {
    const t = this.pointers(id);
    if (!t || t.enabled_revision === null) return false;
    const rev = this.revision(t.enabled_revision);
    const already = this.db
      .prepare('SELECT 1 FROM task_approvals WHERE revision_id = ? AND source_version = ?')
      .get(t.enabled_revision, sourceVersion);
    if (already) return true;
    this.db
      .prepare('INSERT INTO task_approvals (task_id, revision_id, digest, source_version, approved_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, t.enabled_revision, rev.digest, sourceVersion, new Date().toISOString());
    return true;
  }

  /**
   * Record a governed content version as applied, with its sequence and the
   * redline generation it was screened under. The generation is what lets a
   * later sync re-screen the SAME version after the local rules changed
   * (review 2435 blocker 2): a task refused under generation A may be
   * admissible under generation B, and "unchanged version" alone would never
   * revisit it. INSERT OR REPLACE: a re-screen of the same version updates
   * the generation it now stands under.
   */
  recordContentVersion(versionId: string, sequence: number, redlineGeneration?: string): void {
    this.db
      .prepare('INSERT OR REPLACE INTO content_versions (version_id, sequence, redline_generation, applied_at) VALUES (?, ?, ?, ?)')
      .run(versionId, sequence, redlineGeneration ?? null, new Date().toISOString());
  }

  /** The approval ledger for one task, newest first (queryable evidence, #58). */
  approvals(id: string): Array<{ revisionId: number; digest: string; replacedDigest?: string; approvedBy?: string; commandId?: string; redlineGeneration?: string; redlineVerdict?: Verdict; sourceVersion?: string; approvedAt: string }> {
    const rows = this.db
      .prepare('SELECT revision_id, digest, replaced_digest, approved_by, command_id, redline_generation, redline_verdict, source_version, approved_at FROM task_approvals WHERE task_id = ? ORDER BY approval_id DESC')
      .all(id) as Array<{ revision_id: number; digest: string; replaced_digest: string | null; approved_by: string | null; command_id: string | null; redline_generation: string | null; redline_verdict: string | null; source_version: string | null; approved_at: string }>;
    return rows.map((r) => ({
      revisionId: r.revision_id,
      digest: r.digest,
      ...(r.replaced_digest ? { replacedDigest: r.replaced_digest } : {}),
      ...(r.approved_by ? { approvedBy: r.approved_by } : {}),
      ...(r.command_id ? { commandId: r.command_id } : {}),
      ...(r.redline_generation ? { redlineGeneration: r.redline_generation } : {}),
      ...(r.redline_verdict ? { redlineVerdict: r.redline_verdict as Verdict } : {}),
      ...(r.source_version ? { sourceVersion: r.source_version } : {}),
      approvedAt: r.approved_at,
    }));
  }

  /** Full revision history for one task, newest first — append-only by construction. */
  history(id: string): Array<{ revisionId: number; digest: string; createdAt: string }> {
    return (
      this.db
        .prepare('SELECT revision_id, digest, created_at FROM task_revisions WHERE task_id = ? ORDER BY revision_id DESC')
        .all(id) as Array<{ revision_id: number; digest: string; created_at: string }>
    ).map((r) => ({ revisionId: r.revision_id, digest: r.digest, createdAt: r.created_at }));
  }

  // ---------------------------------------------------------------- internals

  private pointers(id: string): { enabled_revision: number | null; draft_revision: number | null; checkpoint_shape: number | null } | undefined {
    return this.db.prepare('SELECT enabled_revision, draft_revision, checkpoint_shape FROM tasks WHERE id = ?').get(id) as
      | { enabled_revision: number | null; draft_revision: number | null; checkpoint_shape: number | null }
      | undefined;
  }

  private revision(revisionId: number): RevisionRow {
    const row = this.db.prepare('SELECT * FROM task_revisions WHERE revision_id = ?').get(revisionId) as RevisionRow | undefined;
    if (!row) throw new Error(`task revision ${revisionId} is missing — the store is corrupt`);
    return row;
  }

  /**
   * Canonical text of structured parts: rendered, then RE-PARSED so the
   * digest, the review card, and the interpreter input are all the same
   * validated bytes. Render/parse drift would be a bug, and it surfaces here.
   */
  private canonicalize(parts: TaskParts, label: string): { canonical: string; def: ActionDefinition } {
    const canonical = renderTaskFile(parts);
    const def = parseTaskFile(canonical, label);
    return { canonical, def };
  }

  /** A revision's definition comes from its FROZEN canonical bytes — never a re-render (review 2355). */
  private definitionOf(row: RevisionRow): ActionDefinition {
    if (row.canonical === null) throw new Error(`task revision ${row.revision_id} has no canonical bytes — migration did not run`);
    return parseTaskFile(row.canonical, `task:${row.task_id}@r${row.revision_id}`);
  }

  private partsOf(row: RevisionRow): TaskParts {
    return {
      shebang: row.shebang,
      headers: {
        'xtrape-task': row.task_id,
        ...(row.title !== null && row.title !== '' ? { title: row.title } : {}),
        version: row.version,
        ...(row.description !== null ? { description: row.description } : {}),
        ...(row.executor !== null ? { executor: row.executor } : {}),
        risk: row.risk,
        // Retired headers (#61) are stored empty for tasks authored without
        // them; an empty column is NO header, not a header with an empty
        // value — emitting one would break both the render and the
        // structural unchanged comparison.
        ...(row.readonly !== '' ? { readonly: row.readonly } : {}),
        servers: row.servers,
        ...(row.approval !== null ? { approval: row.approval } : {}),
        ...(row.interpreter !== null ? { interpreter: row.interpreter } : {}),
        ...(row.timeout_seconds !== null ? { timeout: row.timeout_seconds } : {}),
        ...(row.max_bytes !== null ? { maxBytes: row.max_bytes } : {}),
      },
      params: JSON.parse(row.params) as TaskParts['params'],
      redact: JSON.parse(row.redact) as string[],
      body: row.body,
    };
  }

  private insertRevision(id: string, parts: TaskParts, digest: string, canonical: string): number {
    const res = this.db
      .prepare(
        `INSERT INTO task_revisions (task_id, digest, shebang, title, version, description, executor, risk, readonly, servers, approval, interpreter, timeout_seconds, max_bytes, params, redact, body, canonical, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        digest,
        parts.shebang,
        parts.headers['title'] ?? null,
        parts.headers['version'] ?? '',
        parts.headers['description'] ?? null,
        parts.headers['executor'] ?? null,
        parts.headers['risk'] ?? '',
        parts.headers['readonly'] ?? '',
        parts.headers['servers'] ?? '',
        parts.headers['approval'] ?? null,
        parts.headers['interpreter'] ?? null,
        parts.headers['timeout'] ?? null,
        parts.headers['maxBytes'] ?? null,
        JSON.stringify(parts.params),
        JSON.stringify(parts.redact),
        parts.body,
        canonical,
        new Date().toISOString(),
      );
    return Number(res.lastInsertRowid);
  }

  private stored(revisionId: number, state: StoredTask['state']): StoredTask {
    const row = this.revision(revisionId);
    return { definition: this.decorate(this.definitionOf(row), revisionId), state, revisionId, createdAt: row.created_at };
  }

  /** Stamp the DB coordinate into sourceFile so records name a revision, not a phantom file. */
  private decorate(def: ActionDefinition, revisionId: number): ActionDefinition {
    const sourceVersion = (
      this.db
        .prepare('SELECT source_version FROM task_approvals WHERE revision_id = ? AND source_version IS NOT NULL ORDER BY approval_id DESC LIMIT 1')
        .get(revisionId) as { source_version: string } | undefined
    )?.source_version;
    return { ...def, sourceFile: `task:${def.id}@r${revisionId}`, ...(sourceVersion !== undefined ? { sourceVersion } : {}) };
  }

  /**
   * Run `fn` inside ONE SQLite transaction (savepoint-nested when a TaskDb
   * method inside opens its own): the governed sync's all-or-nothing apply
   * (review 2433 blocker 2). Anything thrown rolls the WHOLE batch back.
   */
  atomically<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }
}
