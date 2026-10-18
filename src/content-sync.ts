import { parseTaskFile } from './task-file.js';
import { splitTaskSource } from './task-file.js';
import { verdictOf, type RedlineSet } from './redlines.js';
import { ActionRegistry } from './registry.js';
import type { ContentSource } from './content-source.js';
import type { TaskDb } from './task-db.js';
import type { ActionDefinition } from './types.js';

/**
 * The live surfaces a sync must keep CONSISTENT with the DB (review 2429
 * blocker 3): the runtime registry serves the script that executes, the DB
 * serves the screening verdict — updated in two places at two times, an old
 * script could run under a new revision's verdict (an old soft-hit script
 * silently losing its confirmation requirement). The apply loop below is
 * deliberately SYNCHRONOUS (better-sqlite3, no awaits), so swapping the
 * registry entry in the same iteration as the DB pointer leaves no event-loop
 * turn in which an execution could observe one without the other.
 */
export interface LiveCatalog {
  register(def: ActionDefinition): void;
  unregister(id: string): void;
}

export interface SyncOutcome {
  versionId: string;
  /** Task ids this version made effective here. */
  applied: string[];
  /** What was refused, with why. A whole-version refusal reports one `(all)` entry. */
  refused: Array<{ id: string; reason: string }>;
  /** Task ids withdrawn because the effective version no longer carries them. */
  withdrawn: string[];
  /** True when the version was already applied and nothing was done. */
  unchanged: boolean;
}

/**
 * Bring the local library to the governed side's current effective version
 * (xtrape-docs#255, owner ruling 2026-08-16: **this Widget keeps only the
 * latest usable version**; history and review live at the governance side).
 *
 * Three refusals shape this function, and each one refuses the WHOLE version:
 *
 * - **Non-monotonic** (review 2427 blocker 2): the effective sequence must be
 *   greater than what is applied here. Lower = a rollback nobody decided
 *   (stale cache, replayed read); equal with a different id = rewritten
 *   history. A "seen versions" set would only stop exact replays — applied
 *   v1 → v3, a first-ever read of old v2 would still have gone backwards.
 * - **Malformed** (review 2427 blocker 3): one unparseable task file refuses
 *   the whole set. Applying the rest would run a shape the governance side
 *   never approved, and the broken file's task — absent from the parsed set —
 *   would be WITHDRAWN as if the reviewers had removed it.
 * - **Empty while tasks run**: a wrong directory or a glitch looks exactly
 *   like "delete everything", and the destructive reading is not the one to
 *   guess.
 *
 * A refused version is NOT recorded, so a corrected read still lands. What is
 * NOT a whole-version refusal: a task hitting a local hard redline (#65) is
 * refused individually and reported — the redline set is a deployment-local
 * fact the governance side does not know; local policy narrows per task, and
 * the task's previously effective version keeps running.
 */
export async function syncEffective(
  store: TaskDb,
  source: ContentSource,
  redlines: RedlineSet,
  report: (line: string) => void = (line) => process.stderr.write(`${line}\n`),
  /** When given, the runtime catalog is swapped in the same synchronous step as each DB pointer. */
  live?: LiveCatalog,
): Promise<SyncOutcome> {
  const effective = await source.fetchEffective();
  const short = effective.versionId.slice(0, 12);
  const refuseAll = (reason: string): SyncOutcome => {
    report(`[content] REFUSED effective version ${short}: ${reason}`);
    return { versionId: effective.versionId, applied: [], refused: [{ id: '(all)', reason }], withdrawn: [], unchanged: false };
  };

  const last = store.lastContentVersion();
  if (last !== undefined) {
    if (effective.sequence < last.sequence) {
      return refuseAll(
        `sequence ${effective.sequence} is OLDER than the applied ${last.sequence} (${last.versionId.slice(0, 12)}) — a rollback nobody decided; check the source for a stale cache or a replayed read`,
      );
    }
    if (effective.sequence === last.sequence) {
      if (effective.versionId !== last.versionId) {
        return refuseAll(
          `sequence ${effective.sequence} equals the applied version's but the content id differs — the effective history was rewritten; this needs a person, not a guess`,
        );
      }
      // Same version. Unchanged — UNLESS the local rule set moved since it
      // was applied (review 2435 blocker 2): a task refused under the old
      // generation may be admissible now, and the governance side has no
      // reason to mint a new version just because THIS deployment relaxed a
      // redline. Re-screening the same version is how it gets its chance.
      if (last.redlineGeneration === redlines.generation) {
        return { versionId: effective.versionId, applied: [], refused: [], withdrawn: [], unchanged: true };
      }
      report(`[content] re-screening effective version ${short} under redline generation ${redlines.generation.slice(0, 19)} (was ${(last.redlineGeneration ?? '(unknown)').slice(0, 19)})`);
    }
  }

  // Validate EVERYTHING first: apply-or-refuse is decided for the set as a
  // whole, before any pointer moves. "Valid" is the same bar the library's
  // own storage enforces (review 2429 blocker 2) — parse, full registry
  // admission on a scratch registry, and id uniqueness — because a file that
  // parses but cannot register would otherwise fail mid-apply after its
  // siblings already landed.
  const parsed: Array<{ id: string; version: string; bytes: string }> = [];
  const ids = new Map<string, string>();
  const scratch = new ActionRegistry();
  for (const file of effective.files) {
    const name = file.path.split('/').pop() ?? file.path;
    try {
      const def = parseTaskFile(file.bytes, name);
      const claimedBy = ids.get(def.id);
      if (claimedBy !== undefined) {
        return refuseAll(`${name} and ${claimedBy} both declare task "${def.id}" — refusing the whole set: apply order must not pick which one wins`);
      }
      ids.set(def.id, name);
      scratch.register(def); // full admission, zero side effects
      parsed.push({ id: def.id, version: def.version, bytes: file.bytes });
    } catch (error) {
      return refuseAll(`${name} fails validation (${error instanceof Error ? error.message : String(error)}) — refusing the whole set: applying the rest would withdraw this task as if reviewers removed it`);
    }
  }

  const enabledNow = store.listAll().filter((t) => t.state === 'enabled');
  if (parsed.length === 0 && enabledNow.length > 0) {
    return refuseAll(
      `it carries no task files while ${enabledNow.length} task(s) are running here — an empty read looks exactly like "withdraw everything"; check the configured source directory`,
    );
  }

  // All-or-nothing apply (review 2433 blocker 2): every DB mutation of this
  // version — pointer moves, screenings, withdrawals, the version record —
  // commits in ONE transaction, or none of it does. Registry swaps are
  // collected during the transaction and applied only after it commits;
  // everything here is synchronous (better-sqlite3), so commit and swaps
  // share one event-loop turn and no execution can observe a half-state.
  const applied: string[] = [];
  const refused: Array<{ id: string; reason: string }> = [];
  const withdrawn: string[] = [];
  const swaps: Array<{ id: string; def?: ActionDefinition }> = [];
  try {
    store.atomically(() => {
      const seen = new Set<string>();
      for (const task of parsed) {
        seen.add(task.id);
        const hits = redlines.screen(task.bytes);
        if (verdictOf(hits) === 'hard') {
          refused.push({ id: task.id, reason: `hard redline: ${hits.filter((h) => h.severity === 'hard').map((h) => h.id).join(', ')}` });
          continue;
        }
        // linux-ops#94 (review 3210): the same migration invariant as the
        // startup composition root — a task enabled under an older definition
        // shape at this SAME version is neither re-enabled nor re-exposed;
        // it waits for the governed content to bump `# version:`.
        const held = store.findEnabled(task.id);
        if (held?.needsReversion === true && held.definition.version === task.version) {
          refused.push({ id: task.id, reason: `enabled under an older Checkpoint definition shape at ${task.version} — re-version required (bump "# version:")` });
          continue;
        }
        const draft = store.saveDraftFromParts(splitTaskSource(task.bytes));
        if (draft.state === 'enabled') {
          // Byte-identical to what is already effective here: nothing to
          // enable — but the revision must still carry THIS governed version
          // as provenance (review 2435 blocker 3), or every later execution
          // of it would lack the versionId in its evidence. This is exactly
          // the first-switch-to-governed case: local tasks matching the
          // Curator's set to the byte.
          store.attachSourceVersion(task.id, effective.versionId);
          // …and the LIVE registry must learn the new provenance too (review
          // 2437 blocker 2): OpsService reads the definition it serves, so a
          // DB-only update would keep stamping the old versionId into every
          // execution record until a restart. Same swap as a real change.
          const enabled = store.findEnabled(task.id);
          if (enabled) swaps.push({ id: task.id, def: enabled.definition });
          continue;
        }
        const { definition } = store.enable(
          task.id,
          draft.definition.scriptDigest,
          { sourceVersion: effective.versionId },
          { generation: redlines.generation, verdict: verdictOf(hits) },
        );
        swaps.push({ id: task.id, def: definition });
        applied.push(task.id);
      }
      // A task the effective version no longer carries stops being
      // executable here. `seen` is complete — the set validated in full
      // above — so a withdrawal is always a reviewed removal.
      for (const task of store.listAll()) {
        if (task.state !== 'enabled' || seen.has(task.definition.id)) continue;
        store.removeEnabled(task.definition.id);
        swaps.push({ id: task.definition.id });
        withdrawn.push(task.definition.id);
      }
      store.recordContentVersion(effective.versionId, effective.sequence, redlines.generation);
    });
  } catch (error) {
    // The transaction rolled the WHOLE version back: no pointer moved, no
    // registry entry is touched, the version is unrecorded, and the next
    // sweep retries the full set — never a half-applied library claiming an
    // old lastContentVersion (review 2433 blocker 2).
    return refuseAll(`storage failure while applying — rolled back whole: ${error instanceof Error ? error.message : String(error)}`);
  }
  for (const swap of swaps) {
    if (live === undefined) break;
    live.unregister(swap.id);
    if (swap.def !== undefined) live.register(swap.def);
  }

  if (applied.length > 0 || withdrawn.length > 0) {
    report(`[content] effective version ${short} (seq ${effective.sequence}): ${applied.length} task(s) applied, ${withdrawn.length} withdrawn`);
  }
  if (refused.length > 0) {
    report(
      `[content] ${refused.length} task(s) in ${short} were REFUSED locally and are not effective here: ` +
        refused.map((r) => `${r.id} (${r.reason})`).join('; '),
    );
  }
  return { versionId: effective.versionId, applied, refused, withdrawn, unchanged: false };
}
