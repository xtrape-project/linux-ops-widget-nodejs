import type { ContentSource } from './content-source.js';
import type { RedlineSet } from './redlines.js';
import type { TaskDb } from './task-db.js';
import type { ActionRegistry } from './registry.js';
import type { ActionDefinition } from './types.js';
import { parseTaskFile } from './task-file.js';
import { syncEffective, type SyncOutcome } from './content-sync.js';

/**
 * One governed-content poll pass with GROW BEFORE EXPOSE made ATOMIC against
 * the durable state (linux-ops#80 review 2674 P1-1): the Checkpoints of the
 * INCOMING effective version are durably published BEFORE `syncEffective`
 * moves any DB pointer or records the version. A publish failure therefore
 * commits NOTHING — the version stays unrecorded, and the next tick retries
 * the publication (the platform routes are insert-only and the local ensure
 * is idempotent per id@version). The sync then applies EXACTLY the content
 * that was published: the fetched snapshot is pinned and handed to
 * `syncEffective` through a one-shot source, so a version advancing between
 * fetch and apply cannot smuggle unpublished tasks past the publication.
 *
 * A file that does not parse publishes nothing here — the sync's own
 * whole-set validation refuses that version, so there is nothing those bytes
 * could ever expose.
 */
export async function syncGovernedContentOnce(deps: {
  source: ContentSource;
  taskStore: TaskDb;
  redlines: RedlineSet;
  registry: ActionRegistry;
  ensureTaskCheckpoints: (tasks: ReadonlyArray<ActionDefinition>) => Promise<void>;
  report?: (line: string) => void;
}): Promise<SyncOutcome> {
  const effective = await deps.source.fetchEffective();
  const incoming: ActionDefinition[] = [];
  for (const file of effective.files) {
    const name = file.path.split('/').pop() ?? file.path;
    try {
      incoming.push(parseTaskFile(file.bytes, name));
    } catch {
      // unparseable ⇒ the sync refuses the whole set; nothing to publish
    }
  }
  // linux-ops#94 (review 3210): a task enabled under an OLDER definition shape
  // at the SAME id@version must not be re-published — the Platform holds the
  // old bytes at that version (immutable). It stays "re-version required"
  // until the governed content bumps `# version:`; only then is the new
  // id@version published (shape 2) and exposed by syncEffective below.
  const publishable = incoming.filter((def) => {
    const enabled = deps.taskStore.findEnabled(def.id);
    const held = enabled?.needsReversion === true && enabled.definition.version === def.version;
    if (held) deps.report?.(`[content] ${def.id}@${def.version} is enabled under an older Checkpoint definition shape — not re-published; bump "# version:" in the governed content to re-enable it`);
    return !held;
  });
  await deps.ensureTaskCheckpoints(publishable);
  const pinned: ContentSource = {
    fetchEffective: async () => effective,
    submit: (input) => deps.source.submit(input),
    reviewUrl: (path) => deps.source.reviewUrl(path),
  };
  return syncEffective(deps.taskStore, pinned, deps.redlines, deps.report, deps.registry);
}
