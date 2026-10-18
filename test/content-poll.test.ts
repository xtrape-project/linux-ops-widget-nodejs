import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { syncGovernedContentOnce } from '../src/content-poll.js';
import type { ContentSource, EffectiveContent } from '../src/content-source.js';
import { ActionRegistry } from '../src/registry.js';
import { RedlineSet } from '../src/redlines.js';
import { TaskDb } from '../src/task-db.js';

/**
 * GROW BEFORE EXPOSE is atomic against the durable state (linux-ops#80
 * review 2674 P1-1, the governed-content half): the incoming version's
 * Checkpoints publish durably BEFORE syncEffective records anything — a
 * publish failure commits NOTHING and the next pass retries in full.
 */

const dirs: string[] = [];
function tstore(): TaskDb {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-poll-'));
  dirs.push(dir);
  return new TaskDb(join(dir, 'tasks.db'));
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const TASK_BYTES = [
  '# xtrape-task: disk.usage',
  '# title: Disk usage',
  '# version: 1.0.0',
  '# description: df',
  '# executor: ssh',
  '# risk: low',
  '# servers: *',
  '',
  '#!/bin/sh',
  'df -h',
].join('\n');

function sourceOf(effective: EffectiveContent): { source: ContentSource; fetches: () => number } {
  const fetchEffective = vi.fn(async () => effective);
  return {
    source: {
      fetchEffective,
      submit: async () => {
        throw new Error('not under test');
      },
      reviewUrl: () => 'https://forge.example/review',
    },
    fetches: () => fetchEffective.mock.calls.length,
  };
}

describe('syncGovernedContentOnce (#80 review 2674 P1-1)', () => {
  it('publishes BEFORE any pointer moves; a publish failure records NOTHING and the next pass retries in full', async () => {
    const effective: EffectiveContent = { versionId: 'c0ffee'.padEnd(40, '0'), sequence: 1, files: [{ path: 'tasks/disk.usage.task', bytes: TASK_BYTES }] };
    const { source } = sourceOf(effective);
    const taskStore = tstore();
    const registry = new ActionRegistry();
    const ensure: (tasks: ReadonlyArray<{ id: string; riskLevel: string; version: string }>) => Promise<void> = vi.fn(async () => {
      throw new Error('platform unreachable');
    });
    const ensureMock = ensure as unknown as { mockImplementation: (fn: () => Promise<void>) => void; mock: { calls: unknown[][] } };

    await expect(
      syncGovernedContentOnce({ source, taskStore, redlines: new RedlineSet([]), registry, ensureTaskCheckpoints: ensure, report: () => {} }),
    ).rejects.toThrow(/platform unreachable/);
    // NOTHING was committed: no enabled task, no runtime registration.
    expect(taskStore.listAll().some((t) => t.state === 'enabled')).toBe(false);
    expect(registry.list()).toHaveLength(0);

    // The next pass retries the SAME version end-to-end and applies it.
    ensureMock.mockImplementation(async () => {});
    const outcome = await syncGovernedContentOnce({ source, taskStore, redlines: new RedlineSet([]), registry, ensureTaskCheckpoints: ensure, report: () => {} });
    expect(outcome.applied).toEqual(['disk.usage']);
    expect(registry.list().map((t) => t.id)).toEqual(['disk.usage']);
    // ensure saw the incoming definition BOTH times (idempotence is the
    // publisher's own property; the pass never skips it on retry).
    expect(ensureMock.mock.calls).toHaveLength(2);
    expect((ensureMock.mock.calls[1]![0] as Array<{ id: string; version: string }>)[0]).toMatchObject({ id: 'disk.usage', version: '1.0.0' });
  });

  it('the applied content is PINNED to the published snapshot: one fetch per pass, sync consumes that exact version', async () => {
    const effective: EffectiveContent = { versionId: 'deadbeef'.padEnd(40, '0'), sequence: 2, files: [{ path: 'tasks/disk.usage.task', bytes: TASK_BYTES }] };
    const { source, fetches } = sourceOf(effective);
    const outcome = await syncGovernedContentOnce({
      source,
      taskStore: tstore(),
      redlines: new RedlineSet([]),
      registry: new ActionRegistry(),
      ensureTaskCheckpoints: async () => {},
      report: () => {},
    });
    expect(outcome.versionId).toBe(effective.versionId);
    expect(fetches()).toBe(1); // the sync consumed the pinned snapshot, not a re-fetch
  });
});

describe('definition-shape migration on the governed-content path (linux-ops#94, review 3210)', () => {
  const bytesAt = (version: string) => TASK_BYTES.replace('# version: 1.0.0', `# version: ${version}`);
  const legacyEnabled = (taskStore: TaskDb, bytes: string) => {
    const draft = taskStore.saveDraft(bytes);
    taskStore.enable('disk.usage', draft.definition.scriptDigest, { commandId: 'cmd_legacy' });
    // A library enabled by a pre-shape Widget: the column is NULL (= shape 1).
    (taskStore as unknown as { db: { prepare: (s: string) => { run: (...a: unknown[]) => unknown } } }).db.prepare('UPDATE tasks SET checkpoint_shape = NULL WHERE id = ?').run('disk.usage');
    expect(taskStore.findEnabled('disk.usage')).toMatchObject({ checkpointShape: 1, needsReversion: true });
  };

  it('a legacy-shape enabled task at the SAME id@version: unchanged effective content ⇒ 0 publish, 0 expose, no error', async () => {
    const taskStore = tstore();
    legacyEnabled(taskStore, TASK_BYTES);
    const registry = new ActionRegistry();
    for (const def of taskStore.enabledDefinitions()) registry.register(def); // startup: not exposed
    expect(registry.list()).toHaveLength(0);
    const published: string[][] = [];
    const ensure = async (tasks: ReadonlyArray<{ id: string; version: string }>) => { published.push(tasks.map((t) => `${t.id}@${t.version}`)); };
    const { source } = sourceOf({ versionId: 'aaaa'.padEnd(40, '0'), sequence: 1, files: [{ path: 'tasks/disk.usage.task', bytes: TASK_BYTES }] });
    const first = await syncGovernedContentOnce({ source, taskStore, redlines: new RedlineSet([]), registry, ensureTaskCheckpoints: ensure, report: () => {} });
    expect(published).toEqual([[]]);
    expect(registry.list()).toHaveLength(0);
    expect(first.applied).toEqual([]);
    expect(taskStore.findEnabled('disk.usage')).toMatchObject({ needsReversion: true });
    // A second, unchanged poll: still nothing published, nothing exposed.
    const again = await syncGovernedContentOnce({ source, taskStore, redlines: new RedlineSet([]), registry, ensureTaskCheckpoints: ensure, report: () => {} });
    expect(again.unchanged).toBe(true);
    expect(published).toEqual([[], []]);
    expect(registry.list()).toHaveLength(0);
  });

  it('a CHANGED body at the same version is refused (not enabled, not exposed) until the version bumps; the bump publishes the new id@version at shape 2 and restores exposure', async () => {
    const taskStore = tstore();
    legacyEnabled(taskStore, TASK_BYTES);
    const registry = new ActionRegistry();
    const published: string[][] = [];
    const ensure = async (tasks: ReadonlyArray<{ id: string; version: string }>) => { published.push(tasks.map((t) => `${t.id}@${t.version}`)); };
    const changedSameVersion = TASK_BYTES.replace('df -h', 'df -h /');
    const { source } = sourceOf({ versionId: 'bbbb'.padEnd(40, '0'), sequence: 1, files: [{ path: 'tasks/disk.usage.task', bytes: changedSameVersion }] });
    const held = await syncGovernedContentOnce({ source, taskStore, redlines: new RedlineSet([]), registry, ensureTaskCheckpoints: ensure, report: () => {} });
    expect(published).toEqual([[]]);
    expect(held.refused).toEqual([{ id: 'disk.usage', reason: expect.stringMatching(/re-version required/) }]);
    expect(registry.list()).toHaveLength(0);
    expect(taskStore.findEnabled('disk.usage')).toMatchObject({ needsReversion: true, definition: { version: '1.0.0' } });
    // The governed content bumps the version: published under the new id@version, enabled at the current shape, exposed.
    const { source: bumped } = sourceOf({ versionId: 'cccc'.padEnd(40, '0'), sequence: 2, files: [{ path: 'tasks/disk.usage.task', bytes: bytesAt('1.0.1') }] });
    const out = await syncGovernedContentOnce({ source: bumped, taskStore, redlines: new RedlineSet([]), registry, ensureTaskCheckpoints: ensure, report: () => {} });
    expect(published[1]).toEqual(['disk.usage@1.0.1']);
    expect(out.applied).toEqual(['disk.usage']);
    expect(taskStore.findEnabled('disk.usage')).toMatchObject({ needsReversion: false, definition: { version: '1.0.1' } });
    expect(registry.list().map((d) => `${d.id}@${d.version}`)).toEqual(['disk.usage@1.0.1']);
  });
});
