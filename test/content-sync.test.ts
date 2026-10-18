import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TaskDb } from '../src/task-db.js';
import { RedlineSet } from '../src/redlines.js';
import { syncEffective } from '../src/content-sync.js';
import type { ContentSource, EffectiveContent, SubmissionResult, SubmitInput } from '../src/content-source.js';

const dirs: string[] = [];
function db(): TaskDb {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-content-'));
  dirs.push(dir);
  return new TaskDb(join(dir, 'tasks.db'));
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const task = (id: string, body: string): string => `#!/usr/bin/env bash
# xtrape-task: ${id}
# version: 1.0.0
# risk: low
# servers: *
# xtrape-script:
${body}
`;

/** A governance side that hands back whatever the test says is effective. */
class FakeSource implements ContentSource {
  submissions: SubmitInput[] = [];
  constructor(public effective: EffectiveContent) {}
  async fetchEffective(): Promise<EffectiveContent> {
    return this.effective;
  }
  async submit(input: SubmitInput): Promise<SubmissionResult> {
    this.submissions.push(input);
    return { submissionId: '7', url: 'https://forge.test/x/y/pulls/7' };
  }
  reviewUrl(): string {
    return 'https://forge.test/x/y/pulls';
  }
}

const RULES = [{ id: 'no-rm-rf', pattern: 'rm\\s+-rf', severity: 'hard' as const, message: '递归强制删除' }];

describe('governed content sync (xtrape-docs#255)', () => {
  it('makes the effective version the library, and records which version it came from', async () => {
    const store = db();
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [
        { path: 'tasks/uptime.sh', bytes: task('system.uptime', 'uptime') },
        { path: 'tasks/disk.sh', bytes: task('system.disk', 'df -h') },
      ],
    });
    const out = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(out.applied.sort()).toEqual(['system.disk', 'system.uptime']);
    expect(store.enabledDefinitions().map((d) => d.id).sort()).toEqual(['system.disk', 'system.uptime']);
    // The ledger says which effective version made it so — the approval itself
    // happened at the governance side, so that is what is attestable here.
    expect(store.approvals('system.uptime')[0]).toMatchObject({ sourceVersion: 'commit-1' });
  });

  it('refuses a task that hits a LOCAL hard redline, and leaves the rest effective', async () => {
    const store = db();
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [
        { path: 'tasks/ok.sh', bytes: task('system.uptime', 'uptime') },
        { path: 'tasks/wipe.sh', bytes: task('demo.wipe', 'rm -rf "$DIR"') },
      ],
    });
    const out = await syncEffective(store, source, new RedlineSet(RULES), () => {});
    expect(out.applied).toEqual(['system.uptime']);
    expect(out.refused).toEqual([{ id: 'demo.wipe', reason: 'hard redline: no-rm-rf' }]);
    expect(store.enabledDefinitions().map((d) => d.id)).toEqual(['system.uptime']);
  });

  it('withdraws a task the new effective version no longer carries', async () => {
    const store = db();
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [
        { path: 'tasks/uptime.sh', bytes: task('system.uptime', 'uptime') },
        { path: 'tasks/disk.sh', bytes: task('system.disk', 'df -h') },
      ],
    });
    await syncEffective(store, source, new RedlineSet([]), () => {});
    source.effective = { versionId: 'commit-2', sequence: 2, files: [{ path: 'tasks/uptime.sh', bytes: task('system.uptime', 'uptime') }] };
    const out = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(out.withdrawn).toEqual(['system.disk']);
    expect(store.enabledDefinitions().map((d) => d.id)).toEqual(['system.uptime']);
  });

  it('versions are MONOTONIC: an older sequence is refused even if never seen here (review 2427)', async () => {
    const store = db();
    const v1 = { versionId: 'commit-1', sequence: 1, files: [{ path: 'tasks/uptime.sh', bytes: task('system.uptime', 'uptime') }] };
    const source = new FakeSource(v1);
    await syncEffective(store, source, new RedlineSet([]), () => {});
    source.effective = { versionId: 'commit-3', sequence: 3, files: [{ path: 'tasks/disk.sh', bytes: task('system.disk', 'df -h') }] };
    await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(store.enabledDefinitions().map((d) => d.id)).toEqual(['system.disk']);

    // The governance side (or a cache) hands back the OLD version again —
    // a version this library has SEEN. Refused by sequence, not by memory.
    source.effective = v1;
    const replay = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(replay.refused[0]?.reason).toContain('OLDER');
    expect(store.enabledDefinitions().map((d) => d.id)).toEqual(['system.disk']);

    // And an old version NEVER seen here (applied 1 -> 3, then 2 arrives)
    // is refused just the same — this is what a seen-set could not do.
    source.effective = { versionId: 'commit-2b', sequence: 2, files: [{ path: 'tasks/x.sh', bytes: task('system.x', 'echo x') }] };
    const unseen = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(unseen.refused[0]?.reason).toContain('OLDER');
    expect(store.enabledDefinitions().map((d) => d.id)).toEqual(['system.disk']);
  });

  it('an equal sequence with a DIFFERENT id is rewritten history — refused for a person to look at', async () => {
    const store = db();
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [{ path: 'tasks/uptime.sh', bytes: task('system.uptime', 'uptime') }] });
    await syncEffective(store, source, new RedlineSet([]), () => {});
    source.effective = { versionId: 'commit-1-rewritten', sequence: 1, files: [{ path: 'tasks/disk.sh', bytes: task('system.disk', 'df -h') }] };
    const out = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(out.refused[0]?.reason).toContain('rewritten');
    expect(store.enabledDefinitions().map((d) => d.id)).toEqual(['system.uptime']);
  });

  it('refuses an EMPTY effective set while tasks are running, instead of withdrawing the library', async () => {
    const store = db();
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [{ path: 'tasks/uptime.sh', bytes: task('system.uptime', 'uptime') }] });
    await syncEffective(store, source, new RedlineSet([]), () => {});

    // A wrong directory, a half-created repo, a glitch — all look like this.
    source.effective = { versionId: 'commit-2', sequence: 2, files: [] };
    const lines: string[] = [];
    const out = await syncEffective(store, source, new RedlineSet([]), (l) => lines.push(l));
    expect(out.withdrawn).toEqual([]);
    expect(out.refused[0]?.id).toBe('(all)');
    expect(store.enabledDefinitions().map((d) => d.id)).toEqual(['system.uptime']);
    expect(lines.join('\n')).toContain('REFUSED');
    // And it is NOT recorded as applied, so a corrected read still lands.
    source.effective = { versionId: 'commit-2', sequence: 2, files: [{ path: 'tasks/disk.sh', bytes: task('system.disk', 'df -h') }] };
    const fixed = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(fixed.applied).toEqual(['system.disk']);
  });

  it('an empty effective set IS applied when nothing is running yet', async () => {
    const store = db();
    const source = new FakeSource({ versionId: 'commit-0', sequence: 0, files: [] });
    const out = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(out.refused).toEqual([]);
    expect(out.unchanged).toBe(false);
  });

  it('an unchanged effective version is a no-op, not a rewrite', async () => {
    const store = db();
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [{ path: 'tasks/uptime.sh', bytes: task('system.uptime', 'uptime') }] });
    await syncEffective(store, source, new RedlineSet([]), () => {});
    const again = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(again).toMatchObject({ unchanged: true, applied: [], withdrawn: [] });
    expect(store.approvals('system.uptime')).toHaveLength(1);
  });

  it('one unparseable file refuses the WHOLE set — partial apply would withdraw its task (review 2427)', async () => {
    const store = db();
    // v1: both tasks fine and effective.
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [
        { path: 'tasks/ok.sh', bytes: task('system.uptime', 'uptime') },
        { path: 'tasks/two.sh', bytes: task('system.disk', 'df -h') },
      ],
    });
    await syncEffective(store, source, new RedlineSet([]), () => {});
    // v2: one file breaks. Partial application would have withdrawn
    // system.disk as if reviewers removed it, and marked v2 applied so a
    // corrected read never lands.
    source.effective = { versionId: 'commit-2', sequence: 2, files: [
      { path: 'tasks/ok.sh', bytes: task('system.uptime', 'uptime') },
      { path: 'tasks/two.sh', bytes: '#!/usr/bin/env bash\necho no header\n' },
    ] };
    const out = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(out.applied).toEqual([]);
    expect(out.withdrawn).toEqual([]);
    expect(out.refused[0]?.id).toBe('(all)');
    // BOTH tasks still run their previously effective versions.
    expect(store.enabledDefinitions().map((d) => d.id).sort()).toEqual(['system.disk', 'system.uptime']);
    // The broken version was NOT recorded, so the corrected v3 lands.
    source.effective = { versionId: 'commit-3', sequence: 3, files: [
      { path: 'tasks/ok.sh', bytes: task('system.uptime', 'uptime') },
      { path: 'tasks/two.sh', bytes: task('system.disk', 'df -h -x tmpfs') },
    ] };
    const fixed = await syncEffective(store, source, new RedlineSet([]), () => {});
    // Only the CHANGED task moves; the unchanged one carries over silently
    // instead of surfacing as a bogus refusal.
    expect(fixed.applied).toEqual(['system.disk']);
    expect(fixed.refused).toEqual([]);
    expect(store.enabledDefinitions().map((d) => d.id).sort()).toEqual(['system.disk', 'system.uptime']);
  });
});

describe('whole-set validation and the live catalog (review 2429)', () => {
  it('two files declaring one task id refuse the WHOLE set — order must not pick a winner', async () => {
    const store = db();
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [
      { path: 'tasks/a.sh', bytes: task('system.uptime', 'uptime') },
      { path: 'tasks/b.sh', bytes: task('system.uptime', 'echo other') },
    ] });
    const out = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(out.refused[0]?.id).toBe('(all)');
    expect(out.refused[0]?.reason).toContain('both declare');
    expect(store.enabledDefinitions()).toEqual([]);
  });

  it('a file that parses but fails registry admission refuses the WHOLE set', async () => {
    const store = db();
    // A duplicate-in-one-set is covered above; an admission failure is e.g.
    // an id the registry refuses. Reserved/invalid action ids are admission
    // territory — craft one with an invalid id shape.
    const bad = `#!/usr/bin/env bash\n# xtrape-task: -leading-dash\n# version: 1.0.0\n# risk: low\n# servers: *\n# xtrape-script:\necho x\n`;
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [
      { path: 'tasks/good.sh', bytes: task('system.uptime', 'uptime') },
      { path: 'tasks/bad.sh', bytes: bad },
    ] });
    const out = await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(out.refused[0]?.id).toBe('(all)');
    expect(store.enabledDefinitions()).toEqual([]);
    // Not recorded: the corrected set (same fix cadence as parse failures) lands.
    const fixed = new FakeSource({ versionId: 'commit-2', sequence: 2, files: [
      { path: 'tasks/good.sh', bytes: task('system.uptime', 'uptime') },
    ] });
    const ok = await syncEffective(store, fixed, new RedlineSet([]), () => {});
    expect(ok.applied).toEqual(['system.uptime']);
  });

  it('the live catalog is swapped in the same synchronous step as each DB pointer', async () => {
    const { ActionRegistry } = await import('../src/registry.js');
    const store = db();
    const registry = new ActionRegistry();
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [
      { path: 'tasks/a.sh', bytes: task('system.uptime', 'uptime') },
      { path: 'tasks/b.sh', bytes: task('system.disk', 'df -h') },
    ] });
    await syncEffective(store, source, new RedlineSet([]), () => {}, registry);
    expect(registry.list().map((d) => d.id).sort()).toEqual(['system.disk', 'system.uptime']);
    // v2 changes one task and withdraws the other: the registry follows both.
    source.effective = { versionId: 'commit-2', sequence: 2, files: [
      { path: 'tasks/a.sh', bytes: task('system.uptime', 'uptime -p') },
    ] };
    await syncEffective(store, source, new RedlineSet([]), () => {}, registry);
    expect(registry.list().map((d) => d.id)).toEqual(['system.uptime']);
    expect(registry.list()[0]!.script).toContain('uptime -p');
  });
});

describe('all-or-nothing apply and per-run evidence (review 2433)', () => {
  it('a storage fault mid-apply rolls the WHOLE version back — pointers, registry and version record', async () => {
    const { ActionRegistry } = await import('../src/registry.js');
    const store = db();
    const registry = new ActionRegistry();
    // v1 effective.
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [
      { path: 'tasks/a.sh', bytes: task('system.uptime', 'uptime') },
    ] });
    await syncEffective(store, source, new RedlineSet([]), () => {}, registry);
    // v2 changes a and adds b — but the second enable hits a storage fault.
    source.effective = { versionId: 'commit-2', sequence: 2, files: [
      { path: 'tasks/a.sh', bytes: task('system.uptime', 'uptime -p') },
      { path: 'tasks/b.sh', bytes: task('system.disk', 'df -h') },
    ] };
    const realEnable = store.enable.bind(store);
    let calls = 0;
    store.enable = ((...args: Parameters<typeof realEnable>) => {
      calls += 1;
      if (calls === 2) throw new Error('disk full (simulated)');
      return realEnable(...args);
    }) as typeof store.enable;
    const lines: string[] = [];
    const out = await syncEffective(store, source, new RedlineSet([]), (l) => lines.push(l), registry);
    store.enable = realEnable;
    expect(out.refused[0]?.id).toBe('(all)');
    expect(lines.join('\n')).toContain('rolled back whole');
    // NOTHING moved: v1's script is still what runs, in DB and registry alike.
    expect(store.enabledDefinitions().find((d) => d.id === 'system.uptime')?.script).toContain('uptime\n');
    expect(registry.list().map((d) => d.id)).toEqual(['system.uptime']);
    expect(registry.list()[0]!.script).toContain('uptime\n');
    expect(store.lastContentVersion()).toMatchObject({ versionId: 'commit-1', sequence: 1 });
    // And the corrected retry lands in full.
    const retry = await syncEffective(store, source, new RedlineSet([]), () => {}, registry);
    expect(retry.applied.sort()).toEqual(['system.disk', 'system.uptime']);
  });

  it('an enabled definition carries the governed version it came from, for per-run evidence', async () => {
    const store = db();
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [
      { path: 'tasks/a.sh', bytes: task('system.uptime', 'uptime') },
    ] });
    await syncEffective(store, source, new RedlineSet([]), () => {});
    expect(store.enabledDefinitions()[0]).toMatchObject({ id: 'system.uptime', sourceVersion: 'commit-1' });
  });
});

describe('rule changes and first-switch provenance (review 2435)', () => {
  it('a task refused under a hard redline is re-tried when the LOCAL rule set relaxes — same governed version', async () => {
    const store = db();
    const source = new FakeSource({ versionId: 'commit-2', sequence: 2, files: [
      { path: 'tasks/ok.sh', bytes: task('system.uptime', 'uptime') },
      { path: 'tasks/wipe.sh', bytes: task('demo.wipe', 'rm -rf "$DIR"') },
    ] });
    const strict = new RedlineSet([{ id: 'no-rm-rf', pattern: 'rm\\s+-rf', severity: 'hard', message: 'x' }]);
    const first = await syncEffective(store, source, strict, () => {});
    expect(first.applied).toEqual(['system.uptime']);
    expect(first.refused.map((r) => r.id)).toEqual(['demo.wipe']);
    // Same version, same rules: unchanged.
    expect((await syncEffective(store, source, strict, () => {})).unchanged).toBe(true);
    // The deployment relaxes its rules. Nothing changed at the governance
    // side — and nothing needs to: the same version is re-screened.
    const relaxed = new RedlineSet([]);
    const retry = await syncEffective(store, source, relaxed, () => {});
    expect(retry.unchanged).toBe(false);
    expect(retry.applied).toEqual(['demo.wipe']);
    expect(store.enabledDefinitions().map((d) => d.id).sort()).toEqual(['demo.wipe', 'system.uptime']);
    // And now it IS settled under the relaxed generation.
    expect((await syncEffective(store, source, relaxed, () => {})).unchanged).toBe(true);
  });

  it('switching a local library to governed attaches provenance to byte-identical tasks — in the DB AND the live registry', async () => {
    const { ActionRegistry } = await import('../src/registry.js');
    const store = db();
    // A LOCAL library, enabled the local way, before governance existed.
    const bytes = task('system.uptime', 'uptime');
    const local = store.saveDraft(bytes).definition;
    store.enable('system.uptime', local.scriptDigest, { commandId: 'cmd_local' });
    expect(store.enabledDefinitions()[0]?.sourceVersion).toBeUndefined();
    const registry = new ActionRegistry();
    for (const def of store.enabledDefinitions()) registry.register(def);
    // The Curator's effective set carries the SAME bytes.
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [{ path: 'tasks/uptime.sh', bytes }] });
    const out = await syncEffective(store, source, new RedlineSet([]), () => {}, registry);
    expect(out.applied).toEqual([]); // nothing to enable…
    // …but the running revision now names the governed version it stands
    // under — in the DB and, crucially, in what OpsService actually reads.
    expect(store.enabledDefinitions()[0]).toMatchObject({ id: 'system.uptime', sourceVersion: 'commit-1' });
    expect(registry.list()[0]).toMatchObject({ id: 'system.uptime', sourceVersion: 'commit-1' });
  });

  it('a later governed version that leaves a task byte-identical still moves its provenance in the live registry (review 2437)', async () => {
    const { ActionRegistry } = await import('../src/registry.js');
    const store = db();
    const registry = new ActionRegistry();
    const bytes = task('system.uptime', 'uptime');
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [{ path: 'tasks/a.sh', bytes }] });
    await syncEffective(store, source, new RedlineSet([]), () => {}, registry);
    expect(registry.list()[0]).toMatchObject({ sourceVersion: 'commit-1' });
    // v2: A unchanged, B added. A's provenance must read v2 everywhere.
    source.effective = { versionId: 'commit-2', sequence: 2, files: [
      { path: 'tasks/a.sh', bytes },
      { path: 'tasks/b.sh', bytes: task('system.disk', 'df -h') },
    ] };
    await syncEffective(store, source, new RedlineSet([]), () => {}, registry);
    expect(registry.list().find((d) => d.id === 'system.uptime')).toMatchObject({ sourceVersion: 'commit-2' });
    expect(store.enabledDefinitions().find((d) => d.id === 'system.uptime')).toMatchObject({ sourceVersion: 'commit-2' });
  });
});

describe('a governed library does not decide its own lifecycle', () => {
  it('edits become submissions and Enable/Disable/Remove point at the review side', async () => {
    const { buildCeActions } = await import('../src/ce-actions.js');
    const { ServerStore } = await import('../src/servers.js');
    const { OpsService } = await import('../src/service.js');
    const { MemoryAuditLogger } = await import('../src/audit.js');
    const { ParamGuardSet } = await import('../src/param-guards.js');
    const { FakeExecutor, makeRegistry, TEST_HOST_KEY_FINGERPRINT } = await import('./helpers.js');

    const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-governed-'));
    dirs.push(dir);
    const store = db();
    const srv = new ServerStore(join(dir, 'servers.json'));
    const registry = makeRegistry();
    const executor = new FakeExecutor();
    const source = new FakeSource({ versionId: 'commit-1', sequence: 1, files: [] });
    const actions = buildCeActions({
      registry,
      taskStore: store,
      store: srv,
      opsService: new OpsService({ registry, servers: srv, executors: [executor], audit: new MemoryAuditLogger() }),
      redlines: new RedlineSet([]),
      paramGuards: new ParamGuardSet([]),
      content: { source, path: (id) => `tasks/${id}.sh` },
      probe: (s) => executor.run(s, { command: 'true' }),
      probeHostKey: () => Promise.resolve(TEST_HOST_KEY_FINGERPRINT),
    });
    const byName = new Map(actions.map((a) => [a.name, a]));

    // No delivered Account -> refused here with the reason, not parked as
    // an unapprovable proposal on the review side (12-command-origin §6.1).
    await expect(
      byName.get('addTask')!.execute({ id: 'demo.deploy', version: '1.0.0', risk: 'low', serverScope: '*', body: 'echo deploy' }, { commandId: 'cmd_41' }),
    ).rejects.toThrow(/no caller Account/);
    await expect(
      byName.get('addTask')!.execute(
        { id: 'demo.deploy', version: '1.0.0', risk: 'low', serverScope: '*', body: 'echo deploy' },
        { commandId: 'cmd_41', origin: { traceId: 'tr_41' } },
      ),
    ).rejects.toThrow(/no caller Account/);
    expect(source.submissions).toHaveLength(0);

    const added = (await byName.get('addTask')!.execute(
      { id: 'demo.deploy', version: '1.0.0', risk: 'low', serverScope: '*', body: 'echo deploy' },
      { commandId: 'cmd_42', origin: { account: 'acct_agent_1', traceId: 'tr_9' } },
    )) as { message: string; data: { state: string; reviewUrl: string } };
    // Not "saved": the caller is told where it is being reviewed, because
    // nothing became effective here.
    expect(added.data.state).toBe('submitted');
    expect(added.data.reviewUrl).toBe('https://forge.test/x/y/pulls/7');
    expect(store.findDraft('demo.deploy')).toBeUndefined();
    // The proposer recorded is the origin the Platform DELIVERED with the
    // command, forwarded verbatim; the carrying command is delivery
    // evidence in the detail, not the identity.
    expect(source.submissions[0]).toMatchObject({ path: 'tasks/demo.deploy.sh', origin: { account: 'acct_agent_1', traceId: 'tr_9' } });
    expect(source.submissions[0]!.detail).toContain('cmd_42');
    expect(source.submissions[0]!.bytes).toContain('echo deploy');

    for (const [name, input] of [
      ['enableTask', { id: 'demo.deploy' }],
      ['disableTask', { id: 'demo.deploy' }],
      ['removeTask', { id: 'demo.deploy', state: 'draft' }],
    ] as const) {
      const out = (await byName.get(name)!.execute(input, { commandId: 'c1' })) as { success: boolean; message: string };
      expect(out.success).toBe(false);
      expect(out.message).toContain('governed');
      expect(out.message).toContain('https://forge.test/x/y/pulls');
    }
  });
});

describe('ActionRegistry.reset (governed content arrives as a SET)', () => {
  it('replaces the whole catalog rather than diffing it entry by entry', async () => {
    const { ActionRegistry } = await import('../src/registry.js');
    const { makeAction } = await import('./helpers.js');
    const registry = new ActionRegistry();
    registry.register(makeAction({ id: 'system.uptime' }));
    registry.register(makeAction({ id: 'system.disk' }));
    registry.reset([makeAction({ id: 'system.disk' }), makeAction({ id: 'system.load' })]);
    expect(registry.list().map((a) => a.id).sort()).toEqual(['system.disk', 'system.load']);
    registry.reset([]);
    expect(registry.list()).toEqual([]);
  });
});
