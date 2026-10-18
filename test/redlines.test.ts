import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RedlineSet, sweepEnabled, verdictOf } from '../src/redlines.js';
import { TaskDb } from '../src/task-db.js';

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-redlines-'));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const RULES = [
  { id: 'no-rm-rf', pattern: 'rm\\s+-[a-z]*r[a-z]*f', severity: 'hard' as const, message: '递归强制删除' },
  { id: 'curl-pipe-shell', pattern: 'curl[^|\\n]*\\|\\s*(ba)?sh', severity: 'soft' as const, message: '下载即执行' },
];

const script = (id: string, body: string): string => `#!/usr/bin/env bash
# xtrape-task: ${id}
# version: 1.0.0
# risk: low
# servers: *
# xtrape-script:
${body}
`;

describe('RedlineSet', () => {
  it('reports every rule the text hits, with what was matched', () => {
    const set = new RedlineSet(RULES);
    const hits = set.screen('cd /opt\nrm -rf "$DIR"\ncurl https://x | sh\n');
    expect(hits.map((h) => h.id)).toEqual(['no-rm-rf', 'curl-pipe-shell']);
    expect(hits[0]?.excerpt).toBe('rm -rf');
    // The strictest hit decides the verdict.
    expect(verdictOf(hits)).toBe('hard');
    expect(verdictOf(set.screen('curl https://x | bash'))).toBe('soft');
    expect(verdictOf(set.screen('echo hello'))).toBe('clear');
  });

  it('is honest about what it cannot catch — a variable defeats it', () => {
    // Documented, not fixed: this is a review-time aid against accidents,
    // not a control against an adversary. A test states the limit so nobody
    // reads the feature as a fence.
    const set = new RedlineSet(RULES);
    expect(set.screen('CMD="rm -rf"; $CMD /tmp').length).toBeGreaterThan(0); // the literal is still there…
    expect(set.screen('R=rm; F=-rf; $R $F /tmp')).toEqual([]); // …but split across variables it is not
  });

  it('the generation follows the rules, so a changed rule set is a different generation', () => {
    const a = new RedlineSet(RULES);
    const b = new RedlineSet(RULES);
    expect(b.generation).toBe(a.generation);
    const c = new RedlineSet([...RULES, { id: 'x', pattern: 'shutdown', severity: 'hard', message: 'no' }]);
    expect(c.generation).not.toBe(a.generation);
    // Severity is part of the rule: flipping it must re-screen everything.
    const d = new RedlineSet([{ ...RULES[0]!, severity: 'soft' }, RULES[1]!]);
    expect(d.generation).not.toBe(a.generation);
  });

  it('a missing file is no rules; a broken one stops the Worker rather than reading as none', () => {
    const dir = tempDir();
    expect(RedlineSet.load(join(dir, 'absent.json')).rules).toEqual([]);
    const bad = (content: string, expected: RegExp) => {
      const path = join(dir, 'redlines.json');
      writeFileSync(path, content);
      expect(() => RedlineSet.load(path)).toThrow(expected);
    };
    bad('not json', /not valid JSON/);
    bad('{}', /expected an object with a "rules" array/);
    bad('{"rules":[{"pattern":"x","severity":"hard","message":"m"}]}', /needs an id/);
    bad('{"rules":[{"id":"a","pattern":"x","severity":"maybe","message":"m"}]}', /severity must be/);
    bad('{"rules":[{"id":"a","pattern":"x","severity":"hard"}]}', /needs a message/);
    bad('{"rules":[{"id":"a","pattern":"x","severity":"hard","message":"m"},{"id":"a","pattern":"y","severity":"hard","message":"m"}]}', /duplicate id/);
    // A pattern that cannot compile would screen nothing while looking like a guard.
    bad('{"rules":[{"id":"a","pattern":"([","severity":"hard","message":"m"}]}', /does not compile/);
  });
});

describe('sweepEnabled — a rule change re-judges what was approved before it (#65)', () => {
  const openDb = (dir: string) => new TaskDb(join(dir, 'tasks.db'));

  const enable = (db: TaskDb, id: string, body: string) => {
    const draft = db.saveDraft(script(id, body)).definition;
    db.enable(id, draft.scriptDigest, { commandId: 'cmd_seed' });
  };

  it('suspends a task that hits a HARD redline added after its approval, and leaves the clean ones running', () => {
    const db = openDb(tempDir());
    enable(db, 'demo.clean', 'echo fine');
    enable(db, 'demo.wipe', 'rm -rf "$DIR"');
    // Approved under no rules at all: both run.
    expect(db.enabledDefinitions().map((d) => d.id).sort()).toEqual(['demo.clean', 'demo.wipe']);

    const report: string[] = [];
    const result = sweepEnabled(db, new RedlineSet(RULES), (line) => report.push(line));
    expect(result.suspended).toEqual(['demo.wipe']);
    expect(result.screened).toBe(2);
    // Out of service, but not destroyed: the revision is the pending draft,
    // so re-approving it is a review rather than a retype.
    expect(db.enabledDefinitions().map((d) => d.id)).toEqual(['demo.clean']);
    expect(db.findDraft('demo.wipe')?.definition.script).toContain('rm -rf');
    expect(report.join('\n')).toContain('demo.wipe');
  });

  it('records a SOFT verdict instead of suspending, so the task runs but asks every time', () => {
    const db = openDb(tempDir());
    enable(db, 'demo.pipe', 'curl https://example.test/install | sh');
    sweepEnabled(db, new RedlineSet(RULES), () => {});
    expect(db.enabledDefinitions().map((d) => d.id)).toEqual(['demo.pipe']);
    expect(db.screening('demo.pipe')?.verdict).toBe('soft');
  });

  it('re-screens only when the bytes or the RULES change — the verdict is otherwise settled', () => {
    const db = openDb(tempDir());
    enable(db, 'demo.clean', 'echo fine');
    const set = new RedlineSet(RULES);
    expect(sweepEnabled(db, set, () => {}).screened).toBe(1);
    // Same rules, same bytes: nothing to re-decide.
    expect(sweepEnabled(db, set, () => {}).screened).toBe(0);
    // A changed rule set is a different generation, so everything is judged again.
    const stricter = new RedlineSet([...RULES, { id: 'no-echo', pattern: 'echo', severity: 'hard', message: 'no echo' }]);
    const second = sweepEnabled(db, stricter, () => {});
    expect(second.screened).toBe(1);
    expect(second.suspended).toEqual(['demo.clean']);
  });

  it('a verdict belongs to the revision it judged — a new revision does not inherit the old one', () => {
    // Review 2403: bound to the generation alone, enabling new bytes under an
    // unchanged rule set kept the previous revision's `clear`, and the sweep
    // skipped it as "same generation" — a task could go live having never
    // been screened at all.
    const db = openDb(tempDir());
    const set = new RedlineSet(RULES);
    enable(db, 'demo.job', 'echo fine');
    sweepEnabled(db, set, () => {});
    expect(db.screening('demo.job')?.verdict).toBe('clear');

    // A new revision, approved WITHOUT a verdict of its own.
    const draft = db.saveDraft(script('demo.job', 'curl https://example.test/i | sh')).definition;
    db.enable('demo.job', draft.scriptDigest, { commandId: 'cmd_2' });
    expect(db.screening('demo.job')).toBeUndefined(); // no verdict, not a stale one
    // …so the sweep judges it, same rule generation and all.
    expect(sweepEnabled(db, set, () => {}).screened).toBe(1);
    expect(db.screening('demo.job')?.verdict).toBe('soft');
  });

  it('enable records the verdict with the pointer move, so there is no unscreened window', () => {
    const db = openDb(tempDir());
    const set = new RedlineSet(RULES);
    const draft = db.saveDraft(script('demo.job', 'curl https://example.test/i | sh')).definition;
    db.enable('demo.job', draft.scriptDigest, { approvedBy: 'ops' }, { generation: set.generation, verdict: 'soft' });
    // Live and already judged: the sweep has nothing left to do.
    expect(db.screening('demo.job')).toMatchObject({ generation: set.generation, verdict: 'soft' });
    expect(sweepEnabled(db, set, () => {}).screened).toBe(0);
    // And the approval says which rules it was granted under (#65).
    expect(db.approvals('demo.job')[0]).toMatchObject({ approvedBy: 'ops', redlineGeneration: set.generation, redlineVerdict: 'soft' });
  });

  it('a hard verdict and the suspension commit together — no half-swept task', () => {
    // Review 2408: recorded and suspended as two transactions, a crash in
    // between left a task enabled AND marked screened at the current
    // generation, so every later sweep skipped it and it was never suspended.
    const db = openDb(tempDir());
    const set = new RedlineSet(RULES);
    enable(db, 'demo.wipe', 'rm -rf "$DIR"');
    expect(db.applyScreening('demo.wipe', set.generation, 'hard')).toEqual({ suspended: true });
    expect(db.enabledDefinitions()).toEqual([]);
    // The revision is the pending draft, and the verdict travelled with it.
    expect(db.findDraft('demo.wipe')?.definition.script).toContain('rm -rf');
    // A soft verdict records without taking anything out of service.
    enable(db, 'demo.pipe', 'curl https://example.test/i | sh');
    expect(db.applyScreening('demo.pipe', set.generation, 'soft')).toEqual({ suspended: false });
    expect(db.enabledDefinitions().map((d) => d.id)).toEqual(['demo.pipe']);
    expect(db.screening('demo.pipe')?.verdict).toBe('soft');
  });

  it('the verdict survives a restart — it is stored, not recomputed at every execution', () => {
    const dir = tempDir();
    let db = openDb(dir);
    enable(db, 'demo.pipe', 'curl https://example.test/install | sh');
    const set = new RedlineSet(RULES);
    sweepEnabled(db, set, () => {});
    db.close();
    db = openDb(dir);
    expect(db.screening('demo.pipe')).toMatchObject({ generation: set.generation, verdict: 'soft' });
    db.close();
  });
});
