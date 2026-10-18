import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { guardVerdict, ParamGuardSet, type GuardContext } from '../src/param-guards.js';
import { OpsService, type ExecuteContext } from '../src/service.js';
import { MemoryAuditLogger } from '../src/audit.js';
import type { ServerDefinition } from '../src/types.js';
import type { ServerResolver } from '../src/servers.js';
import { FakeExecutor, makeAction, makeRegistry, makeServer } from './helpers.js';

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-guards-'));
  dirs.push(dir);
  return dir;
}

const ctx = (over: Partial<GuardContext> = {}): GuardContext => ({
  taskId: 'file.find',
  args: {},
  serverId: 'web-dev-01',
  environment: 'development',
  surface: 'platform',
  ...over,
});

describe('ParamGuardSet — conditions over one invocation (#66)', () => {
  it('tests a parameter by value, pattern, presence and bounds', () => {
    const set = new ParamGuardSet([
      { id: 'root', when: { param: 'path', equals: '/' }, severity: 'hard', message: '整盘' },
      { id: 'tmpish', when: { param: 'path', matches: '^/(proc|sys)(/|$)' }, severity: 'hard', message: '内核伪文件系统' },
      { id: 'forced', when: { param: 'force', present: true }, severity: 'soft', message: '强制模式' },
      { id: 'deep', when: { param: 'depth', atLeast: 10 }, severity: 'soft', message: '很深' },
    ]);
    expect(set.evaluate(ctx({ args: { path: '/' } })).map((h) => h.id)).toEqual(['root']);
    expect(set.evaluate(ctx({ args: { path: '/proc/1' } })).map((h) => h.id)).toEqual(['tmpish']);
    expect(set.evaluate(ctx({ args: { path: '/opt' } }))).toEqual([]);
    expect(set.evaluate(ctx({ args: { force: false } })).map((h) => h.id)).toEqual(['forced']); // present, whatever the value
    expect(set.evaluate(ctx({ args: { depth: 12 } })).map((h) => h.id)).toEqual(['deep']);
    expect(set.evaluate(ctx({ args: { depth: '12' } })).map((h) => h.id)).toEqual(['deep']); // a string number still compares
    expect(set.evaluate(ctx({ args: { depth: 3 } }))).toEqual([]);
  });

  it('combines conditions, and scopes a rule to tasks, servers, environments and surfaces', () => {
    const set = new ParamGuardSet([
      {
        id: 'prod-force',
        task: 'nginx.*',
        when: { all: [{ param: 'force', equals: true }, { environment: 'production' }] },
        severity: 'hard',
        message: '生产上的强制重载',
      },
      { id: 'ai-writes', when: { all: [{ surface: 'mcp' }, { param: 'write', equals: true }] }, severity: 'soft', message: 'AI 面写入' },
      { id: 'not-dev', when: { not: { environment: 'development' } }, severity: 'soft', message: '非开发环境' },
      { id: 'db-hosts', when: { server: 'db-*' }, severity: 'soft', message: '数据库主机' },
    ]);
    // The task selector keeps a rule off tasks it was not written for.
    expect(set.evaluate(ctx({ taskId: 'file.find', args: { force: true }, environment: 'production' })).map((h) => h.id))
      .toEqual(['not-dev']);
    expect(set.evaluate(ctx({ taskId: 'nginx.reload', args: { force: true }, environment: 'production' })).map((h) => h.id))
      .toEqual(['prod-force', 'not-dev']);
    expect(set.evaluate(ctx({ surface: 'mcp', args: { write: true } })).map((h) => h.id)).toEqual(['ai-writes']);
    expect(set.evaluate(ctx({ serverId: 'db-01' })).map((h) => h.id)).toEqual(['db-hosts']);
  });

  it('the strictest hit decides, and a missing parameter never fires a value test', () => {
    const set = new ParamGuardSet([
      { id: 'soft', when: { param: 'a', equals: '1' }, severity: 'soft', message: 's' },
      { id: 'hard', when: { param: 'b', equals: '2' }, severity: 'hard', message: 'h' },
    ]);
    expect(guardVerdict(set.evaluate(ctx({ args: { a: '1' } })))).toBe('soft');
    expect(guardVerdict(set.evaluate(ctx({ args: { a: '1', b: '2' } })))).toBe('hard');
    // Absent parameters test false rather than matching by accident.
    expect(guardVerdict(set.evaluate(ctx({ args: {} })))).toBe('clear');
  });

  it('a missing file is no guards; a rule that could never fire stops the Worker', () => {
    const dir = tempDir();
    expect(ParamGuardSet.load(join(dir, 'absent.json')).rules).toEqual([]);
    const bad = (content: string, expected: RegExp) => {
      const path = join(dir, 'param-guards.json');
      writeFileSync(path, content);
      expect(() => ParamGuardSet.load(path)).toThrow(expected);
    };
    bad('nope', /not valid JSON/);
    bad('{}', /expected an object with a "rules" array/);
    bad('{"rules":[{"when":{"param":"a","equals":1},"severity":"hard","message":"m"}]}', /needs an id/);
    bad('{"rules":[{"id":"a","when":{"param":"x","equals":1},"severity":"maybe","message":"m"}]}', /severity must be/);
    bad('{"rules":[{"id":"a","when":{"param":"x","equals":1},"severity":"hard"}]}', /needs a message/);
    bad('{"rules":[{"id":"a","severity":"hard","message":"m"}]}', /needs a "when" condition/);
    // A condition shape this evaluator would never match reads like a guard
    // while guarding nothing.
    bad('{"rules":[{"id":"a","when":{"nope":1},"severity":"hard","message":"m"}]}', /needs exactly one of param/);
    bad('{"rules":[{"id":"a","when":{"param":"x"},"severity":"hard","message":"m"}]}', /exactly one of equals/);
    bad('{"rules":[{"id":"a","when":{"param":"x","equals":1,"matches":"y"},"severity":"hard","message":"m"}]}', /exactly one of equals/);
    bad('{"rules":[{"id":"a","when":{"param":"x","matches":"(["},"severity":"hard","message":"m"}]}', /does not compile/);
    bad('{"rules":[{"id":"a","when":{"all":[]},"severity":"hard","message":"m"}]}', /non-empty array/);
    bad('{"rules":[{"id":"a","when":{"environment":"prod"},"severity":"hard","message":"m"}]}', /environment must be/);
    // Review 2404: each of these used to LOAD, producing a rule that reads
    // like a guard and never fires the way it is written.
    bad('{"rules":[{"id":"a","when":{"param":"x","present":"false"},"severity":"hard","message":"m"}]}', /"present" needs true or false/);
    bad('{"rules":[{"id":"a","when":{"param":"x","matches":123},"severity":"hard","message":"m"}]}', /"matches" needs a pattern string/);
    bad('{"rules":[{"id":"a","when":{"all":[{"param":"x","equals":1}],"any":[{"param":"y","equals":2}]},"severity":"hard","message":"m"}]}', /exactly one of all \/ any \/ not/);
    bad('{"rules":[{"id":"a","when":{"all":[{"param":"x","equals":1}],"param":"y"},"severity":"hard","message":"m"}]}', /cannot be combined with/);
    bad('{"rules":[{"id":"a","when":{"param":"x","equals":1,"unless":"y"},"severity":"hard","message":"m"}]}', /unknown key\(s\)/);
    bad('{"rules":[{"id":"a","when":{"surface":"mcp","param":"x"},"severity":"hard","message":"m"}]}', /exactly one of param/);
    bad('{"rules":[{"id":"a","when":{"all":["nope"]},"severity":"hard","message":"m"}]}', /must be an object/);
    bad('{"rules":[{"id":"a","when":{"param":"x","atLeast":"3"},"severity":"hard","message":"m"}]}', /atLeast\/atMost need a number/);
    // Review 2409: `equals` is compared through String(), so a non-scalar is
    // silently a different rule — `[]` becomes "" and matches every empty
    // argument.
    bad('{"rules":[{"id":"a","when":{"param":"x","equals":null},"severity":"hard","message":"m"}]}', /"equals" needs a string, a boolean or a finite number/);
    bad('{"rules":[{"id":"a","when":{"param":"x","equals":{}},"severity":"hard","message":"m"}]}', /"equals" needs a string/);
    bad('{"rules":[{"id":"a","when":{"param":"x","equals":[]},"severity":"hard","message":"m"}]}', /"equals" needs a string/);
    // Review 2409: a typo'd key used to load and widen the rule to all tasks.
    bad('{"rules":[{"id":"a","taks":"nginx.*","when":{"param":"x","equals":1},"severity":"hard","message":"m"}]}', /unknown key\(s\) taks/);
    bad('{"rules":["nope"]}', /must be an object/);
    // A non-string task silently widened the rule from one task to all of them.
    bad('{"rules":[{"id":"a","task":7,"when":{"param":"x","equals":1},"severity":"hard","message":"m"}]}', /"task" must be a task id/);
  });
});

describe('parameter guards decide per invocation, and only tighten (#66)', () => {
  const resolver = (...servers: ServerDefinition[]): ServerResolver => {
    const map = new Map(servers.map((s) => [s.id, s]));
    return { get: (id) => map.get(id), list: () => [...map.values()] };
  };
  const ce: ExecuteContext = { surface: 'platform', controlPlaneAvailable: true };
  const base = { serverId: 'web-dev-01', actionId: 'file.find', reason: 'test run' };

  const service = (rules: ParamGuardSet['rules']) => {
    const executor = new FakeExecutor();
    return {
      executor,
      svc: new OpsService({
        registry: makeRegistry(
          makeAction({
            id: 'file.find',
            riskLevel: 'low',
            readonly: true,
            serverScopes: ['*'],
            params: { type: 'object', properties: { path: { type: 'string' } }, required: [], additionalProperties: false },
            script: 'find "$XOPS_path"\n',
          }),
        ),
        servers: resolver(makeServer()),
        executors: [executor],
        audit: new MemoryAuditLogger(),
        paramGuards: new ParamGuardSet(rules),
      }),
    };
  };

  it('a hard guard refuses THESE arguments while the same task runs with others', async () => {
    const { svc, executor } = service([
      { id: 'no-root', when: { param: 'path', equals: '/' }, severity: 'hard', message: '不得对整盘操作' },
    ]);
    const refused = await svc.execute({ ...base, args: { path: '/' } }, ce);
    expect(refused).toMatchObject({ status: 'denied', rule: 'param-guard' });
    if (refused.status === 'denied') expect(refused.reason).toContain('不得对整盘操作');
    expect(executor.commands).toEqual([]);
    // The task itself is fine — it is these arguments that were refused.
    expect((await svc.execute({ ...base, args: { path: '/opt' } }, ce)).status).toBe('executed');
  });

  it('a soft guard raises a low-risk task to the asking threshold, and says why', async () => {
    const { svc, executor } = service([
      { id: 'home', when: { param: 'path', matches: '^/home' }, severity: 'soft', message: '用户目录' },
    ]);
    const asked = await svc.execute({ ...base, args: { path: '/home/ada' } }, ce);
    expect(asked).toMatchObject({ status: 'requires_approval', rule: 'risk-level' });
    if (asked.status === 'requires_approval') expect(asked.reason).toContain('用户目录');
    expect(executor.commands).toEqual([]);
  });

  it('guards never loosen: with no rules, and with rules that do not fire, the ordinary verdict stands', async () => {
    expect((await service([]).svc.execute({ ...base, args: { path: '/opt' } }, ce)).status).toBe('executed');
    const { svc } = service([{ id: 'x', when: { param: 'path', equals: '/' }, severity: 'hard', message: 'no' }]);
    expect((await svc.execute({ ...base, args: { path: '/opt' } }, ce)).status).toBe('executed');
  });
});
