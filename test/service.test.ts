import { describe, expect, it } from 'vitest';
import { OpsService, executionHashOf, type ExecuteContext } from '../src/service.js';
import { MemoryAuditLogger } from '../src/audit.js';
import { redactOutput, trimIncompleteUtf8 } from '../src/redact.js';
import type { ServerDefinition } from '../src/types.js';
import type { ServerResolver } from '../src/servers.js';
import { FakeExecutor, makeAction, makeRegistry, makeServer } from './helpers.js';

function resolver(...servers: ServerDefinition[]): ServerResolver {
  const map = new Map(servers.map((s) => [s.id, s]));
  return { get: (id) => map.get(id), list: () => [...map.values()] };
}

function makeService(opts: { executor?: FakeExecutor } = {}) {
  const executor = opts.executor ?? new FakeExecutor();
  const audit = new MemoryAuditLogger();
  const registry = makeRegistry(
    makeAction(),
    makeAction({
      id: 'nginx.reload',
      riskLevel: 'medium',
      readonly: false,
      serverScopes: ['web-*'],
      script: 'nginx -t\nsystemctl reload nginx\n',
    }),
    makeAction({ id: 'db.drop', riskLevel: 'critical', readonly: false, script: 'dropdb x' }),
    makeAction({ id: 'secret.read', riskLevel: 'high', readonly: true, serverScopes: ['*'], script: 'cat /etc/secret' }),
    makeAction({ id: 'svc.tune', riskLevel: 'medium', readonly: false, serverScopes: ['*'], script: 'tune\n' }),
  );
  const service = new OpsService({
    registry,
    servers: resolver(makeServer(), makeServer({ id: 'web-prod-01', environment: 'production' })),
    executors: [executor],
    audit,
  });
  return { service, audit, executor };
}

const ce: ExecuteContext = { surface: 'platform', controlPlaneAvailable: true };
const base = { serverId: 'web-dev-01', args: {}, reason: 'test run' };

describe('OpsService', () => {
  it('executes an allowed task end to end as one remote command', async () => {
    const { service, executor, audit } = makeService();
    const response = await service.execute({ ...base, actionId: 'nginx.reload' }, ce);
    expect(response.status).toBe('executed');
    // One connection, one exit status. What used to be three remote commands
    // is now the operator's script, sequenced where they can read it.
    expect(executor.commands).toEqual(['bash -s']);
    expect(executor.invocations[0]?.stdin).toBe('nginx -t\nsystemctl reload nginx\n');
    expect(audit.entries.map((e) => e.event)).toEqual(['decision', 'execution']);
  });

  it('supports dry-run without touching the executor', async () => {
    const { service, executor } = makeService();
    const response = await service.execute({ ...base, actionId: 'nginx.reload', dryRun: true }, ce);
    // The preview names the exact script by digest and shows which parameters
    // would be set. It does not hand back the script body: that is operator
    // configuration, and a dry run is also an audit record.
    expect(response).toMatchObject({ status: 'dry_run', command: 'bash -s' });
    if (response.status === 'dry_run') expect(response.scriptDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(executor.commands).toEqual([]);
  });

  it('denies unknown actions, unknown servers, and bad args with audit records', async () => {
    const { service, audit } = makeService();
    expect((await service.execute({ ...base, actionId: 'nope.nope' }, ce)).status).toBe('denied');
    expect((await service.execute({ ...base, actionId: 'system.uptime', serverId: 'ghost' }, ce)).status).toBe('denied');
    expect((await service.execute({ ...base, actionId: 'system.uptime', args: { extra: 1 } }, ce)).status).toBe('denied');
    expect(audit.entries).toHaveLength(3);
    expect(audit.entries.every((e) => e.decision === 'deny')).toBe(true);
  });

  it('human_review is fail-closed: requires_approval, nothing executed', async () => {
    const { service, executor, audit } = makeService();
    const response = await service.execute({ ...base, actionId: 'db.drop' }, ce);
    expect(response).toMatchObject({ status: 'requires_approval', rule: 'risk-level' });
    expect(executor.commands).toEqual([]);
    expect(audit.entries.map((e) => e.event)).toEqual(['decision']);
  });

  it('fail-safe denies non-readonly actions when the control plane is down', async () => {
    const { service } = makeService();
    const response = await service.execute({ ...base, actionId: 'nginx.reload' }, { surface: 'platform', controlPlaneAvailable: false });
    expect(response).toMatchObject({ status: 'denied', rule: 'fail-safe-control-plane' });
  });

  it('reports command_failed (not executed) when the main command exits non-zero', async () => {
    const { service } = makeService({ executor: new FakeExecutor(1) });
    const response = await service.execute({ ...base, actionId: 'system.uptime' }, ce);
    expect(response.status).toBe('command_failed');
    if (response.status === 'command_failed') expect(response.result.exitCode).toBe(1);
  });

  it('hands the executor the script on stdin and the parameters beside it', async () => {
    const executor = new FakeExecutor();
    const registry = makeRegistry(
      makeAction({
        id: 'svc.tune',
        riskLevel: 'medium',
        readonly: false,
        serverScopes: ['*'],
        params: { type: 'object', properties: { level: { type: 'string' } }, required: ['level'], additionalProperties: false },
        script: 'tune "$XOPS_level"\n',
      }),
    );
    const audit = new MemoryAuditLogger();
    const service = new OpsService({ registry, servers: resolver(makeServer()), executors: [executor], audit });
    const response = await service.execute({ ...base, actionId: 'svc.tune', args: { level: 'aggressive' } }, ce);

    expect(response.status).toBe('executed');
    // The operator's script goes to the interpreter as INPUT...
    expect(executor.invocations[0]?.stdin).toBe('tune "$XOPS_level"\n');
    // ...and the caller's value goes beside it, as an environment value. The
    // command itself is fixed text, so no parameter can add a word to it.
    expect(executor.invocations[0]?.command).toBe("XOPS_level='aggressive' bash -s");

    // And the durable record names which parameter was supplied, never what it
    // was. (Asserted on the recorded command, not the whole entry: the fake
    // executor echoes its input into stdout, which a real target does not.)
    const recorded = audit.entries[1]?.results as { result: { command: string } };
    expect(recorded.result.command).toBe("XOPS_level='***' bash -s");
  });

  it('fails human_review closed even with dryRun — no command rendered, nothing run (xtrape)', async () => {
    const { service, executor } = makeService();
    const response = await service.execute({ ...base, actionId: 'db.drop', dryRun: true }, ce);
    expect(response).toMatchObject({ status: 'requires_approval', rule: 'risk-level' });
    expect(response).not.toHaveProperty('command');
    expect(executor.commands).toEqual([]);
  });

  it('fails a readonly human_review action closed over MCP even with dryRun', async () => {
    const { service, executor } = makeService();
    const response = await service.execute({ ...base, actionId: 'secret.read', dryRun: true }, { surface: 'mcp', controlPlaneAvailable: true });
    expect(response).toMatchObject({ status: 'requires_approval', rule: 'risk-level' });
    expect(executor.commands).toEqual([]);
  });

  it('rejects a blank reason before the executor with a validation deny', async () => {
    const { service, executor } = makeService();
    const response = await service.execute({ ...base, actionId: 'system.uptime', reason: '   ' }, ce);
    expect(response).toMatchObject({ status: 'denied', rule: 'missing-reason' });
    expect(executor.commands).toEqual([]);
  });

  it('sanitizes the stored private key content out of executor error messages and audit', async () => {
    const key = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsecretkeybody\n-----END OPENSSH PRIVATE KEY-----\n';
    const throwing = {
      name: 'ssh',
      async run() {
        throw new Error(`ssh: cannot parse key ${key} (bad format)`);
      },
    };
    const registry = makeRegistry(makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime' }));
    const audit = new MemoryAuditLogger();
    const service = new OpsService({ registry, servers: resolver(makeServer({ authMethod: 'privateKey', privateKey: key })), executors: [throwing], audit });
    const response = await service.execute({ ...base, actionId: 'system.uptime' }, ce);
    expect(response.status).toBe('error');
    if (response.status === 'error') {
      expect(response.message).not.toContain('AAAAsecretkeybody');
      expect(response.message).toContain('[redacted-secret]');
    }
    expect(JSON.stringify(audit.entries)).not.toContain('AAAAsecretkeybody');
  });

  describe('MCP surface: one notch of extra risk, plus a stricter evidence grade (#53 P1.5, #61)', () => {
    it('raises the effective risk one notch over MCP — fail-closed without a channel', async () => {
      const { service, executor } = makeService();
      const response = await service.execute({ ...base, actionId: 'nginx.reload' }, { surface: 'mcp', controlPlaneAvailable: true });
      expect(response).toMatchObject({ status: 'requires_approval', rule: 'risk-level' });
      expect(executor.commands).toEqual([]);
    });

    it('a raised action over MCP RUNS once a person approves through the confirmation loop', async () => {
      const executor = new FakeExecutor();
      const audit = new MemoryAuditLogger();
      const registry = makeRegistry(makeAction({ id: 'nginx.reload', riskLevel: 'medium', readonly: false, serverScopes: ['*'], script: 'systemctl reload nginx' }));
      const asked: string[] = [];
      const channel = {
        // MCP-level evidence: the grant ECHOES the digest of the object it
        // approves (review 2328) — a grant without the echo is no grant.
        ask: (q: { taskId: string; executionHash: string }) => {
          asked.push(q.taskId);
          // The anchor is the EXECUTION (#66): it binds the arguments too,
          // so an echo of it proves which run was approved.
          return Promise.resolve({ granted: true, answeredBy: 'operator:ada', approvedDigest: q.executionHash });
        },
      };
      const service = new OpsService({ registry, servers: resolver(makeServer({ authMethod: 'password', password: 'pw' })), executors: [executor], audit, confirmation: channel as never });
      const response = await service.execute({ ...base, actionId: 'nginx.reload' }, { surface: 'mcp', controlPlaneAvailable: true });
      expect(asked).toEqual(['nginx.reload']); // a human WAS asked
      expect(response.status).toBe('executed');
      expect(executor.commands.length).toBe(1);
    });

    it('a grant WITHOUT the execution echo is no grant — MCP evidence binds to bytes AND arguments (reviews 2328, #66)', async () => {
      const executor = new FakeExecutor();
      const registry = makeRegistry(makeAction({ id: 'nginx.reload', riskLevel: 'medium', readonly: false, serverScopes: ['*'], script: 'systemctl reload nginx' }));
      const bare = { ask: () => Promise.resolve({ granted: true, answeredBy: 'operator:ada' }) };
      const service = new OpsService({ registry, servers: resolver(makeServer({ authMethod: 'password', password: 'pw' })), executors: [executor], audit: new MemoryAuditLogger(), confirmation: bare as never });
      const response = await service.execute({ ...base, actionId: 'nginx.reload' }, { surface: 'mcp', controlPlaneAvailable: true });
      expect(response).toMatchObject({ status: 'confirmation_refused', rule: 'risk-level' });
      if (response.status === 'confirmation_refused') expect(response.reason).toContain('did not echo the execution anchor');
      expect(executor.commands).toEqual([]);
      // A wrong-version echo refuses the same way.
      const stale = { ask: () => Promise.resolve({ granted: true, approvedDigest: 'sha256:' + '0'.repeat(64) }) };
      const service2 = new OpsService({ registry: makeRegistry(makeAction({ id: 'nginx.reload', riskLevel: 'medium', readonly: false, serverScopes: ['*'], script: 'systemctl reload nginx' })), servers: resolver(makeServer({ authMethod: 'password', password: 'pw' })), executors: [executor], audit: new MemoryAuditLogger(), confirmation: stale as never });
      const response2 = await service2.execute({ ...base, actionId: 'nginx.reload' }, { surface: 'mcp', controlPlaneAvailable: true });
      expect(response2).toMatchObject({ status: 'confirmation_refused', rule: 'risk-level' });
      expect(executor.commands).toEqual([]);
    });

    it('the echo requirement is a property of the SURFACE, not one rule: a risk-level grant over MCP needs the digest too (review 2330)', async () => {
      const executor = new FakeExecutor();
      // secret.read is READ-ONLY but high-risk: over MCP it reaches
      // human_review through the ordinary risk-level rule, never through
      // the ordinary risk rule — yet the grant authorizes execution on the MCP
      // surface, so it carries the same evidence obligation.
      const mk = (ask: (q: { scriptDigest: string; executionHash: string }) => Promise<unknown>) => new OpsService({
        registry: makeRegistry(makeAction({ id: 'secret.read', riskLevel: 'high', readonly: true, serverScopes: ['*'], script: 'cat /etc/secret' })),
        servers: resolver(makeServer({ authMethod: 'password', password: 'pw' })),
        executors: [executor],
        audit: new MemoryAuditLogger(),
        confirmation: { ask } as never,
      });
      const grantNoEcho = () => Promise.resolve({ granted: true, answeredBy: 'operator:ada' });
      const noEcho = await mk(grantNoEcho).execute({ ...base, actionId: 'secret.read' }, { surface: 'mcp', controlPlaneAvailable: true });
      expect(noEcho).toMatchObject({ status: 'confirmation_refused', rule: 'risk-level' });
      expect(executor.commands).toEqual([]);
      const withEcho = await mk((q) => Promise.resolve({ granted: true, answeredBy: 'operator:ada', approvedDigest: (q as unknown as { executionHash: string }).executionHash }))
        .execute({ ...base, actionId: 'secret.read' }, { surface: 'mcp', controlPlaneAvailable: true });
      expect(withEcho.status).toBe('executed');
      // The same risk-level grant on the PLATFORM surface keeps its shape:
      // no echo demanded there.
      const platform = await mk(grantNoEcho).execute({ ...base, actionId: 'secret.read' }, ce);
      expect(platform.status).toBe('executed');
    });

    it('an echo-refused grant leaves ONE answer record carrying the effective verdict (review 2330)', async () => {
      const executor = new FakeExecutor();
      const audit = new MemoryAuditLogger();
      const registry = makeRegistry(makeAction({ id: 'nginx.reload', riskLevel: 'medium', readonly: false, serverScopes: ['*'], script: 'systemctl reload nginx' }));
      const bare = { ask: () => Promise.resolve({ granted: true, answeredBy: 'operator:ada' }) };
      const service = new OpsService({ registry, servers: resolver(makeServer({ authMethod: 'password', password: 'pw' })), executors: [executor], audit, confirmation: bare as never });
      await service.execute({ ...base, actionId: 'nginx.reload' }, { surface: 'mcp', controlPlaneAvailable: true });
      const answers = audit.entries.filter((e) => e.event === 'approval_answered');
      expect(answers).toHaveLength(1);
      expect(answers[0]).toMatchObject({ granted: false });
      expect(answers[0]?.error).toContain('execution anchor');
    });

    it('a dry run over MCP resolves to requires_approval without paging anyone', async () => {
      const { service, executor } = makeService();
      const response = await service.execute({ ...base, actionId: 'nginx.reload', dryRun: true }, { surface: 'mcp', controlPlaneAvailable: true });
      expect(response).toMatchObject({ status: 'requires_approval', rule: 'risk-level' });
      expect(executor.commands).toEqual([]);
    });

    it('allows a read-only action over MCP', async () => {
      const { service } = makeService();
      const response = await service.execute({ ...base, actionId: 'system.uptime' }, { surface: 'mcp', controlPlaneAvailable: true });
      expect(response.status).toBe('executed');
    });

    it('listActions(mcp) lists mutating actions too — executable behind approval, not hidden', async () => {
      const { service } = makeService();
      const ids = service.listActions('mcp').map((a) => a.id);
      expect(ids).toContain('system.uptime');
      expect(ids).toContain('nginx.reload');
      expect(ids).toContain('db.drop');
    });
  });
});

describe('the recording ceiling is a deployment setting, and never lowers what an author asked for (#61 B)', () => {
  /** Captures the ceiling the service hands the executor. */
  class CeilingSpy extends FakeExecutor {
    seen: number | undefined;
    override run(server: ServerDefinition, invocation: { command: string; stdin?: string; maxOutputBytes?: number }) {
      this.seen = invocation.maxOutputBytes;
      return super.run(server, invocation);
    }
  }
  const service = (opts: { deployment?: number; taskMax?: number }) => {
    const executor = new CeilingSpy();
    const action = makeAction({
      id: 'svc.tune', riskLevel: 'low', readonly: false, serverScopes: ['*'], script: 'tune\n',
      ...(opts.taskMax !== undefined ? { outputPolicy: { maxBytes: opts.taskMax } } : {}),
    });
    return {
      executor,
      svc: new OpsService({
        registry: makeRegistry(action),
        servers: resolver(makeServer()),
        executors: [executor],
        audit: new MemoryAuditLogger(),
        ...(opts.deployment !== undefined ? { maxRecordedOutputBytes: opts.deployment } : {}),
      }),
    };
  };

  it('uses the deployment ceiling by default, and the task keeps a SMALLER one it declared', async () => {
    // No deployment setting: the historical default applies.
    const plain = service({});
    await plain.svc.execute({ ...base, actionId: 'svc.tune' }, ce);
    expect(plain.executor.seen).toBe(65_536);
    // The deployment decides how much it can afford to record.
    const deployed = service({ deployment: 4096 });
    await deployed.svc.execute({ ...base, actionId: 'svc.tune' }, ce);
    expect(deployed.executor.seen).toBe(4096);
    // A stored task asking for LESS still gets less — an upgrade never
    // records more output than its author allowed.
    const stricter = service({ deployment: 65_536, taskMax: 1024 });
    await stricter.svc.execute({ ...base, actionId: 'svc.tune' }, ce);
    expect(stricter.executor.seen).toBe(1024);
    // A stored task asking for MORE does not raise the deployment's ceiling.
    const capped = service({ deployment: 2048, taskMax: 1_000_000 });
    await capped.svc.execute({ ...base, actionId: 'svc.tune' }, ce);
    expect(capped.executor.seen).toBe(2048);
  });
});

describe('executionHashOf', () => {
  const DIGEST_A = 'sha256:aaaa';
  const DIGEST_B = 'sha256:bbbb';

  it('binds serverId + task + version + script + args, independent of arg key order', () => {
    const a = executionHashOf('s1', 'a.b', '1.0.0', DIGEST_A, { x: 1, y: 2 });
    expect(executionHashOf('s1', 'a.b', '1.0.0', DIGEST_A, { y: 2, x: 1 })).toBe(a);
    expect(executionHashOf('s2', 'a.b', '1.0.0', DIGEST_A, { x: 1, y: 2 })).not.toBe(a);
    expect(executionHashOf('s1', 'a.b', '1.0.0', DIGEST_A, { x: 9 })).not.toBe(a);
  });

  it('distinguishes two scripts sharing a task id, version and arguments', () => {
    // A task id and version name a FILE, whose contents an operator can edit
    // in place. Without the script in the hash, evidence for two runs of the
    // same task with the same arguments is identical even when the script was
    // replaced between them — and an approval bound to that hash would carry
    // over to a script nobody approved (review 2165).
    expect(executionHashOf('s1', 'a.b', '1.0.0', DIGEST_A, { x: 1 })).not.toBe(
      executionHashOf('s1', 'a.b', '1.0.0', DIGEST_B, { x: 1 }),
    );
  });
});

describe('redactOutput', () => {
  it('masks secret-looking values and truncates', () => {
    const output = 'password=hunter2 token: abc123 ok=1';
    const redacted = redactOutput(output);
    expect(redacted).toContain('password=***');
    expect(redacted).toContain('token: ***');
    expect(redacted).toContain('ok=1');
    // Redaction no longer truncates (#61 B / review 2382): the recording
    // ceiling is enforced ONCE, at the wire. A second, independently
    // defaulted cut here silently capped a deployment that asked to record
    // more than 64 KiB.
    expect(redactOutput('x'.repeat(100), { maxBytes: 10 })).toBe('x'.repeat(100));
  });

  it('trimIncompleteUtf8 drops only a TRAILING incomplete sequence (reviews 2382/2383)', () => {
    const whole = Buffer.from('世界', 'utf8'); // 6 bytes, two 3-byte characters
    // Whole input is untouched, whatever its content.
    expect(trimIncompleteUtf8(whole).equals(whole)).toBe(true);
    expect(trimIncompleteUtf8(Buffer.from('abc')).toString()).toBe('abc');
    expect(trimIncompleteUtf8(Buffer.alloc(0)).byteLength).toBe(0);
    // A cut mid-character keeps the characters that ARE whole and drops the
    // partial tail — no U+FFFD, and the byte count matches the text.
    for (const cut of [4, 5]) {
      const trimmed = trimIncompleteUtf8(whole.subarray(0, cut));
      expect(trimmed.toString('utf8')).toBe('世');
      expect(trimmed.byteLength).toBe(3);
      expect(trimmed.toString('utf8')).not.toContain('\uFFFD');
    }
    // Nothing whole at all yields nothing, rather than a replacement char.
    expect(trimIncompleteUtf8(whole.subarray(0, 2)).byteLength).toBe(0);
    expect(trimIncompleteUtf8(whole.subarray(1, 3)).byteLength).toBe(0); // continuation bytes only
    // A 4-byte character (emoji) is handled by the same rule.
    const emoji = Buffer.from('a😀', 'utf8'); // 1 + 4
    expect(trimIncompleteUtf8(emoji.subarray(0, 3)).toString('utf8')).toBe('a');
    expect(trimIncompleteUtf8(emoji).equals(emoji)).toBe(true);
  });
});
