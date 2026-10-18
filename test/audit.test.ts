import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync, statSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileAuditLogger, MemoryAuditLogger, type AuditEntry } from '../src/audit.js';
import { OpsService } from '../src/service.js';
import type { ServerResolver } from '../src/servers.js';
import { makeAction, makeRegistry, makeServer } from './helpers.js';
import type { CommandInvocation, CommandResult, Executor, ServerDefinition } from '../src/types.js';

const dirs: string[] = [];
function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), 'linux-ops-widget-audit-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const entry = (overrides: Partial<AuditEntry> = {}): AuditEntry => ({
  timestamp: '2026-07-29T00:00:00.000Z',
  event: 'decision',
  request: {
    serverId: 'web-01',
    actionId: 'system.uptime',
    argsKeys: [],
    reason: 'routine check',
    dryRun: false,
    surface: 'platform',
  },
  ...overrides,
});

describe('FileAuditLogger', () => {
  it('creates the log directory and appends one JSON object per line', () => {
    const dir = join(tempDir(), 'nested', 'logs');
    const logger = new FileAuditLogger(dir);
    logger.write(entry());
    logger.write(entry({ event: 'execution', durationMs: 12 }));

    const file = join(dir, 'audit.jsonl');
    expect(existsSync(file)).toBe(true);
    const lines = readFileSync(file, 'utf8').trimEnd().split('\n');
    expect(lines).toHaveLength(2);
    expect(lines.map((l) => (JSON.parse(l) as AuditEntry).event)).toEqual(['decision', 'execution']);
    expect((JSON.parse(lines[1]!) as AuditEntry).durationMs).toBe(12);
  });

  it('is append-only across logger instances over the same directory', () => {
    const dir = tempDir();
    new FileAuditLogger(dir).write(entry());
    new FileAuditLogger(dir).write(entry({ event: 'error', error: 'boom' }));
    const lines = readFileSync(join(dir, 'audit.jsonl'), 'utf8').trimEnd().split('\n');
    expect(lines).toHaveLength(2); // the second instance appended, it did not truncate
    expect((JSON.parse(lines[0]!) as AuditEntry).event).toBe('decision');
  });

  it('creates the log file 0600 rather than inheriting the umask', () => {
    const dir = tempDir();
    const previous = process.umask(0o000); // the most permissive umask there is
    try {
      new FileAuditLogger(dir).write(entry());
    } finally {
      process.umask(previous);
    }
    expect(statSync(join(dir, 'audit.jsonl')).mode & 0o777).toBe(0o600);
  });

  it('tightens a pre-existing loose log file to 0600 on its first write', () => {
    const dir = tempDir();
    const file = join(dir, 'audit.jsonl');
    writeFileSync(file, '');
    chmodSync(file, 0o644);
    new FileAuditLogger(dir).write(entry());
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readFileSync(file, 'utf8').trimEnd().split('\n')).toHaveLength(1); // still an append
  });

  /**
   * Not just the final mode — the mode *while the record is being written*. A
   * logger that appends first and chmods afterwards leaves that record readable
   * to every local user for the duration of the append, and the record names
   * the target, the action, the operator reason, the provenance and the policy
   * decision. The probe observes the mode from inside `JSON.stringify`, i.e.
   * after the descriptor is opened and before the bytes land.
   */
  it('has already tightened the file by the time a record is serialized', () => {
    const dir = tempDir();
    const file = join(dir, 'audit.jsonl');
    writeFileSync(file, '');
    chmodSync(file, 0o644);

    let modeDuringWrite: number | undefined;
    new FileAuditLogger(dir).write(
      entry({
        results: {
          toJSON() {
            modeDuringWrite = statSync(file).mode & 0o777;
            return 'probe';
          },
        },
      }),
    );

    expect(modeDuringWrite).toBe(0o600); // not 0o644 — the append never rides the loose mode
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('re-tightens on every write, not once per logger instance', () => {
    const dir = tempDir();
    const file = join(dir, 'audit.jsonl');
    const logger = new FileAuditLogger(dir);

    logger.write(entry());
    expect(statSync(file).mode & 0o777).toBe(0o600);

    chmodSync(file, 0o644); // loosened after the first write — by an operator, a rotation tool, anything
    logger.write(entry({ event: 'execution' }));

    expect(statSync(file).mode & 0o777).toBe(0o600); // the same logger restored it
    expect(readFileSync(file, 'utf8').trimEnd().split('\n')).toHaveLength(2); // and still appended
  });
});

/**
 * Data minimization, end to end through the real service into the real durable
 * file: action parameters are a generic extension surface and may carry
 * credentials, so no argument VALUE may reach `audit.jsonl` — not in
 * `request`, and not inside the rendered command in the recorded results.
 */
describe('durable audit data minimization', () => {
  const SECRET = 'sup3r-s3cret-token-value';

  /**
   * Returns fixed output instead of echoing the command, so this test isolates
   * the audit projection: whether a target's own stdout repeats an argument is
   * the output-redaction policy's business, not the minimization rule's.
   */
  class QuietExecutor implements Executor {
    readonly name = 'ssh';
    async run(_server: ServerDefinition, invocation: CommandInvocation): Promise<CommandResult> {
      return { command: invocation.command, exitCode: 0, stdout: 'deployed\n', stderr: '' };
    }
  }

  function runOnce(dir: string) {
    const action = makeAction({
      id: 'app.deploy',
      readonly: false,
      riskLevel: 'medium',
      serverScopes: ['*'],
      params: {
        type: 'object',
        properties: { release: { type: 'string' }, apiToken: { type: 'string' } },
        required: ['release', 'apiToken'],
        additionalProperties: false,
      },
      script: 'deploy --release "$XOPS_release" --token "$XOPS_apiToken"\n',
    });
    const server = makeServer();
    const servers: ServerResolver = { get: (id) => (id === server.id ? server : undefined), list: () => [server] };
    const service = new OpsService({
      registry: makeRegistry(action),
      servers,
      executors: [new QuietExecutor()],
      audit: new FileAuditLogger(dir),
    });
    return service.execute(
      { serverId: server.id, actionId: 'app.deploy', args: { release: 'v9', apiToken: SECRET }, reason: 'ship it' },
      { surface: 'platform', controlPlaneAvailable: true },
    );
  }

  it('records the digest and the argument names, never the values', async () => {
    const dir = tempDir();
    const response = await runOnce(dir);
    expect(response.status).toBe('executed');

    const raw = readFileSync(join(dir, 'audit.jsonl'), 'utf8');
    // The ANSWER is masked too, not only the durable record. Masking one and
    // not the other put the value CE hands to the Platform back on the wire
    // that this minimization exists to keep it off (review 2165).
    expect((response as { result: { command: string } }).result.command).not.toContain(SECRET);
    expect((response as { result: { command: string } }).result.command).toBe(`XOPS_apiToken='***' XOPS_release='***' bash -s`);
    expect(raw).not.toContain(SECRET);
    expect(raw).not.toContain('v9'); // an ordinary argument is minimized too — the rule is not a secret-name heuristic

    const entries = raw.trimEnd().split('\n').map((l) => JSON.parse(l) as AuditEntry);
    expect(entries.map((e) => e.event)).toEqual(['decision', 'execution']);
    for (const e of entries) {
      expect(e.request.argsKeys).toEqual(['apiToken', 'release']); // names, sorted
      expect(e.request).not.toHaveProperty('args');
      expect(e.request.serverId).toBe('web-dev-01');
      expect(e.request.actionId).toBe('app.deploy');
      expect(e.request.reason).toBe('ship it');
    }
    // What ran is still pinned: the digest binds server + task + version +
    // SCRIPT + exact args, and the script digest is recorded beside it.
    expect(entries[1]!.executionHash).toMatch(/^[0-9a-f]{64}$/);
    expect(entries[0]!.executionHash).toBe(entries[1]!.executionHash);
    for (const e of entries) expect(e.scriptDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    // The recorded command names which parameters were supplied, with every
    // value masked. Values cannot leak through it by construction — they were
    // never part of the command text in the first place.
    const results = entries[1]!.results as { result: { command: string } };
    expect(results.result.command).toBe(`XOPS_apiToken='***' XOPS_release='***' bash -s`);
  });

  it('holds the digest stable across runs with the same args', async () => {
    const a = tempDir();
    const b = tempDir();
    await runOnce(a);
    await runOnce(b);
    const hashOf = (dir: string) =>
      (JSON.parse(readFileSync(join(dir, 'audit.jsonl'), 'utf8').trimEnd().split('\n')[1]!) as AuditEntry).executionHash;
    expect(hashOf(a)).toBe(hashOf(b));
  });
});

describe('MemoryAuditLogger', () => {
  it('collects entries in write order', () => {
    const logger = new MemoryAuditLogger();
    logger.write(entry());
    logger.write(entry({ event: 'execution' }));
    expect(logger.entries.map((e) => e.event)).toEqual(['decision', 'execution']);
  });
});

describe('how far audit data minimization reaches', () => {
  /**
   * The bound is on the REQUEST and the COMMAND, and this pins where it stops.
   *
   * The test above uses an executor that prints a fixed string, so on its own
   * it shows only that the request and command fields are clean. A task's
   * stdout is the script's own output, and `redactOutput` is pattern-based —
   * it cannot know an arbitrary argument value. Claiming the whole record
   * never contains one would be claiming something no code here does.
   */
  it('records no argument value in the request or the command, and does not filter a script that prints one', async () => {
    const dir = tempDir();
    const echoing: Executor = {
      name: 'ssh',
      run: (_server, invocation) =>
        Promise.resolve({ command: invocation.command, exitCode: 0, stdout: 'released v9\n', stderr: '' }),
    };
    const action = makeAction({
      id: 'app.echo',
      readonly: false,
      riskLevel: 'medium',
      serverScopes: ['*'],
      params: { type: 'object', properties: { release: { type: 'string' } }, required: ['release'], additionalProperties: false },
      script: 'echo "released $XOPS_release"\n',
    });
    const server = makeServer();
    const servers: ServerResolver = { get: (id) => (id === server.id ? server : undefined), list: () => [server] };
    const service = new OpsService({
      registry: makeRegistry(action),
      servers,
      executors: [echoing],
      audit: new FileAuditLogger(dir),
    });
    await service.execute(
      { serverId: server.id, actionId: 'app.echo', args: { release: 'v9' }, reason: 'ship it' },
      { surface: 'platform', controlPlaneAvailable: true },
    );

    const entries = readFileSync(join(dir, 'audit.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { request: Record<string, unknown>; results?: { result?: { command: string; stdout: string } } });

    for (const entry of entries) {
      expect(entry.request).not.toHaveProperty('args');
      expect(JSON.stringify(entry.request)).not.toContain('v9');
      if (entry.results?.result) expect(entry.results.result.command).not.toContain('v9');
    }
    // And the part the minimization does NOT cover, asserted rather than
    // assumed: the script printed the value, so the value is in the evidence.
    // A task handling something sensitive keeps it out of its own output, or
    // declares `# redact:` for it.
    expect(entries.at(-1)?.results?.result?.stdout).toContain('v9');
  });
});

describe('every record can be attributed to its own execution (review 2166)', () => {
  it('carries the binding on the error path, so two concurrent calls are distinguishable', async () => {
    // The ambiguity this closes: same server, same task, same reason, same
    // parameter NAMES, same executor error — and argument VALUES are never
    // recorded. Without the binding the two error records differed only in
    // their timestamp, and `traceId` is optional, so neither could be tied to
    // the decision it belonged to.
    const dir = tempDir();
    const throwing: Executor = {
      name: 'ssh',
      run: () => Promise.reject(new Error('ssh: connection reset')),
    };
    const action = makeAction({
      id: 'app.deploy',
      readonly: false,
      riskLevel: 'medium',
      serverScopes: ['*'],
      params: { type: 'object', properties: { release: { type: 'string' } }, required: ['release'], additionalProperties: false },
      script: 'deploy "$XOPS_release"\n',
    });
    const server = makeServer();
    const servers: ServerResolver = { get: (id) => (id === server.id ? server : undefined), list: () => [server] };
    const service = new OpsService({
      registry: makeRegistry(action),
      servers,
      executors: [throwing],
      audit: new FileAuditLogger(dir),
    });

    const call = (release: string) =>
      service.execute(
        { serverId: server.id, actionId: 'app.deploy', args: { release }, reason: 'ship it' },
        { surface: 'platform', controlPlaneAvailable: true },
      );
    await Promise.all([call('v9'), call('v10')]);

    const entries = readFileSync(join(dir, 'audit.jsonl'), 'utf8')
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line) as AuditEntry);
    const errors = entries.filter((e) => e.event === 'error');
    const decisions = entries.filter((e) => e.event === 'decision');
    expect(errors).toHaveLength(2);

    // Each error names one execution, and the two are different executions.
    const errorHashes = errors.map((e) => e.executionHash);
    expect(new Set(errorHashes).size).toBe(2);
    for (const hash of errorHashes) expect(hash).toMatch(/^[0-9a-f]{64}$/);

    // And each one matches a decision record, which is what "attributable"
    // means: the pair belongs together.
    expect(new Set(decisions.map((e) => e.executionHash))).toEqual(new Set(errorHashes));

    // The task is named too, digest included, so an edited script is a
    // different record rather than the same one.
    for (const e of errors) {
      expect(e.actionVersion).toBe('1.0.0');
      expect(e.scriptDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
      // A reviewer sees the blast radius in the record, not by opening a task
      // file that may since have been edited.
      expect(e.riskLevel).toBe('medium');
    }
    // Still no argument values anywhere.
    expect(readFileSync(join(dir, 'audit.jsonl'), 'utf8')).not.toContain('v9');
  });

  it('names the task on a refusal that happens after the task is resolved', () => {
    // A deny before the arguments are validated has no execution hash yet, but
    // it does know WHICH task refused — including which script.
    const action = makeAction({ id: 'app.deploy', readonly: false, riskLevel: 'medium', serverScopes: ['*'], script: 'deploy\n' });
    const server = makeServer();
    const servers: ServerResolver = { get: (id) => (id === server.id ? server : undefined), list: () => [server] };
    const audit = new MemoryAuditLogger();
    const service = new OpsService({ registry: makeRegistry(action), servers, executors: [{ name: 'ssh', run: () => Promise.reject(new Error('never reached')) }], audit });

    return service
      .execute({ serverId: server.id, actionId: 'app.deploy', args: {}, reason: '   ' }, { surface: 'platform', controlPlaneAvailable: true })
      .then(() => {
        const entry = audit.entries[0]!;
        expect(entry.policyRule).toBe('missing-reason');
        expect(entry.actionVersion).toBe('1.0.0');
        expect(entry.scriptDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
      });
  });
});
