import { describe, expect, it } from 'vitest';
import { OpsService } from '../src/service.js';
import { MemoryAuditLogger } from '../src/audit.js';
import { describeRequest, type ConfirmationChannel, type ConfirmationRequest } from '../src/confirmation.js';
import { FakeExecutor, makeAction, makeRegistry, makeServer } from './helpers.js';
import type { ServerResolver } from '../src/servers.js';

/** A task that policy holds for a human: `critical` risk is one of the rules. */
const dangerous = makeAction({
  id: 'db.drop',
  readonly: false,
  riskLevel: 'critical',
  serverScopes: ['*'],
  script: 'dropdb x\n',
});

function makeService(channel?: ConfirmationChannel) {
  const executor = new FakeExecutor();
  const server = makeServer();
  const servers: ServerResolver = { get: (id) => (id === server.id ? server : undefined), list: () => [server] };
  const audit = new MemoryAuditLogger();
  const service = new OpsService({
    registry: makeRegistry(dangerous),
    servers,
    executors: [executor],
    audit,
    ...(channel ? { confirmation: channel } : {}),
  });
  return { service, executor, audit, server };
}

const request = { serverId: 'web-dev-01', actionId: 'db.drop', args: {}, reason: 'retiring the staging database' };
const ctx = { surface: 'platform' as const, controlPlaneAvailable: true };

describe('asking a person, from inside a running command', () => {
  it('stops the task and asks nobody when no way to ask is configured', async () => {
    // The state until the Platform offers a way to reach the person behind a
    // command: fail closed, and say so rather than implying someone declined.
    const { service, executor } = makeService();
    const response = await service.execute(request, ctx);
    expect(response).toMatchObject({ status: 'requires_approval', rule: 'risk-level' });
    expect(executor.commands).toEqual([]);
  });

  it('runs the task once a person allows it', async () => {
    let asked: ConfirmationRequest | undefined;
    const { service, executor } = makeService({
      ask: (r) => {
        asked = r;
        return Promise.resolve({ granted: true, answeredBy: 'operator:ada' });
      },
    });
    const response = await service.execute(request, ctx);
    expect(response.status).toBe('executed');
    expect(executor.commands).toHaveLength(1);

    // The question carries WHAT is approved — server, task, version, script
    // digest and arguments — so an answer cannot be carried to different
    // content, and editing the script invalidates it. Which run is asking is
    // the conversation key, asserted separately.
    expect(asked?.executionHash).toMatch(/^[0-9a-f]{64}$/);
    expect(asked?.scriptDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(asked?.rule).toBe('risk-level');
    expect(asked?.reason).toBe('retiring the staging database');
  });

  it('does not run the task when a person declines, and names who decided', async () => {
    const { service, executor } = makeService({
      ask: () => Promise.resolve({ granted: false, answeredBy: 'operator:ada' }),
    });
    const response = await service.execute(request, ctx);
    expect(response).toMatchObject({ status: 'confirmation_refused', answeredBy: 'operator:ada' });
    // Distinct from a policy denial: policy allowed the question to be put.
    expect(response.status).not.toBe('denied');
    expect(executor.commands).toEqual([]);
  });

  it('never pages anyone for a dry run', async () => {
    let asked = 0;
    const { service } = makeService({
      ask: () => {
        asked += 1;
        return Promise.resolve({ granted: true });
      },
    });
    const response = await service.execute({ ...request, dryRun: true }, ctx);
    expect(response).toMatchObject({ status: 'requires_approval' });
    expect(asked).toBe(0);
  });

  it('records that a question was put and how it was answered', async () => {
    const { service, audit } = makeService({
      ask: () => Promise.resolve({ granted: true, answeredBy: 'operator:ada', supplementaryInformation: 'window is 02:00 UTC' }),
    });
    await service.execute(request, ctx);

    const events = audit.entries.map((e) => e.event);
    expect(events).toContain('approval_requested');
    expect(events).toContain('approval_answered');

    const answered = audit.entries.find((e) => e.event === 'approval_answered');
    expect(answered).toMatchObject({ granted: true, answeredBy: 'operator:ada', supplementaryInformationSupplied: true });
    // Which, never what — the same rule arguments follow.
    expect(JSON.stringify(audit.entries)).not.toContain('02:00 UTC');
    // And every record still names the execution it belongs to.
    for (const e of audit.entries) expect(e.executionHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('carries the cancel signal into the wait', async () => {
    // A wait nobody answers ends when the Platform cancels the command; there
    // is no deadline of its own, because a person may take hours.
    const controller = new AbortController();
    const { service } = makeService({
      ask: (_r, signal) =>
        new Promise((resolve, reject) => {
          signal?.addEventListener('abort', () => reject(new Error('command cancelled')), { once: true });
        }),
    });
    setTimeout(() => controller.abort(), 20);
    const response = await service.execute(request, { ...ctx, signal: controller.signal });
    expect(response.status).toBe('error');
  });

  it('discloses what a person needs in order to own their answer', () => {
    const described = describeRequest({
      executionHash: 'a'.repeat(64),
      serverId: 'db-prod-01',
      taskId: 'db.drop',
      taskVersion: '1.0.0',
      scriptDigest: `sha256:${'b'.repeat(64)}`,
      riskLevel: 'critical',
      rule: 'risk-level',
      reason: 'retiring the staging database',
      question: 'Run db.drop on db-prod-01?',
      originActor: { type: 'agent', id: 'assistant-1' },
      interactionId: 'cmd_1',
    });
    // Which task, on which server, why it stopped, who asked. Disclosure is
    // the obligation; being understood is not.
    for (const fragment of ['db.drop@1.0.0', 'db-prod-01', 'agent assistant-1', 'retiring the staging database', 'risk-level', 'critical']) {
      expect(described).toContain(fragment);
    }
  });
});

describe('the ask() adapter (confirmation-ask.ts)', () => {
  const request: Parameters<ConfirmationChannel['ask']>[0] = {
    executionHash: 'e'.repeat(64),
    serverId: 'db-prod-01',
    taskId: 'db.drop',
    taskVersion: '1.0.0',
    scriptDigest: `sha256:${'b'.repeat(64)}`,
    riskLevel: 'critical',
    rule: 'risk-level',
    reason: 'retiring staging',
    question: 'Run db.drop on db-prod-01?',
    commandId: 'cmd_9',
    interactionId: 'cmd_9',
  };

  it('binds the conversation to the execution and carries full disclosure', async () => {
    const { askConfirmationChannel } = await import('../src/confirmation-ask.js');
    let sent: { conversationId: string; content: string; payload?: unknown } | undefined;
    const channel = askConfirmationChannel({
      ask: (opts) => {
        sent = opts;
        return Promise.resolve({ senderId: 'operator:ada', payload: { granted: true } });
      },
    });
    const outcome = await channel.ask(request);
    expect(outcome).toMatchObject({ granted: true, answeredBy: 'operator:ada' });
    // One conversation per EXECUTION, keyed by interactionId — not by the
    // content hash, which two distinct runs of the same task+args share.
    expect(sent?.conversationId).toBe('apr_cmd_9');
    // The hash still travels as WHAT is approved.
    expect(sent?.payload).toMatchObject({ executionHash: 'e'.repeat(64) });
    for (const fragment of ['db.drop@1.0.0', 'db-prod-01', 'retiring staging', 'risk-level']) {
      expect(sent?.content).toContain(fragment);
    }
    expect(sent?.payload).toMatchObject({ commandId: 'cmd_9', executionHash: 'e'.repeat(64) });
  });

  it('treats anything that is not an explicit grant as a refusal', async () => {
    const { askConfirmationChannel } = await import('../src/confirmation-ask.js');
    // Between "run something nobody clearly approved" and "make the person say
    // it again", the second is always the right failure.
    for (const payload of [{ granted: false }, {}, undefined, { granted: 'yes' }, 'yes', 42]) {
      const channel = askConfirmationChannel({ ask: () => Promise.resolve({ senderId: 'operator:ada', payload }) });
      expect((await channel.ask(request)).granted, JSON.stringify(payload)).toBe(false);
    }
  });

  it('carries supplementary information along, for the interaction and nothing else', async () => {
    const { askConfirmationChannel } = await import('../src/confirmation-ask.js');
    const channel = askConfirmationChannel({
      ask: () => Promise.resolve({ senderId: 'op', payload: { granted: true, supplementaryInformation: 'window 02:00 UTC' } }),
    });
    expect((await channel.ask(request)).supplementaryInformation).toBe('window 02:00 UTC');
  });

  it('activates only on an SDK that carries ask()', async () => {
    const { buildConfirmationChannel } = await import('../src/confirmation-ask.js');
    // The probe is about the OBJECT, not the era: anything without ask() —
    // an older SDK's connector, a stray handle — yields undefined and the
    // Widget keeps its fail-closed path; the pinned 0.8.1 SDK passes (the
    // installed-package test below pins that half).
    expect(buildConfirmationChannel({ register: () => {} })).toBeUndefined();
    expect(buildConfirmationChannel(undefined)).toBeUndefined();
    expect(buildConfirmationChannel({ ask: () => Promise.resolve({ senderId: 'x' }) })).toBeDefined();
  });
});

describe('confirmation identity is per execution, not per content (review 2172)', () => {
  it('gives two runs of the same task+args their own conversations', async () => {
    // The executionHash is content: server + task + version + script + args.
    // Two distinct commands — even from two different users — share it when
    // the content matches, so it cannot be the conversation or their two
    // questions land in one thread and either answer resolves both.
    // Asserted through the ADAPTER, on the conversation it actually opens —
    // asserting only that interactionId was passed along proves nothing about
    // where the question goes, which is the whole point.
    const { askConfirmationChannel } = await import('../src/confirmation-ask.js');
    const conversations: string[] = [];
    const channel = askConfirmationChannel({
      ask: (opts) => {
        conversations.push(opts.conversationId);
        return Promise.resolve({ senderId: 'operator:ada', payload: { granted: true } });
      },
    });
    const executor = new FakeExecutor();
    const server = makeServer();
    const servers: ServerResolver = { get: (id) => (id === server.id ? server : undefined), list: () => [server] };
    const service = new OpsService({
      registry: makeRegistry(dangerous),
      servers,
      executors: [executor],
      audit: new MemoryAuditLogger(),
      confirmation: channel,
    });
    await service.execute(request, { ...ctx, commandId: 'cmd_a' });
    await service.execute(request, { ...ctx, commandId: 'cmd_b' });
    // Same server, task, version, script and args — so the same executionHash.
    // Two commands must still get two conversations.
    expect(conversations).toEqual(['apr_cmd_a', 'apr_cmd_b']);
  });

  it('still identifies a run that arrived without a commandId', async () => {
    const { askConfirmationChannel } = await import('../src/confirmation-ask.js');
    const conversations: string[] = [];
    const channel = askConfirmationChannel({
      ask: (opts) => {
        conversations.push(opts.conversationId);
        return Promise.resolve({ senderId: 'operator:ada', payload: { granted: true } });
      },
    });
    const executor = new FakeExecutor();
    const server = makeServer();
    const servers: ServerResolver = { get: (id) => (id === server.id ? server : undefined), list: () => [server] };
    const service = new OpsService({
      registry: makeRegistry(dangerous),
      servers,
      executors: [executor],
      audit: new MemoryAuditLogger(),
      confirmation: channel,
    });
    await service.execute(request, ctx);
    await service.execute(request, ctx);
    expect(conversations).toHaveLength(2);
    expect(conversations[0]).not.toBe(conversations[1]); // a fresh nonce each time
    for (const id of conversations) expect(id).toMatch(/^apr_int_/);
  });
});

describe('what this repository actually ships (reviews 2182, then the 0.8.1 bump)', () => {
  it('has a channel, because the pinned SDK carries ask()', async () => {
    // The deliberate expectation flip review 2182 demanded: the lockfile now
    // pins @xtrape/connector 0.8.1, whose CeServiceConnector carries the
    // interaction primitive — so every build made here finds the method and
    // configures the confirmation channel. Still asserted against the
    // INSTALLED package, so a future downgrade or rename has to come back
    // through this expectation. (Reaching a person end to end additionally
    // needs the Platform-side grant and routing — xtrape-docs#241 — which no
    // assertion here can prove; this pins the Widget+SDK half.)
    const { buildConfirmationChannel } = await import('../src/confirmation-ask.js');
    const connector = (await import('@xtrape/connector')) as unknown as Record<string, { prototype?: object }>;
    const ctor = connector['CeServiceConnector'] ?? connector['CeServiceAgent'];
    const instance = Object.create(ctor?.prototype ?? {}) as object;
    expect(typeof (instance as Record<string, unknown>)['ask']).toBe('function');
    expect(buildConfirmationChannel(instance)).toBeDefined();
  });
});
