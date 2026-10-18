import { describe, expect, it } from 'vitest';
import { evaluate, tighten } from '../src/policy.js';
import type { OpsRequest } from '../src/types.js';
import { makeAction, makeServer } from './helpers.js';

const request = (overrides: Partial<OpsRequest> = {}): OpsRequest => ({
  serverId: 'web-dev-01',
  actionId: 'system.uptime',
  args: {},
  reason: 'routine check',
  ...overrides,
});

const online = { controlPlaneAvailable: true, surface: 'platform' } as const;
const offline = { controlPlaneAvailable: false, surface: 'platform' } as const;
const mcp = { controlPlaneAvailable: true, surface: 'mcp' } as const;

describe('policy engine', () => {
  it('hard-denies forbidden actions', () => {
    const result = evaluate(makeAction({ approvalPolicy: 'forbidden' }), makeServer(), request(), online);
    expect(result).toMatchObject({ decision: 'deny', rule: 'approval-policy-forbidden', hard: true });
  });

  it('hard-denies servers outside action scopes', () => {
    const result = evaluate(
      makeAction({ serverScopes: ['web-*'] }),
      makeServer({ id: 'db-prod-01' }),
      request({ serverId: 'db-prod-01' }),
      online,
    );
    expect(result).toMatchObject({ decision: 'deny', rule: 'server-scope', hard: true });
  });

  it('hard-denies calls without a reason', () => {
    const result = evaluate(makeAction(), makeServer(), request({ reason: '  ' }), online);
    expect(result).toMatchObject({ decision: 'deny', rule: 'missing-reason', hard: true });
  });

  it('fail-safe denies anything above low risk when the control plane is unreachable — a label no longer keeps it running (#61)', () => {
    // The readonly flag used to decide this; now the effective risk does.
    expect(evaluate(makeAction({ riskLevel: 'medium', readonly: true }), makeServer(), request(), offline)).toMatchObject({
      decision: 'deny',
      rule: 'fail-safe-control-plane',
      hard: true,
    });
    // Only genuinely low-risk work proceeds with no control plane.
    expect(evaluate(makeAction({ riskLevel: 'low' }), makeServer(), request(), offline).decision).toBe('allow');
  });

  it('risk is the single axis: high requires a person, low runs, and readonly changes NOTHING (#61)', () => {
    expect(evaluate(makeAction({ riskLevel: 'high' }), makeServer(), request(), online)).toMatchObject({
      decision: 'human_review',
      rule: 'risk-level',
      hard: true,
    });
    expect(evaluate(makeAction({ riskLevel: 'low' }), makeServer(), request(), online).decision).toBe('allow');
    // A read-only HIGH task is not let through by its label…
    expect(evaluate(makeAction({ riskLevel: 'high', readonly: true }), makeServer(), request(), online).decision).toBe('human_review');
    // …and a mutating LOW task is not held back by one either.
    expect(evaluate(makeAction({ riskLevel: 'low', readonly: false }), makeServer(), request(), online).decision).toBe('allow');
  });

  it('a production target and the MCP surface each raise the effective risk one notch (#61)', () => {
    const medium = makeAction({ riskLevel: 'medium' });
    // medium on a dev server through the Panel: automatic.
    expect(evaluate(medium, makeServer(), request(), online).decision).toBe('allow');
    // medium on PRODUCTION: raised to high, so a person decides.
    expect(evaluate(medium, makeServer({ environment: 'production' }), request(), online)).toMatchObject({
      decision: 'human_review',
      rule: 'risk-level',
    });
    // medium over MCP: raised to high the same way.
    expect(evaluate(medium, makeServer(), request(), mcp)).toMatchObject({ decision: 'human_review', rule: 'risk-level' });
    // low over MCP stays automatic — one notch is medium.
    expect(evaluate(makeAction({ riskLevel: 'low' }), makeServer(), request(), mcp).decision).toBe('allow');
    // Both weights compose and saturate at critical.
    expect(evaluate(medium, makeServer({ environment: 'production' }), request(), mcp)).toMatchObject({ decision: 'human_review' });
  });

  it('a redline verdict is another input that can only tighten (#65)', () => {
    const low = makeAction({ riskLevel: 'low' });
    // Soft: the task keeps running, but a person answers for each run.
    expect(evaluate(low, makeServer(), request(), { ...online, screening: 'soft' })).toMatchObject({
      decision: 'human_review',
      rule: 'risk-level',
      hard: true,
    });
    expect(evaluate(low, makeServer(), request(), { ...online, screening: 'soft' }).reason).toContain('a redline its script hits');
    // Hard: refused outright — the second line behind the sweep's suspension.
    expect(evaluate(low, makeServer(), request(), { ...online, screening: 'hard' })).toMatchObject({
      decision: 'deny',
      rule: 'redline',
      hard: true,
    });
    // And it never loosens: a clean verdict leaves the ordinary result.
    expect(evaluate(low, makeServer(), request(), online).decision).toBe('allow');
  });

  it('legacy declarations keep their meaning: always_human still asks, forbidden still denies (#61)', () => {
    const asked = evaluate(makeAction({ approvalPolicy: 'always_human', riskLevel: 'low' }), makeServer(), request(), online);
    expect(asked).toMatchObject({ decision: 'human_review', rule: 'risk-level', hard: true });
    // Raised to the ASKING threshold, not to critical — the operator never
    // declared that severity (review 2365) — and the reason names the cause
    // instead of an empty "raised by" clause.
    expect(asked.reason).toContain('"high"');
    expect(asked.reason).toContain('always_human');
    expect(asked.reason).not.toMatch(/raised by\s*\)/);
    // A critical always_human task is not lowered either.
    expect(evaluate(makeAction({ approvalPolicy: 'always_human', riskLevel: 'critical' }), makeServer(), request(), online).reason).toContain('"critical"');
    expect(evaluate(makeAction({ approvalPolicy: 'forbidden' }), makeServer(), request(), online)).toMatchObject({
      decision: 'deny',
      rule: 'approval-policy-forbidden',
    });
  });
});

describe('tighten (AI reviewer supplement)', () => {
  const allow = { decision: 'allow', rule: 'default-allow', reason: '', hard: false } as const;

  it('lets a reviewer tighten allow to human_review or deny', () => {
    expect(tighten(allow, { decision: 'deny', rule: 'ai-reviewer', reason: 'suspicious', hard: false }).decision).toBe(
      'deny',
    );
  });

  it('never loosens a hard result', () => {
    const hardReview = { decision: 'human_review', rule: 'risk-level', reason: '', hard: true } as const;
    expect(tighten(hardReview, { decision: 'allow', rule: 'ai-reviewer', reason: 'looks fine', hard: false })).toBe(
      hardReview,
    );
  });

  it('ignores reviewer results that are not stricter', () => {
    const review = { decision: 'human_review', rule: 'x', reason: '', hard: false } as const;
    expect(tighten(review, allow)).toBe(review);
  });
});
