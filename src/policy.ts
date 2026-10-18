import type { ActionDefinition, OpsRequest, PolicyResult, RiskLevel, ServerDefinition, Surface } from './types.js';

function scopeMatches(scope: string, serverId: string): boolean {
  if (scope === '*') return true;
  const pattern = scope.split('*').map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${pattern}$`).test(serverId);
}

const hard = (decision: 'deny' | 'human_review', rule: string, reason: string): PolicyResult => ({
  decision,
  rule,
  reason,
  hard: true,
});

export interface PolicyContext {
  controlPlaneAvailable: boolean;
  /** Which surface invoked this execution — an input to the effective risk (#61). */
  surface: Surface;
  /**
   * The task's standing redline verdict, when its script hit the rule set
   * (#65). `soft` raises the effective risk to the asking threshold — the
   * task keeps running, but a person answers for each run; `hard` refuses.
   * A hard-hit task is normally suspended at the sweep, so this is the
   * second line rather than the first.
   */
  screening?: 'soft' | 'hard';
  /**
   * What the parameter guards made of THIS invocation's arguments (#66).
   * Judged per call, because a parameter's value does not exist until
   * somebody calls; like every other input here it may only tighten.
   */
  paramGuard?: 'soft' | 'hard';
  /** The guard messages, for the refusal a caller reads. */
  paramGuardReasons?: string[];
}

/**
 * Deterministic policy engine. Hard results (deny / forced human_review) can
 * never be loosened by any later component, including an AI safety reviewer.
 * Reviewers may only tighten a non-hard `allow` via `tighten()`.
 */
const RISK_ORDER: RiskLevel[] = ['low', 'medium', 'high', 'critical'];

/**
 * Raise a risk level by `notches`, saturating at `critical`.
 */
function raise(level: RiskLevel, notches: number): RiskLevel {
  const at = RISK_ORDER.indexOf(level);
  return RISK_ORDER[Math.min(RISK_ORDER.length - 1, (at < 0 ? 0 : at) + notches)] as RiskLevel;
}

/**
 * The EFFECTIVE risk of one execution (#61, owner ruling 2026-08-13): the
 * declared risk of the task, raised by the context it runs in.
 *
 * Risk is the single authorization axis. The retired `readonly` flag never
 * enters it — "read-only" was never a safety property (a read-only task can
 * read secrets), and letting it widen anything meant trusting a label to
 * open a door. What remains is the author's honest risk declaration, plus
 * two context weights that tighten it:
 *
 * - a PRODUCTION target: same script, larger consequence;
 * - the MCP surface: a person acting through an AI device, one step further
 *   from the bytes than an operator reading the Panel's review card.
 *
 * A future AI risk assessment joins as another input that may only RAISE the
 * level, the same discipline `tighten()` already carries.
 */
export function effectiveRisk(
  action: Pick<ActionDefinition, 'riskLevel' | 'approvalPolicy'>,
  server: Pick<ServerDefinition, 'environment'>,
  ctx: Pick<PolicyContext, 'surface' | 'screening' | 'paramGuard'>,
): RiskLevel {
  // Legacy `# approval: always_human` declarations keep their meaning as the
  // risk level they were always equivalent to (#61): ignoring them would
  // turn a task an operator marked must-ask into an automatic one. It is
  // AT LEAST `high` — the threshold that asks a person — never higher than
  // what it already was (review 2365: raising it to `critical` would invent
  // severity the operator never declared).
  let level: RiskLevel =
    (action.approvalPolicy === 'always_human' || ctx.screening === 'soft' || ctx.paramGuard === 'soft') &&
    RISK_ORDER.indexOf(action.riskLevel) < RISK_ORDER.indexOf('high')
      ? 'high'
      : action.riskLevel;
  if (server.environment === 'production') level = raise(level, 1);
  if (ctx.surface === 'mcp') level = raise(level, 1);
  return level;
}

export function evaluate(
  action: ActionDefinition,
  server: ServerDefinition,
  request: OpsRequest,
  ctx: PolicyContext,
): PolicyResult {
  // Retired from authoring, still honored where stored (#61): a task an
  // operator declared forbidden must not become executable by an upgrade.
  if (action.approvalPolicy === 'forbidden') {
    return hard('deny', 'approval-policy-forbidden', `action "${action.id}" is forbidden by its approval policy`);
  }
  if (!action.serverScopes.some((scope) => scopeMatches(scope, server.id))) {
    return hard('deny', 'server-scope', `server "${server.id}" is outside the scopes of action "${action.id}"`);
  }
  if (!request.reason || request.reason.trim().length === 0) {
    return hard('deny', 'missing-reason', 'a human-readable reason is required for every call');
  }
  if (ctx.screening === 'hard') {
    return hard('deny', 'redline', `action "${action.id}" hits a hard redline; it must be re-reviewed before it can run again`);
  }
  if (ctx.paramGuard === 'hard') {
    return hard(
      'deny',
      'param-guard',
      `these arguments are refused for "${action.id}": ${(ctx.paramGuardReasons ?? []).join('; ')}`,
    );
  }
  const risk = effectiveRisk(action, server, ctx);
  // With the Platform unreachable there is no way to ASK anyone, so anything
  // that could need a person is already stuck; the fail-safe additionally
  // refuses automatic work above the lowest level rather than trusting a
  // label to keep running (#61 supersedes the readonly-based rule).
  if (!ctx.controlPlaneAvailable && risk !== 'low') {
    return hard(
      'deny',
      'fail-safe-control-plane',
      `control plane unreachable; effective risk "${risk}" is denied by local fail-safe`,
    );
  }
  if (risk === 'high' || risk === 'critical') {
    // Name WHAT raised it, and only when something did — an empty "raised
    // by" clause reads as a bug (review 2365).
    const raisedBy = [
      ctx.paramGuard === 'soft' ? `these arguments (${(ctx.paramGuardReasons ?? []).join('; ')})` : '',
      ctx.screening === 'soft' ? 'a redline its script hits' : '',
      action.approvalPolicy === 'always_human' ? 'its always_human declaration' : '',
      server.environment === 'production' ? 'a production target' : '',
      ctx.surface === 'mcp' ? 'the MCP surface' : '',
    ].filter(Boolean);
    return hard(
      'human_review',
      'risk-level',
      `effective risk "${risk}" requires human approval${risk !== action.riskLevel && raisedBy.length > 0 ? ` (declared "${action.riskLevel}", raised by ${raisedBy.join(' and ')})` : ''}`,
    );
  }
  return { decision: 'allow', rule: 'default-allow', reason: 'no deterministic rule matched', hard: false };
}

/**
 * Apply a supplementary (e.g. AI safety reviewer) result: it may only tighten.
 * Hard base results and attempts to loosen are returned unchanged.
 */
export function tighten(base: PolicyResult, review: PolicyResult): PolicyResult {
  if (base.hard) return base;
  const rank: Record<PolicyResult['decision'], number> = { allow: 0, human_review: 1, deny: 2 };
  return rank[review.decision] > rank[base.decision] ? review : base;
}
