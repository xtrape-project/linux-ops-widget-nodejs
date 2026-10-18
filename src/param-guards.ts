import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * Parameter risk control (#66) — the third tier, and the only one that must
 * be judged PER INVOCATION, because a parameter's value does not exist until
 * somebody calls.
 *
 * It stays in this Widget and is not registered to the Platform: it is
 * LOGIC, not a declaration. The Platform holding a rule expression could not
 * evaluate it — evaluation needs what only this Widget has (which fleet
 * entry the target is, what environment it runs in, what a parameter means
 * inside this task). The declarative bounds a schema CAN carry (pattern,
 * enum, minimum, maximum) are already reported in `inputSchema` and remain
 * the Platform's to see.
 *
 * Like every other input on this side, a guard may only TIGHTEN: `soft`
 * raises the effective risk to the asking threshold, `hard` refuses. Nothing
 * here can make an execution more permissive than the task's declared risk
 * already allows.
 */

/** One condition over an invocation. Combinators nest; leaves test one thing. */
export type GuardCondition =
  | { all: GuardCondition[] }
  | { any: GuardCondition[] }
  | { not: GuardCondition }
  | { param: string; equals: string | number | boolean }
  | { param: string; matches: string }
  | { param: string; present: boolean }
  | { param: string; atLeast: number }
  | { param: string; atMost: number }
  | { environment: 'production' | 'staging' | 'development' }
  | { server: string }
  | { surface: 'platform' | 'mcp' };

export interface ParamGuard {
  id: string;
  /** Glob over task ids; absent means every task. */
  task?: string;
  when: GuardCondition;
  severity: 'hard' | 'soft';
  /** What to tell the caller when it fires. Written for the person who must decide. */
  message: string;
}

export interface GuardContext {
  taskId: string;
  args: Record<string, unknown>;
  serverId: string;
  environment: string;
  surface: string;
}

export interface GuardHit {
  id: string;
  severity: 'hard' | 'soft';
  message: string;
}

function globMatches(pattern: string, value: string): boolean {
  if (pattern === '*') return true;
  const source = pattern.split('*').map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${source}$`).test(value);
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === 'number') return value;
  if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) return Number(value);
  return undefined;
}

/** Evaluate one condition against an invocation. Unknown shapes never match. */
export function conditionHolds(condition: GuardCondition, ctx: GuardContext): boolean {
  if ('all' in condition) return condition.all.every((c) => conditionHolds(c, ctx));
  if ('any' in condition) return condition.any.some((c) => conditionHolds(c, ctx));
  if ('not' in condition) return !conditionHolds(condition.not, ctx);
  if ('environment' in condition) return ctx.environment === condition.environment;
  if ('server' in condition) return globMatches(condition.server, ctx.serverId);
  if ('surface' in condition) return ctx.surface === condition.surface;
  const value = ctx.args[condition.param];
  if ('present' in condition) return (value !== undefined) === condition.present;
  if (value === undefined) return false; // a parameter that was not supplied tests false
  if ('equals' in condition) return value === condition.equals || String(value) === String(condition.equals);
  if ('matches' in condition) {
    // Same Unicode semantics as the schema's own `pattern` (Ajv compiles
    // with `u`), so a rule means here what it would mean there.
    try {
      return new RegExp(condition.matches, 'u').test(String(value));
    } catch {
      return false;
    }
  }
  const numeric = asNumber(value);
  if ('atLeast' in condition) return numeric !== undefined && numeric >= condition.atLeast;
  if ('atMost' in condition) return numeric !== undefined && numeric <= condition.atMost;
  return false;
}

export class ParamGuardSet {
  /** Content digest of the rule set, for evidence and for change detection. */
  readonly generation: string;

  constructor(readonly rules: ParamGuard[]) {
    this.generation = `sha256:${createHash('sha256').update(JSON.stringify(rules), 'utf8').digest('hex')}`;
  }

  /** Every guard this invocation fires, in rule order. */
  evaluate(ctx: GuardContext): GuardHit[] {
    return this.rules
      .filter((rule) => (rule.task === undefined || globMatches(rule.task, ctx.taskId)) && conditionHolds(rule.when, ctx))
      .map((rule) => ({ id: rule.id, severity: rule.severity, message: rule.message }));
  }

  /** The guards that could ever fire for a task — what a run panel can say in advance. */
  rulesFor(taskId: string): ParamGuard[] {
    return this.rules.filter((rule) => rule.task === undefined || globMatches(rule.task, taskId));
  }

  /**
   * Load from JSON. A missing file is no guards; anything malformed stops
   * the Worker, for the same reason a broken redline file does: a rule file
   * that fails to load must not read as "no rules".
   */
  static load(path: string): ParamGuardSet {
    let raw: string;
    try {
      raw = readFileSync(path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new ParamGuardSet([]);
      throw error;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(`parameter guard file ${path}: not valid JSON (${err instanceof Error ? err.message : String(err)})`);
    }
    const rules = (parsed as { rules?: unknown })?.rules;
    if (!Array.isArray(rules)) throw new Error(`parameter guard file ${path}: expected an object with a "rules" array`);
    const seen = new Set<string>();
    return new ParamGuardSet(
      rules.map((entry, at) => {
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
          throw new Error(`parameter guard file ${path}, rule ${at + 1}: must be an object`);
        }
        const r = entry as Partial<ParamGuard>;
        const where = `parameter guard file ${path}, rule ${at + 1}`;
        // A CLOSED shape (review 2409): the loader used to pick the five keys
        // it knew and ignore the rest, so `"taks"` for `"task"` loaded fine
        // and silently widened the rule from one task to every task. A rule
        // file must not look like it loaded and mean something else.
        const unknownKeys = Object.keys(entry).filter((k) => !['id', 'task', 'when', 'severity', 'message'].includes(k));
        if (unknownKeys.length > 0) throw new Error(`${where}: unknown key(s) ${unknownKeys.join(', ')} — a rule takes id / task / when / severity / message`);
        if (typeof r.id !== 'string' || r.id === '') throw new Error(`${where}: needs an id`);
        if (seen.has(r.id)) throw new Error(`${where}: duplicate id "${r.id}"`);
        seen.add(r.id);
        if (r.severity !== 'hard' && r.severity !== 'soft') throw new Error(`${where} ("${r.id}"): severity must be "hard" or "soft"`);
        if (typeof r.message !== 'string' || r.message === '') throw new Error(`${where} ("${r.id}"): needs a message for whoever must decide`);
        if (r.when === undefined || typeof r.when !== 'object') throw new Error(`${where} ("${r.id}"): needs a "when" condition`);
        // A non-string `task` used to be dropped, which QUIETLY WIDENED the
        // rule from one task to every task (review 2404).
        if ('task' in (entry as object) && (typeof r.task !== 'string' || r.task === '')) {
          throw new Error(`${where} ("${r.id}"): "task" must be a task id`);
        }
        assertCondition(r.when, `${where} ("${r.id}")`);
        return {
          id: r.id,
          ...(typeof r.task === 'string' ? { task: r.task } : {}),
          when: r.when as GuardCondition,
          severity: r.severity,
          message: r.message,
        };
      }),
    );
  }
}

/**
 * Refuse a condition this evaluator would silently never match — a rule that
 * cannot fire is worse than no rule, because it reads like a guard.
 */
function assertCondition(condition: unknown, where: string): void {
  if (typeof condition !== 'object' || condition === null || Array.isArray(condition)) {
    throw new Error(`${where}: a condition must be an object`);
  }
  const c = condition as Record<string, unknown>;
  const keys = Object.keys(c);
  // Exactly ONE shape per condition (review 2404). `{all:[…], param:"x"}`
  // used to parse as an `all` with the param silently dropped — a rule that
  // reads like it checks a parameter and never does.
  const combinators = ['all', 'any', 'not'].filter((k) => k in c);
  if (combinators.length > 1) throw new Error(`${where}: a condition takes exactly one of all / any / not, not ${combinators.join(' + ')}`);
  if (combinators.length === 1) {
    const kind = combinators[0]!;
    const extra = keys.filter((k) => k !== kind);
    if (extra.length > 0) throw new Error(`${where}: "${kind}" cannot be combined with ${extra.join(', ')}`);
    if (kind === 'not') {
      assertCondition(c['not'], where);
      return;
    }
    const list = c[kind];
    if (!Array.isArray(list) || list.length === 0) throw new Error(`${where}: "all"/"any" needs a non-empty array of conditions`);
    for (const inner of list) assertCondition(inner, where);
    return;
  }
  const leaves = ['environment', 'surface', 'server', 'param'].filter((k) => k in c);
  if (leaves.length !== 1) {
    throw new Error(`${where}: a condition needs exactly one of param / environment / server / surface / all / any / not`);
  }
  if ('environment' in c) {
    if (keys.length > 1) throw new Error(`${where}: "environment" takes no other keys (got ${keys.filter((k) => k !== 'environment').join(', ')})`);
    if (!['production', 'staging', 'development'].includes(String(c['environment']))) {
      throw new Error(`${where}: environment must be production, staging or development`);
    }
    return;
  }
  if ('surface' in c) {
    if (keys.length > 1) throw new Error(`${where}: "surface" takes no other keys (got ${keys.filter((k) => k !== 'surface').join(', ')})`);
    if (!['platform', 'mcp'].includes(String(c['surface']))) throw new Error(`${where}: surface must be platform or mcp`);
    return;
  }
  if ('server' in c) {
    if (keys.length > 1) throw new Error(`${where}: "server" takes no other keys (got ${keys.filter((k) => k !== 'server').join(', ')})`);
    if (typeof c['server'] !== 'string' || c['server'] === '') throw new Error(`${where}: "server" needs a scope`);
    return;
  }
  if (typeof c['param'] !== 'string' || c['param'] === '') throw new Error(`${where}: "param" needs a parameter name`);
  const tests = ['equals', 'matches', 'present', 'atLeast', 'atMost'].filter((k) => k in c);
  if (tests.length !== 1) throw new Error(`${where}: a param condition needs exactly one of equals / matches / present / atLeast / atMost`);
  const unknown = keys.filter((k) => k !== 'param' && !tests.includes(k));
  if (unknown.length > 0) throw new Error(`${where}: unknown key(s) on a param condition: ${unknown.join(', ')}`);
  if ('equals' in c) {
    // `String(value) === String(condition.equals)` is the comparison, so an
    // `equals` that is not a scalar becomes a DIFFERENT rule than it reads as:
    // null compares against "null", {} against "[object Object]", [] against
    // "" — which matches every empty argument (review 2409).
    const eq = c['equals'];
    const scalar = typeof eq === 'string' || typeof eq === 'boolean' || (typeof eq === 'number' && Number.isFinite(eq));
    if (!scalar) throw new Error(`${where}: "equals" needs a string, a boolean or a finite number`);
  }
  if ('matches' in c) {
    // A non-string would be coerced by String() and compile into something
    // else entirely — `{matches: 123}` is a typo, not a rule.
    if (typeof c['matches'] !== 'string' || c['matches'] === '') throw new Error(`${where}: "matches" needs a pattern string`);
    try {
      new RegExp(c['matches'], 'u');
    } catch (err) {
      throw new Error(`${where}: "matches" does not compile (${err instanceof Error ? err.message : String(err)})`);
    }
  }
  // `present: "false"` is truthy and would invert the rule silently.
  if ('present' in c && typeof c['present'] !== 'boolean') throw new Error(`${where}: "present" needs true or false`);
  if (('atLeast' in c && typeof c['atLeast'] !== 'number') || ('atMost' in c && typeof c['atMost'] !== 'number')) {
    throw new Error(`${where}: atLeast/atMost need a number`);
  }
  if (('atLeast' in c && !Number.isFinite(c['atLeast'] as number)) || ('atMost' in c && !Number.isFinite(c['atMost'] as number))) {
    throw new Error(`${where}: atLeast/atMost need a finite number`);
  }
}

/** The strictest severity among some hits. */
export function guardVerdict(hits: GuardHit[]): 'clear' | 'soft' | 'hard' {
  if (hits.some((h) => h.severity === 'hard')) return 'hard';
  return hits.length > 0 ? 'soft' : 'clear';
}
