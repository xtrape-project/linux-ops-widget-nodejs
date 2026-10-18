import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

/**
 * One redline: a pattern over SCRIPT TEXT, with what its hit means.
 *
 * `hard` refuses — an ad-hoc command carrying it is not run, and an enabled
 * task carrying it is suspended until a person re-reviews. `soft` escalates:
 * the task keeps running, but every execution needs a human answer.
 */
export interface Redline {
  id: string;
  /** ECMAScript source, compiled case-insensitively with `u`. */
  pattern: string;
  severity: 'hard' | 'soft';
  /** What to tell the operator. Written for the person reading a review card. */
  message: string;
}

export interface RedlineHit {
  id: string;
  severity: 'hard' | 'soft';
  message: string;
  /** The matched text, bounded so a hit cannot itself become a wall of output. */
  excerpt: string;
}

export type Verdict = 'clear' | 'soft' | 'hard';

/** The strictest verdict among some hits. */
export function verdictOf(hits: RedlineHit[]): Verdict {
  if (hits.some((h) => h.severity === 'hard')) return 'hard';
  return hits.length > 0 ? 'soft' : 'clear';
}

const MAX_EXCERPT = 120;

/**
 * The redline set this Worker screens against (#65).
 *
 * **What this is and is not.** Screening is a REVIEW-TIME aid over script
 * text: it catches the accident — an `rm -rf $DIR` in the middle of a
 * sixty-line deploy where `DIR` may be empty — and it does not catch an
 * adversary, who can spell the same thing through a variable, a quoted
 * split, or a base64 decode. It is a gate for text nobody has reviewed and
 * a prompt for the person reviewing text; it is NOT an unbypassable
 * control. The only enforceable place for that is the target host
 * (restricted shell, sudo policy, read-only mounts, auditd).
 *
 * **Why there is no execution-time screening.** A task runs as ONE
 * `interpreter -s` with the script on stdin; the ten operations inside are
 * that one process's business and this Worker never sees them individually.
 * Screening therefore happens where the text exists and a decision is being
 * made: at review, and again when the rule set itself changes.
 */
export class RedlineSet {
  /** Content digest of the rule set — the generation a screening was made under. */
  readonly generation: string;
  private readonly compiled: Array<{ rule: Redline; re: RegExp }>;

  constructor(readonly rules: Redline[]) {
    const canonical = JSON.stringify(
      rules.map((r) => ({ id: r.id, pattern: r.pattern, severity: r.severity, message: r.message })),
    );
    this.generation = `sha256:${createHash('sha256').update(canonical, 'utf8').digest('hex')}`;
    this.compiled = rules.map((rule) => {
      let re: RegExp;
      try {
        re = new RegExp(rule.pattern, 'giu');
      } catch (err) {
        // A rule that cannot compile would screen NOTHING while looking like
        // a guard, so it stops the Worker instead of silently passing.
        throw new Error(`redline "${rule.id}": pattern does not compile (${err instanceof Error ? err.message : String(err)})`);
      }
      return { rule, re };
    });
  }

  /** Every rule the text hits, in rule order. */
  screen(text: string): RedlineHit[] {
    const hits: RedlineHit[] = [];
    for (const { rule, re } of this.compiled) {
      re.lastIndex = 0;
      const match = re.exec(text);
      if (!match) continue;
      const excerpt = match[0].length > MAX_EXCERPT ? `${match[0].slice(0, MAX_EXCERPT)}…` : match[0];
      hits.push({ id: rule.id, severity: rule.severity, message: rule.message, excerpt });
    }
    return hits;
  }

  /**
   * Load the rule set from a JSON file. A MISSING file is an empty set —
   * screening is opt-in, and a deployment that declared no redlines has
   * none. Anything else (unreadable, malformed, a rule that will not
   * compile) stops the Worker: a broken rule file must not read as "no
   * rules".
   */
  static load(path: string): RedlineSet {
    let raw: string;
    try {
      raw = readFileSync(path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return new RedlineSet([]);
      throw error;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(`redline file ${path}: not valid JSON (${err instanceof Error ? err.message : String(err)})`);
    }
    const rules = (parsed as { rules?: unknown })?.rules;
    if (!Array.isArray(rules)) throw new Error(`redline file ${path}: expected an object with a "rules" array`);
    const seen = new Set<string>();
    return new RedlineSet(
      rules.map((entry, at) => {
        const r = entry as Partial<Redline>;
        const where = `redline file ${path}, rule ${at + 1}`;
        if (typeof r.id !== 'string' || r.id === '') throw new Error(`${where}: needs an id`);
        if (seen.has(r.id)) throw new Error(`${where}: duplicate id "${r.id}"`);
        seen.add(r.id);
        if (typeof r.pattern !== 'string' || r.pattern === '') throw new Error(`${where} ("${r.id}"): needs a pattern`);
        if (r.severity !== 'hard' && r.severity !== 'soft') throw new Error(`${where} ("${r.id}"): severity must be "hard" or "soft"`);
        if (typeof r.message !== 'string' || r.message === '') throw new Error(`${where} ("${r.id}"): needs a message for whoever reads the hit`);
        return { id: r.id, pattern: r.pattern, severity: r.severity, message: r.message };
      }),
    );
  }
}

/**
 * Re-screen every enabled task against the CURRENT rule set and act on what
 * changed (#65).
 *
 * This is the whole reason screening can stay out of the execution path: a
 * revision's bytes are frozen and the rule set has a generation, so a
 * verdict can only change when one of the two does. Screening at approval
 * and again here is therefore complete — and it turns a rule change into a
 * definite answer ("3 of the 12 enabled tasks now violate this") instead of
 * a surprise at 3am.
 */
export function sweepEnabled(
  store: {
    listAll(): Array<{ definition: { id: string; script: string }; state: 'enabled' | 'draft' }>;
    screening(id: string): { generation: string; verdict: Verdict; revisionId: number } | undefined;
    /** Records the verdict and, for a hard hit, suspends — atomically (review 2408). */
    applyScreening(id: string, generation: string, verdict: Verdict): { suspended: boolean };
  },
  redlines: RedlineSet,
  report: (line: string) => void = (line) => process.stderr.write(`${line}\n`),
): { screened: number; suspended: string[]; escalated: string[] } {
  const suspended: string[] = [];
  const escalated: string[] = [];
  let screened = 0;
  for (const task of store.listAll()) {
    if (task.state !== 'enabled') continue;
    const already = store.screening(task.definition.id);
    if (already?.generation === redlines.generation) continue; // same bytes, same rules
    screened += 1;
    const verdict = verdictOf(redlines.screen(task.definition.script));
    // Approved before this rule existed: a hard hit takes the task out of
    // service and puts it back in front of a person, rather than keeping it
    // running or pretending the rule does not apply to what is already
    // enabled. Verdict and suspension commit together — a crash between them
    // used to leave a task enabled and marked screened, which no later sweep
    // would revisit (review 2408).
    const { suspended: wasSuspended } = store.applyScreening(task.definition.id, redlines.generation, verdict);
    if (wasSuspended) {
      suspended.push(task.definition.id);
    } else if (verdict === 'soft') {
      escalated.push(task.definition.id);
    }
  }
  if (suspended.length > 0) {
    report(`[redlines] suspended ${suspended.length} enabled task(s) hitting a HARD redline added after approval: ${suspended.join(', ')} — re-review to enable again`);
  }
  if (escalated.length > 0) {
    report(`[redlines] ${escalated.length} enabled task(s) now hit a soft redline and require a human answer per run: ${escalated.join(', ')}`);
  }
  return { screened, suspended, escalated };
}
