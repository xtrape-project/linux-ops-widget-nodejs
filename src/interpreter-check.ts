import type { ServerDefinition } from './types.js';

/**
 * Executability pre-check (#69): does the TARGET have the interpreter the
 * task's shebang names? The task side is authoritative about WHICH
 * interpreter (task-file.ts, interpreterFromShebang); the server record can
 * carry WHICH ONES THE HOST HAS (`shells`, declared or probed). Put together
 * at review time, "the target has no bash" is said before a person approves
 * and refused before a command leaves — instead of surfacing as an `exit
 * 127` after dispatch, indistinguishable from the script's own 127.
 *
 * Not a control layer: it changes no risk level and relaxes no approval.
 * UNKNOWN (record without `shells`) is not "none": it never blocks, it is
 * only named on the card, so old records keep working exactly as before.
 */
export type InterpreterAvailability =
  | { state: 'ok'; interpreter: string }
  | { state: 'missing'; interpreter: string; known: string[]; source: 'declared' | 'probed'; probedAt?: string }
  | { state: 'unknown'; interpreter: string };

/** The bare command a shebang names, as `command -v` would take it: `/usr/bin/python3` → `python3`. */
export function interpreterName(interpreter: string): string {
  const trimmed = interpreter.trim();
  const slash = trimmed.lastIndexOf('/');
  return slash >= 0 ? trimmed.slice(slash + 1) : trimmed;
}

export function interpreterAvailability(interpreter: string, server: Pick<ServerDefinition, 'shells' | 'shellsSource' | 'shellsProbedAt'>): InterpreterAvailability {
  const name = interpreterName(interpreter);
  if (server.shells === undefined) return { state: 'unknown', interpreter: name };
  if (server.shells.some((s) => interpreterName(s) === name)) return { state: 'ok', interpreter: name };
  return {
    state: 'missing',
    interpreter: name,
    known: server.shells,
    source: server.shellsSource ?? 'declared',
    ...(server.shellsProbedAt ? { probedAt: server.shellsProbedAt } : {}),
  };
}

/** One human line per server, for review cards. */
export function interpreterNotice(interpreter: string, server: Pick<ServerDefinition, 'id' | 'shells' | 'shellsSource' | 'shellsProbedAt'>): string {
  const a = interpreterAvailability(interpreter, server);
  switch (a.state) {
    case 'ok':
      return `${server.id}: has ${a.interpreter}`;
    case 'missing':
      return `${server.id}: NO ${a.interpreter} — ${a.source === 'probed' ? `probed${a.probedAt ? ` at ${a.probedAt}` : ''}` : 'declared'}: ${a.known.length ? a.known.join(', ') : '(none)'}; the run will be REFUSED here`;
    case 'unknown':
      return `${server.id}: interpreters not probed (unknown ≠ missing; run Test on the server to learn)`;
  }
}

/** The lines for a whole eligible set, plus whether any target would refuse. */
export function interpreterNotices(interpreter: string, servers: Array<Pick<ServerDefinition, 'id' | 'shells' | 'shellsSource' | 'shellsProbedAt'>>): { lines: string[]; missing: string[]; unknown: string[] } {
  const lines: string[] = [];
  const missing: string[] = [];
  const unknown: string[] = [];
  for (const s of servers) {
    lines.push(interpreterNotice(interpreter, s));
    const a = interpreterAvailability(interpreter, s);
    if (a.state === 'missing') missing.push(s.id);
    if (a.state === 'unknown') unknown.push(s.id);
  }
  return { lines, missing, unknown };
}
