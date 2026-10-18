/** POSIX single-quote escaping; the value can never break out of the quotes. */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}


/**
 * How each interpreter is told to read the program from STANDARD INPUT, and
 * which of its options would move that source somewhere else (review 2371).
 *
 * `-s` is a SHELL convention, not a universal "read stdin" flag: `python3 -s`
 * means "no user site directory" and would silently change the author's
 * runtime, while `/bin/sh -c -s` makes `-s` the shell's command argument. So
 * the invocation is interpreter-aware and the set is CLOSED: an interpreter
 * this table does not know is refused at parse time rather than invoked on a
 * guess, and an argument in `sourceOptions` is refused because it decides
 * where the program comes from — the one thing this Widget must keep.
 */
export const STDIN_INVOCATION: Record<string, { stdinArg: string; options: string[]; clustered: boolean }> = {
  // `options` is an ALLOW-list, not a deny-list (review 2373): denying the
  // source options one by one missed `-ec`, `-cCODE`, `-mMOD`, `-eCODE` —
  // combined clusters and attached values. Only flags known NOT to move the
  // program are admitted, and everything else fails closed. `clustered`
  // says whether the family accepts single-dash letter clusters (`-eu`),
  // whose every letter must itself be admitted.
  sh: { stdinArg: '-s', options: ['-e', '-u', '-x', '-f', '-v'], clustered: true },
  bash: { stdinArg: '-s', options: ['-e', '-u', '-x', '-f', '-v'], clustered: true },
  dash: { stdinArg: '-s', options: ['-e', '-u', '-x', '-f', '-v'], clustered: true },
  ksh: { stdinArg: '-s', options: ['-e', '-u', '-x', '-f', '-v'], clustered: true },
  zsh: { stdinArg: '-s', options: ['-e', '-u', '-x', '-f', '-v'], clustered: true },
  python: { stdinArg: '-', options: ['-u', '-B', '-E', '-O', '-OO', '-I', '-q', '-S', '-b'], clustered: false },
  python3: { stdinArg: '-', options: ['-u', '-B', '-E', '-O', '-OO', '-I', '-q', '-S', '-b'], clustered: false },
  perl: { stdinArg: '-', options: ['-w', '-W', '-T'], clustered: false },
  ruby: { stdinArg: '-', options: ['-w', '-W0', '-W1', '-W2', '-v'], clustered: false },
};

/** The stdin invocation for an interpreter command or path, or undefined if unknown. */
export function stdinInvocationFor(interpreter: string): { stdinArg: string; options: string[]; clustered: boolean } | undefined {
  const base = interpreter.split('/').pop() ?? interpreter;
  return STDIN_INVOCATION[base];
}

/**
 * Whether a shebang argument is one this Widget knows cannot move the
 * program away from standard input. Clusters (`-eux`) are admitted only for
 * families that take them, and only when EVERY letter is admitted on its
 * own — `-ec` is refused because `c` is not.
 */
export function shebangOptionAdmitted(arg: string, invocation: { options: string[]; clustered: boolean }): boolean {
  if (invocation.options.includes(arg)) return true;
  if (!invocation.clustered) return false;
  if (!/^-[A-Za-z]{2,}$/.test(arg)) return false;
  return [...arg.slice(1)].every((letter) => invocation.options.includes(`-${letter}`));
}

/** The interpreters this Widget can invoke faithfully, for error messages. */
export const SUPPORTED_INTERPRETERS = Object.keys(STDIN_INVOCATION).join(', ');

/** Environment variable prefix under which task parameters reach the script. */
export const PARAM_ENV_PREFIX = 'XOPS_';

/**
 * Build the remote command line for a task: parameter assignments followed by
 * the interpreter reading the script from standard input.
 *
 * WHAT THIS DOES AND DOES NOT GUARANTEE — read both halves.
 *
 * It removes the OPERATOR'S SCRIPT from the injection surface. Under the
 * retired template model a value was spliced into the command an operator
 * wrote, so a `path` of `-delete` became an argument of the program that
 * command invoked, and every template was its own escaping problem. Here the
 * script arrives separately, on stdin, and no caller value can add a word to
 * it.
 *
 * It does NOT make the value stop being shell source. The assignments below
 * are sent to the remote login shell as part of an `exec` command string, so
 * correctness still rests on `shellQuote` — what changed is that the escaping
 * surface collapsed from "every operator's template, each with its own
 * placement" to one function, applied uniformly, at one call site, with tests
 * on it. That is a much smaller thing to get right, not the absence of one.
 *
 * The fully non-shell alternative is the SSH protocol's environment request,
 * and it is not used on purpose: `sshd` accepts only the variables its
 * `AcceptEnv` allows — by default a short `LANG`/`LC_*` list — and silently
 * DROPS the rest. A task whose parameters vanished without error would be a
 * worse failure than a bounded, tested quoting path. Revisit if the fleet's
 * `sshd` configuration is ever ours to set.
 *
 * What a parameter still influences is what the operator's own script does
 * with it. That is the script author's responsibility, and the reason task
 * files declare parameter patterns and enums.
 */
export function buildTaskCommand(
  interpreter: string,
  args: Record<string, unknown>,
  render: (value: unknown) => string = (v) => shellQuote(String(v)),
  interpreterArgs: string[] = [],
  /**
   * The argument that makes the program arrive on stdin. It is DECIDED AT
   * PARSE TIME and carried by the definition (review 2373): a task stored
   * with the retired `# interpreter:` header keeps the `-s` it has always
   * been run with, whatever the current table would say for that command.
   */
  stdinArg = '-s',
): string {
  const assignments = Object.entries(args)
    .filter(([, value]) => value !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, value]) => `${PARAM_ENV_PREFIX}${name}=${render(value)}`);
  // The interpreter is invoked with `-s` plus the arguments the script's OWN
  // shebang named, and nothing this Widget invented. No `-e`, no `-o
  // pipefail`, no wrapper of ours: whatever the script does when run in a
  // shell on the target is what it does here.
  //
  // This Widget delivers the operator's intent; it does not interpret it. A
  // task file is reviewed configuration, and turning on `-e` for everyone
  // would silently change the meaning of every script that did not ask for it
  // — a two-step task that deliberately continues past a failing first step
  // would start stopping. Whether a failure ends the task is the author's
  // sentence to write, in their own file, where a reader can see it.
  //
  // The one deliberate departure from "identical to a shell on the target" is
  // the output ceiling in `../executors/ssh.ts`, which bounds this Worker's
  // own memory rather than the script's behaviour, and reports itself as this
  // Worker's doing rather than as an outcome of the task.
  // The interpreter's OWN arguments are the ones its shebang named — the
  // author's sentence, not this Widget's (review 2370). The only thing this
  // Widget adds is the argument that makes the program arrive on stdin, and
  // that argument is INTERPRETER-SPECIFIC (review 2371): `-s` for a shell,
  // `-` for python/perl/ruby. An unknown interpreter never reaches here —
  // `parseTaskFile` refuses it — so a missing entry is a programming error,
  // not a silently wrong command line.
  // An author who already spelled the stdin argument gets it once.
  const stdin = interpreterArgs.includes(stdinArg) ? [] : [stdinArg];
  return [...assignments, interpreter, ...interpreterArgs, ...stdin].join(' ');
}

/**
 * The audit projection of a task command: the same shape with every parameter
 * value masked. No `executionHash` substitute is needed for the command itself —
 * values never appear in it — but an operator reading audit still needs to see
 * WHICH parameters were supplied.
 */
export function maskedTaskCommand(interpreter: string, args: Record<string, unknown>, interpreterArgs: string[] = [], stdinArg = '-s'): string {
  return buildTaskCommand(interpreter, args, () => "'***'", interpreterArgs, stdinArg);
}
