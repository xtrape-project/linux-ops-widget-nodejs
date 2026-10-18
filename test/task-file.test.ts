import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { parseTaskFile } from '../src/task-file.js';
import { buildTaskCommand, maskedTaskCommand } from '../src/shell.js';
import { ActionRegistry } from '../src/registry.js';

const EXAMPLES = join(import.meta.dirname, '..', 'examples', 'tasks');

const parseExample = (file: string) => parseTaskFile(readFileSync(join(EXAMPLES, file), 'utf8'), file);

// The directory loader retired with the file-era store (#58 — the DB is the
// library now); examples are still one-file-one-task, loaded here explicitly.
const loadExamples = (): ActionRegistry => {
  const registry = new ActionRegistry();
  for (const file of readdirSync(EXAMPLES).filter((f) => f.endsWith('.sh')).sort()) {
    registry.register(parseExample(file));
  }
  return registry;
};

describe('a task file is the task', () => {
  it('loads every shipped example', () => {
    const registry = loadExamples();
    const ids = registry.list().map((a) => a.id).sort();
    expect(ids).toEqual(['file.find', 'nginx.reload', 'service.restart', 'system.uptime', 'xtrape.deploy']);
  });

  it('reads a task with no parameters at all — the plain "run this there" shape', () => {
    const task = parseExample('system-uptime.sh');
    expect(task.id).toBe('system.uptime');
    expect(task.readonly).toBe(true);
    expect(task.params).toMatchObject({ properties: {}, required: [] });
    // The script is the file verbatim, digest included, so audit names the
    // exact text that ran rather than a paraphrase of it.
    expect(task.script).toBe(readFileSync(join(EXAMPLES, 'system-uptime.sh'), 'utf8'));
    expect(task.scriptDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('turns parameter declarations into a closed schema the registry can enforce', () => {
    const registry = loadExamples();
    expect(registry.validateArgs('xtrape.deploy', { ref: '0.8.6' }).ok).toBe(true);
    // The operator declared a pattern; a value outside it never reaches a server.
    expect(registry.validateArgs('xtrape.deploy', { ref: 'latest' }).ok).toBe(false);
    // additionalProperties: false — an undeclared parameter is not a parameter.
    expect(registry.validateArgs('xtrape.deploy', { ref: '0.8.6', extra: 'x' }).ok).toBe(false);
    // service.restart's `service` pattern is the injection boundary (#77): a
    // systemd unit token only — no space, quote, ;, |, $, or backtick.
    expect(registry.validateArgs('service.restart', { service: 'nginx' }).ok).toBe(true);
    expect(registry.validateArgs('service.restart', { service: 'nginx.service' }).ok).toBe(true);
    expect(registry.validateArgs('service.restart', { service: 'a@b_c-d.e' }).ok).toBe(true);
    for (const evil of ['nginx; rm -rf /', 'a b', 'a`id`', 'a$(id)', 'a|b', 'a>b', "a'b", '']) {
      expect(registry.validateArgs('service.restart', { service: evil }).ok, evil).toBe(false);
    }
  });

  it('stops reading declarations at the first line of the script', () => {
    const task = parseTaskFile(
      ['#!/usr/bin/env bash', '# xtrape-task: t.one', '# version: 1.0.0', '# risk: low', '# readonly: true', '# servers: *', 'echo hi', '# risk: critical'].join('\n'),
      't.sh',
    );
    // The second `# risk:` is inside the body, where it is a comment.
    expect(task.riskLevel).toBe('low');
  });
});

describe('what the parser refuses', () => {
  const base = ['# xtrape-task: t.one', '# version: 1.0.0', '# risk: low', '# readonly: true', '# servers: *'];
  const parse = (lines: string[]) => () => parseTaskFile(lines.join('\n'), 't.sh');

  it('refuses a file that does not name its task', () => {
    expect(parse(base.filter((l) => !l.startsWith('# xtrape-task')))).toThrow(/xtrape-task/);
  });

  it('refuses a task that does not state its blast radius', () => {
    expect(parse(base.filter((l) => !l.startsWith('# risk')))).toThrow(/risk/);
  });

  it('takes the interpreter from the SHEBANG — env is unwrapped, flags dropped (#61 / review 2365)', () => {
    const withShebang = (line: string) => parseTaskFile([line, ...base, 'echo hi'].join('\n'), 'sb.sh');
    expect(withShebang('#!/usr/bin/env bash').interpreter).toBe('bash');
    expect(withShebang('#!/bin/sh').interpreter).toBe('/bin/sh');
    expect(withShebang('#!/usr/bin/env python3').interpreter).toBe('python3');
    // Arguments the author asked for are kept VERBATIM (review 2370):
    // dropping `-e` would silently change what the script does.
    expect(withShebang('#!/bin/sh -e')).toMatchObject({ interpreter: '/bin/sh', interpreterArgs: ['-e'] });
    expect(withShebang('#!/usr/bin/env python3 -u')).toMatchObject({ interpreter: 'python3', interpreterArgs: ['-u'] });
    // No shebang at all keeps the historical default.
    expect(parseTaskFile([...base, 'echo hi'].join('\n'), 'sb.sh').interpreter).toBe('bash');
    // A stored task's retired `# interpreter:` header still WINS, so an
    // upgrade never changes what already runs.
    expect(parseTaskFile(['#!/bin/sh', ...base, '# interpreter: zsh', 'echo hi'].join('\n'), 'sb.sh').interpreter).toBe('zsh');
  });

  it('accepts a task with no "# readonly:" declaration — the header is retired (#61)', () => {
    // Risk is the single authorization axis now; `readonly` was never a
    // safety property (a read-only task can read secrets), so it is no
    // longer required, and a stored file that still carries it parses.
    expect(parse(base.filter((l) => !l.startsWith('# readonly')))).not.toThrow();
    expect(parse(base)).not.toThrow();
  });

  it("a default is checked with the SAME Unicode semantics Ajv validates by (review 2388)", () => {
    const withParam = (lines: string[]) => parseTaskFile(['#!/usr/bin/env bash', ...base, ...lines, '# xtrape-script:', 'echo hi'].join('\n'), 'u.sh');
    // maxLength counts CODE POINTS: an emoji is one, not two.
    expect(() => withParam(['# param: p optional string t', '# param.p.maxLength: 1', '# param.p.default: 😀'])).not.toThrow();
    expect(() => withParam(['# param: p optional string t', '# param.p.maxLength: 1', '# param.p.default: ab'])).toThrow(/longer than its maxLength/);
    // `pattern` is compiled with the `u` flag, so a Unicode property escape
    // means what it means at validation time.
    expect(() => withParam(['# param: p optional string t', '# param.p.pattern: ^\\p{L}+$', '# param.p.default: 世界'])).not.toThrow();
    expect(() => withParam(['# param: p optional string t', '# param.p.pattern: ^\\p{L}+$', '# param.p.default: 12'])).toThrow(/does not match its own pattern/);
  });

  it('refuses a constraint that names a parameter which was never declared', () => {
    // Silently ignoring it would leave the operator believing a parameter is
    // constrained when nothing constrains it.
    expect(parse([...base, '# param.path.pattern: ^/'])).toThrow(/not declared/);
  });

  it('refuses a malformed parameter line rather than guessing', () => {
    expect(parse([...base, '# param: path string'])).toThrow(/malformed/);
  });

  it('refuses a parameter that is not a usable environment variable name', () => {
    expect(parse([...base, '# param: my-path required string x'])).toThrow(/malformed/);
  });

  it('refuses a non-scalar parameter at registration', () => {
    const registry = new ActionRegistry();
    const task = parseExample('system-uptime.sh');
    expect(() =>
      registry.register({
        ...task,
        params: { type: 'object', properties: { hosts: { type: 'array' } }, additionalProperties: false },
      }),
    ).toThrow(/scalar/);
  });
});

describe('how a parameter crosses the boundary', () => {
  it('sends parameters as environment values, never as words of the command', () => {
    const command = buildTaskCommand('bash', { path: '/etc', namePattern: "*.conf'; touch pwned; #" });
    // Everything after the assignments is fixed text: the interpreter and its
    // stdin flag. No caller value can add a word to it.
    expect(command.endsWith(' bash -s')).toBe(true);
    expect(command.startsWith("XOPS_namePattern='")).toBe(true);
    expect(command).toContain("XOPS_path='/etc'");
  });

  it('omits a parameter that was not supplied, so the script sees it unset', () => {
    expect(buildTaskCommand('bash', { a: '1', b: undefined })).toBe("XOPS_a='1' bash -s");
    // The interpreter's own arguments come from the shebang and are passed
    // through before `-s` (review 2370): `#!/bin/sh -e` really runs -e.
    expect(buildTaskCommand('/bin/sh', { a: '1' }, undefined, ['-e'])).toBe("XOPS_a='1' /bin/sh -e -s");
    expect(maskedTaskCommand('/bin/sh', { a: '1' }, ['-e'])).toBe("XOPS_a='***' /bin/sh -e -s");
  });

  it('masks values for audit while still naming which parameters were supplied', () => {
    const masked = maskedTaskCommand('bash', { ref: '0.8.6' });
    expect(masked).toBe("XOPS_ref='***' bash -s");
    expect(masked).not.toContain('0.8.6');
  });
});

/**
 * The delivery mechanism, run for real against a local shell: the command line
 * carries the parameters, the script arrives on standard input. This is the
 * same pair `OpsService` hands the SSH executor.
 */
describe('the interpreter is invoked FAITHFULLY, and really executes that way (review 2371)', () => {
  /**
   * Execution-level, not string-level: the command this Widget builds is
   * handed to a real shell with the script on stdin — the same pair the SSH
   * executor sends — and the assertions are about what the script DID.
   */
  const runTask = (source: string): { code: number; stdout: string } => {
    const task = parseTaskFile(source, 'exec.sh');
    const res = spawnSync('/bin/sh', ['-c', buildTaskCommand(task.interpreter, {}, undefined, task.interpreterArgs ?? [], task.interpreterStdinArg ?? '-s')], {
      encoding: 'utf8',
      input: task.script,
    });
    return { code: res.status ?? -1, stdout: res.stdout };
  };
  const header = (shebang: string) => `${shebang}
# xtrape-task: exec.demo
# version: 1.0.0
# risk: low
# servers: *
# xtrape-script:
`;

  it("honours a shell shebang's own flags: -e really stops at the first failure", () => {
    const body = 'false\necho reached\n';
    // Without -e the script continues, which is the shell's own default.
    const plain = runTask(header('#!/bin/sh') + body);
    expect(plain.stdout).toContain('reached');
    // With -e the author asked for the opposite, and gets it.
    const strict = runTask(header('#!/bin/sh -e') + body);
    expect(strict.stdout).not.toContain('reached');
    expect(strict.code).not.toBe(0);
  });

  it('runs a python task as PYTHON reading stdin — never `python3 -s`, which means something else', () => {
    const probe = spawnSync('python3', ['-c', 'print(1)'], { encoding: 'utf8' });
    if (probe.status !== 0) return; // no python3 on this host; the string-level assertion below still holds
    const out = runTask(header('#!/usr/bin/env python3 -u') + 'import sys\nprint("py", sys.version_info[0])\n');
    expect(out.code).toBe(0);
    expect(out.stdout).toContain('py 3');
  });

  it('builds the stdin argument per interpreter, not a universal -s', () => {
    expect(buildTaskCommand('/bin/sh', {}, undefined, ['-e'], '-s')).toBe('/bin/sh -e -s');
    expect(buildTaskCommand('python3', {}, undefined, ['-u'], '-')).toBe('python3 -u -');
    expect(buildTaskCommand('perl', {}, undefined, [], '-')).toBe('perl -');
    // An author who already spelled the stdin argument gets it once.
    expect(buildTaskCommand('bash', {}, undefined, ['-s'], '-s')).toBe('bash -s');
  });

  it('fails CLOSED on an interpreter it cannot invoke faithfully, and on ANY option not known to be safe (review 2373)', () => {
    expect(() => parseTaskFile(header('#!/usr/bin/env node') + 'console.log(1)\n', 'x.sh')).toThrow(/not one this Widget can run/);
    // Exact source options…
    expect(() => parseTaskFile(header('#!/bin/sh -c') + 'echo hi\n', 'x.sh')).toThrow(/not one this Widget knows to be safe/);
    expect(() => parseTaskFile(header('#!/usr/bin/env python3 -c') + 'print(1)\n', 'x.sh')).toThrow(/not one this Widget knows to be safe/);
    // …and the shapes a deny-list missed: a COMBINED cluster carrying `c`,
    // and an ATTACHED value (`-cCODE`, `-mMOD`, `-eCODE`).
    expect(() => parseTaskFile(header('#!/bin/sh -ec') + 'echo hi\n', 'x.sh')).toThrow(/not one this Widget knows to be safe/);
    // (charset-clean so the allow-list is what refuses it, not the syntax check)
    expect(() => parseTaskFile(header('#!/usr/bin/env python3 -cpass') + 'x\n', 'x.sh')).toThrow(/not one this Widget knows to be safe/);
    expect(() => parseTaskFile(header('#!/usr/bin/env python3 -mjson') + 'x\n', 'x.sh')).toThrow(/not one this Widget knows to be safe/);
    expect(() => parseTaskFile(header('#!/usr/bin/env perl -eprint') + 'x\n', 'x.sh')).toThrow(/not one this Widget knows to be safe/);
    // A cluster of ADMITTED letters is fine — the author's -e -u -x.
    expect(parseTaskFile(header('#!/bin/sh -eux') + 'echo hi\n', 'x.sh').interpreterArgs).toEqual(['-eux']);
  });

  it('a shebang that names NO interpreter is refused — only a missing shebang defaults to bash (review 2374)', () => {
    // Started the sentence and did not finish it: answering "bash" would put
    // words in the author's mouth.
    expect(() => parseTaskFile(header('#!') + 'echo hi\n', 'x.sh')).toThrow(/names no interpreter/);
    expect(() => parseTaskFile(header('#!/usr/bin/env') + 'echo hi\n', 'x.sh')).toThrow(/names no interpreter/);
    expect(() => parseTaskFile(header('#!   ') + 'echo hi\n', 'x.sh')).toThrow(/names no interpreter/);
    // No shebang at all keeps the historical default, unchanged.
    const noShebang = parseTaskFile(`# xtrape-task: exec.demo
# version: 1.0.0
# risk: low
# servers: *
# xtrape-script:
echo hi
`, 'x.sh');
    expect(noShebang.interpreter).toBe('bash');
    expect(noShebang.interpreterStdinArg).toBe('-s');
  });

  it('refuses env forms whose environment settings cannot be delivered, instead of dropping them (review 2373)', () => {
    expect(() => parseTaskFile(header('#!/usr/bin/env FOO=bar python3') + 'print(1)\n', 'x.sh')).toThrow(/cannot deliver/);
    expect(() => parseTaskFile(header('#!/usr/bin/env -i bash') + 'echo hi\n', 'x.sh')).toThrow(/cannot deliver/);
    // The plain launcher form stays exactly as it was.
    expect(parseTaskFile(header('#!/usr/bin/env bash') + 'echo hi\n', 'x.sh').interpreter).toBe('bash');
  });

  it('a stored task with the retired "# interpreter:" header keeps its FROZEN invocation (review 2373)', () => {
    // The closed set is the SHEBANG contract; it must not reach back into
    // frozen revisions — neither to refuse them nor to change how they run.
    const legacy = (command: string) => parseTaskFile(
      `#!/usr/bin/env bash
# xtrape-task: exec.legacy
# version: 1.0.0
# risk: low
# servers: *
# interpreter: ${command}
echo hi
`,
      'legacy.sh',
    );
    // An interpreter the new table never heard of still parses…
    const node = legacy('node');
    expect(node.interpreter).toBe('node');
    // …and every legacy task keeps the `-s` it has always been run with,
    // including one whose command IS in the table with a different argument.
    expect(node.interpreterStdinArg).toBe('-s');
    expect(legacy('python3').interpreterStdinArg).toBe('-s');
    expect(buildTaskCommand('python3', {}, undefined, [], legacy('python3').interpreterStdinArg)).toBe('python3 -s');
  });
});

describe('running a shipped task the way the executor runs it', () => {
  const task = parseExample('file-find.sh');
  let dir: string;

  const run = (args: Record<string, unknown>): { code: number; stdout: string; stderr: string } => {
    const res = spawnSync('/bin/sh', ['-c', buildTaskCommand(task.interpreter, args)], {
      encoding: 'utf8',
      input: task.script,
      cwd: dir,
    });
    return { code: res.status ?? -1, stdout: res.stdout, stderr: res.stderr };
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'task-find-'));
    writeFileSync(join(dir, 'keep.conf'), 'keep');
    writeFileSync(join(dir, 'other.txt'), 'other');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  /** The task needs `timeout` (coreutils); it is on the Linux targets, not on every dev machine. */
  const hasTimeout = spawnSync('/bin/sh', ['-c', 'command -v timeout'], { encoding: 'utf8' }).status === 0;

  it('does the thing it says it does', () => {
    // Driven with a root of this test's own, because the admitted-root ENUM is
    // enforced by the schema (asserted below), not by the script — so this
    // exercises the delivery path and the script, without depending on what
    // exists under `/etc` on whatever machine runs the suite.
    const { code, stdout, stderr } = run({ root: dir, namePattern: '*.conf' });
    if (!hasTimeout) {
      // Asserted rather than skipped, because it is the repository's rule for
      // a missing command: the shell says `command not found` and exits 127,
      // the task fails, and that report reaches the caller unaltered. Nothing
      // ran unbounded, and nothing dressed the message up.
      expect(code).toBe(127);
      expect(stderr).toContain('timeout');
      return;
    }
    expect(code).toBe(0);
    expect(stdout).toContain('keep.conf');
    expect(stdout).not.toContain('other.txt');
  });

  /**
   * Runs the task with `find` and `timeout` stubbed, so the status the task
   * reports for a given underlying status is observable on any host.
   *
   * The previous version of this test asserted that the script CONTAINED
   * `timeout 20s find` and `124`. Both strings were present the whole time the
   * script was reporting a timeout as success (review 2164): `status=$?` after
   * `if ! cmd` reads the status of the negation, which is 0. A test that reads
   * the source proves the source says something, not that it does it.
   */
  const withStubbedFind = (findExit: number): number => {
    const bin = mkdtempSync(join(tmpdir(), 'stub-bin-'));
    try {
      writeFileSync(join(bin, 'find'), `#!/bin/sh\nexit ${String(findExit)}\n`);
      // Drops the duration and runs the rest, so the stubbed `find` decides.
      writeFileSync(join(bin, 'timeout'), '#!/bin/sh\nshift\nexec "$@"\n');
      chmodSync(join(bin, 'find'), 0o755);
      chmodSync(join(bin, 'timeout'), 0o755);
      const res = spawnSync('/bin/sh', ['-c', buildTaskCommand(task.interpreter, { root: '/etc', namePattern: '*.conf' })], {
        encoding: 'utf8',
        input: task.script,
        env: { ...process.env, PATH: `${bin}:${process.env['PATH'] ?? ''}` },
      });
      return res.status ?? -1;
    } finally {
      rmSync(bin, { recursive: true, force: true });
    }
  };

  it('reports a search that finished as success', () => {
    expect(withStubbedFind(0)).toBe(0);
  });

  it('reports a search cut off by its own bound, and does not call it success', () => {
    // A search matching nothing produces no output, so the wire ceiling never
    // fires; and the execution timeout ends the connection, not the remote
    // `find`. `timeout` is what bounds it, and its 124 becomes this task's
    // own 3 rather than a search that quietly found nothing.
    expect(withStubbedFind(124)).toBe(3);
  });

  it('passes a genuine find failure through, rather than swallowing it', () => {
    expect(withStubbedFind(7)).toBe(7);
  });

  it('admits only the roots the operator listed', () => {
    const registry = loadExamples();
    expect(registry.validateArgs('file.find', { root: '/etc', namePattern: '*.conf' }).ok).toBe(true);
    // Any absolute path used to satisfy this. An operator-admitted enum is
    // what stops the task being a general filesystem reader on every server it
    // is scoped to (review 2157) — `-xdev` and `-maxdepth` bound where
    // traversal goes, not what a caller may point it at.
    for (const root of ['/', '/home', '/proc', '/etc/../home', '/opt/../root']) {
      expect(registry.validateArgs('file.find', { root, namePattern: '*' }).ok, root).toBe(false);
    }
  });

  it('cannot be made to run a second command through a parameter', () => {
    // The value is not part of the operator's script, so there is nothing
    // there for a shell to re-parse. `find` simply matches nothing.
    const { code, stdout } = run({ root: dir, namePattern: "*.conf'; touch injected; echo '" });
    // The property under test holds either way: nothing ran. On a host without
    // `timeout` the script refuses before searching at all, which is also
    // nothing running.
    expect(existsSync(join(dir, 'injected'))).toBe(false);
    expect(stdout).not.toContain('keep.conf');
    expect(code).toBe(hasTimeout ? 0 : 127);
  });

  it('refuses a name pattern that find would read as an option', () => {
    // Quoting never covered this: to `find`, a leading `-` is an option and
    // not data. The script checks, in the open.
    // Checked before `timeout` is even looked for, so this holds on any host.
    expect(run({ root: dir, namePattern: '-delete' }).code).toBe(2);
    expect(readdirSync(dir).sort()).toEqual(['keep.conf', 'other.txt']);
  });
});

describe('a mistyped declaration must not widen anything (review 2157)', () => {
  const base = ['# xtrape-task: t.one', '# version: 1.0.0', '# risk: low', '# readonly: true', '# servers: web-*'];
  const parse = (lines: string[]) => () => parseTaskFile(lines.join('\n'), 't.sh');

  it('refuses an unknown declaration instead of ignoring it', () => {
    // `# server:` was silently ignored, and the missing `# servers:` then
    // defaulted to every server — a typo that widened scope.
    expect(parse([...base.filter((l) => !l.startsWith('# servers')), '# server: web-*'])).toThrow(/unknown declaration/);
    expect(parse([...base, '# aproval: always_human'])).toThrow(/unknown declaration/);
  });

  it('refuses a task that names no server scope, rather than assuming every server', () => {
    expect(parse(base.filter((l) => !l.startsWith('# servers')))).toThrow(/servers/);
    // An operator who means every server says so.
    expect(parseTaskFile([...base.filter((l) => !l.startsWith('# servers')), '# servers: *'].join('\n'), 't.sh').serverScopes).toEqual(['*']);
  });
});

describe('constraints are read in the parameter\'s own type (review 2157)', () => {
  const base = ['# xtrape-task: t.one', '# version: 1.0.0', '# risk: low', '# readonly: true', '# servers: *'];
  const parse = (lines: string[]) => parseTaskFile([...base, ...lines].join('\n'), 't.sh');

  it('gives an integer parameter integer enum members', () => {
    // Written as strings this produced {"type":"integer","enum":["1","2"]} —
    // a schema no integer satisfies, so the task was quietly unusable.
    const task = parse(['# param: retries required integer', '# param.retries.enum: 1|2']);
    const props = (task.params as { properties: Record<string, { enum?: unknown[] }> }).properties;
    expect(props['retries']?.enum).toEqual([1, 2]);

    const registry = new ActionRegistry();
    registry.register(task);
    expect(registry.validateArgs('t.one', { retries: 2 }).ok).toBe(true);
    expect(registry.validateArgs('t.one', { retries: 3 }).ok).toBe(false);
  });

  it('lets a number parameter carry a fractional bound', () => {
    const task = parse(['# param: ratio required number', '# param.ratio.minimum: 0.5']);
    const props = (task.params as { properties: Record<string, { minimum?: unknown }> }).properties;
    expect(props['ratio']?.minimum).toBe(0.5);
  });

  it('refuses a constraint that cannot apply to the parameter type', () => {
    expect(() => parse(['# param: retries required integer', '# param.retries.maxLength: 4'])).toThrow(/string parameters only/);
    expect(() => parse(['# param: retries required integer', '# param.retries.pattern: ^1$'])).toThrow(/string parameters only/);
    expect(() => parse(['# param: name required string', '# param.name.minimum: 1'])).toThrow(/numeric parameters only/);
  });

  it('refuses an integer bound that is not an integer', () => {
    expect(() => parse(['# param: retries required integer', '# param.retries.minimum: 0.5'])).toThrow(/integer/);
  });
});

describe('a constraint cannot be quietly replaced (review 2159)', () => {
  const base = ['# xtrape-task: t.one', '# version: 1.0.0', '# risk: low', '# readonly: true', '# servers: *'];
  const parse = (lines: string[]) => () => parseTaskFile([...base, ...lines].join('\n'), 't.sh');

  it('refuses the same constraint declared twice', () => {
    // The second line silently replaced the first, so a repeated `enum` could
    // put back exactly what the first one excluded — widening the boundary the
    // operator wrote the constraint to draw.
    expect(parse(['# param: root required string', '# param.root.enum: /etc', '# param.root.enum: /etc|/'])).toThrow(/declared twice/);
    expect(parse(['# param: p required string', '# param.p.pattern: ^/a', '# param.p.pattern: ^/'])).toThrow(/declared twice/);
  });

  it('still lets different constraints on the same parameter coexist', () => {
    const task = parseTaskFile([...base, '# param: p required string', '# param.p.pattern: ^/', '# param.p.maxLength: 64'].join('\n'), 't.sh');
    const props = (task.params as { properties: Record<string, Record<string, unknown>> }).properties;
    expect(props['p']).toMatchObject({ pattern: '^/', maxLength: 64 });
  });

  it('refuses bounds that cross, which admit nothing', () => {
    expect(parse(['# param: n required integer', '# param.n.minimum: 10', '# param.n.maximum: 1'])).toThrow(/greater than maximum/);
  });
});

describe('a numeric declaration must mean what it says (review 2162)', () => {
  const base = ['# xtrape-task: t.one', '# version: 1.0.0', '# risk: low', '# readonly: true', '# servers: *'];
  const parse = (lines: string[]) => () => parseTaskFile([...base, ...lines].join('\n'), 't.sh');

  it('refuses an integer past the range that survives exactly', () => {
    // 9007199254740993 becomes ...992, so the schema would admit a value the
    // operator never wrote — an enum silently gaining a member.
    expect(parse(['# param: n required integer', '# param.n.enum: 1|9007199254740993'])).toThrow(/exactly/);
    expect(parse(['# param: n required integer', '# param.n.maximum: 9007199254740993'])).toThrow(/exactly/);
  });

  it('refuses exponent form, where a literal most easily stops meaning what it says', () => {
    // `1e400` becomes Infinity and `1e-400` becomes 0. Both parse cleanly, and
    // both declare a bound the operator did not write (review 2162/2164).
    expect(parse(['# param: r required number', '# param.r.maximum: 1e400'])).toThrow(/plain decimal/);
    expect(parse(['# param: r required number', '# param.r.minimum: 1e-400'])).toThrow(/plain decimal/);
  });

  it('refuses a decimal that does not survive conversion', () => {
    // 9007199254740992.5 becomes ...992: to the operator's own precision it is
    // a different number from the one in the file.
    expect(parse(['# param: r required number', '# param.r.maximum: 9007199254740992.5'])).toThrow(/does not survive/);
  });

  it('refuses a plain decimal too large to represent', () => {
    expect(parse(['# param: r required number', `# param.r.maximum: 1${'0'.repeat(400)}`])).toThrow(/too large/);
  });

  it('accepts decimals that are not exactly representable but do mean what they say', () => {
    // 0.1 is not exact in binary. It is still accepted, because to one decimal
    // place it is 0.1 and every comparison against this bound uses that same
    // value — the test is whether the LITERAL survived, not whether binary
    // floating point is exact.
    for (const [raw, expected] of [['0.1', 0.1], ['0.0000001', 1e-7], ['-2.50', -2.5], ['007', 7]] as const) {
      const task = parseTaskFile([...base, '# param: r required number', `# param.r.minimum: ${raw}`].join('\n'), 't.sh');
      const props = (task.params as { properties: Record<string, { minimum?: number }> }).properties;
      expect(props['r']?.minimum, raw).toBe(expected);
    }
  });

  it('still accepts values inside the range', () => {
    const task = parseTaskFile([...base, '# param: n required integer', '# param.n.maximum: 9007199254740991'].join('\n'), 't.sh');
    const props = (task.params as { properties: Record<string, { maximum?: number }> }).properties;
    expect(props['n']?.maximum).toBe(9_007_199_254_740_991);
  });
});

describe('a command the target does not have', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'missing-cmd-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const runScript = (script: string): { code: number; stderr: string } => {
    const res = spawnSync('/bin/sh', ['-c', buildTaskCommand('bash', {})], {
      encoding: 'utf8',
      input: script,
      cwd: dir,
      // A minimal PATH, so the "missing" command really is missing.
      env: { PATH: '/usr/bin:/bin', HOME: process.env['HOME'] ?? '' },
    });
    return { code: res.status ?? -1, stderr: res.stderr };
  };

  it('is reported exactly as the shell reported it, with nothing added', () => {
    const { code, stderr } = runScript('xtrape-no-such-command --go\n');
    expect(code).toBe(127);
    expect(stderr).toContain('xtrape-no-such-command');
    expect(stderr).toMatch(/not found/);
  });

  it('behaves exactly as the same script would in a shell on the target', () => {
    // No `set -e`, so the shell carries on — and so does the task. This Widget
    // delivers the operator's intent; it does not interpret it. Turning on
    // `-e` for everyone would silently change the meaning of every script that
    // did not ask for it, which is the one thing a delivery tool must not do.
    const { code } = runScript(
      ['touch step-one', 'xtrape-no-such-command', 'touch step-three'].join('\n') + '\n',
    );
    // The last command decides the status, the same as it would on the target.
    expect(code).toBe(0);
    expect(readdirSync(dir).sort()).toEqual(['step-one', 'step-three']);
  });

  it('stops where the author said to stop, and only where they said it', () => {
    // The same script with the author's own `set -e`: the sentence is theirs
    // to write, in their own file, where a reader can see it.
    const { code } = runScript(
      ['set -e', 'touch step-one', 'xtrape-no-such-command', 'touch step-three'].join('\n') + '\n',
    );
    expect(code).toBe(127);
    expect(readdirSync(dir).sort()).toEqual(['step-one']);
  });

  it('leaves a script that handles the failure in charge of it', () => {
    const { code } = runScript(
      ['status=0', 'xtrape-no-such-command || status=$?', 'touch ran-anyway', 'exit "$status"'].join('\n') + '\n',
    );
    expect(code).toBe(127);
    expect(readdirSync(dir)).toContain('ran-anyway');
  });
});

describe('a task declares its own deadline, or none (owner, 2026-08-08)', () => {
  const base = ['# xtrape-task: t.one', '# version: 1.0.0', '# risk: low', '# readonly: true', '# servers: *'];

  it('has no deadline unless the task asks for one', () => {
    // Many tasks legitimately run for a long time. A Worker-side clock over
    // every task was this Widget deciding something no author asked for.
    expect(parseTaskFile(base.join('\n'), 't.sh').timeoutSeconds).toBeUndefined();
  });

  it('carries the one the task declared', () => {
    expect(parseTaskFile([...base, '# timeout: 900'].join('\n'), 't.sh').timeoutSeconds).toBe(900);
  });

  it('refuses a deadline that bounds nothing', () => {
    expect(() => parseTaskFile([...base, '# timeout: 0'].join('\n'), 't.sh')).toThrow(/positive/);
    expect(() => parseTaskFile([...base, '# timeout: -5'].join('\n'), 't.sh')).toThrow(/positive/);
  });

  it('gives the shipped deploy example room for a real pull', () => {
    // The flagship example runs `docker compose pull` + `up -d`. Under the
    // retired 60-second Worker deadline it could not finish on a real target.
    expect(parseExample('xtrape-deploy.sh').timeoutSeconds).toBe(900);
  });
});

describe('one command, one execution (owner, 2026-08-08)', () => {
  it('answers a repeated delivery with the first outcome, without running again', async () => {
    // This Widget does not retry, but that says nothing about being ASKED
    // twice: a retried push or a reconnect can deliver the same commandId
    // again, and re-running a task with side effects would be an effect nobody
    // requested.
    const { OpsService } = await import('../src/service.js');
    const { MemoryAuditLogger } = await import('../src/audit.js');
    const helpers = await import('./helpers.js');
    const executor = new helpers.FakeExecutor();
    const server = helpers.makeServer();
    const service = new OpsService({
      registry: helpers.makeRegistry(helpers.makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime\n' })),
      servers: { get: (id: string) => (id === server.id ? server : undefined), list: () => [server] },
      executors: [executor],
      audit: new MemoryAuditLogger(),
    });
    const ctx = { surface: 'platform' as const, controlPlaneAvailable: true, commandId: 'cmd_1' };
    const req = { serverId: server.id, actionId: 'system.uptime', args: {}, reason: 'twice' };

    const first = await service.execute(req, ctx);
    const second = await service.execute(req, ctx);

    expect(first.status).toBe('executed');
    expect(second).toBe(first);
    expect(executor.commands).toHaveLength(1);
  });

  it('runs each distinct command, and anything with no commandId at all', async () => {
    const { OpsService } = await import('../src/service.js');
    const { MemoryAuditLogger } = await import('../src/audit.js');
    const helpers = await import('./helpers.js');
    const executor = new helpers.FakeExecutor();
    const server = helpers.makeServer();
    const service = new OpsService({
      registry: helpers.makeRegistry(helpers.makeAction({ id: 'system.uptime', readonly: true, serverScopes: ['*'], script: 'uptime\n' })),
      servers: { get: (id: string) => (id === server.id ? server : undefined), list: () => [server] },
      executors: [executor],
      audit: new MemoryAuditLogger(),
    });
    const req = { serverId: server.id, actionId: 'system.uptime', args: {}, reason: 'distinct' };
    await service.execute(req, { surface: 'platform', controlPlaneAvailable: true, commandId: 'cmd_a' });
    await service.execute(req, { surface: 'platform', controlPlaneAvailable: true, commandId: 'cmd_b' });
    await service.execute(req, { surface: 'platform', controlPlaneAvailable: true });
    expect(executor.commands).toHaveLength(3);
  });
});
