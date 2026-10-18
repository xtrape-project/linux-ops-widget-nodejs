import { createHash } from 'node:crypto';
import type { ActionDefinition, ApprovalPolicy, RiskLevel } from './types.js';
import { PARAM_ENV_PREFIX, shebangOptionAdmitted, stdinInvocationFor, SUPPORTED_INTERPRETERS } from './shell.js';

/**
 * A task is one shell script file. The file IS the task: the operator writes
 * the commands, and a header of `# key: value` comment lines declares what the
 * Widget needs to know about it — its identity, who may run it on which
 * servers, and which parameters it accepts.
 *
 * The header stops at the first line that is neither the shebang, a comment,
 * nor blank, so the declaration cannot drift into the body.
 */
/**
 * Explicit end-of-declarations marker; the canonical render always emits it.
 * Deliberately HEADER_LINE-shaped with a key the old grammar never knew
 * (review 2355): the pre-marker parser REFUSED unknown `# key:` declarations
 * in the header block, so no valid legacy file can contain this line — a
 * plain `# ---` comment, which legacy files may legally hold, is NOT the
 * marker and stays an ignored comment.
 */
export const HEADER_END_MARKER = '# xtrape-script:';

const HEADER_LINE = /^#\s*([A-Za-z][A-Za-z0-9_.-]*)\s*:\s*(.*)$/;

/** `# param: <name> <required|optional> <type> <description…>` */
const PARAM_LINE = /^([A-Za-z_][A-Za-z0-9_]*)\s+(required|optional)\s+(string|integer|number|boolean)(?:\s+(.*))?$/;

/**
 * Parameters cross the boundary as environment variables, so a name has to be
 * a portable environment variable name — and one the prefix keeps clear of the
 * target's own environment.
 */
const PARAM_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

const TASK_ID = /^[a-z0-9]+(\.[a-z0-9_-]+)+$/;
const VERSION = /^\d+\.\d+\.\d+$/;
const INTERPRETER = /^[A-Za-z0-9_./-]+$/;
const INTERPRETER_ARG = /^[A-Za-z0-9_.=/-]+$/;

/**
 * Every header key this parser understands. An unknown key is REFUSED, not
 * ignored: a task file is a safety declaration, and the failure mode of
 * tolerance is silent widening — `# server: web-*` misspelt would fall back to
 * every server, `# aproval: always_human` to ordinary policy (review 2157).
 */
const KNOWN_HEADERS = new Set<string>([
  'xtrape-task',
  'title',
  'version',
  'description',
  'executor',
  'risk',
  'readonly',
  'servers',
  'approval',
  'interpreter',
  'maxBytes',
  'timeout',
]);

const RISK_LEVELS = new Set<string>(['low', 'medium', 'high', 'critical']);
const APPROVAL_POLICIES = new Set<string>(['policy', 'always_human', 'forbidden']);

interface ParamSpec {
  type: string;
  /** Operator-facing field label (#61 C-8); becomes the schema's `title`. */
  title?: string;
  /** Value the form starts from; becomes the schema's `default`. */
  default?: string | number | boolean;
  description?: string;
  pattern?: string;
  enum?: (string | number | boolean)[];
  maxLength?: number;
  minimum?: number;
  maximum?: number;
}

const STRING_ONLY = new Set(['pattern', 'maxLength']);
const NUMERIC_ONLY = new Set(['minimum', 'maximum']);

function parseBoolean(key: string, raw: string): boolean {
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  throw new Error(`"${key}" must be true or false, got "${raw}"`);
}

function parseInteger(key: string, raw: string): number {
  if (!/^-?\d+$/.test(raw)) throw new Error(`"${key}" must be an integer, got "${raw}"`);
  const value = Number(raw);
  // `Number('9007199254740993')` is 9007199254740992. Past the safe range the
  // schema would admit a value the operator did not write — a boundary
  // declaration that quietly moved is worse than one that failed to load
  // (review 2162).
  if (!Number.isSafeInteger(value)) {
    throw new Error(`"${key}" is outside the range integers survive exactly (±${String(Number.MAX_SAFE_INTEGER)}), so "${raw}" would not mean what it says`);
  }
  return value;
}

/**
 * Read a bound in the parameter's OWN type. `minimum` on a `number` may be
 * fractional; on an `integer` it may not, or the schema would admit a bound the
 * parameter can never take.
 */
function parseBound(key: string, raw: string, type: string): number {
  if (type === 'integer') return parseInteger(key, raw);

  // Plain decimal only. Exponent form is where a literal most easily stops
  // meaning what it says — `1e-400` parses cleanly and becomes 0 — and a task
  // file has no need for it.
  const parts = /^(-?)(\d+)(?:\.(\d+))?$/.exec(raw);
  if (!parts) throw new Error(`"${key}" must be a plain decimal number such as 1.5 or -20 (no exponent form), got "${raw}"`);
  const fraction = parts[3] ?? '';
  if (fraction.length > 100) throw new Error(`"${key}" has more decimal places than a number can carry, so "${raw}" would not mean what it says`);

  const value = Number(raw);
  if (!Number.isFinite(value)) throw new Error(`"${key}" is too large to represent, so "${raw}" would bound nothing`);

  // Does the parsed value still say what the operator wrote? Compared at the
  // operator's OWN precision, which is the question that matters: `0.1` is not
  // exactly representable in binary and is accepted, because to one decimal
  // place it is 0.1 and every comparison against this bound uses that same
  // value. `9007199254740992.5` is refused, because to one decimal place it is
  // ...992.0 — a different number from the one in the file (review 2164).
  const written = normalizeDecimal(parts[1] as string, parts[2] as string, fraction);
  if (value.toFixed(fraction.length) !== written) {
    throw new Error(`"${key}" does not survive conversion: "${raw}" becomes ${value.toFixed(fraction.length)}, so the declared bound would not be the one written`);
  }
  return value;
}

/** The written literal in the shape `toFixed` produces, so the two compare. */
function normalizeDecimal(sign: string, integer: string, fraction: string): string {
  const digits = `${integer.replace(/^0+(?=\d)/, '')}${fraction === '' ? '' : `.${fraction}`}`;
  // `toFixed` never signs a zero, so neither does this.
  const signed = /^0(\.0*)?$/.test(digits) ? '' : sign;
  return `${signed}${digits}`;
}

/**
 * Read enum members in the parameter's OWN type.
 *
 * Written as strings unconditionally, `# param.retries.enum: 1|2` on an
 * `integer` produced `{"type":"integer","enum":["1","2"]}` — a schema no
 * integer can satisfy, so the parameter was unusable and the task silently
 * unreachable rather than loudly wrong (review 2157).
 */
function parseEnum(key: string, raw: string, type: string): (string | number | boolean)[] {
  const members = raw.split('|').map((v) => v.trim());
  if (members.length === 0 || members.some((v) => v === '')) throw new Error(`"${key}" has an empty member`);
  if (type === 'string') return members;
  if (type === 'boolean') return members.map((v) => parseBoolean(key, v));
  return members.map((v) => parseBound(key, v, type));
}

/**
 * Parse one task script into the definition the rest of the Widget consumes.
 *
 * The whole file — header included — is kept as `script`: it is what gets fed
 * to the interpreter, and `scriptDigest` covers exactly those bytes, so the
 * audit record names the precise text that ran.
 */
/**
 * The command a script's shebang names, or `bash` when it has none.
 * `#!/usr/bin/env python3` → `python3`; `#!/bin/sh -e` → `sh` (arguments are
 * dropped: the script arrives on stdin, so a shebang's flags cannot be
 * honoured without writing the file to the target).
 */
export function interpreterFromShebang(source: string): { command: string; args: string[]; envExtras?: string[]; malformed?: string } {
  const first = source.split('\n', 1)[0] ?? '';
  // NO shebang is the only case that defaults (review 2374): a file that
  // says nothing about its interpreter has always been read as `bash`. A
  // file that DOES open a shebang and then names no command is a different
  // thing — the author started saying which interpreter to use and did not
  // finish — and answering "bash" would put words in their mouth.
  if (!first.startsWith('#!')) return { command: 'bash', args: [] };
  const parts = first.slice(2).trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return { command: 'bash', args: [], malformed: first.trim() };
  let command = parts[0] as string;
  let rest = parts.slice(1);
  // `env` is a launcher, not the interpreter: take what it would exec, and
  // keep the arguments meant for THAT command (env's own options and
  // NAME=VALUE assignments are dropped — they configure env, not the script).
  if (/(^|\/)env$/.test(command)) {
    // `env` is a launcher, and only its PLAIN form is supported (review
    // 2373): anything before the command — its own options (`-i`, `-u`,
    // `-S`) or `NAME=VALUE` assignments — configures the environment the
    // script runs in, and silently dropping that would run the author's
    // script under an environment they did not ask for. (On Linux the
    // kernel hands the whole line to `env` as ONE argument anyway, so such
    // shebangs do not work outside `env -S` to begin with.) Refusing is
    // reported by the caller, which has the failure vocabulary.
    // `#!/usr/bin/env` with nothing after it names no interpreter either.
    if (rest.length === 0) return { command: 'bash', args: [], malformed: first.trim() };
    const [next, ...after] = rest as [string, ...string[]];
    if (next.startsWith('-') || next.includes('=')) return { command: 'bash', args: [], envExtras: rest };
    command = next;
    rest = after;
  }
  // Arguments are kept VERBATIM (review 2370): `#!/bin/sh -e` means the
  // author asked for -e, and dropping it silently changes what the script
  // does. Feeding the script on stdin does not prevent `/bin/sh -e -s`.
  return { command, args: rest };
}

export function parseTaskFile(source: string, sourceFile: string): ActionDefinition {
  const fail = (message: string): never => {
    throw new Error(`task file ${sourceFile}: ${message}`);
  };

  const header = new Map<string, string>();
  const params = new Map<string, ParamSpec>();
  const paramOrder: string[] = [];
  const declaredConstraints = new Set<string>();
  const required: string[] = [];
  const redact: string[] = [];

  for (const line of source.split('\n')) {
    if (line.startsWith('#!')) continue;
    const trimmed = line.trim();
    if (trimmed === '') continue;
    if (!trimmed.startsWith('#')) break;

    const match = HEADER_LINE.exec(trimmed);
    // A plain comment among the declarations is a comment, not an error.
    if (!match) continue;
    const key = match[1] as string;
    // The explicit header/body boundary (reviews 2354/2355): everything
    // after this marker is the operator's script VERBATIM, even lines that
    // look like declarations — the canonical render always emits it, so a
    // body that begins with "# executor: ..." can never be re-read as
    // metadata.
    if (key === 'xtrape-script') break;
    const value = (match[2] as string).trim();

    if (key === 'param') {
      const p = PARAM_LINE.exec(value);
      if (!p) {
        fail(`malformed "# param:" line — expected "<name> <required|optional> <string|integer|number|boolean> [description]", got "${value}"`);
        return undefined as never;
      }
      const name = p[1] as string;
      if (params.has(name)) fail(`parameter "${name}" declared twice`);
      const description = p[4]?.trim();
      params.set(name, { type: p[3] as string, ...(description ? { description } : {}) });
      paramOrder.push(name);
      if (p[2] === 'required') required.push(name);
      continue;
    }

    if (key === 'redact') {
      redact.push(value);
      continue;
    }

    // `# param.<name>.<constraint>: <value>` tightens a declared parameter.
    if (key.startsWith('param.')) {
      const parts = key.split('.');
      if (parts.length !== 3) fail(`malformed constraint key "${key}" — expected "param.<name>.<constraint>"`);
      const [, name, constraint] = parts as [string, string, string];
      const spec = params.get(name);
      // Ordering matters: a constraint naming a parameter that was never
      // declared would otherwise silently do nothing.
      if (!spec) {
        fail(`constraint "${key}" names parameter "${name}", which is not declared above it`);
        return undefined as never;
      }
      // A constraint that cannot apply to the parameter's type is refused
      // rather than attached. `maxLength` on an integer constrains nothing,
      // and a constraint that constrains nothing reads as a guard that is not
      // there.
      // Same guard as `# param:` and the plain headers, applied BEFORE any
      // dispatch: a repeated declaration silently replaced the earlier one,
      // so a second `enum` line could put back what the first excluded —
      // widening exactly the boundary an operator wrote it to draw (review
      // 2159). `redact` stays repeatable because accumulating is what it
      // means; `label`/`default` are single-valued like the rest.
      if (declaredConstraints.has(key)) fail(`declaration "${key}" declared twice`);
      declaredConstraints.add(key);
      // `label` and `default` are per-parameter ANNOTATIONS (#61 C-8), not
      // constraints: they say how the field is presented and what it starts
      // from, and they apply to every type. Declared through the same
      // `param.<name>.<key>` syntax because that is where a reader looks for
      // anything said about one parameter.
      if (constraint === 'label') {
        spec.title = value;
        continue;
      }
      if (constraint === 'default') {
        spec.default =
          spec.type === 'boolean'
            ? parseBoolean(key, value)
            : spec.type === 'integer'
            ? parseInteger(key, value)
            : spec.type === 'number'
            ? (parseBound(key, value, 'number') as number)
            : value;
        continue;
      }
      if (STRING_ONLY.has(constraint) && spec.type !== 'string') {
        fail(`constraint "${key}" applies to string parameters only, but "${name}" is ${spec.type}`);
      }
      if (NUMERIC_ONLY.has(constraint) && spec.type !== 'integer' && spec.type !== 'number') {
        fail(`constraint "${key}" applies to numeric parameters only, but "${name}" is ${spec.type}`);
      }
      if (constraint === 'pattern') spec.pattern = value;
      else if (constraint === 'enum') spec.enum = parseEnum(key, value, spec.type);
      else if (constraint === 'maxLength') spec.maxLength = parseInteger(key, value);
      else if (constraint === 'minimum') spec.minimum = parseBound(key, value, spec.type);
      else if (constraint === 'maximum') spec.maximum = parseBound(key, value, spec.type);
      else fail(`unknown declaration "${constraint}" on parameter "${name}" (label, default, pattern, enum, maxLength, minimum, maximum)`);
      continue;
    }

    if (!KNOWN_HEADERS.has(key)) {
      fail(`unknown declaration "${key}". Known keys: ${[...KNOWN_HEADERS].sort().join(', ')}, param, param.<name>.<constraint>, redact`);
    }
    // `description` is the one MULTI-LINE header (#61): consecutive
    // declarations are joined with newlines, so an operator can explain a
    // task in a paragraph instead of one cramped line. Every other header
    // stays single-valued — a repeat silently replaced the earlier value.
    if (key === 'description') {
      const previous = header.get('description');
      header.set('description', previous === undefined ? value : `${previous}\n${value}`);
      continue;
    }
    if (header.has(key)) fail(`"${key}" declared twice`);
    header.set(key, value);
  }

  const id = header.get('xtrape-task');
  if (!id) fail('no "# xtrape-task: <id>" declaration — every task file must name the task it defines');
  if (!TASK_ID.test(id as string)) fail(`task id "${id}" must look like "system.uptime" (lowercase, dot-separated)`);

  const version = header.get('version');
  if (!version) fail('no "# version:" declaration');
  if (!VERSION.test(version as string)) fail(`version "${version}" must be MAJOR.MINOR.PATCH`);

  const risk = header.get('risk');
  if (!risk) fail('no "# risk:" declaration — the operator must state the blast radius of this task');
  if (!RISK_LEVELS.has(risk as string)) fail(`risk "${risk}" must be one of low, medium, high, critical`);

  // RETIRED from authoring (#61, owner ruling 2026-08-13): `readonly` was an
  // authorization input, and "read-only" is not a safety property — a
  // read-only task can read secrets. Risk is the single axis now. The header
  // is still ACCEPTED because stored revisions are frozen byte streams that
  // must keep parsing; its value no longer decides anything.
  const readonlyRaw = header.get('readonly');

  const approval = header.get('approval') ?? 'policy';
  if (!APPROVAL_POLICIES.has(approval)) fail(`approval "${approval}" must be one of policy, always_human, forbidden`);

  // The interpreter comes from the SHEBANG (#61 / review 2365): one place
  // says which command runs the script, the way every shell script already
  // spells it. `#!/usr/bin/env bash` and `#!/bin/sh` both name their
  // command; `env` is unwrapped because the script is fed to the command on
  // stdin (the file never lands on the target, so the kernel never reads the
  // shebang — this Widget reads it locally instead). A retired
  // `# interpreter:` header on a stored task still wins, so an upgrade
  // changes nothing about what already runs.
  // Two paths, deliberately (review 2373):
  //
  // - a RETIRED `# interpreter:` header on a stored task keeps exactly the
  //   invocation it has always had — any syntactically valid command, run
  //   with `-s`. The new closed set must not reach back into frozen
  //   revisions and change what they do (or refuse to parse them at all);
  // - a SHEBANG is the current contract: a known interpreter, admitted
  //   options only, and that interpreter's own stdin argument.
  const declared = header.get('interpreter');
  const interpreter = declared ?? interpreterFromShebang(source).command;
  if (!INTERPRETER.test(interpreter)) fail(`interpreter "${interpreter}" contains characters that are not a plain command name or path`);
  let interpreterArgs: string[] = [];
  let interpreterStdinArg = '-s';
  if (declared === undefined) {
    const fromShebang = interpreterFromShebang(source);
    if (fromShebang.malformed !== undefined) {
      fail(`shebang "${fromShebang.malformed}" names no interpreter — write "#!<interpreter>" (e.g. "#!/usr/bin/env bash"), or omit the shebang entirely to keep the default`);
    }
    if (fromShebang.envExtras && fromShebang.envExtras.length > 0) {
      fail(`shebang uses "env ${fromShebang.envExtras.join(' ')}", whose environment settings this Widget cannot deliver — write "#!<interpreter>" and set what you need inside the script`);
    }
    // FAIL CLOSED on anything this Widget cannot invoke faithfully with the
    // script on stdin (review 2371): guessing an invocation is how `-s` was
    // appended to `python3`, where it means something else entirely.
    const invocation = stdinInvocationFor(interpreter);
    if (!invocation) {
      fail(`interpreter "${interpreter}" is not one this Widget can run with the script on standard input; supported: ${SUPPORTED_INTERPRETERS}`);
      return undefined as never;
    }
    interpreterArgs = fromShebang.args;
    interpreterStdinArg = invocation.stdinArg;
    for (const arg of interpreterArgs) {
      if (!INTERPRETER_ARG.test(arg)) fail(`shebang argument "${arg}" contains characters that are not a plain option or value`);
      // ALLOW-list, so a combined cluster (`-ec`) or an attached value
      // (`-cCODE`, `-mMOD`, `-eCODE`) cannot slip a source option past the
      // check — each of those would take the program from somewhere else,
      // and the script would never be read.
      if (!shebangOptionAdmitted(arg, invocation)) {
        fail(`shebang argument "${arg}" is not one this Widget knows to be safe with a program on standard input; admitted for ${interpreter}: ${invocation.options.join(', ')}`);
      }
    }
  }

  // No default. `*` is the widest possible scope, and a scope nobody wrote
  // down is not a decision anyone made — an operator who wants every server
  // has to type `# servers: *`.
  const serversRaw = header.get('servers');
  if (serversRaw === undefined) {
    fail('no "# servers:" declaration — name the server scopes this task may run on, or "*" for every server');
  }
  const servers = (serversRaw as string)
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '');
  if (servers.length === 0) fail('"# servers:" is present but names no scope');

  const properties: Record<string, unknown> = {};
  for (const name of paramOrder) {
    if (!PARAM_NAME.test(name)) fail(`parameter "${name}" is not a usable environment variable name`);
    const spec = params.get(name) as ParamSpec;
    const schema: Record<string, unknown> = { type: spec.type };
    if (spec.description) schema['description'] = spec.description;
    if (spec.pattern) schema['pattern'] = spec.pattern;
    if (spec.enum) schema['enum'] = spec.enum;
    if (spec.maxLength !== undefined) schema['maxLength'] = spec.maxLength;
    // Bounds that cross admit nothing. By the same rule as a constraint that
    // cannot apply to its type, an unsatisfiable one is a declaration error
    // rather than a task that silently accepts no input.
    if (spec.minimum !== undefined && spec.maximum !== undefined && spec.minimum > spec.maximum) {
      fail(`parameter "${name}": minimum ${String(spec.minimum)} is greater than maximum ${String(spec.maximum)}, so no value can satisfy it`);
    }
    if (spec.minimum !== undefined) schema['minimum'] = spec.minimum;
    if (spec.maximum !== undefined) schema['maximum'] = spec.maximum;
    // Presentation, carried on the same schema the Platform renders (#61
    // C-8): `title` is the operator's label for the field, `default` the
    // value its form starts from. A declared default that the parameter's
    // own constraints reject would be a task shipping a value it refuses.
    if (spec.title !== undefined) schema['title'] = spec.title;
    if (spec.default !== undefined) {
      if (spec.enum && !spec.enum.includes(spec.default)) {
        fail(`parameter "${name}": default ${JSON.stringify(spec.default)} is not one of its enum values`);
      }
      if (typeof spec.default === 'string' && spec.pattern) {
        // Ajv compiles `pattern` with the `u` flag (its `unicodeRegExp`
        // default), so this check must too (review 2388) — otherwise a
        // pattern like `\p{L}+` means one thing here and another at
        // validation time. A pattern that does not compile under `u` is left
        // to Ajv to report at registry admission, where the message names
        // the schema.
        let re: RegExp | undefined;
        try {
          re = new RegExp(spec.pattern, 'u');
        } catch {
          re = undefined;
        }
        if (re && !re.test(spec.default)) {
          fail(`parameter "${name}": default ${JSON.stringify(spec.default)} does not match its own pattern`);
        }
      }
      if (typeof spec.default === 'number') {
        if (spec.minimum !== undefined && spec.default < spec.minimum) fail(`parameter "${name}": default ${spec.default} is below its minimum`);
        if (spec.maximum !== undefined && spec.default > spec.maximum) fail(`parameter "${name}": default ${spec.default} is above its maximum`);
      }
      // JSON Schema counts `maxLength` in Unicode CODE POINTS, not UTF-16
      // code units (review 2388): `"😀".length` is 2, and rejecting it
      // against maxLength 1 would refuse a default Ajv accepts.
      if (typeof spec.default === 'string' && spec.maxLength !== undefined && [...spec.default].length > spec.maxLength) {
        fail(`parameter "${name}": default ${JSON.stringify(spec.default)} is longer than its maxLength`);
      }
      schema['default'] = spec.default;
    }
    properties[name] = schema;
  }

  // Optional, and there is no default. A task that may run for hours simply
  // does not declare one; a task that wants a bound says so.
  const timeoutRaw = header.get('timeout');
  const timeoutSeconds = timeoutRaw === undefined ? undefined : parseInteger('timeout', timeoutRaw);
  if (timeoutSeconds !== undefined && timeoutSeconds <= 0) fail('"# timeout:" must be a positive number of seconds');

  const maxBytesRaw = header.get('maxBytes');
  const outputPolicy =
    redact.length > 0 || maxBytesRaw !== undefined
      ? {
          ...(redact.length > 0 ? { redact } : {}),
          ...(maxBytesRaw !== undefined ? { maxBytes: parseInteger('maxBytes', maxBytesRaw) } : {}),
        }
      : undefined;

  return {
    id: id as string,
    ...(header.get('title') !== undefined ? { title: header.get('title') as string } : {}),
    version: version as string,
    ...(header.get('description') !== undefined ? { description: header.get('description') as string } : {}),
    executor: header.get('executor') ?? 'ssh',
    riskLevel: risk as RiskLevel,
    readonly: readonlyRaw === undefined ? false : parseBoolean('readonly', readonlyRaw),
    serverScopes: servers,
    approvalPolicy: approval as ApprovalPolicy,
    params: { type: 'object', properties, required, additionalProperties: false },
    interpreter,
    ...(interpreterArgs.length > 0 ? { interpreterArgs } : {}),
    interpreterStdinArg,
    script: source,
    scriptDigest: `sha256:${createHash('sha256').update(source, 'utf8').digest('hex')}`,
    sourceFile,
    ...(timeoutSeconds !== undefined ? { timeoutSeconds } : {}),
    ...(outputPolicy ? { outputPolicy } : {}),
  };
}

/** Environment variable a parameter arrives in, for documentation and errors. */
export function paramEnvName(param: string): string {
  return `${PARAM_ENV_PREFIX}${param}`;
}

/**
 * The structured form of a task's declarations (#58): what the DB stores as
 * COLUMNS, and what a future structured form edits directly. Raw header
 * values are kept as written (validation is `parseTaskFile`'s job — this
 * shape is storage/rendering, not a second validator).
 */
export interface TaskParamDecl {
  /** The full `# param:` value as written: `<name> <required|optional> <type> [description]`. */
  declaration: string;
  /** Constraint lines for this parameter, in declaration order: `{ key: "param.x.pattern", value: "..." }`. */
  constraints: Array<{ key: string; value: string }>;
}

export interface TaskParts {
  /** Shebang line, kept as written (default applied when absent). */
  shebang: string;
  /** Plain `# key: value` headers as written, in KNOWN_HEADERS vocabulary. */
  headers: Record<string, string>;
  /** Parameter declarations with their constraints, in declaration order. */
  params: TaskParamDecl[];
  /** `# redact:` values, in order (repeatable by design). */
  redact: string[];
  /** Everything from the first non-comment line down — the operator's script. */
  body: string;
}

/**
 * Split validated task SOURCE into its structured parts. Call
 * `parseTaskFile` FIRST — this function assumes the source already passed
 * full validation and only separates, never judges. Leading free-form
 * comments (a `#` line that is not a declaration) are not part of any part
 * and do not survive a canonical re-render; comments in the BODY do.
 */
export function splitTaskSource(source: string): TaskParts {
  const lines = source.split('\n');
  let shebang = '#!/usr/bin/env bash';
  const headers: Record<string, string> = {};
  const params: TaskParamDecl[] = [];
  const byName = new Map<string, TaskParamDecl>();
  const redact: string[] = [];
  let bodyStart = lines.length;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.startsWith('#!')) {
      shebang = line;
      continue;
    }
    const trimmed = line.trim();
    if (trimmed === '') continue;
    if (!trimmed.startsWith('#')) {
      bodyStart = i;
      break;
    }
    const match = HEADER_LINE.exec(trimmed);
    if (!match) continue; // plain comment among the declarations
    const key = match[1] as string;
    if (key === 'xtrape-script') {
      // Explicit boundary: the body starts on the NEXT line and is verbatim
      // from there — leading comments included (reviews 2354/2355).
      bodyStart = i + 1;
      break;
    }
    const value = (match[2] as string).trim();
    if (key === 'param') {
      const name = (PARAM_LINE.exec(value) as RegExpExecArray)[1] as string;
      const decl: TaskParamDecl = { declaration: value, constraints: [] };
      params.push(decl);
      byName.set(name, decl);
    } else if (key === 'redact') {
      redact.push(value);
    } else if (key.startsWith('param.')) {
      byName.get(key.split('.')[1] as string)!.constraints.push({ key, value });
    } else if (key === 'description') {
      const previous = headers['description'];
      headers['description'] = previous === undefined ? value : `${previous}\n${value}`;
    } else {
      headers[key] = value;
    }
  }
  return { shebang, headers, params, redact, body: lines.slice(bodyStart).join('\n') };
}

/** Canonical header order for `renderTaskFile` — a fixed order so equal parts render equal bytes. */
const RENDER_ORDER = ['xtrape-task', 'title', 'version', 'description', 'executor', 'risk', 'readonly', 'servers', 'approval', 'interpreter', 'timeout', 'maxBytes'] as const;

/**
 * Render structured parts back into the canonical task-file text — the exact
 * bytes the digest covers, the review card shows, and the interpreter is fed.
 * `renderTaskFile(splitTaskSource(s))` normalizes formatting (header order,
 * spacing, leading free comments) but never meaning: callers re-parse the
 * render and treat any semantic drift as a bug.
 */
export function renderTaskFile(parts: TaskParts, marker = true): string {
  const out: string[] = [parts.shebang];
  for (const key of RENDER_ORDER) {
    const value = parts.headers[key];
    if (value === undefined) continue;
    // A multi-line description round-trips as consecutive declarations.
    for (const line of key === 'description' ? value.split('\n') : [value]) out.push(`# ${key}: ${line}`);
  }
  for (const param of parts.params) {
    out.push(`# param: ${param.declaration}`);
    for (const c of param.constraints) out.push(`# ${c.key}: ${c.value}`);
  }
  for (const r of parts.redact) out.push(`# redact: ${r}`);
  if (marker) out.push(HEADER_END_MARKER);
  out.push(parts.body);
  return out.join('\n');
}

/**
 * Write-side normalization (review 2354): the optional headers that HAVE
 * defaults are materialized before storing, so a stored revision is always
 * explicit about executor / interpreter / approval — and an untouched
 * Edit → Save round-trips to the exact same bytes instead of a phantom
 * new digest. Read paths never normalize: a stored row renders exactly the
 * columns it holds.
 */
export function normalizeTaskParts(parts: TaskParts): TaskParts {
  // Nothing is materialized any more (#61): `approval` / `interpreter` /
  // `executor` retired from authoring, so writing them into a NEW task
  // would resurrect the retired vocabulary. A stored task that carries them
  // keeps them — the form passes them through untouched.
  return parts;
}
