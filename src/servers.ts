import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, unlinkSync, openSync, fsyncSync, closeSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { AuthMethod, Environment, ServerDefinition } from './types.js';
import { HOST_KEY_FINGERPRINT_PATTERN } from './executors/ssh.js';

const ENVIRONMENTS: Environment[] = ['production', 'staging', 'development'];

export interface ServerResolver {
  get(id: string): ServerDefinition | undefined;
  list(): ServerDefinition[];
}

const AUTH_METHODS: AuthMethod[] = ['privateKey', 'privateKeyWithPassphrase', 'password'];

/** Fields an operator may set through manageServers; secrets are never returned. */
export interface ServerInput {
  id: string;
  host: string;
  port?: number;
  username: string;
  /**
   * The chosen auth method is the authority over which secrets apply (#42):
   * switching it retires the other method's stored secrets, which is what
   * replaced the old clearPassword/clearPassphrase toggles. On update it may
   * be omitted to keep the stored method.
   */
  authMethod?: string;
  /** Raw secrets, when configured (see ServerDefinition). Stored, never returned. */
  privateKey?: string;
  password?: string;
  passphrase?: string;
  environment: Environment;
  hostKeyFingerprint?: string;
  /** Interpreters declared available on the target (#69); command names. */
  shells?: string[];
}

/**
 * The host key fingerprint is OPTIONAL at admission (#44): an entry without
 * one is pinned on first use by `SshExecutor` (accept-new), so absence means
 * "trust the first endpoint that answers", not "never verify". When present
 * it must be well-formed, and its provenance is recorded (`operator` here;
 * `first-use` only through `pinHostKey`).
 */
function validate(input: ServerInput): ServerDefinition {
  const id = String(input.id ?? '').trim();
  if (!/^[a-z0-9][a-z0-9._-]*$/i.test(id)) throw new Error('server id must be a non-empty [a-z0-9._-] token');
  const host = String(input.host ?? '').trim();
  if (!host) throw new Error('host is required');
  const username = String(input.username ?? '').trim();
  if (!username) throw new Error('username is required');
  if (!ENVIRONMENTS.includes(input.environment)) {
    throw new Error(`environment must be one of ${ENVIRONMENTS.join(', ')}`);
  }
  if (input.port !== undefined && (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535)) {
    throw new Error('port must be an integer in 1..65535');
  }
  const shells = normalizeShells(input.shells);
  const hostKeyFingerprint = String(input.hostKeyFingerprint ?? '').trim();
  if (hostKeyFingerprint && !HOST_KEY_FINGERPRINT_PATTERN.test(hostKeyFingerprint)) {
    throw new Error('hostKeyFingerprint must be an OpenSSH SHA-256 fingerprint of the form SHA256:<43 base64 chars>');
  }
  return {
    id,
    host,
    username,
    environment: input.environment,
    ...(input.port !== undefined ? { port: input.port } : {}),
    ...(hostKeyFingerprint ? { hostKeyFingerprint, hostKeyAdmittedBy: 'operator' as const } : {}),
    ...(shells !== undefined ? { shells, shellsSource: 'declared' as const } : {}),
  };
}

/**
 * The auth invariant (#42): the chosen `authMethod` is the authority, and the
 * stored secrets must be EXACTLY the ones that method uses — a plain key has
 * no passphrase and no password, an encrypted key has both key and passphrase,
 * password auth has only the password. A definition violating this either
 * holds a secret nothing would use or lacks the one its method needs; both are
 * refused rather than admitted (the same fail-at-the-door posture as reviews
 * 2254/2284 for the passphrase-without-key shape).
 */
function assertAuthShape(def: { authMethod?: AuthMethod; privateKey?: string; passphrase?: string; password?: string }): void {
  switch (def.authMethod) {
    case 'privateKey':
      if (!def.privateKey) throw new Error('authMethod "privateKey" requires the privateKey content');
      if (def.passphrase) throw new Error('a passphrase belongs to authMethod "privateKeyWithPassphrase"');
      if (def.password) throw new Error('a password belongs to authMethod "password"');
      return;
    case 'privateKeyWithPassphrase':
      if (!def.privateKey) throw new Error('authMethod "privateKeyWithPassphrase" requires the privateKey content');
      if (!def.passphrase) throw new Error('authMethod "privateKeyWithPassphrase" requires the passphrase that decrypts the key');
      if (def.password) throw new Error('a password belongs to authMethod "password"');
      return;
    case 'password':
      if (!def.password) throw new Error('authMethod "password" requires the password');
      if (def.privateKey || def.passphrase) throw new Error('a private key belongs to authMethod "privateKey" / "privateKeyWithPassphrase"');
      return;
    default:
      // No method: legal only as an inert legacy entry with no secrets at all
      // (the executor refuses to connect to it until it is reconfigured).
      if (def.privateKey || def.passphrase || def.password) {
        throw new Error(`authMethod is required and must be one of ${AUTH_METHODS.join(', ')}`);
      }
  }
}

/**
 * Resolve the auth block of a candidate definition from operator input and,
 * on update, the stored entry (#42):
 *
 * - `authMethod` omitted keeps the stored method (update); setting any secret
 *   with no effective method is refused.
 * - A supplied secret the effective method does not use is CONTRADICTORY and
 *   refused, never silently dropped (the same posture as the old clear+new
 *   refusal, review 2254 P2). The Panel never sends one — hidden fields are
 *   dropped on submit — so one arriving means a raw API caller disagreeing
 *   with itself.
 * - With the method UNCHANGED, an omitted/blank secret keeps the stored value
 *   (secrets are write-only and never prefilled, so a blank edit submit must
 *   not clear the working credential). ANY method switch starts fresh —
 *   review 2305: even between the two key methods, because encrypting or
 *   decrypting a key changes its BYTES; carrying the old content across
 *   would persist a method that disagrees with the key format it holds.
 *   Switching methods IS the retirement of the previous method's secrets.
 * - Secrets are used verbatim — trimming a value whose whitespace is
 *   legitimate would silently corrupt it.
 */
function resolveAuth(
  input: ServerInput,
  existing?: ServerDefinition,
): Pick<ServerDefinition, 'authMethod' | 'privateKey' | 'passphrase' | 'password'> {
  const rawMethod = input.authMethod === undefined || String(input.authMethod).trim() === '' ? undefined : String(input.authMethod).trim();
  if (rawMethod !== undefined && !(AUTH_METHODS as string[]).includes(rawMethod)) {
    throw new Error(`authMethod must be one of ${AUTH_METHODS.join(', ')}`);
  }
  const method = (rawMethod as AuthMethod | undefined) ?? existing?.authMethod;
  const inKey = input.privateKey ? String(input.privateKey) : undefined;
  const inPassphrase = input.passphrase ? String(input.passphrase) : undefined;
  const inPassword = input.password ? String(input.password) : undefined;
  if (method === undefined) {
    if (inKey || inPassphrase || inPassword) {
      throw new Error(`authMethod is required and must be one of ${AUTH_METHODS.join(', ')}`);
    }
    return {};
  }
  const keyFamily = method === 'privateKey' || method === 'privateKeyWithPassphrase';
  if (keyFamily && inPassword) throw new Error(`a password does not apply under authMethod "${method}" — choose authMethod "password" to use one`);
  if (method === 'privateKey' && inPassphrase) throw new Error('a passphrase does not apply under authMethod "privateKey" — choose "privateKeyWithPassphrase" for an encrypted key');
  if (method === 'password' && (inKey || inPassphrase)) throw new Error('a private key does not apply under authMethod "password" — choose a key authMethod to use one');
  const sameMethod = existing?.authMethod === method;
  const privateKey = keyFamily ? inKey ?? (sameMethod ? existing?.privateKey : undefined) : undefined;
  const passphrase = method === 'privateKeyWithPassphrase' ? inPassphrase ?? (sameMethod ? existing?.passphrase : undefined) : undefined;
  const password = method === 'password' ? inPassword ?? (sameMethod ? existing?.password : undefined) : undefined;
  return {
    authMethod: method,
    ...(privateKey ? { privateKey } : {}),
    ...(passphrase ? { passphrase } : {}),
    ...(password ? { password } : {}),
  };
}

/**
 * The target-server fleet is this Service's own business config (the Platform
 * stores none of it): it is configured through the `manageServers` entry action and
 * persisted here. Mutations validate a full candidate snapshot, commit it to a
 * temp file (0600) + atomic rename, and only then swap the in-memory snapshot —
 * so a failed write leaves both memory and the previous file unchanged, and a
 * crash mid-write cannot truncate the only copy (#27, archived review).
 */
/** A shell/interpreter name as `command -v` takes it: a bare command word, no path, no options. */
export const SHELL_NAME_PATTERN = /^[A-Za-z0-9._+-]{1,64}$/;

/**
 * Normalize a declared/probed interpreter list: trimmed, deduplicated,
 * order-preserving; `undefined` when nothing was given (= unknown, which is
 * distinct from an explicit empty list = "none of them"). Refuses anything
 * that is not a plain command name — a path or an option would not be what
 * `command -v` reports and would never match a shebang's command.
 */
export function normalizeShells(raw: unknown): string[] | undefined {
  if (raw === undefined || raw === null) return undefined;
  const list = Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(/[,\s]+/) : [];
  const out: string[] = [];
  for (const item of list) {
    const name = String(item ?? '').trim();
    if (name === '') continue;
    if (!SHELL_NAME_PATTERN.test(name)) throw new Error(`shells: "${name}" is not a plain interpreter command name (as \`command -v\` reports it: sh, bash, python3, …)`);
    if (!out.includes(name)) out.push(name);
  }
  return out;
}

/**
 * The secret-free identity of the ENDPOINT + EXECUTION IDENTITY a probe ran
 * against (#69, review 2481): everything that can change what `command -v`
 * sees or which host answers, and nothing that is a credential. A probe
 * observation is sealed with this and a confirmation is refused unless the
 * record still matches it — one snapshot instead of field-by-field TOCTOU.
 */
export interface ProbeTargetSnapshot {
  host: string;
  /** Effective port (default 22). */
  port: number;
  /** The SSH user the probe ran as — the interpreters `command -v` sees are that user's. */
  username: string;
  /** The admitted host key fingerprint, '' when none is recorded yet. */
  hostKeyFingerprint: string;
  /** The record generation (remove + re-add is a new record). */
  generation: string;
}

export function probeTargetSnapshot(server: ServerDefinition): ProbeTargetSnapshot {
  return {
    host: server.host,
    port: server.port ?? 22,
    username: server.username,
    hostKeyFingerprint: server.hostKeyFingerprint ?? '',
    generation: server.generation ?? '',
  };
}

export function sameProbeTarget(a: ProbeTargetSnapshot, b: ProbeTargetSnapshot): boolean {
  return a.host === b.host && a.port === b.port && a.username === b.username && a.hostKeyFingerprint === b.hostKeyFingerprint && a.generation === b.generation;
}

export class ServerStore implements ServerResolver {
  private servers: Map<string, ServerDefinition>;
  /**
   * True while the LAST published state has not been confirmed durable — a
   * post-rename directory sync failed and no later sync succeeded (review
   * 2313). Mechanically recognizable and mechanically clearable: one
   * successful fsync of the directory confirms every rename published into
   * it before, so any later successful commit — or `ensureDurable()` —
   * settles the debt for the whole file.
   */
  private durabilityUnconfirmed = false;

  constructor(private readonly file: string) {
    this.servers = new Map();
    if (existsSync(file)) {
      // Tighten a pre-existing store file to 0600 on load — it holds credential
      // reference paths AND (since password/passphrase auth) raw SSH secrets,
      // and may have been created with a looser umask before. Plaintext at 0600
      // is the transitional at-rest posture until a vault-widget takes over.
      try { chmodSync(file, 0o600); } catch { /* best-effort */ }
      const parsed = JSON.parse(readFileSync(file, 'utf8')) as unknown;
      if (!Array.isArray(parsed)) throw new Error(`${file}: server store root must be a JSON array`);
      for (const raw of parsed) {
        const rec = { ...(raw as Record<string, unknown>) };
        // Retired shape (#42): `privateKeyPath` referenced a key FILE on the
        // executor host; auth now stores the key CONTENT, and there is no
        // content to migrate a path to. ANY entry carrying the retired
        // reference drops to inert AS A WHOLE — passphrase and password
        // included (review 2305): the old model let key and password ride
        // one connection together, so a surviving password would silently
        // pick a method the OPERATOR never chose. The drop is LOUD, and the
        // executor refuses the credential-less entry until it is
        // reconfigured through manageServers — same lenient-load posture as
        // an entry with no admitted host key: fixable from the Panel, not a
        // crash.
        if (rec.privateKeyPath) {
          console.warn(
            `[servers] ${file}: entry "${String(rec.id ?? '?')}" uses the retired privateKeyPath — ` +
              'dropping its credentials (key reference, passphrase, password); choose an authMethod and re-enter the secret through manageServers (#42)',
          );
          delete rec.privateKeyPath;
          delete rec.passphrase;
          delete rec.password;
        }
        // Pre-#42 stores carried no authMethod; password-only (no retired key
        // reference anywhere) is the one legacy shape that maps one-to-one.
        if (!rec.authMethod && rec.password && !rec.privateKey && !rec.passphrase) rec.authMethod = 'password';
        const input = rec as unknown as ServerInput;
        const def: ServerDefinition = { ...validate(input), ...resolveAuth(input) };
        // Record generation (review 2325): persisted entries keep theirs; a
        // pre-generation store gets one minted here. Minted-at-load values
        // stabilize on the first commit; until then a pre-restart mismatch
        // observation refuses (stale generation) — fail-closed, re-run Test.
        def.generation = typeof rec.generation === 'string' && rec.generation ? rec.generation : randomBytes(8).toString('hex');
        // A persisted first-use pin stays a first-use pin across restarts —
        // validate() can only know about operator admission (#44).
        if (def.hostKeyFingerprint && rec.hostKeyAdmittedBy === 'first-use') def.hostKeyAdmittedBy = 'first-use';
        // A probe's observation survives a restart with its provenance (#69):
        // validate() only knows a declaration.
        if (def.shells !== undefined && rec.shellsSource === 'probed') {
          def.shellsSource = 'probed';
          if (typeof rec.shellsProbedAt === 'string') def.shellsProbedAt = rec.shellsProbedAt;
        }
        // The durable ingress enforces the SAME auth invariant as the
        // mutation ingress (review 2284): a shape no released version
        // produced is refused at load rather than silently admitted.
        assertAuthShape(def);
        if (this.servers.has(def.id)) throw new Error(`${file}: duplicate server id "${def.id}"`);
        this.servers.set(def.id, def);
      }
      // Startup durability sync (review 2314): a process restart is NOT
      // durability evidence — the file just read may still ride a rename
      // whose directory sync never succeeded (the very state the previous
      // process refused to trust), and a fresh in-memory flag would launder
      // it into "confirmed". Syncing the directory HERE settles it for
      // real: success makes everything previously renamed durable; failure
      // starts the store unconfirmed — LOUDLY — and the executor's
      // ensureDurable gate keeps every recorded fingerprint unusable until
      // a sync actually succeeds. Deliberately not fail-stop: the same
      // lenient-load posture as the rest of this constructor, because the
      // gate already withholds the trust and the state self-heals on next
      // use.
      try {
        this.syncDir();
      } catch (err) {
        this.durabilityUnconfirmed = true;
        console.warn(
          `[servers] ${file}: startup directory sync failed (${err instanceof Error ? err.message : String(err)}) — ` +
            'recorded host keys stay durability-unconfirmed and unusable until a sync succeeds (#44, review 2314)',
        );
      }
    }
  }

  get(id: string): ServerDefinition | undefined {
    return this.servers.get(id);
  }

  list(): ServerDefinition[] {
    return [...this.servers.values()].sort((a, b) => a.id.localeCompare(b.id));
  }

  /** Servers whose id matches any of the given glob scopes (`*` wildcard). */
  listMatching(scopes: string[]): ServerDefinition[] {
    return this.list().filter((s) => scopes.some((scope) => scopeMatches(scope, s.id)));
  }

  add(input: ServerInput): ServerDefinition {
    // A fresh generation per ADMISSION: remove + re-add is a NEW trust
    // record even when every visible value matches (review 2325).
    const def: ServerDefinition = { ...validate(input), ...resolveAuth(input), generation: randomBytes(8).toString('hex') };
    // Admission chooses how the target is reached: an entry that cannot be
    // reached at all is refused at the door (legacy inert entries exist only
    // through the lenient LOAD of an old store, never through admission).
    if (!def.authMethod) throw new Error(`authMethod is required and must be one of ${AUTH_METHODS.join(', ')}`);
    assertAuthShape(def);
    if (this.servers.has(def.id)) throw new Error(`server "${def.id}" already exists; use updateServer`);
    const next = new Map(this.servers);
    next.set(def.id, def);
    this.commit(next);
    return def;
  }

  update(input: ServerInput): ServerDefinition {
    const existing = this.servers.get(String(input.id ?? '').trim());
    if (!existing) throw new Error(`unknown server "${input.id}"`);
    // Auth resolution (#42): the effective method keeps stored secrets on a
    // blank edit submit, refuses contradictory input, and retires the other
    // method's secrets on a switch — see `resolveAuth`.
    // The generation SURVIVES an update: editing a record is the same trust
    // record continuing, and the rotation CAS catches the value changes.
    const def: ServerDefinition = { ...validate(input), ...resolveAuth(input, existing), ...(existing.generation ? { generation: existing.generation } : {}) };
    // An update that omits the fingerprint KEEPS the recorded admission —
    // silently unpinning a verified endpoint would downgrade it to
    // trust-on-next-use (#44). Replacing it (host key rotation) supplies the
    // new value explicitly and is an operator admission again.
    if (!def.hostKeyFingerprint && existing.hostKeyFingerprint) {
      def.hostKeyFingerprint = existing.hostKeyFingerprint;
      if (existing.hostKeyAdmittedBy) def.hostKeyAdmittedBy = existing.hostKeyAdmittedBy;
    } else if (def.hostKeyFingerprint && def.hostKeyFingerprint === existing.hostKeyFingerprint && existing.hostKeyAdmittedBy) {
      // Resubmitting the UNCHANGED value is not an admission event (review
      // 2311): the edit form prefills the fingerprint, so editing an
      // unrelated field would otherwise silently launder a first-use pin
      // into "operator" provenance. Only a DIFFERENT value — a deliberate
      // replacement — earns the operator label.
      def.hostKeyAdmittedBy = existing.hostKeyAdmittedBy;
    }
    // An update that says nothing about interpreters KEEPS what is known —
    // a probe's observation must not be erased by editing the port (#69).
    if (def.shells === undefined && existing.shells !== undefined) {
      def.shells = existing.shells;
      if (existing.shellsSource) def.shellsSource = existing.shellsSource;
      if (existing.shellsProbedAt) def.shellsProbedAt = existing.shellsProbedAt;
    } else if (def.shells !== undefined && existing.shellsSource === 'probed') {
      // A declaration does not override an observation (#69: "probe wins",
      // review 2480: no silent probed → declared laundering). What the host
      // said it has is what the record says; a person who knows better
      // re-probes, or removes and re-adds the entry.
      throw new Error(`server "${input.id}": interpreters were PROBED on the target (${existing.shells?.join(', ') || 'none'}); a declaration cannot override an observation — run Test to re-probe`);
    }
    assertAuthShape(def);
    const next = new Map(this.servers);
    next.set(def.id, def);
    this.commit(next);
    return def;
  }

  /**
   * Record what a probe OBSERVED on the target (#69) — after a person
   * confirmed it (review 2475: a Test is a read, not an implicit config
   * write). The observation crossed a command round-trip before the
   * confirmation, so it carries the {@link ProbeTargetSnapshot} it was made
   * against and this refuses if the entry no longer matches it — rehosted,
   * re-ported, a different SSH user (`command -v` runs AS that user, so the
   * visible interpreters can differ; review 2481), a different admitted host
   * key, or removed and re-added (review 2480). One snapshot, not a growing
   * list of fields. An observation of the live host wins over a declaration
   * and is stamped with its time.
   */
  recordProbedShells(id: string, observation: { shells: string[]; probedAt: string }, expected: ProbeTargetSnapshot): ServerDefinition {
    const existing = this.servers.get(id);
    if (!existing) throw new Error(`unknown server "${id}"`);
    if (!sameProbeTarget(probeTargetSnapshot(existing), expected)) {
      throw new Error(`server "${id}" changed since the interpreters were probed (host / port / user / admitted host key / record generation differ from the observation); run Test again`);
    }
    const def: ServerDefinition = { ...existing, shells: normalizeShells(observation.shells) ?? [], shellsSource: 'probed', shellsProbedAt: observation.probedAt };
    const next = new Map(this.servers);
    next.set(id, def);
    this.commit(next);
    return def;
  }

  remove(id: string): void {
    if (!this.servers.has(id)) throw new Error(`unknown server "${id}"`);
    const next = new Map(this.servers);
    next.delete(id);
    this.commit(next);
  }

  /**
   * First-use pinning (#44, accept-new): record the host key the endpoint
   * presented at the first key exchange. Compare-and-set on BOTH axes:
   *
   * - the pin belongs to the handshake that observed the key, and that
   *   handshake was opened against a specific record (review 2311) — if the
   *   entry changed while the exchange was in flight (rehosted, removed and
   *   re-added), the observed key describes an endpoint the CURRENT record
   *   no longer names, and writing it would admit the old target's key into
   *   the new configuration. `snapshot` is the exact record the connection
   *   was opened with; every mutation swaps the stored object (`commit`),
   *   so reference inequality precisely means "changed since read" in this
   *   single-process store.
   * - an entry that already has ANY fingerprint refuses the pin (an
   *   operator admission is never overwritten, and a recorded pin never
   *   silently moves; rotation goes through updateServer).
   *
   * Durable before it is trusted: the commit uses the same
   * failed-write-changes-nothing path as every mutation, and the CALLER
   * treats a throw here as "refuse the connection" — a pin that did not
   * persist would make every connection the first one.
   */
  pinHostKey(snapshot: ServerDefinition, fingerprint: string): ServerDefinition {
    const current = this.servers.get(snapshot.id);
    if (!current) throw new Error(`unknown server "${snapshot.id}"`);
    if (current !== snapshot) {
      throw new Error(
        `server "${snapshot.id}" changed while the handshake was in flight; refusing to pin a key observed against the previous configuration`,
      );
    }
    if (current.hostKeyFingerprint) {
      throw new Error(`server "${snapshot.id}" already has an admitted host key; a pin never replaces it — rotate through updateServer`);
    }
    if (!HOST_KEY_FINGERPRINT_PATTERN.test(fingerprint)) {
      throw new Error('hostKeyFingerprint must be an OpenSSH SHA-256 fingerprint of the form SHA256:<43 base64 chars>');
    }
    const def: ServerDefinition = { ...current, hostKeyFingerprint: fingerprint, hostKeyAdmittedBy: 'first-use' };
    const next = new Map(this.servers);
    next.set(snapshot.id, def);
    this.commit(next);
    return def;
  }

  /**
   * Host key rotation with a VALUE compare-and-set (#46, review 2321): the
   * new fingerprint was observed against a specific record state — a
   * particular host, a particular admitted key — and the observation crosses
   * a command round-trip before a human confirms it. If the entry was
   * rehosted, removed-and-re-added, or already rotated by someone else in
   * that window, the stale observation describes an endpoint the CURRENT
   * record no longer names, and applying it would overwrite a newer truth.
   * Value-based (not reference-based like pinHostKey) because the expected
   * binding travels over the wire. Only the fingerprint changes; auth
   * secrets and every other field are untouched.
   */
  rotateHostKey(
    id: string,
    expected: { host: string; port: number; fingerprint: string; generation: string },
    newFingerprint: string,
  ): ServerDefinition {
    const current = this.servers.get(id);
    if (!current) throw new Error(`unknown server "${id}"`);
    // Full binding (review 2325): host AND effective port (the same host on
    // another port is another endpoint), the admitted key, AND the record
    // generation — values can all collide across a remove + re-add, only the
    // generation proves this is the SAME trust record the mismatch was
    // observed against.
    if (
      current.host !== expected.host ||
      (current.port ?? 22) !== expected.port ||
      (current.hostKeyFingerprint ?? '') !== expected.fingerprint ||
      (current.generation ?? '') !== expected.generation
    ) {
      throw new Error(
        `server "${id}" changed since the mismatch was observed (host, port, admitted key or record generation differs); re-run testServer and decide against the current state`,
      );
    }
    if (!HOST_KEY_FINGERPRINT_PATTERN.test(newFingerprint)) {
      throw new Error('hostKeyFingerprint must be an OpenSSH SHA-256 fingerprint of the form SHA256:<43 base64 chars>');
    }
    // A rotation confirmed by a person is an operator admission.
    const def: ServerDefinition = { ...current, hostKeyFingerprint: newFingerprint, hostKeyAdmittedBy: 'operator' };
    const next = new Map(this.servers);
    next.set(id, def);
    this.commit(next);
    return def;
  }

  /** Durably persist the candidate snapshot, then swap it in only on success. */
  private commit(next: Map<string, ServerDefinition>): void {
    const snapshot = [...next.values()].sort((a, b) => a.id.localeCompare(b.id));
    mkdirSync(dirname(this.file), { recursive: true });
    // Unique temp name (concurrent writers don't collide), 0600 from creation,
    // fsync before rename for power-loss durability, atomic rename to publish.
    const tmp = `${this.file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
    let fd: number | undefined;
    try {
      fd = openSync(tmp, 'wx', 0o600);
      writeFileSync(fd, `${JSON.stringify(snapshot, null, 2)}\n`);
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      renameSync(tmp, this.file);
    } catch (err) {
      // Pre-publication failure: nothing changed, on disk or in memory.
      if (fd !== undefined) { try { closeSync(fd); } catch { /* ignore */ } }
      try { if (existsSync(tmp)) unlinkSync(tmp); } catch { /* best-effort cleanup */ }
      throw err;
    }
    // PUBLICATION POINT. From here the new snapshot is what every reader of
    // the file sees, so no failure below may be reported as "nothing
    // changed" — memory follows the published file EITHER WAY (review 2312:
    // keeping the old in-memory state after a successful rename is a
    // disk-new/memory-old split brain).
    //
    // The rename is not durable until the DIRECTORY entry is: fsync(2) on
    // the file does not cover the directory that names it, so after a crash
    // the rename itself may be gone. That used to be a crash-consistency
    // nicety; #44 makes it a security precondition (review 2311) —
    // pinHostKey trusts a connection BECAUSE the pin is recorded. A
    // directory-sync failure therefore still THROWS — distinguished as
    // published-but-not-confirmed-durable, so the TOFU caller refuses the
    // connection (fail-closed) — but the state it reports on is consistent:
    // the change is live now and a crash may or may not keep it. The
    // `durabilityUnconfirmed` flag keeps that state MECHANICALLY visible
    // (review 2313): `ensureDurable()` refuses to let an unconfirmed pin be
    // exercised until a directory sync actually succeeds. Losing an
    // unconfirmed pin to a crash merely re-runs accept-new on the next
    // boot, which is never worse than the baseline.
    this.servers = next;
    try {
      this.syncDir();
      // One successful directory sync confirms every rename published into
      // this directory before it — an earlier commit's unpaid debt included.
      this.durabilityUnconfirmed = false;
    } catch (err) {
      this.durabilityUnconfirmed = true;
      throw new Error(
        `server store updated but its durability is NOT confirmed (directory sync failed: ${err instanceof Error ? err.message : String(err)}); the change is visible now and may not survive a crash`,
      );
    }
  }

  /** fsync the directory that names the store file — the durability step of a rename. */
  private syncDir(): void {
    let dirFd: number | undefined;
    try {
      dirFd = openSync(dirname(this.file), 'r');
      fsyncSync(dirFd);
    } finally {
      if (dirFd !== undefined) { try { closeSync(dirFd); } catch { /* ignore */ } }
    }
  }

  /**
   * Re-confirm (re-performing if needed) the durability of the published
   * state (review 2313). The one gate an unconfirmed pin must pass before it
   * is TRUSTED again: after a post-rename directory-sync failure the pin is
   * live in memory and on the (page-cached) file, but a crash could erase
   * it — treating it as an ordinary admitted key would execute commands on
   * trust that was never made durable. Cheap no-op in the confirmed steady
   * state; a throw here means "refuse to execute".
   */
  ensureDurable(): void {
    if (!this.durabilityUnconfirmed) return;
    try {
      this.syncDir();
    } catch (err) {
      throw new Error(
        `server store durability is still NOT confirmed (directory sync failed again: ${err instanceof Error ? err.message : String(err)})`,
      );
    }
    this.durabilityUnconfirmed = false;
  }
}

export function scopeMatches(scope: string, serverId: string): boolean {
  if (scope === '*') return true;
  const pattern = scope.split('*').map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${pattern}$`).test(serverId);
}
