import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, statSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { ServerStore, type ServerInput } from '../src/servers.js';

const dirs: string[] = [];
function tempFile(): string {
  const dir = mkdtempSync(join(tmpdir(), 'linux-ops-widget-servers-'));
  dirs.push(dir);
  return join(dir, 'servers.json');
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

/** A well-formed OpenSSH SHA-256 host key fingerprint (a digest of a public key; not a secret). */
const FP = 'SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt4';
const FP2 = 'SHA256:Ls6zgAoI+ZpTKLdiiZlRqmB83T2nk73T4Z04PDAvyC8';

/** Auth-less base for composing per-method inputs (exactOptionalPropertyTypes forbids `field: undefined` overrides). */
const base = { id: 'web-01', host: '10.0.0.1', username: 'ops', environment: 'production' as const, hostKeyFingerprint: FP };
const web = { ...base, authMethod: 'password' as const, password: 'pw' };

/** A stand-in for pasted private key CONTENT (#42) — multiline, like a real PEM. */
const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfakekeybody\n-----END OPENSSH PRIVATE KEY-----\n';

describe('ServerStore', () => {
  it('adds, lists, updates, and removes servers, persisting to disk', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    store.add(web);
    store.add({ id: 'db-01', host: '10.0.0.2', username: 'ops', environment: 'staging', port: 2222, hostKeyFingerprint: FP, authMethod: 'password', password: 'pw' });
    expect(store.list().map((s) => s.id)).toEqual(['db-01', 'web-01']); // sorted

    store.update({ ...web, host: '10.0.0.9' });
    expect(store.get('web-01')?.host).toBe('10.0.0.9');

    // a fresh store over the same file sees the persisted state
    const reopened = new ServerStore(file);
    expect(reopened.get('db-01')?.port).toBe(2222);
    expect(JSON.parse(readFileSync(file, 'utf8')).length).toBe(2);

    store.remove('db-01');
    expect(store.list().map((s) => s.id)).toEqual(['web-01']);
  });

  it('listMatching filters by glob server scopes', () => {
    const store = new ServerStore(tempFile());
    store.add({ id: 'web-a', host: 'h', username: 'u', environment: 'development', hostKeyFingerprint: FP, authMethod: 'password', password: 'pw' });
    store.add({ id: 'web-b', host: 'h', username: 'u', environment: 'development', hostKeyFingerprint: FP, authMethod: 'password', password: 'pw' });
    store.add({ id: 'db-a', host: 'h', username: 'u', environment: 'development', hostKeyFingerprint: FP, authMethod: 'password', password: 'pw' });
    expect(store.listMatching(['web-*']).map((s) => s.id)).toEqual(['web-a', 'web-b']);
    expect(store.listMatching(['*']).length).toBe(3);
  });

  it('rejects invalid input and duplicate/missing ids', () => {
    const store = new ServerStore(tempFile());
    store.add(web);
    expect(() => store.add(web)).toThrow(/already exists/);
    expect(() => store.update({ ...web, id: 'ghost' })).toThrow(/unknown server/);
    expect(() => store.remove('ghost')).toThrow(/unknown server/);
    expect(() => store.add({ ...web, id: 'bad id!' })).toThrow(/server id/);
    expect(() => store.add({ ...web, id: 'ok', host: '' })).toThrow(/host/);
    expect(() => store.add({ ...web, id: 'ok', environment: 'prod' as never })).toThrow(/environment/);
    expect(() => store.add({ ...web, id: 'ok', port: 70000 })).toThrow(/port/);
  });

  it('fails closed on a malformed root or duplicate stored ids', () => {
    const f1 = tempFile();
    writeFileSync(f1, '{"not":"an array"}');
    expect(() => new ServerStore(f1)).toThrow(/must be a JSON array/);
    const f2 = tempFile();
    writeFileSync(f2, JSON.stringify([web, { ...web }]));
    expect(() => new ServerStore(f2)).toThrow(/duplicate server id/);
  });

  it('persists with 0600 permissions', () => {
    const file = tempFile();
    new ServerStore(file).add(web);
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('tightens a pre-existing loose store file to 0600 on load', () => {
    const file = tempFile();
    writeFileSync(file, JSON.stringify([web]));
    chmodSync(file, 0o644);
    new ServerStore(file);
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('admits a server without a host key fingerprint as accept-new; blank update keeps the recorded admission (#44)', () => {
    const store = new ServerStore(tempFile());
    const noFingerprint: ServerInput = { id: web.id, host: web.host, username: web.username, environment: web.environment, authMethod: 'password', password: 'pw' };
    store.add(noFingerprint);
    expect(store.get('web-01')?.hostKeyFingerprint).toBeUndefined();
    expect(store.get('web-01')?.hostKeyAdmittedBy).toBeUndefined();
    // Supplying one later is an operator admission.
    store.update({ ...noFingerprint, hostKeyFingerprint: FP });
    expect(store.get('web-01')?.hostKeyFingerprint).toBe(FP);
    expect(store.get('web-01')?.hostKeyAdmittedBy).toBe('operator');
    // A blank/omitted update never silently UNPINS a verified endpoint —
    // that would downgrade it to trust-on-next-use.
    store.update({ ...noFingerprint, hostKeyFingerprint: '' });
    expect(store.get('web-01')?.hostKeyFingerprint).toBe(FP);
    expect(store.get('web-01')?.hostKeyAdmittedBy).toBe('operator');
  });

  it('pinHostKey records a first-use pin exactly once — compare-and-set, never over an existing admission (#44)', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    const snap = store.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' });
    const pinned = store.pinHostKey(snap, FP);
    expect(pinned.hostKeyFingerprint).toBe(FP);
    expect(pinned.hostKeyAdmittedBy).toBe('first-use');
    // CAS axis 1: a second pin refuses — a recorded pin never silently moves
    // (the old snapshot is stale AND the entry now has a key; both refuse).
    expect(() => store.pinHostKey(store.get('web-01')!, FP2)).toThrow(/already has an admitted host key/);
    expect(() => store.pinHostKey(snap, FP2)).toThrow(/changed while the handshake was in flight/);
    // Nor does a pin ever overwrite an OPERATOR admission.
    const snap2 = store.add({ ...web, id: 'web-02' });
    expect(() => store.pinHostKey(snap2, FP2)).toThrow(/already has an admitted host key/);
    expect(() => store.pinHostKey({ ...snap, id: 'ghost' }, FP)).toThrow(/unknown server/);
    // The pin is durable and keeps its provenance across a reload.
    const reopened = new ServerStore(file);
    expect(reopened.get('web-01')?.hostKeyFingerprint).toBe(FP);
    expect(reopened.get('web-01')?.hostKeyAdmittedBy).toBe('first-use');
    // Rotation goes through updateServer and becomes an operator admission.
    store.update({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', hostKeyFingerprint: FP2 });
    expect(store.get('web-01')?.hostKeyFingerprint).toBe(FP2);
    expect(store.get('web-01')?.hostKeyAdmittedBy).toBe('operator');
  });

  it('rotateHostKey applies only against the FULL observed binding — any changed axis wins over a stale observation (reviews 2321/2325)', () => {
    const store = new ServerStore(tempFile());
    const added = store.add({ ...web, host: 'a.example' });
    const gen = added.generation!;
    expect(gen).toMatch(/^[0-9a-f]{16}$/);
    // Happy path: every axis still matches → exactly the fingerprint
    // changes, as an operator admission; the generation SURVIVES (same
    // trust record continuing).
    const rotated = store.rotateHostKey('web-01', { host: 'a.example', port: 22, fingerprint: FP, generation: gen }, FP2);
    expect(rotated.hostKeyFingerprint).toBe(FP2);
    expect(rotated.hostKeyAdmittedBy).toBe('operator');
    expect(rotated.password).toBe('pw'); // everything else untouched
    expect(rotated.generation).toBe(gen);
    // Someone already rotated (stale fingerprint axis): refuse.
    expect(() => store.rotateHostKey('web-01', { host: 'a.example', port: 22, fingerprint: FP, generation: gen }, FP2)).toThrow(/changed since the mismatch was observed/);
    // Port axis (review 2325): the same host on another port is another
    // endpoint — an observation from :22 cannot admit into :2222.
    store.update({ ...web, host: 'a.example', port: 2222, hostKeyFingerprint: FP2 });
    expect(() => store.rotateHostKey('web-01', { host: 'a.example', port: 22, fingerprint: FP2, generation: gen }, FP)).toThrow(/changed since the mismatch was observed/);
    // Host axis: rehosted in the window.
    store.update({ ...web, host: 'b.example', port: 2222, hostKeyFingerprint: FP2 });
    expect(() => store.rotateHostKey('web-01', { host: 'a.example', port: 2222, fingerprint: FP2, generation: gen }, FP)).toThrow(/changed since the mismatch was observed/);
    // Generation axis (review 2325): remove + re-add a LOOKALIKE — same id,
    // host, port, fingerprint — and the old observation still refuses,
    // because only the generation proves it is the same trust record.
    store.remove('web-01');
    store.add({ ...web, host: 'b.example', port: 2222, hostKeyFingerprint: FP2 });
    expect(() => store.rotateHostKey('web-01', { host: 'b.example', port: 2222, fingerprint: FP2, generation: gen }, FP)).toThrow(/changed since the mismatch was observed/);
    // Unknown id (removed without a successor).
    expect(() => store.rotateHostKey('ghost', { host: 'a.example', port: 22, fingerprint: FP, generation: gen }, FP2)).toThrow(/unknown server/);
    // The new value is validated like every admission.
    const fresh = store.get('web-01')!;
    expect(() => store.rotateHostKey('web-01', { host: 'b.example', port: 2222, fingerprint: FP2, generation: fresh.generation! }, 'MD5:aa')).toThrow(/OpenSSH SHA-256 fingerprint/);
  });

  it('the generation survives updates and reloads, and a re-add mints a NEW one (review 2325)', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    const gen = store.add(web).generation!;
    store.update({ ...web, host: '10.0.0.9' });
    expect(store.get('web-01')?.generation).toBe(gen); // edit = same record
    const reopened = new ServerStore(file);
    expect(reopened.get('web-01')?.generation).toBe(gen); // persisted
    reopened.remove('web-01');
    const readded = reopened.add(web);
    expect(readded.generation).not.toBe(gen); // re-add = new trust record
  });

  it('pinHostKey CAS axis 2: a record that changed mid-handshake refuses the pin (review 2311)', () => {
    const store = new ServerStore(tempFile());
    const snap = store.add({ id: 'web-01', host: 'a.example', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' });
    // The entry is rehosted while connection A's key exchange is in flight:
    // A's observation describes the OLD endpoint and must not admit into the
    // new configuration.
    store.update({ id: 'web-01', host: 'b.example', username: 'ops', environment: 'production' });
    expect(() => store.pinHostKey(snap, FP)).toThrow(/changed while the handshake was in flight/);
    expect(store.get('web-01')?.hostKeyFingerprint).toBeUndefined(); // nothing was admitted
    // A handshake opened against the CURRENT record pins normally.
    const fresh = store.get('web-01')!;
    expect(store.pinHostKey(fresh, FP).hostKeyAdmittedBy).toBe('first-use');
    // Malformed fingerprints refuse against a fresh snapshot too.
    const store2 = new ServerStore(tempFile());
    const s3 = store2.add({ id: 'web-03', host: 'h', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' });
    expect(() => store2.pinHostKey(s3, 'MD5:aa')).toThrow(/OpenSSH SHA-256 fingerprint/);
  });

  it('an edit that RESUBMITS the prefilled fingerprint does not launder first-use into operator (review 2311)', () => {
    const store = new ServerStore(tempFile());
    const snap = store.add({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', authMethod: 'password', password: 'pw' });
    store.pinHostKey(snap, FP);
    // The edit form prefills the fingerprint; changing an unrelated field
    // resubmits the SAME value — not an admission event.
    store.update({ id: 'web-01', host: 'h', username: 'ops', environment: 'staging', hostKeyFingerprint: FP });
    expect(store.get('web-01')?.environment).toBe('staging');
    expect(store.get('web-01')?.hostKeyAdmittedBy).toBe('first-use');
    // Omitting it keeps provenance too.
    store.update({ id: 'web-01', host: 'h', username: 'ops', environment: 'production' });
    expect(store.get('web-01')?.hostKeyAdmittedBy).toBe('first-use');
    // A DIFFERENT value is a deliberate replacement — operator admission.
    store.update({ id: 'web-01', host: 'h', username: 'ops', environment: 'production', hostKeyFingerprint: FP2 });
    expect(store.get('web-01')?.hostKeyAdmittedBy).toBe('operator');
  });

  it('rejects a malformed host key fingerprint', () => {
    const store = new ServerStore(tempFile());
    for (const bad of ['MD5:aa:bb', 'SHA256:short', FP.slice(7), `${FP}extra`, 'SHA256:BXfYDQo9GigRWVMVtCXKJBG9z5LXQiav4rZLeMQ6Tt=']) {
      expect(() => store.add({ ...web, hostKeyFingerprint: bad })).toThrow(/OpenSSH SHA-256 fingerprint/);
    }
    expect(store.list()).toEqual([]);
  });

  it('re-admits a rotated host key only through an explicit update', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    store.add(web);
    store.update({ ...web, host: '10.0.0.9' }); // unrelated edit keeps the admitted key
    expect(store.get('web-01')?.hostKeyFingerprint).toBe(FP);
    store.update({ ...web, hostKeyFingerprint: FP2 });
    expect(store.get('web-01')?.hostKeyFingerprint).toBe(FP2);
    expect(new ServerStore(file).get('web-01')?.hostKeyFingerprint).toBe(FP2);
  });

  it('loads a stored entry that predates host key admission without crashing, and leaves it unadmitted', () => {
    // A store file written before this field existed must not crash-loop the
    // Widget; since #44 such an entry is accept-new — its host key is pinned
    // at the first key exchange — rather than inert.
    const file = tempFile();
    const legacy: ServerInput = { id: web.id, host: web.host, username: web.username, environment: web.environment };
    writeFileSync(file, JSON.stringify([legacy]));
    const store = new ServerStore(file);
    expect(store.get('web-01')?.hostKeyFingerprint).toBeUndefined();
    // ...and editing it (still without a fingerprint) keeps it accept-new.
    store.update({ ...legacy, host: '10.0.0.9' });
    expect(store.get('web-01')?.host).toBe('10.0.0.9');
    expect(store.get('web-01')?.hostKeyFingerprint).toBeUndefined();
  });

  it('preserves stored secrets when update omits or blanks them (secrets are write-only, never prefilled)', () => {
    const store = new ServerStore(tempFile());
    const enc = { ...base, id: 'enc-01', authMethod: 'privateKeyWithPassphrase' as const };
    store.add({ ...enc, privateKey: KEY, passphrase: 'key phrase' });
    expect(store.get('enc-01')?.privateKey).toBe(KEY);
    expect(store.get('enc-01')?.passphrase).toBe('key phrase');
    store.update({ ...enc, host: 'h2' }); // secrets omitted
    expect(store.get('enc-01')?.privateKey).toBe(KEY);
    expect(store.get('enc-01')?.passphrase).toBe('key phrase');
    store.update({ ...enc, host: 'h3', privateKey: '', passphrase: '' }); // blank
    expect(store.get('enc-01')?.privateKey).toBe(KEY);
    expect(store.get('enc-01')?.passphrase).toBe('key phrase');
    // A non-blank submit replaces exactly the supplied secret.
    store.update({ ...enc, passphrase: 'new phrase' });
    expect(store.get('enc-01')?.privateKey).toBe(KEY); // untouched
    expect(store.get('enc-01')?.passphrase).toBe('new phrase');
    // authMethod omitted on update keeps the stored method.
    store.update({ ...base, id: 'enc-01', host: 'h4' });
    expect(store.get('enc-01')?.authMethod).toBe('privateKeyWithPassphrase');
    expect(store.get('enc-01')?.passphrase).toBe('new phrase');
  });

  it('stores a secret verbatim — surrounding whitespace is not trimmed away', () => {
    const store = new ServerStore(tempFile());
    store.add({ ...web, password: '  spaced pw  ' });
    expect(store.get('web-01')?.password).toBe('  spaced pw  ');
  });

  it('a failed durable write leaves both memory and the previous file unchanged', () => {
    const file = tempFile();
    const store = new ServerStore(file);
    store.add(web);
    const before = readFileSync(file, 'utf8');
    chmodSync(dirname(file), 0o500); // read+execute, no write
    try {
      let threw = false;
      try {
        store.add({ id: 'db-01', host: 'h', username: 'u', environment: 'staging', hostKeyFingerprint: FP, authMethod: 'password', password: 'pw' });
      } catch {
        threw = true;
      }
      if (!threw) return; // permissive fs (e.g. running as root) — cannot exercise the failure
      expect(store.get('db-01')).toBeUndefined(); // in-memory snapshot unchanged
      expect(readFileSync(file, 'utf8')).toBe(before); // durable file unchanged
    } finally {
      chmodSync(dirname(file), 0o700);
    }
  });

  it('switching authMethod retires the other method secrets and demands the new method secret (#42)', () => {
    const store = new ServerStore(tempFile());
    store.add(web); // password auth
    // A switch without the new method's secret is refused, and refusal
    // changes nothing.
    expect(() => store.update({ ...base, authMethod: 'privateKey' })).toThrow(/requires the privateKey content/);
    expect(store.get('web-01')?.password).toBe('pw');
    // Password -> plain key: the password is retired with the switch.
    store.update({ ...base, authMethod: 'privateKey', privateKey: KEY });
    expect(store.get('web-01')?.authMethod).toBe('privateKey');
    expect(store.get('web-01')?.privateKey).toBe(KEY);
    expect(store.get('web-01')?.password).toBeUndefined();
    // Plain key -> encrypted key: the OLD BYTES DO NOT SURVIVE (review 2305 —
    // encrypting a key changes its content; carrying the plaintext bytes
    // forward would persist a method that disagrees with its key format).
    // Both the key and its passphrase must come in with the switch.
    expect(() => store.update({ ...base, authMethod: 'privateKeyWithPassphrase', passphrase: 'kp' })).toThrow(/requires the privateKey content/);
    expect(store.get('web-01')?.authMethod).toBe('privateKey'); // refusal changed nothing
    const ENC_KEY = `${KEY}encrypted`;
    store.update({ ...base, authMethod: 'privateKeyWithPassphrase', privateKey: ENC_KEY, passphrase: 'kp' });
    expect(store.get('web-01')?.privateKey).toBe(ENC_KEY);
    expect(store.get('web-01')?.passphrase).toBe('kp');
    // Encrypted key -> plain key: same rule in the other direction — the
    // decrypted key is different bytes and must be supplied.
    expect(() => store.update({ ...base, authMethod: 'privateKey' })).toThrow(/requires the privateKey content/);
    store.update({ ...base, authMethod: 'privateKey', privateKey: KEY });
    expect(store.get('web-01')?.privateKey).toBe(KEY);
    expect(store.get('web-01')?.passphrase).toBeUndefined();
    // Key -> password: nothing survives either.
    store.update({ ...base, authMethod: 'password', password: 'back' });
    expect(store.get('web-01')?.password).toBe('back');
    expect(store.get('web-01')?.privateKey).toBeUndefined();
  });

  it('refuses a secret the chosen method does not use — contradictory input is never silently dropped (#42)', () => {
    const store = new ServerStore(tempFile());
    expect(() => store.add({ ...web, id: 'a', privateKey: KEY })).toThrow(/does not apply/);
    expect(() => store.add({ ...web, id: 'b', authMethod: 'privateKey', privateKey: KEY })).toThrow(/does not apply/);
    expect(() => store.add({ ...base, id: 'c', authMethod: 'privateKey', privateKey: KEY, passphrase: 'kp' })).toThrow(/does not apply/);
    expect(() => store.add({ ...base, id: 'd', authMethod: 'agent', password: 'pw' })).toThrow(/authMethod must be one of/);
    // Setting a secret with no method at all is refused too.
    expect(() => store.add({ ...base, id: 'e', password: 'pw' })).toThrow(/authMethod is required/);
    expect(store.list()).toEqual([]);
  });

  it('refuses to LOAD a persisted record whose secrets disagree with its method — the durable ingress enforces the same invariant (review 2284 P2)', () => {
    const f1 = tempFile();
    writeFileSync(f1, JSON.stringify([{ id: 'web-01', host: 'h', username: 'ops', environment: 'development', passphrase: 'kp' }]), { mode: 0o600 });
    expect(() => new ServerStore(f1)).toThrow(/authMethod/);
    const f2 = tempFile();
    writeFileSync(f2, JSON.stringify([{ id: 'web-01', host: 'h', username: 'ops', environment: 'development', authMethod: 'privateKey', password: 'pw' }]), { mode: 0o600 });
    expect(() => new ServerStore(f2)).toThrow(/does not apply|belongs to/);
  });

  it('loads a pre-#42 store: password-only derives authMethod "password"; ANY privateKeyPath entry drops to inert whole', () => {
    const file = tempFile();
    writeFileSync(
      file,
      JSON.stringify([
        { id: 'pw-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: FP, password: 'hunter2' },
        { id: 'key-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: FP, privateKeyPath: '/keys/id', passphrase: 'kp' },
        { id: 'both-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: FP, privateKeyPath: '/keys/id', password: 'hunter2' },
      ]),
      { mode: 0o600 },
    );
    const store = new ServerStore(file);
    // The only legacy shape that maps one-to-one: password with NO retired
    // key reference anywhere.
    expect(store.get('pw-01')?.authMethod).toBe('password');
    expect(store.get('pw-01')?.password).toBe('hunter2');
    // The retired key REFERENCE has no content to migrate: the entry loads
    // inert (no method, no secrets — the executor refuses it) instead of
    // crash-looping the Widget, and is reconfigured through manageServers.
    expect(store.get('key-01')).toBeDefined();
    expect(store.get('key-01')?.authMethod).toBeUndefined();
    expect(store.get('key-01')?.privateKey).toBeUndefined();
    expect(store.get('key-01')?.passphrase).toBeUndefined();
    // key + password rode ONE connection in the old model — deriving
    // password-only would pick a method the operator never chose (review
    // 2305): the whole entry drops to inert, password included.
    expect(store.get('both-01')?.authMethod).toBeUndefined();
    expect(store.get('both-01')?.password).toBeUndefined();
    // Reconfiguring with content works.
    store.update({ id: 'key-01', host: 'h', username: 'ops', environment: 'development', hostKeyFingerprint: FP, authMethod: 'privateKey', privateKey: KEY });
    expect(store.get('key-01')?.authMethod).toBe('privateKey');
  });
});
