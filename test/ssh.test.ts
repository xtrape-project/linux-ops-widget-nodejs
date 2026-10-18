import { afterEach, describe, expect, it } from 'vitest';
import { createRequire } from 'node:module';
import { generateKeyPairSync } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { SshExecutor, fetchHostKeyFingerprint, hostKeyFingerprint } from '../src/executors/ssh.js';
import type { ServerDefinition } from '../src/types.js';

// ssh2's Server is CJS-only in its type surface; require it directly.
const require_ = createRequire(import.meta.url);
const { Server, utils } = require_('ssh2') as typeof import('ssh2');

/**
 * The SSH executor is the only real execution path in this Widget, so it is
 * exercised against a genuine in-process SSH server rather than a mock: the
 * behaviour that matters (exec channel, stdout/stderr split, exit code, timeout)
 * lives in the ssh2 protocol handling, which a hand-rolled fake would not cover.
 */
const hostKey = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
}).privateKey;

/** The wire-format public key blob — the same bytes `ssh-keygen -lf` digests. */
function publicSSH(privateKeyPem: string): Buffer {
  const parsed = utils.parseKey(privateKeyPem);
  if (parsed instanceof Error) throw parsed;
  return parsed.getPublicSSH();
}

/** The fingerprint of the host key the in-process server actually presents. */
const serverFingerprint = hostKeyFingerprint(publicSSH(hostKey));

/** A well-formed fingerprint of some OTHER key — an impersonated endpoint. */
const otherFingerprint = hostKeyFingerprint(
  publicSSH(
    generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
      publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    }).privateKey,
  ),
);

let server: import('ssh2').Server | undefined;

afterEach(async () => {
  await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
  server = undefined;
});

/** Start an SSH server that answers every exec with the given script. */
async function startServer(
  handle: (command: string) => { stdout?: string; stderr?: string; code?: number; hang?: boolean; flood?: 'stdout' | 'stderr' | 'both'; floodBytes?: number; rawChunks?: Buffer[] },
  requirePassword?: string,
  requirePublicKey?: string, // OpenSSH public key line: only this key authenticates (real two-phase negotiation)
): Promise<number> {
  const allowedKey = requirePublicKey ? utils.parseKey(requirePublicKey) : undefined;
  if (allowedKey instanceof Error) throw allowedKey;
  server = new Server({ hostKeys: [hostKey] }, (client) => {
    // A client that rejects our host key aborts key exchange; ssh2 surfaces
    // that on the server connection as KEY_EXCHANGE_FAILED. Expected here —
    // swallow it so it does not become an unhandled 'error' event.
    client.on('error', () => {});
    client.on('authentication', (ctx) => {
      // Default: accept any method. When a password is required, only a
      // matching 'password' attempt is accepted — a real negotiation, so the
      // executor genuinely proves it sent the stored password.
      if (allowedKey) {
        // Real publickey negotiation: blob match, then SIGNATURE verification
        // on the second phase — the client genuinely proves it decrypted and
        // holds the private key (review 2254 P2: passphrase auth must be
        // exercised for real, not stubbed).
        if (ctx.method === 'publickey' && ctx.key.algo === allowedKey.type && ctx.key.data.equals(allowedKey.getPublicSSH())) {
          if (!ctx.signature) return ctx.accept(); // probe phase
          if (allowedKey.verify(ctx.blob!, ctx.signature, ctx.hashAlgo) === true) return ctx.accept();
          return ctx.reject(['publickey']);
        }
        return ctx.reject(['publickey']);
      }
      if (requirePassword === undefined) return ctx.accept();
      if (ctx.method === 'password' && ctx.password === requirePassword) return ctx.accept();
      return ctx.reject(['password']);
    }).on('ready', () => {
      client.on('session', (accept) => {
        const session = accept();
        session.on('exec', (acceptExec, _reject, info) => {
          const out = handle(info.command);
          if (out.hang) return; // never respond — drives the timeout path
          const stream = acceptExec();
          if (out.flood !== undefined) {
            // A verbose command: it writes a lot and then FINISHES with its
            // own exit status. `floodBytes` undefined means it never stops,
            // which is what an unbounded command looks like from this side.
            const chunk = 'x'.repeat(4096);
            let closed = false;
            let written = 0;
            stream.on('close', () => {
              closed = true;
            });
            const pump = (): void => {
              if (closed) return;
              for (let i = 0; i < 64; i += 1) {
                if (out.floodBytes !== undefined && written >= out.floodBytes) {
                  stream.exit(out.code ?? 0);
                  stream.end();
                  return;
                }
                if (out.flood === 'stdout' || (out.flood === 'both' && i % 2 === 0)) stream.write(chunk);
                if (out.flood === 'stderr' || (out.flood === 'both' && i % 2 === 1)) stream.stderr.write(chunk);
                written += chunk.length;
              }
              setImmediate(pump);
            };
            pump();
            return;
          }
          if (out.rawChunks) {
            // Byte-level control: lets a test split a multi-byte character
            // across two network chunks, which is what a real stream does.
            for (const chunk of out.rawChunks) stream.write(chunk);
            stream.exit(out.code ?? 0);
            stream.end();
            return;
          }
          if (out.stdout) stream.write(out.stdout);
          if (out.stderr) stream.stderr.write(out.stderr);
          stream.exit(out.code ?? 0);
          stream.end();
        });
      });
    });
  });
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  return (server!.address() as AddressInfo).port;
}

/** `null` means no admitted fingerprint at all (an unverifiable target). */
const target = (port: number, hostKeyFp: string | null = serverFingerprint): ServerDefinition => ({
  id: 'web-01',
  host: '127.0.0.1',
  port,
  username: 'linux-ops',
  environment: 'development',
  // The in-process server accepts any method by default; a stored credential
  // must exist for the executor's own credential-less refusal (review 2305)
  // to let the connection proceed at all. Auth-specific tests override it.
  authMethod: 'password',
  password: 'any',
  ...(hostKeyFp ? { hostKeyFingerprint: hostKeyFp } : {}),
});

/** The same target with NO stored credential — the inert legacy shape. */
const credentialless = (port: number): ServerDefinition => {
  const rest = { ...target(port) };
  delete rest.authMethod;
  delete rest.password;
  return rest;
};

describe('SshExecutor', () => {
  it('authenticates with a stored password against a password-requiring server', async () => {
    const port = await startServer(() => ({ stdout: 'ok\n', code: 0 }), 'hunter2');
    const result = await new SshExecutor().run({ ...target(port), password: 'hunter2' }, { command: 'whoami' });
    expect(result).toMatchObject({ command: 'whoami', exitCode: 0 });
    expect(result.stdout).toBe('ok\n');
  });

  it('fails to connect when the stored password is wrong (auth is real, not bypassed)', async () => {
    const port = await startServer(() => ({ stdout: 'ok\n', code: 0 }), 'hunter2');
    await expect(new SshExecutor().run({ ...target(port), password: 'wrong' }, { command: 'whoami' })).rejects.toThrow();
  });

  it('refuses a credential-less entry BEFORE connecting — even a none-auth-friendly target runs nothing (review 2305)', async () => {
    // This in-process server accepts ANY auth method by default, `none`
    // included — exactly the target that would let a supposedly-inert legacy
    // entry (retired privateKeyPath dropped at load) keep executing. The
    // refusal must come from the executor, before ssh2 ever offers `none`.
    let executed = false;
    const port = await startServer(() => {
      executed = true;
      return { stdout: 'should never run\n', code: 0 };
    });
    await expect(new SshExecutor().run(credentialless(port), { command: 'whoami' })).rejects.toThrow(/no usable credential/);
    expect(executed).toBe(false);
  });

  // The encrypted client key for the passphrase tests: ssh2's own generator
  // produces OpenSSH-format material both the in-process server (public line)
  // and the executor's client (encrypted private) genuinely parse.
  const encryptedClient = (utils as unknown as { generateKeyPairSync: (type: string, opts: Record<string, unknown>) => { public: string; private: string } })
    .generateKeyPairSync('rsa', { bits: 2048, passphrase: 'kp-correct-horse', cipher: 'aes256-cbc' });

  it('decrypts an ENCRYPTED private key with the stored passphrase and authenticates (real key auth)', async () => {
    // The key CONTENT is the stored secret (#42) — nothing touches the filesystem.
    const port = await startServer(() => ({ stdout: 'ok\n', code: 0 }), undefined, encryptedClient.public);
    const result = await new SshExecutor().run(
      { ...credentialless(port), authMethod: 'privateKeyWithPassphrase', privateKey: encryptedClient.private, passphrase: 'kp-correct-horse' },
      { command: 'whoami' },
    );
    expect(result).toMatchObject({ command: 'whoami', exitCode: 0 });
  });

  it('fails with a WRONG passphrase for an encrypted key (decryption is real, not bypassed)', async () => {
    const port = await startServer(() => ({ stdout: 'ok\n', code: 0 }), undefined, encryptedClient.public);
    await expect(
      new SshExecutor().run(
        { ...credentialless(port), authMethod: 'privateKeyWithPassphrase', privateKey: encryptedClient.private, passphrase: 'kp-wrong' },
        { command: 'whoami' },
      ),
    ).rejects.toThrow();
  });

  it('runs a command and returns stdout, stderr, and the exit code', async () => {
    const port = await startServer(() => ({ stdout: 'up 3 days\n', stderr: 'warn\n', code: 0 }));
    const result = await new SshExecutor().run(target(port), { command: 'uptime' });
    expect(result).toMatchObject({ command: 'uptime', exitCode: 0 });
    expect(result.stdout).toBe('up 3 days\n');
    expect(result.stderr).toBe('warn\n');
  });

  it('reports a non-zero exit code rather than throwing', async () => {
    const port = await startServer(() => ({ stderr: 'nginx: configuration file test failed\n', code: 1 }));
    const result = await new SshExecutor().run(target(port), { command: 'nginx -t' });
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('test failed');
  });

  it.each(['stdout', 'stderr', 'both'] as const)(
    'records at most maxOutputBytes but lets the task FINISH when %s floods (#61 B)',
    async (where) => {
      // The ceiling bounds what this Worker RECORDS, not what the task may
      // do: beyond it output is read and dropped, so this process's memory
      // stays bounded across both streams together while the command runs to
      // completion and reports its own exit status. Cutting the channel here
      // used to buy bandwidth at the price of the outcome — a verbose task
      // with side effects was killed mid-run and answered "unknown".
      const port = await startServer(() => ({ flood: where, floodBytes: 200_000, code: 3 }));
      const result = await new SshExecutor().run(target(port), { command: 'flood', maxOutputBytes: 32_768 });
      expect(result.stdout.length + result.stderr.length).toBe(32_768);
      // The task's OWN exit status, observed because it was allowed to finish.
      expect(result.exitCode).toBe(3);
      expect(result.terminatedBy).toBeUndefined();
      // How much was dropped is stated as a field, which the output policy
      // cannot trim away the way it could an appended note.
      expect(result.outputTruncated?.recordedBytes).toBe(32_768);
      expect(result.outputTruncated?.discardedBytes).toBeGreaterThan(0);
    },
    20_000,
  );

  it('records nothing beyond the default ceiling even when the caller names none (review 2162)', async () => {
    // The task path passes one; `testServer`'s connectivity probe did not, and
    // the default was Infinity — so a host already in the fleet, misbehaving
    // or taken over, could flood the one path that was not bounded. A default
    // nobody can forget is worth more than one every call site is told to pass.
    const port = await startServer(() => ({ flood: 'stdout', floodBytes: 300_000, code: 0 }));
    const result = await new SshExecutor().run(target(port), { command: 'true' });
    expect(result.stdout.length + result.stderr.length).toBe(65_536);
    expect(result.exitCode).toBe(0);
    expect(result.outputTruncated?.discardedBytes).toBeGreaterThan(0);
  }, 20_000);

  it('records MORE than the old 64 KiB default when the deployment asks for it (review 2382)', async () => {
    // The redaction pass used to cut at its own 64 KiB default, so a
    // deployment configured for 256 KiB still only ever saw 64 KiB.
    const port = await startServer(() => ({ flood: 'stdout', floodBytes: 400_000, code: 0 }));
    const result = await new SshExecutor().run(target(port), { command: 'flood', maxOutputBytes: 262_144 });
    expect(result.stdout.length).toBe(262_144);
    expect(result.exitCode).toBe(0);
    expect(result.outputTruncated?.recordedBytes).toBe(262_144);
  }, 20_000);

  it('never records a half character at the ceiling (review 2382)', async () => {
    // Three-byte characters against a ceiling that lands mid-character: the
    // kept text must be whole characters, with the count agreeing.
    const port = await startServer(() => ({ stdout: '世'.repeat(10), code: 0 }));
    const result = await new SshExecutor().run(target(port), { command: 'echo', maxOutputBytes: 10 });
    expect(result.stdout).toBe('世'.repeat(3)); // 9 bytes; the 10th would split one
    expect(result.stdout).not.toContain('\uFFFD');
    expect(result.outputTruncated?.recordedBytes).toBe(9);
  }, 20_000);

  it('decodes a character SPLIT ACROSS chunks correctly (review 2383)', async () => {
    // '世' is three bytes. Split across writes: decoding each chunk on its
    // own would produce replacement characters in the middle of the output,
    // where no ceiling is even involved.
    const whole = Buffer.from('世界世界', 'utf8');
    const port = await startServer(() => ({
      rawChunks: [whole.subarray(0, 2), whole.subarray(2, 7), whole.subarray(7)],
      code: 0,
    }));
    const result = await new SshExecutor().run(target(port), { command: 'echo' });
    expect(result.stdout).toBe('世界世界');
    expect(result.stdout).not.toContain('\uFFFD');
    expect(result.outputTruncated).toBeUndefined();
  }, 20_000);

  it('recorded + discarded accounts for everything the remote wrote (review 2383)', async () => {
    // The counts are DERIVED from one accumulation, so they cannot drift: an
    // independently incremented "discarded" disagreed with what was kept.
    const written = 400_000;
    const port = await startServer(() => ({ flood: 'both', floodBytes: written, code: 0 }));
    const result = await new SshExecutor().run(target(port), { command: 'flood', maxOutputBytes: 50_000 });
    const truncated = result.outputTruncated!;
    expect(truncated.recordedBytes).toBe(50_000);
    expect(truncated.recordedBytes).toBe(
      Buffer.byteLength(result.stdout, 'utf8') + Buffer.byteLength(result.stderr, 'utf8'),
    );
    expect(truncated.recordedBytes + truncated.discardedBytes).toBeGreaterThanOrEqual(written);
  }, 20_000);

  it('a task with truly unbounded output is bounded by its DEADLINE, not by the recording ceiling (#61 B)', async () => {
    // Nothing about recording less ends a command. What ends one is the
    // task's own `# timeout:` — or a Platform-delivered cancel.
    const port = await startServer(() => ({ flood: 'stdout' })); // never finishes
    await expect(
      new SshExecutor().run(target(port), { command: 'flood', maxOutputBytes: 4096, timeoutMs: 400 }),
    ).rejects.toThrow(/timed out after 400ms/);
  }, 20_000);

  it('rejects when a task that declared a deadline exceeds it', async () => {
    const port = await startServer(() => ({ hang: true }));
    await expect(
      new SshExecutor().run(target(port), { command: 'sleep 60', timeoutMs: 200 }),
    ).rejects.toThrow(/timed out after 200ms/);
  });

  it('waits with no deadline at all when the task declared none', async () => {
    // A task may legitimately run for hours. The Worker imposing 60 seconds on
    // everything was this Widget deciding something no author asked for.
    const port = await startServer(() => ({ hang: true }));
    const controller = new AbortController();
    const run = new SshExecutor().run(target(port), { command: 'sleep forever', signal: controller.signal });
    const settled = run.then(() => 'settled').catch(() => 'settled');
    const raced = await Promise.race([
      settled,
      new Promise((resolve) => setTimeout(() => resolve('still waiting'), 700)),
    ]);
    expect(raced).toBe('still waiting');
    // Only the test's own cancel ends it — nothing on the Worker side would have.
    controller.abort();
    await settled;
  }, 10_000);

  it('stops waiting when the Platform cancels the command', async () => {
    // The escape hatch that replaces the mandatory deadline: unbounded, but
    // cancellable. Ignoring the signal left CANCEL with no effect here.
    const port = await startServer(() => ({ hang: true }));
    const controller = new AbortController();
    const run = new SshExecutor().run(target(port), { command: 'sleep forever', signal: controller.signal });
    setTimeout(() => controller.abort(), 100);
    await expect(run).rejects.toThrow(/cancelled/);
  }, 10_000);

  it('rejects when the connection fails', async () => {
    // Port 1 on loopback: nothing listens, so connect() errors out.
    await expect(new SshExecutor().run(target(1), { command: 'uptime' })).rejects.toThrow();
  });
});

/**
 * Host key admission, against the same real in-process SSH server. These are
 * the negative cases: the executor must refuse an endpoint it cannot prove is
 * the admitted host, and it must refuse *before* the command reaches the wire.
 */
describe('SshExecutor host key verification', () => {
  it('accepts the endpoint whose host key matches the admitted fingerprint', async () => {
    const port = await startServer(() => ({ stdout: 'ok\n', code: 0 }));
    const result = await new SshExecutor().run(target(port, serverFingerprint), { command: 'uptime' });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('ok\n');
  });

  it('refuses an endpoint presenting a different host key, and runs nothing', async () => {
    const commands: string[] = [];
    const port = await startServer((command) => {
      commands.push(command);
      return { stdout: 'should never run\n', code: 0 };
    });
    await expect(new SshExecutor().run(target(port, otherFingerprint), { command: 'uptime' })).rejects.toThrow(
      /host key verification failed for server "web-01"/,
    );
    // The command never reached the endpoint: verification runs during key
    // exchange, before authentication and before any exec channel exists.
    expect(commands).toEqual([]);
  });

  it('names both fingerprints so a rotation is distinguishable from an impersonation', async () => {
    const port = await startServer(() => ({ code: 0 }));
    await expect(new SshExecutor().run(target(port, otherFingerprint), { command: 'uptime' })).rejects.toThrow(
      new RegExp(`presented ${serverFingerprint.replace(/[+/]/g, '\\$&')}`),
    );
  });

  it('refuses to connect when no fingerprint is admitted AND no pinner is configured', async () => {
    const commands: string[] = [];
    const port = await startServer((command) => {
      commands.push(command);
      return { stdout: 'should never run\n', code: 0 };
    });
    await expect(new SshExecutor().run(target(port, null), { command: 'uptime' })).rejects.toThrow(
      /no admitted SSH host key fingerprint and this executor has no pinner/,
    );
    expect(commands).toEqual([]);
  });

  it('accept-new (#44): pins the presented host key on first use, and the pinned value is the REAL one', async () => {
    const pins: Array<{ id: string; fp: string }> = [];
    // The pinner receives the exact record SNAPSHOT the connection was
    // opened with (review 2311) — the store CAS-es the pin against it.
    const executor = new SshExecutor({ pin: (server, fp) => void pins.push({ id: server.id, fp }), ensureDurable: () => {} });
    const port = await startServer(() => ({ stdout: 'ok\n', code: 0 }));
    const snapshot = target(port, null);
    const result = await executor.run(snapshot, { command: 'uptime' });
    expect(result.exitCode).toBe(0);
    expect(pins).toEqual([{ id: 'web-01', fp: serverFingerprint }]);
  });

  it('accept-new (#44): a pin that cannot persist REFUSES the connection and runs nothing', async () => {
    const executor = new SshExecutor({ pin: () => { throw new Error('disk full'); }, ensureDurable: () => {} });
    const commands: string[] = [];
    const port = await startServer((command) => {
      commands.push(command);
      return { stdout: 'should never run\n', code: 0 };
    });
    await expect(executor.run(target(port, null), { command: 'uptime' })).rejects.toThrow(
      /could not durably pin the host key .*disk full/,
    );
    expect(commands).toEqual([]);
  });

  it('accept-new (#44): an ADMITTED fingerprint is never re-pinned — mismatch still refuses with a pinner present', async () => {
    const pins: string[] = [];
    const executor = new SshExecutor({ pin: (_server, fp) => void pins.push(fp), ensureDurable: () => {} });
    const port = await startServer(() => ({ stdout: 'should never run\n', code: 0 }));
    await expect(executor.run(target(port, otherFingerprint), { command: 'uptime' })).rejects.toThrow(
      /host key verification failed/,
    );
    expect(pins).toEqual([]); // the pinner was never consulted
  });

  it('an unconfirmed pin blocks EXECUTION on the very next connection, same process, until durability truly confirms (review 2313)', async () => {
    // The real store adopts the pin in memory but marks durability
    // unconfirmed when the post-rename directory sync fails; this pinner
    // reproduces that contract.
    let unconfirmed = false;
    let syncWorks = false;
    const pinner = {
      pin: (): void => {
        unconfirmed = true;
        throw new Error('server store updated but its durability is NOT confirmed');
      },
      ensureDurable: (): void => {
        if (!unconfirmed) return;
        if (!syncWorks) throw new Error('directory sync failed again');
        unconfirmed = false;
      },
    };
    const executor = new SshExecutor(pinner);
    const commands: string[] = [];
    const port = await startServer((command) => {
      commands.push(command);
      return { stdout: 'ok\n', code: 0 };
    });
    // 1) First connection: TOFU pin, durability sync fails → refused.
    await expect(executor.run(target(port, null), { command: 'uptime' })).rejects.toThrow(/could not durably pin/);
    expect(commands).toEqual([]);
    // 2) The store's memory now carries the fingerprint (the adopted pin).
    //    An IMMEDIATE second connection in the same process must NOT treat
    //    it as an ordinary admitted key: re-confirmation runs, still fails,
    //    execution refused — nothing ran on the unconfirmed pin.
    await expect(executor.run(target(port, serverFingerprint), { command: 'uptime' })).rejects.toThrow(
      /durability is not confirmed.*refusing to execute on an unconfirmed pin/,
    );
    expect(commands).toEqual([]);
    // 3) Durability heals: the gate re-performs the sync, confirms, and only
    //    THEN does the pin behave as admitted.
    syncWorks = true;
    const result = await executor.run(target(port, serverFingerprint), { command: 'uptime' });
    expect(result.exitCode).toBe(0);
    expect(commands).toEqual(['uptime']);
    expect(unconfirmed).toBe(false);
  });

  it('fetchHostKeyFingerprint probes the endpoint without any credential and admits nothing (#44)', async () => {
    const commands: string[] = [];
    const port = await startServer((command) => {
      commands.push(command);
      return { stdout: 'should never run\n', code: 0 };
    });
    const fp = await fetchHostKeyFingerprint('127.0.0.1', port, 5000);
    expect(fp).toBe(serverFingerprint);
    expect(commands).toEqual([]); // key exchange only — nothing executed
    await expect(fetchHostKeyFingerprint('127.0.0.1', 1, 2000)).rejects.toThrow(); // no listener → error, not a guess
  });

  it('computes the OpenSSH SHA-256 fingerprint form', () => {
    expect(serverFingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
    expect(serverFingerprint).not.toBe(otherFingerprint);
  });
});
