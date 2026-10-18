import { createHash } from 'node:crypto';
import { Client } from 'ssh2';
import type { CommandInvocation, CommandResult, Executor, ServerDefinition } from '../types.js';
import { trimIncompleteUtf8 } from '../redact.js';

/**
 * Output ceiling applied when a caller names none.
 *
 * Fail-safe by default rather than by convention: `Infinity` meant every call
 * site had to remember to pass a ceiling, and `testServer`'s connectivity
 * probe did not — so a host already in the fleet, misbehaving or taken over,
 * could flood that path without limit even though the task path was bounded
 * (review 2162). A bound nobody can forget is worth more than one everybody
 * is told to pass.
 */
const DEFAULT_MAX_OUTPUT_BYTES = 65_536;

/** `SHA256:` + unpadded base64 — the form `ssh-keygen -lf` prints and operators recognise. */
export const HOST_KEY_FINGERPRINT_PATTERN = /^SHA256:[A-Za-z0-9+/]{43}$/;

/**
 * OpenSSH host key fingerprint of a raw public key blob: base64 of the SHA-256
 * digest, padding stripped. `ssh2` hands the wire-format blob to `hostVerifier`,
 * and that is the same byte sequence `ssh-keygen -lf` digests, so a fingerprint
 * an operator reads off the host matches the one computed here.
 */
export function hostKeyFingerprint(publicKey: Buffer): string {
  return `SHA256:${createHash('sha256').update(publicKey).digest('base64').replace(/=+$/, '')}`;
}

/**
 * A host key MISMATCH, as a typed error (#46): the caller that can offer the
 * operator a rotation flow (testServer) needs the two fingerprints as DATA,
 * not as prose to re-parse out of a message. Fingerprints are digests of
 * public keys — safe to carry and to show. The message keeps the exact
 * wording every other caller already surfaces.
 */
export class HostKeyMismatchError extends Error {
  constructor(
    readonly serverId: string,
    readonly host: string,
    /** The effective port the mismatch was observed on — part of the rotation CAS basis (review 2325). */
    readonly port: number,
    readonly admitted: string,
    readonly presented: string,
    /** The record generation the connection was opened against — the anti-remove/re-add axis of the CAS. */
    readonly generation: string,
  ) {
    super(
      `ssh host key verification failed for server "${serverId}" (${host}:${port}): endpoint presented ${presented}, admitted ${admitted}. Connection refused. If the host key was rotated legitimately, update the fingerprint through manageServers.`,
    );
    this.name = 'HostKeyMismatchError';
  }
}

/**
 * Where a first-use host key pin is recorded (#44). Backed by the
 * ServerStore in production; the executor treats a throw as "refuse the
 * connection" — a pin that did not persist would make every connection the
 * first one, which is never-verify wearing accept-new's clothes.
 */
export interface HostKeyPinner {
  /**
   * `server` is the exact record snapshot this connection was opened with —
   * the pin is CAS'd against it (review 2311): a record that changed while
   * the handshake was in flight refuses the pin, so an old handshake can
   * never write its observation into a newer configuration.
   */
  pin(server: ServerDefinition, fingerprint: string): void;
  /**
   * Re-confirm — re-performing if needed — the durability of previously
   * recorded pins (review 2313). Called before an ADMITTED fingerprint is
   * exercised: a pin whose durability sync failed is live in memory but
   * could vanish with a crash, and #44's invariant is that such a pin is
   * not trusted until a sync actually succeeds. A throw refuses execution.
   */
  ensureDurable(): void;
}

/**
 * Fetch the host key fingerprint an endpoint presents, WITHOUT authenticating
 * (#44): the SSH key exchange happens before authentication, so no credential
 * is needed — the verifier captures the fingerprint and aborts the exchange.
 * This is the probe behind `probeHostKey`: it hands the operator the value to
 * confirm, it admits nothing by itself.
 */
export function fetchHostKeyFingerprint(host: string, port = 22, timeoutMs = 10_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = new Client();
    let fingerprint: string | undefined;
    const timer = setTimeout(() => {
      client.end();
      reject(new Error(`probing ${host}:${port} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    client
      .on('error', (err) => {
        clearTimeout(timer);
        // The abort we caused IS the success path; any error before the
        // verifier ran means the endpoint was never reached or spoke no SSH.
        if (fingerprint !== undefined) resolve(fingerprint);
        else reject(err);
      })
      .on('ready', () => {
        // Unreachable in practice (the verifier always aborts), but a server
        // library quirk must not leave a dangling session.
        clearTimeout(timer);
        client.end();
        if (fingerprint !== undefined) resolve(fingerprint);
        else reject(new Error(`probing ${host}:${port} completed without observing a host key`));
      })
      .connect({
        host,
        port,
        username: 'host-key-probe',
        hostVerifier: (key: Buffer): boolean => {
          fingerprint = hostKeyFingerprint(key);
          return false; // capture only — a probe admits nothing
        },
      });
  });
}

/**
 * SSH executor. Connects with the per-server least-privilege user declared in
 * the server definition; there is no shared high-privilege account.
 *
 * The endpoint is authenticated before anything else happens: `hostVerifier`
 * runs during key exchange — before authentication, before any command
 * reaches the wire. An ADMITTED fingerprint is exact: a key that does not
 * match aborts the connection. An entry with no fingerprint pins the key it
 * observes at the FIRST exchange (accept-new, #44) — durably, through the
 * pinner, before the connection may proceed — and enforces it exactly from
 * then on; with nowhere to record a pin, it refuses outright. Without the
 * recorded key, `host` names whichever endpoint currently answers for that
 * name: anyone able to bend DNS or routing could read every command and its
 * arguments and hand back forged output — an operator-admitted fingerprint
 * closes that from the first connection, a first-use pin from the second.
 */
export class SshExecutor implements Executor {
  readonly name = 'ssh';

  constructor(private readonly pinner?: HostKeyPinner) {}

  run(server: ServerDefinition, invocation: CommandInvocation): Promise<CommandResult> {
    const { command, stdin, maxOutputBytes, timeoutMs, signal } = invocation;
    return new Promise((resolve, reject) => {
      const admitted = server.hostKeyFingerprint;
      // No admitted fingerprint = accept-new (#44): the key exchange below
      // pins the presented key, durably, before the connection is allowed to
      // proceed. That is only possible with somewhere to record it.
      if (!admitted && !this.pinner) {
        return reject(
          new Error(
            `server "${server.id}" has no admitted SSH host key fingerprint and this executor has no pinner; refusing to connect to an unverifiable endpoint. Set hostKeyFingerprint through manageServers (\`ssh-keygen -lf\` on the host's public key prints the SHA256:… value).`,
          ),
        );
      }
      // An ADMITTED fingerprint may be a first-use pin whose durability sync
      // failed (review 2313): still un-trustable until a sync succeeds. The
      // gate is cheap in the steady state and self-heals a transient
      // failure; a throw refuses execution BEFORE any connection is opened.
      if (admitted && this.pinner) {
        try {
          this.pinner.ensureDurable();
        } catch (err) {
          return reject(
            new Error(
              `server "${server.id}" has a recorded host key whose durability is not confirmed, and re-confirming it failed: ${err instanceof Error ? err.message : String(err)}; refusing to execute on an unconfirmed pin (#44)`,
            ),
          );
        }
      }
      // An entry with no stored credential (a legacy record whose retired
      // privateKeyPath was dropped at load) must be INERT, not best-effort
      // (review 2305): without this refusal ssh2 attempts `none`
      // authentication, and a target that accepts it would let a
      // supposedly-inert entry execute commands.
      if (!server.privateKey && !server.password) {
        return reject(
          new Error(
            `server "${server.id}" has no usable credential; refusing to connect. Choose an authMethod and re-enter the secret through manageServers (#42).`,
          ),
        );
      }

      const client = new Client();
      let presented: string | undefined;
      let pinFailure: string | undefined;
      // NO default deadline. A task may legitimately run for hours — a deploy,
      // a migration, a task waiting on a human — and a Worker-side clock that
      // cut it off would be this Widget deciding something the task's author
      // did not ask for. A task that wants a bound sets one, in its own script
      // (`timeout 20s …`) or with `# timeout:`; what always applies is the
      // output ceiling, which bounds this process rather than the task.
      //
      // Ending the wait is not ending the work: `client.end()` closes the
      // channel, and whether the remote shell and anything it forked act on
      // that is the target's business. A task with side effects should be
      // written to be re-runnable.
      const timer =
        timeoutMs === undefined
          ? undefined
          : setTimeout(() => {
              client.end();
              reject(new Error(`ssh command timed out after ${String(timeoutMs)}ms; the connection was closed, which does not guarantee the remote command stopped`));
            }, timeoutMs);

      // A cancel delivered by the Platform is the operator's way to stop an
      // unbounded task. Ignoring it left CANCEL with no effect on this Widget.
      const onAbort = (): void => {
        client.end();
        reject(new Error('command cancelled; the connection was closed, which does not guarantee the remote command stopped'));
      };
      if (signal !== undefined) {
        if (signal.aborted) return onAbort();
        signal.addEventListener('abort', onAbort, { once: true });
      }
      const settle = (): void => {
        if (timer !== undefined) clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
      };

      client
        .on('ready', () => {
          client.exec(command, (err, stream) => {
            if (err) {
              settle();
              client.end();
              return reject(err);
            }
            // The task script is written to the remote process's standard
            // input and the stream is closed, so the interpreter sees a
            // complete program and then EOF. Closing matters: an interpreter
            // reading from an open stdin would wait forever.
            if (stdin !== undefined) stream.end(stdin);
            else stream.end();
            // RAW BYTES until the end (review 2383): a multi-byte character
            // split across two network chunks decodes to two replacement
            // characters if each chunk is decoded on its own. Assembling
            // bytes and decoding once makes the chunk boundary a non-event.
            const stdoutParts: Buffer[] = [];
            const stderrParts: Buffer[] = [];
            // The ceiling bounds what this Worker RECORDS, not what the task
            // is allowed to do (#61 B, owner ruling: "生成日志的按照业务需要
            // 生成,记录日志的按照实际能够承受的负载记录"). Beyond it, output
            // is read and DISCARDED: this process's memory stays bounded
            // across both streams together, the task runs to completion, and
            // its real exit status is observed and reported.
            //
            // Cutting the channel here — the previous behaviour — bought
            // bandwidth at the price of the outcome: a verbose task with side
            // effects was killed mid-run and answered "remote result
            // unknown", which is the worst of both. A task's RUNTIME is
            // bounded where it belongs: its own `# timeout:`, or a
            // Platform-delivered cancel.
            const ceiling = maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
            // Everything the remote wrote, and how much of it was kept. The
            // dropped count is DERIVED from the two at the end, so the three
            // numbers cannot disagree (review 2383: an independently
            // incremented counter drifted from what was actually kept).
            let writtenBytes = 0;
            let keptBytes = 0;
            const take = (chunk: Buffer, parts: Buffer[]): void => {
              writtenBytes += chunk.byteLength;
              const room = ceiling - keptBytes;
              if (room <= 0) return;
              const slice = chunk.byteLength <= room ? chunk : chunk.subarray(0, room);
              parts.push(slice);
              keptBytes += slice.byteLength;
            };
            stream
              .on('data', (chunk: Buffer) => take(chunk, stdoutParts))
              .stderr.on('data', (chunk: Buffer) => take(chunk, stderrParts));
            stream.on('close', (code: number | null) => {
              settle();
              client.end();
              // Decode once, on whole characters: the ceiling cut is the only
              // place a sequence can be left incomplete, and dropping that
              // tail is what keeps the text whole and the counts honest.
              const outBuf = trimIncompleteUtf8(Buffer.concat(stdoutParts));
              const errBuf = trimIncompleteUtf8(Buffer.concat(stderrParts));
              const stdout = outBuf.toString('utf8');
              const stderr = errBuf.toString('utf8');
              const recordedBytes = outBuf.byteLength + errBuf.byteLength;
              const discarded = writtenBytes - recordedBytes;
              // The exit status is ALWAYS what the task reported — recording
              // less of its output never changes its outcome. How much was
              // dropped is stated as its own field so the note cannot be
              // trimmed away by the output policy that follows.
              resolve({
                command,
                exitCode: code ?? -1,
                stdout,
                stderr,
                ...(discarded > 0 ? { outputTruncated: { recordedBytes, discardedBytes: discarded } } : {}),
              });
            });
          });
        })
        .on('error', (err) => {
          settle();
          // ssh2 surfaces a rejected host key as a generic verification error.
          // Name both fingerprints instead: an operator facing a key change has
          // to be able to tell a rotated host from an impersonated one, and a
          // fingerprint is a digest of a public key — safe to show.
          reject(
            pinFailure !== undefined
              ? new Error(
                  `could not durably pin the host key presented by server "${server.id}" (${server.host}): ${pinFailure}. Connection refused — an unrecorded pin would leave every connection "the first one".`,
                )
              : presented !== undefined
              ? // Typed (#46): testServer turns the two fingerprints into a
                // structured rotation prompt; the message is unchanged for
                // every caller that only shows text.
                new HostKeyMismatchError(server.id, server.host, server.port ?? 22, admitted!, presented, server.generation ?? '')
              : err,
          );
        })
        .connect({
          host: server.host,
          port: server.port ?? 22,
          username: server.username,
          hostVerifier: (key: Buffer): boolean => {
            const fingerprint = hostKeyFingerprint(key);
            if (admitted) {
              if (fingerprint === admitted) return true;
              presented = fingerprint;
              return false;
            }
            // First use (#44): record the pin BEFORE trusting it — the store
            // write is synchronous and refuses to overwrite anything. A pin
            // that cannot persist aborts the exchange.
            try {
              this.pinner!.pin(server, fingerprint);
              return true;
            } catch (err) {
              pinFailure = err instanceof Error ? err.message : String(err);
              return false;
            }
          },
          // Authentication, in the shape ssh2 negotiates. The store's auth
          // invariant (#42) already guarantees the secrets present are exactly
          // the chosen method's — key (+ passphrase when encrypted) XOR
          // password — so the executor simply supplies what is stored. The key
          // is the stored CONTENT; nothing is read from the filesystem.
          ...(server.privateKey
            ? {
                privateKey: server.privateKey,
                ...(server.passphrase ? { passphrase: server.passphrase } : {}),
              }
            : {}),
          ...(server.password ? { password: server.password } : {}),
        });
    });
  }
}
