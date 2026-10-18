import { readFileSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

/**
 * Stable Worker identity across restarts: env override, else a persisted
 * `conf/instance-id`. `instanceId` is the frozen wire key of the CE
 * registration contract; the entity it names is the Worker (xtrape-docs
 * reference/00-terminology: "Service Instance is not an independent entity …
 * the registered running instance is the Worker").
 *
 * Permissions are tightened to 0600 on a pre-existing file **regardless of its
 * content** — Node's `writeFile` `mode` option only applies when creating a
 * file, so an overwrite (e.g. a blank existing file) is chmod'd explicitly too.
 * The chmod is intentionally **best-effort**: a failure (e.g. a read-only mount)
 * is tolerated rather than blocking startup — the id itself is not a secret, the
 * 0600 is defense-in-depth.
 */
export function loadOrCreateInstanceId(confDir: string): string {
  const fromEnv = process.env.LINUX_OPS_WIDGET_INSTANCE_ID?.trim();
  if (fromEnv) return fromEnv;

  const file = join(confDir, 'instance-id');
  let existing = '';
  let fileExists = false;
  try {
    existing = readFileSync(file, 'utf8').trim();
    fileExists = true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
  if (fileExists) {
    try { chmodSync(file, 0o600); } catch { /* best-effort */ }
  }
  if (existing) return existing;

  // Missing or blank: (re)write a fresh id and enforce 0600 (mode is create-only).
  const id = `linux-ops-widget-${randomUUID().slice(0, 8)}`;
  mkdirSync(confDir, { recursive: true });
  writeFileSync(file, `${id}\n`, { mode: 0o600 });
  try { chmodSync(file, 0o600); } catch { /* best-effort */ }
  return id;
}
