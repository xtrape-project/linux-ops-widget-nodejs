import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { LINUX_OPS_WIDGET_VERSION, LINUX_OPS_WIDGET_TENANT, buildManifest } from '../src/manifest.js';

describe('manifest / release identity', () => {
  it('advertises the same version as package.json', () => {
    const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'));
    expect(LINUX_OPS_WIDGET_VERSION).toBe(pkg.version);
    expect(buildManifest().service.version).toBe(pkg.version);
  });

  it('pins the tenant to default for this CE phase', () => {
    expect(LINUX_OPS_WIDGET_TENANT).toBe('default');
    expect(buildManifest().tenant).toBe('default');
  });

  it('declares its ops capabilities', () => {
    expect(buildManifest().capabilities).toContain('ops.execute');
    expect(buildManifest().capabilities).toContain('server.management');
  });
});
