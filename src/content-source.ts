import { createHash } from 'node:crypto';
import type { CommandOrigin } from '@xtrape/contracts';

/**
 * Where this Widget's task content comes from when the library is GOVERNED
 * (xtrape-docs#255).
 *
 * The model, in one line: **the governance side owns versions and review; this
 * Widget keeps only the latest effective version** (owner ruling 2026-08-16).
 * So a governed library is not edited here — a change is SUBMITTED, reviewed
 * somewhere else, and comes back as a new effective version. History and
 * review live at the other end of a link.
 *
 * This port is deliberately small, and deliberately says nothing about HOW
 * review happens: branches, pull requests, who approves, whether the approver
 * is a person or another AI — none of it is this Widget's business. It only
 * needs three things: send a proposal, read what is currently effective, and
 * know where to send a person who wants to see why.
 *
 * That silence is what lets the far end be a Forgejo repo today and the
 * governance Service later without touching anything here.
 */
export interface ContentSource {
  /** The approved content set as it stands now. */
  fetchEffective(): Promise<EffectiveContent>;
  /**
   * Propose a change. It NEVER becomes effective through this call — that is
   * the whole point of a governed library.
   */
  submit(input: SubmitInput): Promise<SubmissionResult>;
  /** Where a person reads history and reviews. Shown on cards, never fetched. */
  reviewUrl(path?: string): string;
}

export interface EffectiveContent {
  /** Opaque identity of this exact content set (a commit id for a git backend). */
  versionId: string;
  /**
   * Strictly increasing along the governance side's effective history
   * (review 2427 blocker 2): the versionId alone is opaque, so this is the
   * field monotonicity is enforced on. A version with a LOWER sequence than
   * what is applied here is a rollback and is refused.
   */
  sequence: number;
  files: Array<{ path: string; bytes: string }>;
}

export interface SubmitInput {
  path: string;
  bytes: string;
  /** One line, used as the change's title. */
  message: string;
  /** Free text for the reviewer: why, and what was considered. */
  detail?: string;
  /**
   * The proposing origin — the authenticated Account context the Platform
   * delivered with the command that carries this edit (xtrape-docs
   * runtime-platform/12, #256), forwarded UNCHANGED. Shape and vocabulary are
   * the contracts `CommandOrigin`. `approver ≠ author` is enforced by the
   * governance side against `account`, which is why it travels with the
   * proposal rather than being inferred there — and why this Widget never
   * substitutes a static deployment identity for it.
   */
  origin: CommandOrigin;
}

export interface SubmissionResult {
  submissionId: string;
  /** Where the review happens. This is what a caller gets back instead of "saved". */
  url: string;
}

export function digestOf(bytes: string): string {
  return `sha256:${createHash('sha256').update(bytes, 'utf8').digest('hex')}`;
}

/**
 * The CE service-to-service convention (xtrape-docs#255): one shared
 * deployment credential authenticates the peer; the originator context rides
 * a second header as FACT, so an AI's edit stays an AI's edit after passing
 * through this Widget.
 */
export const S2S_TOKEN_HEADER = 'x-xtrape-service-token';
export const S2S_ORIGIN_HEADER = 'x-xtrape-origin';

export interface CuratorContentSourceOptions {
  /** The Curator's s2s base, e.g. `http://127.0.0.1:8790`. */
  baseUrl: string;
  /** Shared deployment credential. */
  serviceToken: string;
  /** Directory of task files inside the governed repository. */
  dir: string;
  /** Where a person reads reviews — the Curator's Panel, or the repo UI. */
  reviewUrlBase?: string;
  fetchImpl?: typeof fetch;
}

/**
 * A ContentSource over the Curator Widget (curator-git-widget-nodejs).
 *
 * This client knows nothing about git, branches or reviews — versioning and
 * approval are the Curator's whole job (owner ruling 2026-08-16: for this
 * Widget the governance side is a versioned store; how it manages content is
 * transparent here).
 */
export class CuratorContentSource implements ContentSource {
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: CuratorContentSourceOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  private async call(method: string, path: string, body?: unknown, origin?: string): Promise<unknown> {
    const res = await this.fetchImpl(`${this.options.baseUrl.replace(/\/+$/, '')}${path}`, {
      method,
      headers: {
        [S2S_TOKEN_HEADER]: this.options.serviceToken,
        'content-type': 'application/json',
        ...(origin !== undefined ? { [S2S_ORIGIN_HEADER]: origin } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`curator ${method} ${path} failed: HTTP ${res.status}${text ? ` — ${text.slice(0, 200)}` : ''}`);
    }
    return text ? (JSON.parse(text) as unknown) : undefined;
  }

  async fetchEffective(): Promise<EffectiveContent> {
    const out = (await this.call('GET', `/v1/current?dir=${encodeURIComponent(this.options.dir)}`)) as {
      versionId?: string;
      sequence?: number;
      files?: Array<{ path?: string; bytes?: string }>;
    };
    if (typeof out?.versionId !== 'string' || typeof out.sequence !== 'number' || !Array.isArray(out.files)) {
      throw new Error('curator /v1/current returned no usable content set');
    }
    // Every file must be well-formed, or the WHOLE set refuses (review 2427
    // blocker 3): silently dropping a malformed entry would apply a set the
    // governance side never approved in that shape.
    const files: Array<{ path: string; bytes: string }> = [];
    for (const f of out.files) {
      if (typeof f?.path !== 'string' || typeof f?.bytes !== 'string') {
        throw new Error('curator /v1/current returned a malformed file entry; refusing the whole content set');
      }
      files.push({ path: f.path, bytes: f.bytes });
    }
    return { versionId: out.versionId, sequence: out.sequence, files };
  }

  async submit(input: SubmitInput): Promise<SubmissionResult> {
    // The delivered origin travels as the s2s header — the field the Curator
    // records and enforces approver ≠ author against. It is forwarded as
    // received (12-command-origin §6.3), never rewritten or filled in here.
    const origin = JSON.stringify(input.origin);
    const out = (await this.call(
      'POST',
      '/v1/submit',
      { path: input.path, bytes: input.bytes, title: input.message, ...(input.detail !== undefined ? { detail: input.detail } : {}) },
      origin,
    )) as { id?: string };
    const id = typeof out?.id === 'string' ? out.id : '(unknown)';
    return { submissionId: id, url: this.reviewUrl() };
  }

  reviewUrl(): string {
    return this.options.reviewUrlBase ?? `${this.options.baseUrl.replace(/\/+$/, '')} (Curator 的提案评审面板)`;
  }
}
