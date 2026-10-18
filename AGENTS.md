# AGENTS.md

## Repository role

`xtrape/linux-ops-widget-nodejs` is the **Linux Ops Widget** — the single source and canonical
Capability owner for the Linux ops capability set. Starting this Widget produces a **Service**
(logical Service ID `linux-ops-widget-nodejs`); each running process is a **Worker** of that
Service; it
connects through the **Connector** SDK `@xtrape/connector`.

Predecessors `xtrape/ops-linux` and `infra/mcp-ops-nodejs` are retired only after migration,
compatibility, and running evidence are complete (repo issue #28). Do not treat either as a
current authority, and do not modify them from here.

## Architecture authority

Canonical product architecture is **`xtrape/xtrape-docs`**. Read the relevant canonical document
before touching a boundary — do not infer design intent from this repository's code:

| Topic | Read first |
| --- | --- |
| Platform boundary and responsibilities | `xtrape-docs/docs/products/server/00-overview.md` |
| Service model (capability / config / credentials) | `xtrape-docs/docs/concepts/05-service-model.md` |
| Platform object model (Widget / Service / Worker / Connector) | `xtrape-docs/docs/concepts/09-platform-object-model.md` |
| Action / configuration model (entry action + hidden sub-op + inline affordance) | `xtrape-docs/docs/runtime-platform/10-action-model-self-describing-affordances.md` |
| Command delivery / Connector contract | `xtrape-docs/docs/runtime-platform/09-transport-and-command-delivery.md` |
| Controlled Exposure, Checkpoints, invocation authorization | `xtrape-docs/docs/architecture/16-controlled-exposure-and-invocation-authorization.md` |
| Runtime baseline (Node 24) | `xtrape-docs/docs/reference/10-runtime-baseline.md` |
| Terminology | `xtrape-docs/docs/reference/00-terminology.md` |

When canonical conflicts with this code, **canonical wins**.

## Implementation red lines

- No raw shell and no execution path that bypasses the action registry.
- Deterministic policy verdicts (`deny`, forced `human_review`) are never overridable by an AI
  reviewer. `tighten()` narrows only.
- **Local policy may only narrow or deny Platform authority; it may never broaden it.**
- No governance logic sinks into this repository. Authorization, approval, the canonical Service
  registry, the Exposure Task registry, and authoritative audit belong to the **Platform**. What
  lives here is a local fail-safe boundary and local evidence.
- No MCP transport, session, or tool projection here. That is `xtrape/xtrape-exposure`.
- No secrets in logs or output; sanitize the credential reference path *before* redaction.

## Naming discipline

Use current concept names in all prose, comments, identifiers, and docs: **Platform** (not
server-ce / server), **Worker** (not Runner / instance), **Connector** (not Agent), **Service
Token** (not Agent Token), **Checkpoint**, **Widget**, **Resource**.

**Do not rewrite wire bytes.** Action names, the `_servers` category, `serverId` / `reason` /
`dryRun`, failure codes, audited policy rule names, `runtime.agent`, `instanceId`, and SDK
callback routes and headers are frozen. See the "Frozen wire identifiers" section of the README.
A concept correction that silently breaks a wire identifier is a defect, not a correction.

## Runtime baseline

Node 24, declared in three places that must agree: `package.json` `engines.node`, the CI job
container image, and the `Dockerfile` stages. `scripts/check-runtime-baseline.mjs` enforces this
in CI — if you change one, change all three.

## CI constraints on this Forgejo instance

- The runner has **no github.com egress**. Pin actions to the mirrored commit already used in the
  other Xtrape Node repositories; never download a tool from a github release (this is why the
  secret scanner is secretlint from npm, not gitleaks).
- The internal npm mirror has **no audit endpoint** — `pnpm audit` must pin
  `--registry https://registry.npmjs.org/`.
- **Alpine job containers cannot run `actions/checkout`** and have no package-CDN egress. Use
  `node:24-bookworm`.
- There is **one runner**: serialize container jobs with `needs`.
- Cross-organization `actions/checkout` fails on token scope. Vendor shared scripts.

## Working rules

- Changes go through a branch and a PR with review. The default branch is protected — never push
  to it directly.
- One issue is completed in one PR. If the work does not fit, split the issue rather than
  overloading the PR.
- A task declares its id, title, version, **risk level** — the single authorization axis (#61):
  effective risk = declared risk, +1 notch on a production target, +1 notch on the MCP surface,
  and `high` or above requires a person — its server scopes, and a schema for every parameter it
  accepts. `readonly` and `approval` are retired from authoring; where a stored task still
  carries them they keep their meaning, and nothing new should emit them.
- Tasks are managed online through `manageTasks` (the library is a SQLite DB, #58);
  `conf/tasks/*.sh` is the provisioning/import channel, imported once per task id.
- Run `pnpm lint`, `pnpm typecheck`, `pnpm build`, and `pnpm test` before opening a PR, and record
  the actual output — not "should pass".
- Every module carrying behaviour needs a test that genuinely executes it, not just imports it.
- A PUBLISHED Checkpoint `id@version` is immutable on every Platform that holds it. The 17
  management rows are ONE version cohort (`MGMT_CHECKPOINT_VERSION`): a change to any management
  definition — schema record, review face, classification, anything in the admitted bytes — bumps
  the cohort in the same change. `test/frozen-management-definitions.json` snapshots the canonical
  bytes of every management `id@version`; the test turns a changed definition into an explicit
  fixture diff (built ≠ pin), refuses an unpinned new version and a pin no longer built. What the
  test cannot prove is the review rule: **an existing pin is never edited** — a change that edits
  code and pin together under the same version passes the test and is a review defect; bump the
  cohort and add the new identities instead. m1-local being purged on every rebuild is not
  evidence that a mutation is safe: the first persistent deployment refuses it with
  `CHECKPOINT_IMMUTABLE_CONFLICT` (linux-ops#100, host2 2026-09-07).
- Commit messages use `feat:` / `fix:` / `docs:` prefixes, one subject each.
