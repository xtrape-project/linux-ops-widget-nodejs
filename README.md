# linux-ops-widget-nodejs

Official Xtrape **Widget** for controlled Linux host operations, implemented in Node.js.

This repository is the **single source and canonical Capability owner** for the Linux ops
capability set (repo issue #28). `xtrape/ops-linux` and `infra/mcp-ops-nodejs` are the
predecessor repositories; they are retired only after migration, compatibility, and running
evidence are complete — **migrate first, delete second**.

## The five roles this repository implements

| Role | What it is here |
| --- | --- |
| **Widget** | This repository. The deployable/runnable Artifact — a definition, not a running thing. |
| **Service** | What starting this Widget produces. Logical Service ID `linux-ops-widget-nodejs`; one Service Token; the task entry point. It executes nothing itself. |
| **Worker** | The process that actually runs and executes. Each running instance of `dist/index.js` is a Worker of that Service. `instanceId` on the wire names the Worker. |
| **Connector** | `@xtrape/connector` — the Platform component used to connect this runtime to Xtrape. Not an Agent, not a Service peer. |
| **Resource** | The governed external targets: Linux hosts, services, files, processes, accounts. Canonical form `service:linux-ops-widget-nodejs@host-001`. |

Object direction, stated the canonical way: **`Command` requests `Action`**. An Action does not
run a Command.

## What a task is

**A task is one shell script file.** You work out an operation once — connect, check, deploy,
verify — and keep it as one script. Provision it as a file under `conf/tasks/` (imported into
the task library at startup) or create it in **Add Task**, whose structured form asks for the
risk level, the server binding (one admitted server, "choose at run time", or a custom scope
glob), and the script body — no header syntax to memorize. Invoking it later means naming a server and
that task, instead of reassembling the commands. The scripts and the server credentials both
live here; the caller supplies neither.

### The library grows online (#53/#55)

Tasks are managed through the **`manageTasks`** entry action, not by logging into the Widget
host. The library lives in a **SQLite database** (`data/tasks.db`, #58) with three concerns
kept apart: **history** — `task_revisions` is append-only, one row of metadata COLUMNS
(risk, servers, approval, params, …) plus the script body per distinct saved version, and no
workflow operation ever deletes a revision or an approval; **current state** — two pointers
per task (`enabled_revision`, `draft_revision`) that move on save/enable/disable/remove,
so removing a draft withdraws it without consuming its history; and **approvals** —
`task_approvals` records every online Enable (revision, digest, what it replaced, when, and
the provenance the surface attests: the delivering commandId today, the deciding Account once
the interaction contract carries it). Add/Edit are **structured forms** whose fields map 1:1 to those columns — risk is a choice,
the server binding is a live dropdown of the admitted fleet (plus "*" for run-time choice and
a custom scope-glob entry), parameters are **rows** (name / label / type / required / default / pattern / enum / description) and redaction patterns a tag list, so nothing about a parameter is hand-typed syntax — and they land a draft revision: parse- and registry-validated up
front, never registered, never executable, never in the catalog; a save that restores the
enabled bytes **withdraws** the pending draft rather than minting a phantom one. A task runs only after a person approves it via **Enable**, whose dialog renders the
complete canonical text and digest; submitting that form is the explicit human decision, and
the approval binds to the reviewed **bytes** through an HMAC-sealed binding minted by the
prepare — the same per-incarnation-key mechanism as the run panel's `reviewBinding`, so it
cannot be hand-written, and an edited draft refuses with "changed since it was reviewed".
The header-comment file format is only the import/export serialization: the canonical
rendered text is what the digest covers, what the review card shows, and what the interpreter
is fed — metadata and body stay one approved byte stream. Enabling hot-swaps the runtime
registry and the live catalog — no restart, no re-registration. Disable demotes back to a
draft. Durability is the transaction's (WAL, `synchronous=FULL`): a committed mutation
survives a crash, which is what retires the file era's fsync/reconcile state machine.
Every lifecycle step also lands in the local audit log with the before/after digests.

**Provisioned files are the bootstrap channel:** `conf/tasks/*.sh` (and `conf/tasks/drafts/`)
are imported into the DB at startup, **once per task id** — a `tasks/` file arrives enabled
and a same-id `drafts/` file arrives with it as its pending replacement draft (an upgrade
never drops a pending review); a task the DB already manages is skipped entirely: once a task
is managed online, the DB is the truth and host files stop being an edit channel. A broken
provisioned file fails startup loudly rather than being skipped.

**Multi-Worker boundary (declared):** the task library — like `servers.json` — is per-Worker
state. Run a second Worker of this Service and the libraries can diverge; what CANNOT happen is
silent wrong-bytes execution: a Worker without the task denies `unknown-action`, and the
review-to-execution binding refuses cross-incarnation executes. Divergence degrades
availability, never integrity. A shared library is future work.

```sh
#!/bin/sh
# xtrape-task: xtrape.deploy
# title: Deploy the Xtrape stack
# version: 1.0.0
# description: Pull the pinned Xtrape stack images and restart the deployment
# risk: high
# servers: xtrape-*
# param: ref required string Stack version to deploy, e.g. 0.8.6
# param.ref.pattern: ^[0-9]+\.[0-9]+\.[0-9]+$
set -eu

cd /opt/xtrape
export XTRAPE_VERSION="$XOPS_ref"
docker compose pull
docker compose up -d --remove-orphans
```

The `# key: value` header is what the Widget reads; everything from the first real line down is
the operator's own script, run as written. See [`examples/tasks/`](examples/tasks/).

| Header | Meaning |
| --- | --- |
| `xtrape-task` | Task id, e.g. `system.uptime`. Required, and independent of the file name. |
| `version` | `MAJOR.MINOR.PATCH`. Required. |
| `description` | Shown to whoever is choosing a task, human or agent. May be declared on several consecutive lines, which are joined. |
| `risk` | `low` / `medium` / `high` / `critical`. Required, and the **single authorization axis** (#61): effective risk ≥ `high` needs a person. A production target raises it a notch; the MCP surface raises it a notch. Declaring it honestly is the author's obligation. |
| `title` | Human-readable display name. The id is the immutable identity; this is what people read. |
| `servers` | **Required.** Comma-separated scopes, e.g. `web-*`. Say `*` if you mean every server. |
| `approval` | **Retired from authoring** (#61) — risk decides. Still honored where a stored task carries it: `always_human` ≡ raised to `high`, `forbidden` ≡ refused. Use the risk level, or disable the task. |
| *(shebang)* | The first line decides the interpreter and its flags: `#!/bin/sh -e` runs `/bin/sh -e -s`, `#!/usr/bin/env python3 -u` runs `python3 -u -`. Default when the file has **no** shebang at all: `bash` — a shebang that opens and names no interpreter (`#!`, `#!/usr/bin/env`) is refused rather than defaulted. The interpreter must be one this Widget can hand a program on **standard input** — `sh`, `bash`, `dash`, `ksh`, `zsh`, `python`, `python3`, `perl`, `ruby` — and its options are an **allow-list** per interpreter (shells: `-e -u -x -f -v`, including clusters like `-eux`; python: `-u -B -E -O -OO -I -q -S -b`; perl: `-w -W -T`; ruby: `-w -W0..2 -v`). Anything else is refused rather than guessed at, because an option like `-c`, `-cCODE`, `-mMOD` or `-ec` takes the program from somewhere else and the script would never be read. `env` is supported only in its plain launcher form: `#!/usr/bin/env FOO=bar python3` is refused rather than run with `FOO` quietly dropped. |
| `interpreter` | **Retired from authoring** — the shebang decides. Still honored where a stored task carries it. |
| `param` | `<name> <required\|optional> <string\|integer\|number\|boolean> <description>` |
| `param.<name>.<c>` | Says one more thing about a parameter: **`label`** (the field's operator-facing name) and **`default`** (what its form starts from) alongside the constraints `pattern`, `enum`, `maxLength`, `minimum`, `maximum`. Declared at most once each. Numeric values are plain decimals (no exponent form) and are refused if the parsed value would not be the one written. A `default` that its own constraints reject is refused — a task must not ship a value it would decline. |
| `redact` | Extra pattern to redact from output. Repeatable. |
| `maxBytes` | **Retired from authoring** (#61 B) — how much output can be recorded is the deployment's call (`LINUX_OPS_WIDGET_MAX_RECORDED_OUTPUT_BYTES`). A stored task's declaration is still honored when it asks for LESS. |
| `timeout` | Seconds. **No default** — a task that may run for hours declares none. |

**An unrecognised header is refused, not ignored.** A task file is a safety
declaration, and the failure mode of tolerance is silent widening: `# server:`
misspelt would leave the scope unstated, and `# rsik:` would leave a dangerous
task at no declared risk at all. Constraints are read in the parameter's own type, so
`# param.retries.enum: 1|2` on an `integer` yields integers — as a string enum
it produced a schema no integer could satisfy, making the task quietly
unusable rather than loudly wrong.

### What the parameter channel does and does not guarantee

**A caller's parameter never enters the operator's script.** The script goes to the interpreter's
standard input; the parameters arrive beside it as `XOPS_<name>` environment values. Nothing a
caller sends can add a word to what the operator wrote.

Two things that are *not* guaranteed, stated plainly because both matter when you write a task:

- **The value is still shell source at the far end.** The assignments are part of an SSH `exec`
  command string, so correctness still rests on `shellQuote`. What changed is the size of the
  surface: one function, applied uniformly at one call site, with tests on it — instead of every
  operator's template with its own placement. The fully non-shell alternative is the SSH
  environment request, and it is deliberately unused: `sshd` accepts only what `AcceptEnv` allows
  and silently drops the rest, and parameters vanishing without an error is a worse failure.
- **The script's own use of the value is yours to guard.** `find "$XOPS_path"` given `-delete`
  hands `find` an action rather than a directory, and no quoting ever covered that (#36). Declare
  a `pattern` or an `enum`, keep admitted roots to a list you wrote, and check in the script for
  anything a program could read as one of its own options.

### Two bounds, and the Widget only provides one

**Output is bounded at the wire — the RECORDING is, not the task** (#61 B). The Worker stops
accumulating at the deployment's ceiling — across stdout and stderr together — and reads and
DISCARDS the rest, so this process's memory is bounded without the task being cut short: it
runs to completion and its own exit status is reported, with `outputTruncated`
(`recordedBytes` / `discardedBytes`) saying how much was dropped. Closing the channel instead —
the earlier behaviour — bought bandwidth at the price of the outcome: a verbose task with side
effects was killed mid-run and answered "remote result unknown", which is the worst of both.
A task's *runtime* is bounded where it belongs: its own `# timeout:`, or a Platform cancel.

The ceiling is a **deployment** setting (`LINUX_OPS_WIDGET_MAX_RECORDED_OUTPUT_BYTES`, default
64 KiB): a task generates what its business needs, and what can be kept is decided by whoever
carries the load. A stored task that declared a smaller `# maxBytes:` still gets the smaller of
the two — an upgrade never records more than its author allowed.

**Work on the target is not bounded, and cannot be from here.** There is no Worker-side deadline
unless the task declares `# timeout:` — many tasks legitimately run for hours, and a clock over
all of them would be this Widget deciding something no author asked for. What can stop an
unbounded task from this side is a **cancel** delivered by the Platform (which reaches a running
action only on a transport that delivers one — see the confirmation note below). And even a declared
deadline ends the *connection*: a process that ignored the hangup or had already detached keeps
running, and a task that produces no output produces nothing to hit the output ceiling either. A
`find` over a huge tree that matches nothing is the plain case: silent, unbounded, and invisible
to both limits above.

So bound the work where it happens — in the script. `timeout 20s …`, `nice`, `ionice`,
`--max-count`, a narrower `-maxdepth`: the shipped `file-find.sh` uses `timeout` and reports its
124 as its own outcome. And write tasks with side effects to be re-runnable, because a task that
was cut off may have finished on the target anyway.

### Faithful delivery: the task behaves as it would on the target

**This Widget delivers the operator's intent. It does not interpret it.** The interpreter is
invoked with whatever the script's own shebang asked for, plus the one argument that makes the
program arrive on standard input (`-s` for a shell, `-` for python/perl/ruby) — this Widget
adds no `-e`, no `-o pipefail`, no wrapper of its own — so a task file does
on the target exactly what the same file would do if you pasted it into a shell there. The
execution effect is the reference, and this Widget is not entitled to change it.

A worked example, because this is the part that surprises people:

| The script says | What happens | Why |
| --- | --- | --- |
| a step's command does not exist | `command not found`, exit 127, and the *next step still runs* | that is what a shell does |
| the same, with `set -e` at the top | the task stops at that step | the author asked for it |
| `cmd \|\| status=$?` | the failure is the script's to handle | the author handled it |

Whether a failure ends the task is the author's sentence to write, in their own file, where a
reader can see it. Turning `-e` on for everyone would silently change the meaning of every script
that did not ask for it.

**Rolling back is the script's job.** Nothing here knows what a task's steps mean or how to undo
them. A task that can leave a target half-changed should undo its own work on failure — `trap`,
an explicit cleanup path — or be written so that running it again finishes the job.

**Two deliberate departures, and no others.**

*The output ceiling.* The Worker stops RECORDING at the deployment's ceiling and reads and
discards the rest, because that bounds its own memory rather than the script's behaviour. The
task runs to completion and reports its own exit status; how much was dropped is stated as its
own field (`outputTruncated`), never as an outcome of the task (#61 B).

*Output redaction.* What a task printed is not what a caller reads back: `redactOutput` masks
`key=value` shapes around `password`, `token`, `secret`, `private_key` and `authorization` before
the output leaves this process, in the result as well as in local evidence. It is a heuristic over
a task's own bytes, so it is a real departure from "what the shell would have shown you" and is
named as one — it was previously described here as if only the ceiling touched a task's output. It
is also, being pattern-based, no guarantee: see the evidence note below for what it does not
cover. A task can widen it with `# redact:`.

### What this Widget is responsible for

Five things, and nothing else:

1. **Hold the SSH credentials** for the target fleet.
2. **Hold the reviewed commands** — one script per task, in the task library (`data/tasks.db`; provisioned via `conf/tasks/` or added online through `manageTasks`).
3. **Execute them**, faithfully, as described above.
4. **Run the confirmation mechanism for dangerous tasks.**
5. **Run the safety fence for commands that have not been reviewed.**

**It does not retry.** A failed task is a failed task; there is no retry loop
anywhere in this repository, and adding one would make it an orchestrator.
Whether to run something again is a decision, and decisions belong to whoever
made the first one.

Not retrying is not the same as not being **asked** twice. A delivery can
repeat — a retried push, a reconnect — so a repeated `commandId` is answered
with the first execution's outcome rather than run again.

That collapse is **best effort, not a durable guarantee**: the memory is
in-process and bounded, so past its size or across a Worker restart the same
command runs again, and it only engages on a transport that hands over a
`commandId` — World A does, and so does registered World B since connector
0.8.1. A durable, transport-independent guarantee needs
persisted command outcomes (#39 (internal tracking)).
Until then, write tasks with side effects to be re-runnable.

### Danger: this Widget detects it, and this Widget asks

Only this Widget knows that `xtrape.deploy` is dangerous and `system.uptime`
is not — so detecting and grading danger is its job, declared per task with
`# risk:`, and so is putting the question. **The Platform
originates no execution requirement and holds no management information about
a task; it relays.** What this Widget must not do is be the one who decides
nobody was asked.

**There is one mechanism, and it is this Widget's.** The Platform holds no
management information about a task and decides nothing about it, so it cannot
gate a run before dispatch. A command arrives; this Widget's policy decides a
person is needed; this Widget asks; the Platform relays. When to ask is a
business decision — before the work, partway through it — and the mechanism is
the same either way.

The Widget does not choose a recipient. The execution request reached the
Platform carrying the requester's identity credential, so deriving who to ask
and which interactive layer they are on belongs on the Platform's side of the
line — this Widget never holds it. That is the division of labour, not a
description of running code; the Platform side of it is unbuilt, as the next
paragraph says.

**What is built here, and what is not.** This Widget's half is written:
policy decides, `src/confirmation.ts` states the question, and
`src/confirmation-ask.ts` carries it to the Connector SDK's `ask()` primitive
(xtrape-connector-nodejs#87 (internal tracking)),
which posts it as an `APPROVAL_REQUEST` and correlates the `APPROVAL_RESPONSE`.
Two things beyond this repository are still missing, so the path does not yet
end at a person: creating the `apr_*` conversation needs a Platform grant, and
routing the question to the requester's interactive layer is Platform-side work
that does not exist (xtrape-docs#241 (internal tracking)).
**As this repository stands, the Widget's half is live.** `pnpm-lock.yaml`
pins `@xtrape/connector` 0.8.1, which carries `ask()`, so every build from
this lockfile finds the method and configures the channel — the deliberate
dependency bump the previous revision of this paragraph reserved. On an SDK
without the method the Widget still fails closed (`HUMAN_REVIEW_UNAVAILABLE`:
the task stops, nobody is asked), and the installed-package test pins which
of the two ships. End to end still waits on the two Platform-side pieces
above; until they land, a question may be posted and answered by nobody,
which is why an unanswered wait ends only on cancel.

**It is not proven end to end, and is not claimed to be.** A wait for a person
outlives any HTTP forward window by design, so whether it survives depends on
the transport settling the command independently and delivering a cancel to a
running action — both of which the Connector only gained in
xtrape-connector-nodejs#87 (internal tracking),
and neither of which this repository can verify on its own. Cross-transport
regression against a released SDK is the acceptance for that, not the unit
tests here.

**Identity: what is approved versus which run asked.** `executionHash` answers
*what* — server, task, version, script digest, arguments — and two separate
runs share it whenever those match. The conversation is therefore keyed on
`interactionId` (the `commandId` when the Platform gave one, a per-invocation
nonce otherwise), so two runs of the same task never land in one thread where
either answer resolves both. The hash still travels with the question as the
content being approved, which is what makes an answer unusable for different
content: edit the script and the digest changes, so the hash does too.

**A question discloses; it does not undertake to be understood.** It carries
what is known — which task, on which server, why it stopped, what the answer
will be used for, who started the run — because disclosing that is the
obligation. Making a person understand is not: someone who cannot follow what
they are being asked, and answers anyway, still owns that answer, and neither
this Widget nor the Platform should bend its actual work to that problem.

**An answer serves the interaction and nothing else.** It must not reach past
the question it answered — above all it must not, through some arrangement of
symbols, change what the task was already going to do. It crosses the same
quoting boundary as a parameter, for the same reason a filename with a space in
it is quoted: not distrust of the person, but the difference between data and
instruction. There is no attempt to classify what a person sends, either. This
is a trust system — an untrusted Widget has no business being registered to a
Platform in the first place — and nothing here can tell a password from a
ticket number; a filter that pretended to would fail quietly, which is worse
than not having one.

Only an explicit grant runs the task; anything else is a refusal, reported as
`CONFIRMATION_REFUSED` rather than `POLICY_DENIED`, because policy allowed the
question to be put and a person answered no. Waiting has no deadline — a person
may take hours — and a cancelled command is what ends a wait nobody answers. A
dry run never asks anyone.

### Where the fence is, and where it is not

A task is **reviewed configuration**: an operator wrote it and it entered the
enabled library through a review — a provisioned `conf/tasks/` file, or an
online draft approved via Enable. An enabled task is executed as its author
intended. There is no command allow-list, no blacklist and no inspection of
what a script contains — screening a file the operator already approved would
be theatre, and it would break the faithful-delivery guarantee above.

The fence around *invocation* is deterministic, evaluated before the command is
built and before the executor is reached, and no later component — including
an AI reviewer — can loosen it:

| Outcome | When |
| --- | --- |
| Requires a human | effective risk `high` or `critical` — the declared `# risk:`, raised a notch by a `production` target and a notch by the MCP surface |
| Refused | the named server is outside the task's `# servers:` scopes |
| Refused | no reason was given |
| Refused | effective risk above `low` while the control plane is unreachable |
| Refused | a stored task still declaring the retired `# approval: forbidden` |

**The fence for un-reviewed commands is responsibility 5, and it is not built.**
Every execution today goes through a registered task; there is no path here for
running a command nobody wrote down. When that path exists — an agent asking to
run something for a new requirement — screening it is this Widget's job, not
somebody else's, and it is a different trust story from the one above rather
than a widening of it.

### This is a governed external call

An SSH command on a managed host is a third-party side effect: the host is
outside the Platform, credentials are involved, and the effect is real and
irreversible. `architecture/00` §1 requires such calls to go through **Fence,
or an explicitly approved, fail-closed Fence-compatible enforcement path** —
and this Widget is the second of those, for infrastructure. The danger
vocabulary belongs to Fence; detecting and managing danger belongs here.
Recognising that formally, and settling what Fence owns versus what stays here,
is `xtrape-docs#241`.

## What this repository is not

- **Not an MCP server.** MCP is a protocol projection under **Xtrape Exposure**, and its
  authority is `xtrape/xtrape-exposure`. A Widget that spoke MCP directly would be a second,
  ungoverned entry point into the same capabilities. The predecessor repository's `src/server.ts`
  (MCP transport, tool registration) was **deliberately not migrated** here.
- **Not an authorization, approval, or audit authority.** Account/Device/Participant authority,
  the canonical Service registry, global authorization and approval truth, the Exposure Task
  registry, the Artifact Repository, and the authoritative audit all belong to the **Platform**.
  This Service keeps only local evidence and local safety checks.
- **Not a raw shell.** A caller cannot send a command. It names a server and a task, and the
  task is a script file the operator put there in advance.
- **Not a deployment controller.** It is not `xtrape-launcher` and does not become one.

## One authorization axis: risk (#61)

**Risk is the only thing that decides whether a person must approve a run.** The effective
risk of one execution is the task's declared risk, raised by the context it runs in:

| Input | Effect |
| --- | --- |
| declared `# risk:` | `low` / `medium` / `high` / `critical` |
| a **production** target | +1 notch |
| the **MCP** surface (a person acting through an AI device) | +1 notch |
| **effective risk ≥ `high`** | a person must approve; on MCP the grant must also echo the script digest |
| control plane unreachable | only `low` proceeds — nothing else can be asked anyway |

What this deliberately removed: the `readonly` flag as an authorization input. "Read-only" was
never a safety property — a read-only task can read secrets — and a label that opens a door is
a label worth mis-declaring. `approval: always_human` and `forbidden` are retired from
authoring for the same reason (say `high`, or disable the task); where a stored task still
carries them they keep their meaning, because an upgrade must never loosen what an operator
declared. **Declaring risk honestly is the author's obligation**; a future AI risk assessment
joins as another input that may only RAISE the level, never lower it.

## Redlines: a review-time screen over script text (#65)

A deployment may declare **redlines** in `conf/redlines.json` — patterns over
script text with what a hit means:

```json
{ "rules": [
  { "id": "no-rm-rf", "pattern": "rm\\s+-[a-z]*r[a-z]*f", "severity": "hard", "message": "递归强制删除" },
  { "id": "curl-pipe-shell", "pattern": "curl[^|\\n]*\\|\\s*(ba)?sh", "severity": "soft", "message": "下载即执行" }
] }
```

`hard` refuses; `soft` raises the effective risk to the asking threshold, so
the task keeps running but a person answers for each run. A missing file is
no rules; a malformed one — or a pattern that will not compile — stops the
Worker, because a broken rule file must not read as "no rules".

Screening happens where the text exists and a decision is being made:

| When | What happens |
| --- | --- |
| **Enable** | Hits are shown on the review card, in front of the person approving. A hard hit refuses the approval; a soft one is recorded with the rule generation |
| **The rule set changes** | Every enabled task's frozen bytes are re-screened at startup. Hard hits are **suspended** — the enabled pointer is cleared and the revision becomes the pending draft, so re-approving is a review, not a retype — and soft hits are recorded |
| **Execution** | Nothing is scanned. The verdict is a stored flag, because frozen bytes plus a generationed rule set mean the answer can only change at the two moments above |

**What this is not.** It catches the accident — an `rm -rf $DIR` in the
middle of a sixty-line deploy where `DIR` may be empty. It does not catch an
adversary: the same thing spells through a variable, a quoted split, or a
base64 decode, and a test in `test/redlines.test.ts` states that limit
rather than hiding it. The only enforceable place for in-flight control is
the target host — restricted shell, sudo policy, read-only mounts, auditd.
There is no execution-time screening because there is nothing to screen: a
task runs as one `interpreter -s` with the script on stdin, and the
operations inside it are that one process's business.

## Parameter guards: judged per invocation (#66)

A redline reads the script; a **parameter guard** reads the CALL. Its rules
live in `conf/param-guards.json` and are evaluated every time somebody
invokes a task, because a parameter's value does not exist until then:

```json
{ "rules": [
  { "id": "no-root", "task": "file.*", "when": { "param": "root", "equals": "/" },
    "severity": "hard", "message": "不得对整盘操作" },
  { "id": "prod-force", "task": "nginx.*",
    "when": { "all": [ { "param": "force", "equals": true }, { "environment": "production" } ] },
    "severity": "soft", "message": "生产上的强制重载需要人确认" }
] }
```

A condition tests a parameter (`equals` / `matches` / `present` / `atLeast` /
`atMost`), the target (`server`, `environment`), or the caller (`surface`),
and `all` / `any` / `not` compose them. A rule may name the tasks it applies
to. `hard` refuses those arguments; `soft` raises the effective risk to the
asking threshold — and the refusal or the question quotes the rule's own
message, so the person deciding is told what fired.

**Why this stays in the Widget and is not registered to the Platform.** It is
LOGIC, not a declaration: evaluating it needs what only this Widget has —
which fleet entry the target is, what environment it runs in, what a
parameter means inside this task. The declarative bounds a schema *can*
carry (`pattern`, `enum`, `minimum`, `maximum`) are already reported in
`inputSchema` and remain the Platform's to see.

**Where it is judged.** Authoritatively at EXECUTE, on the arguments that
will actually run — a preview cannot bind, because the caller may submit
different ones. The run panel lists the guards a task could trip so an
operator knows in advance which values will stop and ask. And an approval on
the MCP surface must echo the **`executionHash`**, which covers the
arguments as well as the script: echoing the script digest alone proved only
which file was approved, leaving the argument set to whatever the AI
relaying the question chose to describe.

## A governed task library: the review side owns versions (xtrape-docs#255)

By default this Widget's task library is local: you add, edit and enable tasks
through the Panel, and the DB is the truth.

A deployment can instead point the library at the **Curator Widget**
(`curator-git-widget-nodejs`) — the review side. Then:

- **Edits become proposals.** Add Task and Edit Task submit to the Curator and
  hand back where the review happens. Nothing is saved locally, because
  nothing became effective. The proposal's author is the Account the Platform
  delivered with the command (`context.origin`, xtrape-docs
  runtime-platform/12 · #256), forwarded verbatim over s2s (`x-xtrape-origin`,
  the contracts `CommandOrigin` shape). An edit that arrives without a caller
  Account is refused here with the reason — a proposal without an attributed
  author could never be approved — and no per-deployment identity stands in
  (`LINUX_OPS_WIDGET_SUBMIT_AS` is retired and refused at startup).
- **Enable / Disable / Remove are refused here** and point at the review. What
  runs is decided by whoever approves the proposal — a person, or another AI
  account; the Curator enforces approver ≠ author.
- **This Widget keeps only the latest effective version.** History, comments
  and approvals live at the Curator (and in its git repository), one link away.
- **The local screening still applies.** A task that hits a hard redline (#65)
  is refused HERE and reported, even though it was approved there: the redline
  set is a fact about this deployment that the review side does not know. Local
  policy may only narrow.

Configure both of these together — a partial setting is an error rather than a
silent fallback to an ungoverned library:

```bash
LINUX_OPS_WIDGET_CURATOR_URL=http://127.0.0.1:8790    # the Curator's s2s surface
LINUX_OPS_WIDGET_CURATOR_TOKEN=...                     # shared deployment credential
# optional
LINUX_OPS_WIDGET_CURATOR_DIR=tasks                     # directory of task files in the governed repo
LINUX_OPS_WIDGET_CURATOR_REVIEW_URL=…                  # where cards send a person to read reviews
LINUX_OPS_WIDGET_CONTENT_POLL_SECONDS=60               # 0 disables polling
```

Two behaviours worth knowing before you switch a running deployment:

- **Adopting governance replaces the local library.** The first sync makes the
  Curator's effective set the library here; a local task it does not carry
  stops being executable. Submit what you want to keep first.
- **An empty read is refused, not obeyed.** If the effective version carries no
  task files while tasks are running here, the sync refuses and says so — a
  wrong directory or a glitch looks exactly like "delete everything", and the
  destructive reading is not the one to guess.

Availability is deliberately one-directional: the Curator is needed to
*change* the library, never to *run* it. If it is unreachable at startup or
during a poll, the last effective version stays live and the Widget says so.

## Local policy may only narrow

`src/policy.ts` is the fail-closed local engine. Hard results (`deny`, forced `human_review`)
can never be loosened by any later component; `tighten()` accepts a supplementary verdict **only
when it is stricter**. Local policy exists to narrow or deny what the Platform authorized — it
can never broaden it.

## Current scope (0.8.6 bootstrap)

This round establishes the runnable project base and migrates the reusable capability modules.
**The Checkpoint layer is not implemented yet** — publishing immutable versioned Checkpoints,
Resource extraction, and bounded invocation-credential validation are the next piece of work
(repo issues #12 / #21, xtrape-docs `architecture/16`).

What works today: registration with the Platform through `serveCeService`, an action catalog
projected into the Panel, SSH execution against a managed server fleet, output redaction, and a
local append-only JSONL evidence log.

## Getting started

```bash
pnpm install
pnpm build        # TypeScript → dist/
pnpm lint         # eslint
pnpm typecheck    # tsc --noEmit over src + test
pnpm test         # vitest
```

Runtime baseline is **Node 24** (xtrape-docs `reference/10-runtime-baseline.md`). It is declared
in exactly three places — `package.json` `engines.node`, the CI job container image, and the
`Dockerfile` stages — and `scripts/check-runtime-baseline.mjs` fails CI if they disagree.

### Running

```bash
LINUX_OPS_WIDGET_PLATFORM_URL=http://xtrape-platform-ce.docker:3000 \
LINUX_OPS_WIDGET_CALLBACK_TOKEN=... \
LINUX_OPS_WIDGET_CONF_DIR=./conf \
LINUX_OPS_WIDGET_LOG_DIR=./logs \
LINUX_OPS_WIDGET_DATA_DIR=./data \
node dist/index.js
```

There is no standalone mode. Without `LINUX_OPS_WIDGET_PLATFORM_URL` the process exits: with no
Platform there is no command authority, no authorization, and no central audit, so nothing here
is allowed to execute on its own.

| Variable | Meaning |
| --- | --- |
| `LINUX_OPS_WIDGET_PLATFORM_URL` | **Required.** Xtrape Platform CE address. |
| `LINUX_OPS_WIDGET_CALLBACK_TOKEN` | **Required.** Authenticates the callback listener (prepare/execute/messages). Without it the SDK accepts unauthenticated calls and anyone who can reach the listener bypasses Platform command authorization and audit. |
| `LINUX_OPS_WIDGET_ALLOW_INSECURE_CALLBACK` | Local dev only; waives the token, forces a loopback bind, and warns. |
| `LINUX_OPS_WIDGET_REGISTRATION_TOKEN` | Registration token exchanged for the Service Token. |
| `LINUX_OPS_WIDGET_CALLBACK_PORT` / `_HOST` / `_ADDRESS` | Callback listener port / bind / address advertised to the Platform. |
| `LINUX_OPS_WIDGET_INSTANCE_ID` | Stable Worker identity. Unset → generated and persisted at `conf/instance-id`, reused across restarts. |
| `LINUX_OPS_WIDGET_SERVICE_ID` | Logical Service ID; defaults to `linux-ops-widget-nodejs` (`DEFAULT_SERVICE_ID` in [`src/manifest.ts`](src/manifest.ts) — the single switch point). |
| `LINUX_OPS_WIDGET_CONF_DIR` | Default `./conf`. Holds `servers.json` and the provisioned `tasks/*.sh` bootstrap files (imported into the task DB once per task id; see [`examples/`](examples/)). A missing `tasks/` directory is a valid empty start: the Worker publishes no ops task Actions until tasks are added online. A malformed provisioned task file still stops startup. |
| `LINUX_OPS_WIDGET_LOG_DIR` | Default `./logs`. Append-only `audit.jsonl` local evidence. |
| `LINUX_OPS_WIDGET_DATA_DIR` | Default `./data`. Holds `tasks.db` — the task library (revisions + approvals), SQLite/WAL. |
| `conf/param-guards.json` | Optional. Parameter risk rules evaluated per invocation (#66) — see above. Absent means no guards. |
| `conf/redlines.json` | Optional. The redline rule set screened at review time (#65) — see above. Absent means no screening. |
| `LINUX_OPS_WIDGET_MAX_RECORDED_OUTPUT_BYTES` | Default 65536. How much task output this deployment records across stdout and stderr together; beyond it output is read and dropped and the task still finishes (#61 B). A stored task's smaller `# maxBytes:` still wins. |

The tenant is pinned to `default` for this CE phase.

### Actions

Each ops capability is registered as its own visible entry action; `prepare()` renders the
`serverId` enum live from the fleet, filtered by the action's `serverScopes`. `manageServers` is
the entry action for this Service's **own business config** — the target server fleet — with
`addServer` / `updateServer` / `removeServer` / `testServer` as hidden sub-ops under the reserved
`_servers` category, reached through the list affordances. The Platform routes and audits
`execute`; it does not store this fleet.

`hostKeyFingerprint` on `addServer` / `updateServer` is optional since #44: an explicit value
admits the endpoint from the very first connection (the stronger posture), while a blank one
pins whatever key the endpoint presents at the FIRST key exchange (accept-new) and enforces it
exactly from then on — provenance is visible per entry (`operator` vs `first-use`).
`probeHostKey` fetches the SHA256:… value without authenticating for operators who want to
confirm before admitting. Automation registering a host it just provisioned still reads the
value from the host key it generated (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk
'{print $2}'`) and passes it in the same `addServer` call.

**What the target can run — `shells` (#69).** A task's interpreter comes from its shebang;
whether the *target* has it is a fact the server record carries: `shells` (command names as
`command -v` resolves them: `sh`, `bash`, `python3`, …). `testServer` probes a reachable target
and SHOWS what it finds as a **sealed observation** (`{probe target snapshot + interpreters +
time}` under this Worker incarnation's key, where the snapshot is the secret-free identity of
what was probed: host, effective port, **SSH user** — `command -v` sees that user's PATH —
admitted host key, record generation); a person records it through the offered
`recordProbedShells` affordance (a Test is a read, not a configuration write), which verifies the
seal and CAS-refuses if the record no longer matches that snapshot (rehosted, re-ported, another
user, another admitted key, removed and re-added).
`probed` therefore only ever means "the target answered this": nothing lets a caller mint or edit
a probed list. A recorded probe (`shellsSource: probed`, with the time) wins over a declaration —
declarations drift, probes do not — and a declaration cannot override one (`updateServer` with
`shells` on a probed record is refused: re-probe, or remove and re-add). `addServer` /
`updateServer` accept a declared list on records without a probe, and an edit that says nothing
keeps what is known. With it, the run card and the enable card say `alpine: NO bash —
probed …` where the approver reads, and an execute against a target known to lack the interpreter
is refused **before** dispatch under its own rule, `interpreter-unavailable`, surfaced as the code
`NOT_EXECUTABLE` — not `POLICY_DENIED` (it is not policy) and never mistakable for the script's
own `exit 127`. Unknown is not
"none": a record with no `shells` is never blocked on this, only marked as unprobed on the cards.
Not a control layer — it changes no risk level and relaxes no approval.

**Authentication: an explicit three-way choice (#42).** `authMethod` selects how a target is
reached — `privateKey` (the key content, pasted whole), `privateKeyWithPassphrase` (an
encrypted key plus the passphrase that decrypts it), or `password` — and the methods are
**exclusive**: the chosen method is the authority over which secrets apply, and switching it
retires the other method's stored secrets (this is what replaced the old `clearPassword` /
`clearPassphrase` toggles; the retired `privateKeyPath` reference is gone — the key CONTENT is
stored, so a fleet entry no longer depends on the executor host's filesystem). All three
secrets are raw credentials persisted in this Service's own server store, **write-only from
the Panel**: `publicServer` projects only `authMethod` and `keyConfigured` /
`passwordConfigured` / `passphraseConfigured` booleans, never a value; a blank field on edit
keeps the current secret while the method is unchanged — ANY method switch starts fresh, the
two key methods included, because encrypting or decrypting a key changes its bytes; and
`sanitizeMessage` strips the stored values — the multiline key included — from any error
before it is returned. A `passphrase` is only meaningful with a key — it decrypts it and
authenticates nothing on its own, and this executor has **no SSH-agent support**. A secret the
chosen method does not use is refused as contradictory, never silently dropped.

**At-rest posture, stated honestly.** That store is a **0600 JSON file** (durable write + atomic
rename), not a database and not encrypted: a stored password is plaintext behind file
permissions. That is a deliberate transitional posture — the raw-secret home until a dedicated
**vault-widget** holds widget secrets centrally. Where that fits: a submitted
`password` DOES transit the Platform — that is the Sensitive Action Input path (RFC-0008,
platform docs/09 §6.2): the Platform holds it **ephemerally only** (split out of durable
command state, reserved in process memory, overlaid into the delivery, wiped on consumption
evidence). It never enters Platform **durable** state, the wire projections, or the evidence
log; at rest it lives only in this Widget's store, and at runtime it leaves the executor
host's process only onto the SSH connection it authenticates.

It must be the fingerprint of the key type the connection actually negotiates. The client
prefers `ssh-ed25519`, so the ed25519 host key is the right one for any host that has one; a
host that offers only RSA or ECDSA presents that key instead, and admitting the wrong type
fails closed. The rejection names the fingerprint the endpoint presented, so recovering from a
wrong or rotated value is a copy from the error into `updateServer`.

A `deny` verdict returns before the command is built and before the executor, on both surfaces and
including dry runs. A `human_review` verdict puts the question to a person through the interaction
primitive (see *Danger* above); with no channel configured it fails closed with
`HUMAN_REVIEW_UNAVAILABLE`, and a dry run never asks anyone.

## Code map

| Module | Responsibility |
| --- | --- |
| `src/task-file.ts` | Parses one task script into a definition: the `# key: value` header, the parameter declarations, and the digest over the file's exact bytes. |
| `src/registry.ts` | Runtime task registration and validation (params schema must be `additionalProperties: false`; every parameter must be a scalar with a usable environment variable name; reserved top-level input names rejected). |
| `src/task-db.ts` | The task library: SQLite store of task revisions and approval records; bootstrap import from provisioned `conf/tasks/` files. |
| `src/shell.ts` | Builds the remote command line: parameter assignments plus the interpreter, and the masked projection of it for audit. |
| `src/policy.ts` | Deterministic local policy — `deny` / `human_review` / `allow`; hard results are unloosenable, `tighten()` narrows only. |
| `src/service.ts` | Orchestration: validation → surface gate → policy → dry-run / fail-closed / execute → redact → local evidence. Also `executionHashOf` and `sanitizeMessage`. |
| `src/servers.ts` | Target server fleet store; durable 0600 write with atomic rename; secrets never returned. |
| `src/ce-actions.ts` | CE action catalog: independent ops entry actions + `manageServers` + hidden sub-ops + inline affordances. |
| `src/executors/ssh.ts` | SSH executor; per-server least-privilege user, no shared high-privilege account; fail-closed host key verification against the admitted fingerprint. |
| `src/audit.ts` / `src/redact.ts` | Append-only local JSONL evidence; output redaction and truncation. |
| `src/instance.ts` | Stable Worker identity across restarts. |
| `src/manifest.ts` | Service manifest reported at registration. |
| `src/index.ts` | Widget entrypoint: `serveCeService` registration and the callback listener. |

## Frozen wire identifiers

The 0.8.x concept correction updates prose, comments, and internal names. It does **not** rewrite
bytes on the wire. These stay exactly as they are: the action names (`manageServers`,
`addServer`, `updateServer`, `removeServer`, `testServer`, `listServers`), the reserved `_servers`
category, the `serverId` / `reason` / `dryRun` input keys, the failure codes (`POLICY_DENIED`,
`VALIDATION_FAILED`, `HUMAN_REVIEW_UNAVAILABLE`, `COMMAND_FAILED`,
`ACTION_ERROR`), the policy rule names recorded in audit, the `runtime.agent` and `instanceId`
manifest keys, and the callback routes and header supplied by the Connector SDK.

### Failure codes that changed with the task model

Moving from `commandTemplate` + `prechecks` / `postchecks` to one script file **is** a wire
change, not only an internal one, and the freeze above no longer covers these. Recorded here
rather than glossed, because a downstream reading the old list would be reading a promise this
repository stopped keeping:

| Code | Then | Now |
| --- | --- | --- |
| `PRECHECK_FAILED` | A declared precheck exited non-zero; the main command had not run | **Removed.** A precheck is the first line of the script, so its failure is the task's failure: `COMMAND_FAILED` |
| `POSTCHECK_FAILED` | The command ran, then verification failed. All postchecks ran, and the report said the effect may already have occurred | **Removed.** Verification is a step of the script; a task whose script stops there reports `COMMAND_FAILED` |
| `OUTPUT_LIMIT_EXCEEDED` | — | An executor had to stop a command before any exit status was observed, so the remote outcome is unknown. Since #61 B the RECORDING ceiling no longer does this — output beyond it is dropped while the task finishes — so this code is reserved for a genuine forced termination |

Two consequences a task author should know rather than discover:

- **Phase is no longer in the code.** Which step failed is in the task's own output, not in the
  failure code. A script that wants the distinction should say so itself — `echo` before each
  stage, or exit with distinct statuses.
- **Whether a failing step stops the rest is the script's own decision.** The retired `postchecks`
  ran every check even after one failed, then reported once. A plain script does the same thing —
  nothing here turns on `set -e` — so a script wanting the retired behaviour needs no change,
  while one wanting to stop at the first failure writes `set -e` itself. Either way the task's
  exit status is whatever its script reports.

## Security baseline

- Deterministic deny and forced-human-review rules cannot be overridden by an AI reviewer.
- **Every SSH target is admitted by its host key.** Each server carries a
  `hostKeyFingerprint` (`SHA256:…`, exactly what `ssh-keygen -lf` prints — or what the
  credential-free `probeHostKey` sub-op fetches for you), set through `manageServers`.
  `SshExecutor` verifies it during key exchange — before authentication and before any command
  reaches the wire — and refuses a key that does not match. Since #44 the fingerprint is
  **optional at admission**: an entry without one is **pinned on first use** (accept-new) —
  the executor records the key the endpoint presents at the first key exchange, durably and
  compare-and-set (a pin that cannot persist refuses the connection; a recorded fingerprint,
  operator-admitted or pinned, is never silently replaced), and every later mismatch fails
  closed. The fleet shows which trust each entry holds (`operator` vs `first-use`): a first-use
  pin protects against later substitution, not an impostor already answering at first contact —
  an explicit operator fingerprint remains the stronger posture and re-admitting a rotated key
  is still a deliberate `updateServer`.
- **Executor and probe errors are sanitized**: every stored secret is stripped by exact match
  before redaction, and `redactOutput` then masks the usual `password` / `token` / `secret`
  shapes. That is a pattern filter over messages, not a guarantee about a task's own output —
  see the evidence bullet below for where it stops.
- **The local evidence log is data-minimized and mode-enforced.** `audit.jsonl` records the
  server, task, version, reason, provenance, argument *names*, the `scriptDigest` of the exact
  script that ran, and the `executionHash` binding all of it. The request fields carry no
  argument values, and the recorded command has every parameter value masked — **as does the
  command returned to the caller**, so the value this Service keeps out of its own evidence does
  not leave in the answer either.

  **The scope of that is the request and the command, and no wider.** A task's stdout and stderr
  are recorded too, and they are the script's own output: a script that echoes `$XOPS_release`
  writes that value into evidence. `redactOutput` is pattern-based (`token`, `password`,
  `secret`, …) and cannot know an arbitrary argument value. A task handling something sensitive
  keeps it out of its own output, or declares `# redact:` for it. The file is created at `0600`, and every append
  re-enforces `0600` with `fchmod` on the descriptor it is about to write to — before the write,
  so no record is ever appended to a file that is still world-readable, and on the same open file,
  so the mode cannot land on something else that took the path in between. The mode therefore
  depends on neither the process umask nor on the file having stayed as this Service last left it.
- Approval binds task + script digest + args (`executionHashOf`). The script digest is in it
  because a task id and version name a file whose contents can be edited in place; without it an
  approval would carry over to a script nobody approved.
- High-risk operations (production, data, permissions, network, security config, irreversible)
  default conservative.

## AI Agent

Read [`AGENTS.md`](AGENTS.md) before starting work in this repository.
