#!/usr/bin/env bash
# Static self-test of .forgejo/workflows/publish-snapshot.yml — the template
# invariants every component repository copies (review 3317):
#   1. the job is scoped to THIS source repository by exact name;
#   2. the public target is xtrape-project/<same repository>;
#   3. the credential's reach is proved before anything is pushed;
#   4. every mandatory gate this repository declares in package.json
#      (lint / typecheck / build / test, whichever exist) runs before publish;
#   5. the guard denies the retired github.com/xtrape-com coordinates.
# Run without network; the repository name comes from the checkout's origin.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WF="$ROOT/.forgejo/workflows/publish-snapshot.yml"
pass=0; fail=0
ok() { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }

repo_name="$(git -C "$ROOT" remote get-url origin 2>/dev/null | sed -E 's#.*/##; s#\.git$##')"
[ -n "$repo_name" ] || repo_name="$(basename "$ROOT")"
source_repo="xtrape/${repo_name}"
public_repo="xtrape-project/${repo_name}"

grep -Eq "if: \\$\\{\\{ github\\.repository == '${source_repo}' \\}\\}" "$WF" && ok "job is scoped to ${source_repo}" || bad "job is not scoped to ${source_repo} by exact name"
grep -Eq "SOURCE_REPO: ${source_repo}$" "$WF" && ok "SOURCE_REPO is ${source_repo}" || bad "SOURCE_REPO is not ${source_repo}"
grep -Eq "PUBLIC_REPO_URL: https://forgejo\\.xtrape\\.com/${public_repo}\\.git$" "$WF" && ok "PUBLIC_REPO_URL is ${public_repo}" || bad "PUBLIC_REPO_URL is not ${public_repo}"
grep -q "scripts/verify-publish-credential.sh" "$WF" && ok "credential reach is proved before publishing" || bad "no credential reach check"

# Trigger semantics (review 3548): manual-only, and manual dispatch is bound to
# main. These are the invariants the trigger redesign rests on; without them a
# future template drift could silently re-open automatic publication, or drop
# the main-ref guard, while every other assertion here still passes.
grep -Eq "^  workflow_dispatch:" "$WF" && ok "workflow_dispatch entry point exists" || bad "no workflow_dispatch entry point"
# The invariant is "no automatic push trigger AT ALL", not "no main filter":
# `on: push:` bare, or `push: branches: [develop]`, must fail too (review 3556).
grep -Eq "^  push:" "$WF" && bad "an automatic push trigger is still present" || ok "no automatic push trigger of any kind"
# The ref must reach the guard as environment data, never as shell source:
# `$(...)` and backticks are legal in a git ref name.
grep -Eq 'PUBLISH_REF: \$\{\{ github\.ref \}\}' "$WF" && ok "github.ref is passed as environment data" || bad "github.ref is not passed as environment data"
grep -Eq 'ref="\$\{\{ github\.ref \}\}"' "$WF" && bad "github.ref is interpolated directly into shell source" || ok "github.ref is not interpolated into shell source"
grep -q 'refs/heads/main' "$WF" && ok "dispatch is bound to refs/heads/main" || bad "dispatch is not bound to refs/heads/main"
grep -q 'rev-parse FETCH_HEAD' "$WF" && ok "dispatched revision is compared against origin/main" || bad "dispatched revision is not compared against origin/main"
# The revision guard must precede the first credential use.
guard_line="$(grep -n 'refs/heads/main' "$WF" | head -1 | cut -d: -f1)"
# The first ACTUAL use of the credential, not the first mention of its name:
# the header comment references PUBLISH_TOKEN long before any step reads it.
cred_line="$(grep -n 'secrets\.PUBLISH_TOKEN' "$WF" | head -1 | cut -d: -f1)"
if [ -n "$guard_line" ] && [ -n "$cred_line" ] && [ "$guard_line" -lt "$cred_line" ]; then
  ok "source-revision guard precedes any credential use"
else
  bad "source-revision guard does not precede credential use"
fi
# The reach check must run BEFORE the publish step.
reach_line="$(grep -n "scripts/verify-publish-credential.sh" "$WF" | head -1 | cut -d: -f1)"
publish_line="$(grep -n "scripts/publish-snapshot.sh" "$WF" | head -1 | cut -d: -f1)"
[ -n "$reach_line" ] && [ -n "$publish_line" ] && [ "$reach_line" -lt "$publish_line" ] && ok "reach check precedes the publish step" || bad "reach check does not precede the publish step"
grep -q 'github\\.com/xtrape-com' "$WF" && ok "guard denies github.com/xtrape-com (retired public coordinate)" || bad "guard does not deny github.com/xtrape-com"

for gate in lint typecheck build test; do
  if python3 -c 'import json,sys; sys.exit(0 if sys.argv[1] in (json.load(open(sys.argv[2])).get("scripts") or {}) else 1)' "$gate" "$ROOT/package.json"; then
    grep -Eq "^\s+pnpm ${gate}$" "$WF" && ok "mandatory gate '${gate}' runs before publish" || bad "package.json declares '${gate}' but the workflow does not run it"
  fi
done
for t in test-verify-public-link.sh test-publish-guard.sh test-verify-publish-credential.sh test-publish-workflow.sh; do
  grep -q "scripts/${t}" "$WF" && ok "self-test ${t} runs in the workflow" || bad "self-test ${t} is not run by the workflow"
done
echo "publish-workflow self-test: $pass passed, $fail failed"
[ "$fail" = 0 ]
