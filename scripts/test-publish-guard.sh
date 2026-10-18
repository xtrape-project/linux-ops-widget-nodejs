#!/usr/bin/env bash
# Regression tests for the publish guard in publish-snapshot.sh, run against a
# throwaway source repository with DRY_RUN=1 (no network, no push).
#
# The two properties review 3122 found missing, now pinned:
#   1. an operator deny pattern (a SECRET) never appears in the guard output —
#      only its 1-based index and the matched path:line:content do;
#   2. an acknowledgement is bound to LOCATION, not to the set of distinct
#      values: the same acknowledged false-positive address appearing at a new
#      path must invalidate the old PUBLISH_GUARD_ACK.
# Plus the four dispositions: clean / refuse without ack / wrong ack refuses /
# matching ack publishes.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/publish-snapshot.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
REPO="$TMP/src"
mkdir -p "$REPO/scripts"
# The guard sources scripts/verify-public-link.sh from the SOURCE tree it
# publishes, so the fixture repository carries a copy.
cp "$HERE/verify-public-link.sh" "$REPO/scripts/"
git -C "$REPO" init -q
git -C "$REPO" -c user.name=t -c user.email=t@example.com commit -q --allow-empty -m init
commit() { git -C "$REPO" add -A && git -C "$REPO" -c user.name=t -c user.email=t@example.com commit -q -m "$1"; }

# Runs the guard in the fixture repo; stdout+stderr to $OUT, exit code in $RC.
run() { # run [ENV=VAL ...]
  OUT="$TMP/out"; : > "$OUT"
  ( cd "$REPO" && env -u GITHUB_REPOSITORY -u PUBLISH_GUARD_ACK -u EXTRA_DENY_PATTERNS \
      DRY_RUN=1 PUBLIC_REPO_URL=https://public.invalid/fixture.git \
      SOURCE_REPO=xtrape/fixture "$@" bash "$SCRIPT" ) >"$OUT" 2>&1
  RC=$?
}
fingerprint() { sed -n 's/^  PUBLISH_GUARD_ACK=\([0-9a-f]\{64\}\)$/\1/p' "$OUT" | head -1; }

pass=0; fail=0
ok()  { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); sed 's/^/    | /' "$OUT"; }
# The address is a FIXTURE (deliberately non-project) so the guard has
# something to find. It is assembled from pieces so this test file — which is
# itself published — does not contain an address literal for the guard to flag.
ADDR="someone""@""fixture-domain.test"

# --- clean tree publishes -------------------------------------------------
printf 'nothing to see\n' > "$REPO/README.md"; commit clean
run
if [ $RC -eq 0 ] && grep -q 'publish guard: clean' "$OUT" && grep -q 'dry run: would publish' "$OUT"; then ok "clean tree publishes"; else bad "clean tree publishes"; fi

# --- one finding: refuse, then accept the exact fingerprint ---------------
printf 'contact: %s\n' "$ADDR" > "$REPO/a.md"; commit "one email"
run
FP1="$(fingerprint)"
if [ $RC -ne 0 ] && [ -n "$FP1" ] && grep -q "a.md:1:$ADDR" "$OUT"; then ok "email finding refuses without ack and is path:line-bound"; else bad "email finding refuses without ack"; fi
run PUBLISH_GUARD_ACK=0000000000000000000000000000000000000000000000000000000000000000
if [ $RC -ne 0 ]; then ok "wrong ack still refuses"; else bad "wrong ack still refuses"; fi
run PUBLISH_GUARD_ACK="$FP1"
if [ $RC -eq 0 ] && grep -q 'findings acknowledged' "$OUT" && grep -q 'dry run: would publish' "$OUT"; then ok "matching ack publishes"; else bad "matching ack publishes"; fi
run PUBLISH_GUARD_ACK="$FP1"
if [ $RC -eq 0 ]; then ok "fingerprint is stable across runs"; else bad "fingerprint is stable across runs"; fi

# --- the SAME address at a new path invalidates the old ack (review 3122) --
printf 'also: %s\n' "$ADDR" > "$REPO/b.md"; commit "same email, second file"
run PUBLISH_GUARD_ACK="$FP1"
FP2="$(fingerprint)"
if [ $RC -ne 0 ] && [ -n "$FP2" ] && [ "$FP2" != "$FP1" ] && grep -q "b.md:1:$ADDR" "$OUT"; then
  ok "acknowledged address at a NEW path invalidates the old ack (review-3122 P1)"
else bad "acknowledged address at a NEW path invalidates the old ack"; fi
# ...and the same address moving to another LINE of the same file does too.
printf '\ncontact: %s\n' "$ADDR" > "$REPO/a.md"; rm "$REPO/b.md"; commit "same email, moved line"
run PUBLISH_GUARD_ACK="$FP1"
if [ $RC -ne 0 ] && [ "$(fingerprint)" != "$FP1" ] && grep -q "a.md:2:$ADDR" "$OUT"; then ok "acknowledged address on a new LINE invalidates the old ack"; else bad "acknowledged address on a new LINE invalidates the old ack"; fi

# --- operator deny pattern is never rendered (review 3122) ----------------
printf 'nothing to see\n' > "$REPO/README.md"; rm -f "$REPO/a.md"
printf 'token=FIXTUREDENY42\n' > "$REPO/c.md"; commit "deny fixture"
PAT='FIXTUREDENY[0-9]+'
run EXTRA_DENY_PATTERNS="$(printf 'no-such-thing-zzz\n%s' "$PAT")"
if [ $RC -ne 0 ] && grep -q 'deny pattern #2 ==' "$OUT" && grep -q 'c.md:1:token=FIXTUREDENY42' "$OUT" && ! grep -qF "$PAT" "$OUT"; then
  ok "deny pattern reported by index + matched location, pattern text never rendered (review-3122 P1)"
else bad "deny pattern never rendered"; fi
FPD="$(fingerprint)"
run EXTRA_DENY_PATTERNS="$(printf 'no-such-thing-zzz\n%s' "$PAT")" PUBLISH_GUARD_ACK="$FPD"
if [ $RC -eq 0 ] && grep -q 'dry run: would publish' "$OUT"; then ok "deny finding is acknowledgeable by fingerprint"; else bad "deny finding is acknowledgeable by fingerprint"; fi

echo "publish-guard self-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
