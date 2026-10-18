#!/usr/bin/env bash
# Regression for the immutable-coordinate gate (review 3323): a stub `docker`
# plays the registry; every verdict below is pinned.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "  ok   $1"; }
bad() { fail=$((fail+1)); echo "  FAIL $1"; }
# stub docker: STUB_MODE decides what `imagetools inspect` does; every push is logged
mkdir -p "$tmp/bin"; cat > "$tmp/bin/docker" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = buildx ] && [ "$2" = imagetools ] && [ "$3" = inspect ]; then
  case "$STUB_MODE" in
    exists)     printf '"%s"\n' "$STUB_DIGEST"; exit 0;;
    notfound)   echo "ERROR: $4: not found" >&2; exit 1;;
    unknown)    echo "ERROR: failed to resolve: manifest unknown: manifest unknown" >&2; exit 1;;
    unauth)     echo "ERROR: unexpected status from HEAD request to https://forgejo.xtrape.com/v2/x/manifests/1.0.0: 401 Unauthorized" >&2; exit 1;;
    unauth-nf)  echo "ERROR: unauthorized: not found" >&2; exit 1;;
    forbidden)  echo "ERROR: unexpected status: 403 Forbidden" >&2; exit 1;;
    five03)     echo "ERROR: unexpected status from HEAD request: 503 Service Unavailable" >&2; exit 1;;
    timeout)    echo "ERROR: failed to do request: Head \"https://forgejo.xtrape.com/v2/\": dial tcp: i/o timeout" >&2; exit 1;;
    garbage)    echo "not-a-digest" ; exit 0;;
    weird)      echo "ERROR: something nobody anticipated" >&2; exit 1;;
    tls-url)    echo "ERROR: failed to do request: Head \"https://forgejo.xtrape.com/v2/x/manifests/${4##*:}\": tls: failed to verify certificate: x509: certificate signed by unknown authority" >&2; exit 1;;
    five03-url) echo "ERROR: unexpected status from HEAD request to https://forgejo.xtrape.com/v2/x/manifests/${4##*:}: 503 Service Unavailable" >&2; exit 1;;
    code-nf)    echo "ERROR: $4: unexpected status from HEAD request to https://forgejo.xtrape.com/v2/x/manifests/${4##*:}: ${4##*:} Upstream Failure: not found" >&2; exit 1;;
  esac
fi
if [ "$1" = push ]; then echo "$2" >> "$STUB_PUSH_LOG"; exit 0; fi
echo "stub docker: unexpected $*" >&2; exit 99
STUB
chmod +x "$tmp/bin/docker"
export PATH="$tmp/bin:$PATH" STUB_PUSH_LOG="$tmp/pushes"
D1="sha256:$(printf 'a%.0s' $(seq 1 64))"; D2="sha256:$(printf 'b%.0s' $(seq 1 64))"
digest_of() { STUB_MODE="$1" STUB_DIGEST="${2:-}" "$here/oci-remote-digest.sh" reg/img:1.0.0 2>/dev/null; }
# --- oci-remote-digest.sh verdicts
[ "$(digest_of exists "$D1")" = "$D1" ] && ok "existing coordinate → its digest" || bad "existing coordinate → its digest"
out="$(digest_of notfound)" && [ -z "$out" ] && ok "'not found' → absent (empty, exit 0)" || bad "'not found' → absent"
out="$(digest_of unknown)" && [ -z "$out" ] && ok "'manifest unknown' → absent" || bad "'manifest unknown' → absent"
for m in unauth unauth-nf forbidden five03 timeout garbage weird; do
  if digest_of "$m" >/dev/null; then bad "$m → must fail closed (exit 1)"; else ok "$m → fail closed (exit 1)"; fi
done
# --- oci-publish-coordinate.sh decisions
run_pub() { : > "$STUB_PUSH_LOG"; STUB_MODE="$1" STUB_DIGEST="${2:-}" "$here/oci-publish-coordinate.sh" reg/img:1.0.0 "$D1" >"$tmp/out" 2>"$tmp/err"; }
run_pub notfound && [ "$(cat "$STUB_PUSH_LOG")" = "reg/img:1.0.0" ] && ok "absent → pushed exactly once" || bad "absent → pushed"
run_pub exists "$D1" && [ ! -s "$STUB_PUSH_LOG" ] && grep -q identical "$tmp/out" && ok "same digest → idempotent, no push" || bad "same digest → idempotent"
if run_pub exists "$D2"; then bad "different digest → must refuse"; else [ ! -s "$STUB_PUSH_LOG" ] && grep -q 'different content' "$tmp/err" && ok "different digest → refused, no push" || bad "different digest → refused without push"; fi
if run_pub unauth; then bad "unauthorized → must not push"; else [ ! -s "$STUB_PUSH_LOG" ] && ok "unauthorized → stopped, no push" || bad "unauthorized → no push"; fi
if run_pub five03; then bad "503 → must not push"; else [ ! -s "$STUB_PUSH_LOG" ] && ok "503 → stopped, no push" || bad "503 → no push"; fi
if "$here/oci-publish-coordinate.sh" reg/img:1.0.0 not-a-digest >/dev/null 2>&1; then bad "bad candidate digest → must refuse"; else ok "bad candidate digest → refused"; fi
# --- regression: a candidate tag embeds a 40-hex source SHA whose digit runs
# look like status codes. Task 7406 (2026-09-11) refused a first push because
# "...8914d638574" matched 5[0-9][0-9]. The first ref is that exact coordinate.
CAND="reg/img:candidate-ca5bfad27b678ce3ffba144b57f1e8914d638574"
CAND2="reg/img:candidate-401f503e429d0000000000000000000000000000"
SHA_TWIN="reg/img:sha-401f503e429d0000000000000000000000000000"
digest_ref() { STUB_MODE="$1" STUB_DIGEST="${3:-}" "$here/oci-remote-digest.sh" "$2" 2>/dev/null; }
for r in "$CAND" "$CAND2" "$SHA_TWIN"; do
  out="$(digest_ref notfound "$r")" && [ -z "$out" ] && ok "'not found' on ${r#*:} → absent" || bad "'not found' on ${r#*:} → absent (status-code false match)"
done
for m in tls-url five03-url; do
  if digest_ref "$m" "$CAND" >/dev/null; then bad "$m on candidate ref → must fail closed"; else ok "$m on candidate ref → fail closed"; fi
done
# --- a tag may itself be a status code (review 3624): only the coordinate is
# masked, so a standalone status equal to the tag must still fail closed even
# when the same message also says "not found"
for t in 503 429 401; do
  if digest_ref code-nf "reg/img:$t" >/dev/null; then bad "tag $t + standalone $t + not found → must fail closed"; else ok "tag $t + standalone $t + not found → fail closed"; fi
done
out="$(digest_ref notfound reg/img:503)" && [ -z "$out" ] && ok "'not found' on tag 503 → absent" || bad "'not found' on tag 503 → absent"
: > "$STUB_PUSH_LOG"
STUB_MODE=notfound "$here/oci-publish-coordinate.sh" "$CAND" "$D1" >"$tmp/out" 2>"$tmp/err" \
  && [ "$(cat "$STUB_PUSH_LOG")" = "$CAND" ] && ok "absent candidate → pushed exactly once" || bad "absent candidate → pushed"
echo "oci-publish-coordinate self-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
