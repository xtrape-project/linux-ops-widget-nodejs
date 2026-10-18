#!/usr/bin/env bash
# Regression tests for verify-public-link.sh with a stubbed curl.
# Covers exactly the fail-open shapes review 2025 found:
#   web 200 + API 404/500/timeout  -> must block
#   web 200 + API 200 but HTML     -> must block
#   declared issue, target is a PR -> must block
# plus the pattern/normalization behaviour for deep file paths.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/verify-public-link.sh"

STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$STUB_DIR"' EXIT
cat > "$STUB_DIR/curl" <<'STUB'
#!/usr/bin/env bash
# curl stub: behaviour driven by STUB_WEB_CODE / STUB_API_CODE / STUB_API_BODY.
out=/dev/null; url=""
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  case "${args[i]}" in
    -o) out="${args[i+1]}"; ((i++)) ;;
    -w|--max-time) ((i++)) ;;
    -sS) ;;
    *) url="${args[i]}" ;;
  esac
done
case "$url" in
  */api/v1/*) printf '%s' "${STUB_API_BODY:-}" > "$out"; printf '%s' "${STUB_API_CODE:-200}" ;;
  *)          printf '%s' "${STUB_WEB_CODE:-200}" ;;
esac
STUB
chmod +x "$STUB_DIR/curl"
export PATH="$STUB_DIR:$PATH"

NS=xtrape-project
BASE="https://forgejo.xtrape.com/$NS/xtrape-site"
pass=0; fail=0
expect() { # expect <ok|err:substr> <desc> -- env then url
  local want="$1" desc="$2" url="$3" out rc
  out="$(verify_public_link "$url" "$NS")"; rc=$?
  if [ "$want" = "ok" ]; then
    if [ $rc -eq 0 ]; then echo "PASS: $desc"; pass=$((pass+1));
    else echo "FAIL: $desc -> unexpectedly blocked: $out"; fail=$((fail+1)); fi
  else
    local sub="${want#err:}"
    if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qF "$sub"; then echo "PASS: $desc"; pass=$((pass+1));
    else echo "FAIL: $desc -> rc=$rc out=$out"; fail=$((fail+1)); fi
  fi
}

STUB_WEB_CODE=404 expect "err:not anonymously reachable" "web 404 blocks" "$BASE/issues/7"
STUB_WEB_CODE=200 STUB_API_CODE=404 expect "err:does not resolve anonymously via the API" "web 200 + API 404 blocks (review-2025 P1)" "$BASE/issues/7"
STUB_WEB_CODE=200 STUB_API_CODE=500 expect "err:does not resolve anonymously via the API" "web 200 + API 500 blocks" "$BASE/issues/7"
STUB_WEB_CODE=200 STUB_API_CODE=000 expect "err:does not resolve anonymously via the API" "web 200 + API timeout blocks" "$BASE/pulls/7"
STUB_WEB_CODE=200 STUB_API_CODE=200 STUB_API_BODY='<html>login</html>' expect "err:not with parseable JSON" "API 200 with HTML blocks" "$BASE/issues/7"
STUB_WEB_CODE=200 STUB_API_CODE=200 STUB_API_BODY='{"number":7,"pull_request":{"merged":false}}' expect "err:target is a pull request" "issue link to a PR blocks" "$BASE/issues/7"
STUB_WEB_CODE=200 STUB_API_CODE=200 STUB_API_BODY='{"number":7}' expect ok "clean issue passes" "$BASE/issues/7"
STUB_WEB_CODE=200 STUB_API_CODE=200 STUB_API_BODY='{"number":7,"head":{}}' expect ok "clean PR via pulls endpoint passes" "$BASE/pulls/7"
STUB_WEB_CODE=200 expect ok "plain deep file link, web 200, passes" "$BASE/src/branch/main/CITATION.cff"
STUB_WEB_CODE=404 expect "err:not anonymously reachable" "dead deep file path blocks (review-2025 P2)" "$BASE/src/branch/main/NO_SUCH_FILE.md"

# Pattern + normalization: deep paths are captured whole; fragments, trailing
# dots and .git are normalized, and the pattern the guard greps with is the
# SAME function under test.
pat="$(public_link_pattern "$NS")"
sample="see (${BASE}/src/branch/main/CITATION.cff) and ${BASE}.git and ${BASE}/issues/7#note."
got="$(printf '%s' "$sample" | grep -Eoh "$pat")"
echo "$got" | grep -qx "${BASE}/src/branch/main/CITATION.cff" && { echo "PASS: pattern keeps full file path"; pass=$((pass+1)); } || { echo "FAIL: pattern truncated file path: $got"; fail=$((fail+1)); }
n="$(normalize_public_link "${BASE}/issues/7#note.")"
[ "$n" = "${BASE}/issues/7" ] && { echo "PASS: normalization strips fragment+dot"; pass=$((pass+1)); } || { echo "FAIL: normalize -> $n"; fail=$((fail+1)); }
n="$(normalize_public_link "${BASE}.git")"
[ "$n" = "$BASE" ] && { echo "PASS: normalization strips .git"; pass=$((pass+1)); } || { echo "FAIL: normalize -> $n"; fail=$((fail+1)); }

echo "----"
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
