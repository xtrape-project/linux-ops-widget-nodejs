#!/usr/bin/env bash
# Regression tests for verify-publish-credential.sh with a curl stub: no
# network, no real token. Three dispositions: exact target → OK; a token that
# also pushes elsewhere → REFUSED; a token that pushes nowhere → REFUSED; plus
# pagination (the target on page 2 still counts, an extra on page 2 still refuses).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/verify-publish-credential.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0
ok() { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1 -> $2"; fail=$((fail+1)); }

# The stub answers /user and /user/repos?page=N from files the test writes.
cat > "$TMP/curl" <<'STUB'
#!/usr/bin/env bash
url="${@: -1}"
case "$url" in
  */user) cat "$STUB_DIR/user.json" ;;
  *page=1*) cat "$STUB_DIR/page1.json" ;;
  *page=2*) cat "$STUB_DIR/page2.json" ;;
  *) echo "[]" ;;
esac
STUB
chmod +x "$TMP/curl"
export STUB_DIR="$TMP" CURL="$TMP/curl" PUBLIC_REPO_URL="https://forgejo.example/xtrape-project/thing.git" PUBLISH_TOKEN="not-a-real-token"
echo '{"login":"publisher-bot"}' > "$TMP/user.json"
repo() { printf '{"full_name":"%s","permissions":{"push":%s}}' "$1" "$2"; }
run() { bash "$SCRIPT" >"$TMP/out" 2>"$TMP/err"; echo $?; }

printf '[%s]' "$(repo xtrape-project/thing true)" > "$TMP/page1.json"; echo '[]' > "$TMP/page2.json"
[ "$(run)" = 0 ] && grep -q "exactly xtrape-project/thing" "$TMP/out" && ok "exact target is accepted" || bad "exact target" "$(cat "$TMP/err")"

printf '[%s,%s]' "$(repo xtrape-project/thing true)" "$(repo xtrape-project/other true)" > "$TMP/page1.json"
[ "$(run)" = 1 ] && grep -q "xtrape-project/other" "$TMP/err" && ok "a token that also pushes to a sibling public repository is refused, naming the extra reach" || bad "extra reach" "$(cat "$TMP/err")"

printf '[%s,%s]' "$(repo xtrape-project/thing true)" "$(repo xtrape-project/other false)" > "$TMP/page1.json"
[ "$(run)" = 0 ] && ok "read-only reach elsewhere does not count as push reach" || bad "pull-only elsewhere" "$(cat "$TMP/err")"

printf '[%s]' "$(repo xtrape-project/thing false)" > "$TMP/page1.json"
[ "$(run)" = 1 ] && grep -q "(nothing)" "$TMP/err" && ok "a token that pushes nowhere is refused" || bad "no reach" "$(cat "$TMP/err")"

# Pagination: 50 pull-only rows on page 1, the target on page 2 → accepted; an extra on page 2 → refused.
python3 - "$TMP" <<'PY'
import json,sys,os
d=sys.argv[1]
page1=[{"full_name":"x/r%d"%i,"permissions":{"push":False}} for i in range(50)]
json.dump(page1,open(os.path.join(d,"page1.json"),"w"))
json.dump([{"full_name":"xtrape-project/thing","permissions":{"push":True}}],open(os.path.join(d,"page2.json"),"w"))
PY
[ "$(run)" = 0 ] && ok "pagination: the target on page 2 is found" || bad "pagination target" "$(cat "$TMP/err")"
python3 - "$TMP" <<'PY'
import json,sys,os
d=sys.argv[1]
json.dump([{"full_name":"xtrape-project/thing","permissions":{"push":True}},{"full_name":"xtrape-project/other","permissions":{"push":True}}],open(os.path.join(d,"page2.json"),"w"))
PY
[ "$(run)" = 1 ] && ok "pagination: an extra push reach on page 2 still refuses" || bad "pagination extra" "$(cat "$TMP/err")"

echo '{}' > "$TMP/user.json"
[ "$(run)" = 1 ] && ok "a token that identifies no user is refused" || bad "no login" "$(cat "$TMP/err")"

echo "verify-publish-credential self-test: $pass passed, $fail failed"
[ "$fail" = 0 ]
