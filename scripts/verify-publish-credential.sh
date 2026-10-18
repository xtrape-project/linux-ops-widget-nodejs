#!/usr/bin/env bash
#
# Prove, before anything is pushed, that the publication credential reaches
# EXACTLY the one public target this repository publishes to — and nothing
# else (docs#212 blast-radius rule; docs#234: "write access to
# xtrape-project/<repo> and nothing else"; review 3317 P1).
#
# The check is mechanical and credential-bound: the token is asked which
# repositories it can push to (Forgejo `GET /api/v1/user/repos`, paginated),
# and that set must be exactly { PUBLIC_REPO }. A token that can also write
# another xtrape-project/* canonical would let one compromised source
# repository or one mistyped PUBLIC_REPO_URL rewrite a sibling's public
# history; such a token is refused here, whatever else it could do.
#
# Required environment:
#   PUBLIC_REPO_URL   https URL of the canonical public repository
#   PUBLISH_TOKEN     the credential the publication will use
# Optional:
#   FORGEJO_API       API base (default: derived from PUBLIC_REPO_URL host)
#   CURL              curl command (tests substitute a stub)
#
# Prints the token's login (not a secret) and the verdict. Exit 0 = exact.
set -euo pipefail

: "${PUBLIC_REPO_URL:?PUBLIC_REPO_URL is required}"
: "${PUBLISH_TOKEN:?PUBLISH_TOKEN is required}"
CURL="${CURL:-curl}"

host_and_path="${PUBLIC_REPO_URL#https://}"
host="${host_and_path%%/*}"
target="${host_and_path#*/}"
target="${target%.git}"
API="${FORGEJO_API:-https://${host}/api/v1}"

auth() { "$CURL" -sS -f -H "Authorization: token ${PUBLISH_TOKEN}" "$@"; }

login="$(auth "${API}/user" | sed -n 's/.*"login":"\([^"]*\)".*/\1/p' | head -n 1)"
[ -n "$login" ] || { echo "publish-credential: the token does not identify a user; refusing" >&2; exit 1; }

# Every repository the credential can PUSH to, across all pages.
pushable=""
page=1
while :; do
  body="$(auth "${API}/user/repos?limit=50&page=${page}")"
  names="$(printf '%s' "$body" | python3 -c '
import json,sys
rows=json.load(sys.stdin)
for r in rows:
    if (r.get("permissions") or {}).get("push"): print(r["full_name"])
print("__COUNT__%d" % len(rows))')"
  count="$(printf '%s\n' "$names" | sed -n 's/^__COUNT__//p')"
  pushable="$(printf '%s\n%s\n' "$pushable" "$(printf '%s\n' "$names" | grep -v '^__COUNT__' || true)")"
  [ "${count:-0}" -ge 50 ] || break
  page=$((page + 1))
done
pushable="$(printf '%s\n' "$pushable" | sed '/^$/d' | LC_ALL=C sort -u)"

if [ "$pushable" = "$target" ]; then
  echo "publish-credential: token of '${login}' pushes to exactly ${target} — OK"
  exit 0
fi
echo "publish-credential: REFUSED — the token of '${login}' must push to exactly '${target}', but its push reach is:" >&2
if [ -z "$pushable" ]; then echo "  (nothing)" >&2; else printf '  %s\n' $pushable >&2; fi
echo "  Install a target-scoped credential (a publication account that collaborates on that one public repository only) as this repository's PUBLISH_TOKEN secret." >&2
exit 1
