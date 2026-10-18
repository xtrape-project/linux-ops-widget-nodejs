#!/usr/bin/env bash
# Verification of one public link, extracted from publish-snapshot.sh so the
# logic is unit-testable with a stubbed curl (scripts/test-verify-public-link.sh).
#
# verify_public_link URL PUBLIC_NAMESPACE
#   prints one error line and returns 1 on any failure; silent 0 on success.
#
# Fail-closed by construction:
#   - the web fetch must answer HTTP 200 anonymously (no credentials, ever);
#   - for /issues/N and /pulls/N links the DECLARED kind is queried on its own
#     API endpoint, which must also answer 200 anonymously — an API timeout,
#     404, 429, 500 or HTML body blocks publication instead of passing;
#   - the API body must parse as strict JSON (node, which the publish
#     container guarantees), and a link declared as an issue must not resolve
#     to a pull request.

verify_public_link() {
  local url="$1" ns="$2"
  local code="" attempt host_url repo_path num kind_path kind repo api tmp

  for attempt in 1 2 3; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$url" || echo 000)"
    [ "$code" = "200" ] && break
    sleep 2
  done
  if [ "$code" != "200" ]; then
    echo "public link not anonymously reachable (HTTP $code): $url"
    return 1
  fi

  case "$url" in
    */issues/[0-9]*|*/pulls/[0-9]*) : ;;
    *) return 0 ;;
  esac

  # Derive the host from the link itself; a literal API base written here
  # would trip the namespace allowlist when the guard scans this very script.
  host_url="${url%%/${ns}/*}"
  repo_path="${url#"${host_url}"/}"                    # ns/repo/kind/n
  num="${repo_path##*/}"
  kind_path="${repo_path%/*}"; kind="${kind_path##*/}" # issues|pulls
  repo="${repo_path%/"$kind"/"$num"}"

  # Query the DECLARED kind on its own endpoint: /pulls/N answers 404 for an
  # issue, so a mistyped link fails right here — the web route conflates the
  # two, the API does not.
  if [ "$kind" = "pulls" ]; then
    api="${host_url}/api/v1/repos/${repo}/pulls/${num}"
  else
    api="${host_url}/api/v1/repos/${repo}/issues/${num}"
  fi

  tmp="$(mktemp)"
  code="$(curl -sS -o "$tmp" -w '%{http_code}' --max-time 20 "$api" || echo 000)"
  if [ "$code" != "200" ]; then
    rm -f "$tmp"
    echo "declared ${kind%s} does not resolve anonymously via the API (HTTP $code): $url"
    return 1
  fi

  # Strict structural parse. Exit codes: 0 ok, 3 not-JSON, 4 kind mismatch.
  # (No `if !` here: the bang inverts $? and would collapse the two failure
  # kinds into one — the test suite caught exactly that.)
  local rc=0
  node -e '
    const fs = require("fs");
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); }
    catch (e) { process.exit(3); }
    if (typeof parsed !== "object" || parsed === null) process.exit(3);
    const isPr = parsed.pull_request !== undefined && parsed.pull_request !== null;
    if (process.argv[2] === "issues" && isPr) process.exit(4);
    process.exit(0);
  ' "$tmp" "$kind" || rc=$?
  rm -f "$tmp"
  if [ "$rc" != "0" ]; then
    if [ "$rc" = "4" ]; then
      echo "link says issue but target is a pull request: $url"
    else
      echo "API answered 200 but not with parseable JSON for: $url"
    fi
    return 1
  fi
  return 0
}

# The extraction pattern lives here too so the test asserts the SAME pattern
# the guard uses. Full URL paths are captured — not just the repository root —
# so a dead file link (…/src/branch/main/NO_SUCH_FILE) fails its own fetch.
public_link_pattern() {
  local ns="$1"
  printf '%s' "https://forgejo\\.xtrape\\.com/${ns}/[A-Za-z0-9_./%?=&-]*[A-Za-z0-9_/-]"
}

# Normalization applied to each extracted URL before fetching:
# strip a #fragment (not sent on the wire), a trailing sentence dot, and a
# trailing .git (clone URLs answer as the repository page).
normalize_public_link() {
  local url="$1"
  url="${url%%#*}"
  url="${url%.}"
  url="${url%.git}"
  printf '%s' "$url"
}
