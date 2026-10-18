#!/usr/bin/env bash
#
# Publish the reviewed content of this repository as a snapshot commit on the
# canonical public repository.
#
# Why a snapshot instead of a mirror: this repository's Git history contains
# pre-publication drafting commits whose author metadata is not publishable.
# The public repository therefore carries its OWN history, beginning at the
# reviewed baseline, and gains exactly one commit per merge here. It is
# append-only — this script never force-pushes and never rewrites public
# history.
#
# Review happens on the pull request in this repository. Publishing is the
# mechanical step that follows a merge, not a second review gate.
#
# This script is itself published, so it travels to the public repository
# along with its workflow. It must therefore refuse to run anywhere except
# the source repository — see "source identity" below. Never assume the
# published copy is inert because the target happens to have Actions
# disabled or no token configured.
#
# Required environment:
#   PUBLIC_REPO_URL   https URL of the canonical public repository
#   SOURCE_REPO       owner/name of the repository allowed to publish
#   PUBLISH_TOKEN     token with write access to the public repository ONLY
# Optional:
#   PUBLIC_NAMESPACE     Forgejo namespace allowed in published links
#                        (default: xtrape-project)
#   EXTRA_DENY_PATTERNS  newline-separated extra egrep patterns for the guard
#                        (kept out of this file so the denylist itself is not
#                        published)
#   DRY_RUN=1            do everything except the push

set -euo pipefail

: "${PUBLIC_REPO_URL:?PUBLIC_REPO_URL is required}"
: "${SOURCE_REPO:?SOURCE_REPO is required}"
PUBLIC_NAMESPACE="${PUBLIC_NAMESPACE:-xtrape-project}"
if [ "${DRY_RUN:-0}" != "1" ]; then
  : "${PUBLISH_TOKEN:?PUBLISH_TOKEN is required unless DRY_RUN=1}"
fi

# --- Source identity -------------------------------------------------------
# Publication flows in exactly one direction. A copy of this script running
# anywhere other than the source repository must stop, whether it was reached
# through the published workflow, a fork, or a mirror.
if [ -n "${GITHUB_REPOSITORY:-}" ] && [ "$GITHUB_REPOSITORY" != "$SOURCE_REPO" ]; then
  echo "publish: running in $GITHUB_REPOSITORY, not the source repository $SOURCE_REPO; refusing" >&2
  exit 1
fi

SRC_DIR="$(git rev-parse --show-toplevel)"
SRC_SHA="$(git -C "$SRC_DIR" rev-parse HEAD)"
SRC_SHORT="$(git -C "$SRC_DIR" rev-parse --short HEAD)"

# The published commit message is built ONLY from commit hashes. The source
# commit subject is deliberately not carried over: the guard scans the tree,
# so a private URL, address, or hostname written in a source commit title
# would otherwise reach public history unscanned. Hashes are inert, and the
# Source-Snapshot trailer already gives full traceability to anyone with
# access to the source repository.
case "$SRC_SHA" in
  *[!0-9a-f]* | "") echo "publish: unexpected source commit id" >&2; exit 1 ;;
esac

WORK="$(mktemp -d)"
STAGE="$WORK/stage"
PUBLIC="$WORK/public"
mkdir -p "$STAGE"
trap 'rm -rf "$WORK"' EXIT

# The tree exactly as it would be published.
git -C "$SRC_DIR" archive HEAD | tar -x -C "$STAGE"

# ---------------------------------------------------------------------------
# Guard: scan for anything that must not become public.
#
# Findings are WARNINGS with a confirmation obligation, not an unconditional
# refusal (owner decision 2026-09-05). Publication is refused while findings
# exist UNLESS the operator acknowledges the EXACT findings by fingerprint via
# PUBLISH_GUARD_ACK: a real leak is never published silently, while a reviewed
# false positive (a test fixture, not a real private value) can be forced
# through deliberately.
#
# The rules are generic on purpose. A denylist of real names or addresses would
# itself be published by this very script, so identity leaks are caught by
# shape (any non-project email domain) rather than by enumeration. Findings are
# accumulated (the offending lines, path-relative) so the fingerprint is bound
# to the actual content.
# ---------------------------------------------------------------------------
FINDINGS="$WORK/findings"
: > "$FINDINGS"
# report() accumulates a finding line into $FINDINGS (path-relative content, so
# the fingerprint computed from it is stable across runs and does not leak the
# local temp dir). It no longer forces an unconditional refusal — see the
# disposition block below.
report() { printf '%s\n' "$1" >> "$FINDINGS"; }

# Any email address outside the project domain. The documentation-only
# exceptions are anchored to whole domains; a prefix match would let a
# lookalike domain that merely STARTS with the exempt name through. (No
# literal sample address appears here — this file is published, and the
# guard would rightly flag its own comment.)
#
# Every OCCURRENCE is recorded as path:line:address (review 3122 P1): an
# acknowledgement of a known false-positive address must stop matching the
# moment that same address appears at another path or line, so the finding
# — and therefore the fingerprint — is bound to location, not to the set of
# distinct addresses. `-o` keeps the finding to the address itself rather than
# the whole surrounding line.
emails="$(grep -rEon '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$STAGE" \
     | grep -vE '@xtrape\.com$' \
     | grep -vE '@(example\.(com|org|net)|localhost)$' \
     | sed "s|${STAGE}/||g" | LC_ALL=C sort || true)"
if [ -n "$emails" ]; then
  report "== email addresses outside @xtrape.com (path:line:address) =="
  printf '%s\n' "$emails" >> "$FINDINGS"
fi

# Forgejo links are checked against an ALLOWLIST of public namespaces rather
# than a denylist of internal ones: the host also carries infra, qluna,
# witbill and any organisation added later, and a denylist silently misses
# every namespace nobody remembered to add.
FORGEJO_HOST='forgejo\.xtrape\.com'
BAD_NS="$(grep -rEoh "${FORGEJO_HOST}/[A-Za-z0-9_.-]+" "$STAGE" \
            | sed 's|.*/||' | sort -u | grep -vxF "$PUBLIC_NAMESPACE" || true)"
if [ -n "$BAD_NS" ]; then
  report "== Forgejo links outside the public namespace '$PUBLIC_NAMESPACE' =="
  while IFS= read -r ns; do
    [ -z "$ns" ] && continue
    # Strip the ephemeral stage path so the finding (and thus the fingerprint)
    # is stable across runs and does not itself leak the local temp directory.
    grep -rEn "${FORGEJO_HOST}/${ns}([^A-Za-z0-9_.-]|$)" "$STAGE" | sed "s|${STAGE}/||g" | LC_ALL=C sort >> "$FINDINGS" || true
  done <<< "$BAD_NS"
fi

# Private address literals (full dotted quads only, so dependency version
# strings such as 10.0.2 do not false-positive) and internal hostnames.
OCTET='[0-9]{1,3}'
ips="$(grep -rEn "\b(10\.${OCTET}\.${OCTET}\.${OCTET}|192\.168\.${OCTET}\.${OCTET}|172\.(1[6-9]|2[0-9]|3[01])\.${OCTET}\.${OCTET})\b|\b[a-z0-9-]+\.docker\b" "$STAGE" | sed "s|${STAGE}/||g" | LC_ALL=C sort || true)"
if [ -n "$ips" ]; then
  report "== private network addresses or internal hostnames =="
  printf '%s\n' "$ips" >> "$FINDINGS"
fi

# The deny patterns come from a SECRET and must never be rendered: the
# findings are echoed to the workflow log, so naming the pattern here would
# open the disclosure path the secret exists to close (review 3122 P1). A
# finding names the rule by its 1-based position in EXTRA_DENY_PATTERNS —
# stable for the fingerprint, meaningless to a reader without the secret —
# and carries only the matched path:line:content, which is what the reviewer
# needs and what binds the acknowledgement to the actual occurrence.
if [ -n "${EXTRA_DENY_PATTERNS:-}" ]; then
  n=0
  while IFS= read -r pat; do
    n=$((n+1))
    [ -z "$pat" ] && continue
    m="$(grep -rEn "$pat" "$STAGE" | sed "s|${STAGE}/||g" | LC_ALL=C sort || true)"
    if [ -n "$m" ]; then
      report "== matched operator-supplied deny pattern #${n} =="
      printf '%s\n' "$m" >> "$FINDINGS"
    fi
  done <<< "$EXTRA_DENY_PATTERNS"
fi

# Links into the public namespace passed the allowlist above, but the
# allowlist cannot see whether the target actually resolves for an anonymous
# reader, or whether a link that claims to be an issue in fact points at a
# pull request. Verification logic lives in scripts/verify-public-link.sh so
# it is unit-tested with a stubbed curl (scripts/test-verify-public-link.sh);
# the pattern and normalization used here are the SAME functions under test.
#
# DELIBERATELY NO CREDENTIALS on these requests — a token would make private
# targets answer 200 and turn this whole check into a false green. Full URL
# paths are verified, not just repository roots, so a dead file link fails
# its own fetch. Fail-closed throughout.
. "$SRC_DIR/scripts/verify-public-link.sh"
PUBLIC_LINKS="$(grep -rEoh "$(public_link_pattern "$PUBLIC_NAMESPACE")" "$STAGE" | sort -u || true)"
if [ -n "$PUBLIC_LINKS" ]; then
  while IFS= read -r raw; do
    [ -z "$raw" ] && continue
    url="$(normalize_public_link "$raw")"
    if ! msg="$(verify_public_link "$url" "$PUBLIC_NAMESPACE")"; then
      report "$msg"
    fi
  done <<< "$PUBLIC_LINKS"
fi

if [ ! -s "$FINDINGS" ]; then
  echo "publish guard: clean"
else
  echo "PUBLISH GUARD: content that is normally kept out of public history (review each):" >&2
  cat "$FINDINGS" >&2
  # The acknowledgement is a fingerprint of the EXACT findings — every entry
  # above is path:line-bound and deterministically ordered — so a new or
  # changed leak, INCLUDING an already-acknowledged value reappearing at a new
  # location, yields a new fingerprint and re-refuses. A stale ack cannot wave
  # a different leak through (regression: scripts/test-publish-guard.sh).
  if command -v sha256sum >/dev/null 2>&1; then
    fp="$(sha256sum "$FINDINGS" | awk '{print $1}')"
  else
    fp="$(shasum -a 256 "$FINDINGS" | awk '{print $1}')"
  fi
  if [ "${PUBLISH_GUARD_ACK:-}" = "$fp" ]; then
    echo "PUBLISH GUARD: findings acknowledged (PUBLISH_GUARD_ACK matches ${fp}); publishing anyway." >&2
  else
    echo "PUBLISH GUARD: refusing to publish ${SRC_SHORT} without acknowledgement." >&2
    echo "Review every finding above. If each is a false positive (e.g. a test fixture, not a real" >&2
    echo "private value), publish anyway by re-running with:" >&2
    echo "  PUBLISH_GUARD_ACK=${fp}" >&2
    echo "The acknowledgement is bound to these exact findings; any change to them needs a new one." >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Sync the snapshot onto the public repository as one append-only commit.
# ---------------------------------------------------------------------------
if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "dry run: would publish $SRC_SHORT to $PUBLIC_REPO_URL"
  exit 0
fi

AUTH_URL="${PUBLIC_REPO_URL/https:\/\//https://x-access-token:${PUBLISH_TOKEN}@}"
git clone --quiet --depth 1 "$AUTH_URL" "$PUBLIC"

cd "$PUBLIC"
# Replace the tracked tree wholesale so deletions propagate.
git rm -rq --ignore-unmatch .
tar -c -C "$STAGE" . | tar -x -C "$PUBLIC"
git add -A

if git diff --cached --quiet; then
  echo "public repository already matches $SRC_SHORT; nothing to publish"
  exit 0
fi

git -c user.name="The Xtrape Project" \
    -c user.email="opensource@xtrape.com" \
    commit --quiet -m "Publish reviewed snapshot ${SRC_SHORT}

Source-Snapshot: ${SRC_SHA}"

git push --quiet origin HEAD:main
echo "published ${SRC_SHORT} to ${PUBLIC_REPO_URL}"
