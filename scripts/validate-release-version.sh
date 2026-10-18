#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
NUM='(0|[1-9][0-9]*)'
IDENT='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
# OCI tags cannot contain SemVer build metadata (`+...`), so release versions
# intentionally support the strict core/prerelease subset only.
SEMVER_RE="^${NUM}\\.${NUM}\\.${NUM}(-${IDENT}(\\.${IDENT})*)?$"
[[ "$VERSION" =~ $SEMVER_RE ]] || {
  echo "release version is not strict OCI-compatible SemVer: $VERSION" >&2
  exit 1
}
