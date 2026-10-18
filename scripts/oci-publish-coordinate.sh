#!/usr/bin/env bash
# Publish ONE immutable coordinate: push only when the registry positively
# reports it absent; accept when it already holds exactly the candidate;
# refuse when it holds anything else; stop when it cannot be read.
#
#   oci-publish-coordinate.sh <image-ref> <candidate-digest>
#
# exit 0  pushed, or already identical (idempotent re-run)
# exit 1  coordinate holds different content, or could not be read
set -euo pipefail
image="${1:?image ref}"; candidate="${2:?candidate digest}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "$candidate" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "oci-publish-coordinate: candidate digest is not a sha256 digest: $candidate" >&2; exit 1; }
existing="$("$here/oci-remote-digest.sh" "$image")" || exit 1
if [ -z "$existing" ]; then
  docker push "$image"
  echo "pushed $image"
elif [ "$existing" = "$candidate" ]; then
  echo "already published with identical content: $image@$existing"
else
  echo "immutable coordinate already contains different content: $image@$existing (candidate $candidate)" >&2
  exit 1
fi
