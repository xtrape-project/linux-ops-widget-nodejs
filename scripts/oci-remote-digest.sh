#!/usr/bin/env bash
# Read the manifest digest an OCI coordinate currently holds, fail-closed.
#
#   oci-remote-digest.sh <image-ref>
#
# stdout + exit 0  the digest (sha256:…) the coordinate holds
# empty  + exit 0  the registry POSITIVELY said the tag/manifest does not exist
# exit 1           anything else: unauthorized/forbidden, 5xx, network, TLS,
#                  timeouts, unparseable output — "cannot read" is never "absent"
#
# The immutable-coordinate gate (publish-oci.yml) relies on this distinction:
# pushing over a coordinate whose content could not be read would let a
# version be re-pointed without anyone noticing (review 3323).
set -euo pipefail
image="${1:?image ref}"
err="$(mktemp)"; trap 'rm -f "$err"' EXIT
if out="$(docker buildx imagetools inspect "$image" --format '{{json .Manifest.Digest}}' 2>"$err")"; then
  digest="$(printf '%s' "$out" | tr -d '"[:space:]')"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "oci-remote-digest: unparseable digest for $image: $out" >&2; exit 1; }
  printf '%s' "$digest"; exit 0
fi
# Any authority / transport signal makes the answer unreadable, even when the
# same message also contains a not-found phrase.
# Classify on the error text with the coordinate itself removed. The error echoes
# the image reference (and the manifest URL, which carries the tag), and a
# candidate tag embeds a 40-hex source SHA: a digit run such as "...d638574"
# would otherwise match a status-code pattern and turn a positive "not found"
# into "cannot read" — the gate then refuses EVERY first push of a candidate.
# Status codes must also stand as whole tokens, never as digits inside a word.
# Mask the tag ONLY where it appears as part of the coordinate (the echoed ref,
# the manifest URL path): a tag may legally be "503", and a global replace would
# erase a real "503 Service Unavailable" and let "not found" read as absent.
msg="$(cat "$err")"
tag="${image##*:}"
msg="${msg//"$image"/<ref>}"
[ -n "$tag" ] && [ "$tag" != "$image" ] && msg="${msg//"/manifests/$tag"//manifests/<tag>}"
if printf '%s' "$msg" | grep -Eqi 'unauthorized|forbidden|denied|authentication|(^|[^[:alnum:]])(401|403|429|5[0-9][0-9])([^[:alnum:]]|$)|timeout|timed out|connection|refused|unreachable|eof|tls|certificate|no such host|temporary failure'; then
  echo "oci-remote-digest: cannot read $image (not treated as absent):" >&2; cat "$err" >&2; exit 1
fi
if printf '%s' "$msg" | grep -Eqi 'not found|manifest unknown|no such manifest|manifest_unknown|name_unknown'; then
  exit 0
fi
echo "oci-remote-digest: unrecognised inspect failure for $image:" >&2; cat "$err" >&2; exit 1
