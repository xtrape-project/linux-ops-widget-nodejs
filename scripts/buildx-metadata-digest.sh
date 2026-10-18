#!/usr/bin/env bash
# Extract the image digest from a `docker buildx build --metadata-file` document
# and prove it is the layer we are allowed to compare against the registry.
#
# WHY THIS EXISTS
# ---------------
# The previous inline extraction was:
#
#     sed -n 's/.*"containerimage.digest":"\([^"]*\)".*/\1/p'
#
# which requires the value to follow the colon with no space.
#
# Scope of that defect, stated no wider than the evidence: on the pretty-printed
# output this runner's Buildx currently produces — `"containerimage.digest":
# "sha256:…"` — the pattern reads empty deterministically, reproduced directly
# on the host2 dind engine. It is NOT a defect that holds across every driver,
# version or formatter: a compact, space-free document would in fact match it.
#
# The extraction returning empty makes the caller's format check fail the job.
# That matches the five candidate builds of 2026-09-09 (tasks 7085/7089/7091/
# 7095/7097) directly: server-side job logs show all five built successfully,
# pushed nothing, and stopped on exactly that check. The five runs' own metadata
# files were not retained, so the link is established by the reproduction plus
# the identical failure point, and is closed by the real-repository metadata
# recorded for acceptance criterion 1.
#
# THE LAYER INVARIANT
# -------------------
# `imagetools inspect --format '{{json .Manifest.Digest}}'` returns the TOP-LEVEL
# descriptor of the coordinate. For a parity comparison to mean anything, the
# digest taken from build metadata must be that same layer — not the config
# digest, not a child manifest of an index.
#
# This script does not assume which layer `containerimage.digest` holds. It
# REFUSES to answer unless the metadata itself proves the layer, by carrying a
# `containerimage.descriptor` whose mediaType is an index or manifest media type
# and whose digest equals `containerimage.digest`.
#
# Consequence, stated deliberately: metadata WITHOUT a descriptor is rejected
# rather than trusted. Some environments produce that shape (a plain Docker
# Desktop `docker` driver does, and there `containerimage.digest` is the CONFIG
# digest — exactly the value that must never reach a parity check). Failing
# closed there is the point: the alternative is comparing two different layers
# and calling a mismatch a corruption.
#
# Usage:  buildx-metadata-digest.sh <metadata-file>
# Output: the verified digest on stdout.
# Exit:   0 on success; 1 with a reason on stderr otherwise.

set -euo pipefail

METADATA="${1:-}"
[ -n "$METADATA" ] || { echo "usage: buildx-metadata-digest.sh <metadata-file>" >&2; exit 1; }
[ -f "$METADATA" ] || { echo "buildx metadata file not found: $METADATA" >&2; exit 1; }

# Media types whose digest is the top-level descriptor of a coordinate. A config
# media type is deliberately absent: a config digest is never a valid parity
# subject.
_media_type_is_addressable() {
  case "$1" in
    application/vnd.oci.image.index.v1+json) return 0 ;;
    application/vnd.oci.image.manifest.v1+json) return 0 ;;
    application/vnd.docker.distribution.manifest.list.v2+json) return 0 ;;
    application/vnd.docker.distribution.manifest.v2+json) return 0 ;;
    *) return 1 ;;
  esac
}

# Top-level "containerimage.digest". Tolerant of whitespace around the colon;
# anchored to the two-space top-level indent so a same-named key nested inside
# another object cannot be picked up instead.
TOP_DIGEST="$(sed -n 's/^  "containerimage\.digest"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$METADATA" | head -n 1)"
if [ -z "$TOP_DIGEST" ]; then
  # Distinguish "the key is absent" from "this file is not the pretty-printed
  # shape this parser is anchored to". Top-level-indent anchoring is what keeps
  # a same-named key nested inside another object from being picked up; the
  # price is that a compact, single-line document is not parseable here. Say so
  # rather than reporting it as a missing key.
  if [ "$(wc -l < "$METADATA")" -le 1 ] && grep -q '"containerimage\.digest"' "$METADATA"; then
    echo "buildx metadata is not pretty-printed; this parser anchors on the top-level indent to avoid picking up a nested key of the same name, so it cannot read a compact document: $METADATA" >&2
    exit 1
  fi
  echo "buildx metadata has no top-level \"containerimage.digest\": $METADATA" >&2
  exit 1
fi

# The descriptor block, delimited by its own top-level indent.
DESC_BLOCK="$(sed -n '/^  "containerimage\.descriptor"[[:space:]]*:[[:space:]]*{/,/^  }/p' "$METADATA")"
[ -n "$DESC_BLOCK" ] || {
  echo "buildx metadata carries no \"containerimage.descriptor\"; the digest layer cannot be proven, refusing to guess: $METADATA" >&2
  exit 1; }

DESC_MEDIA="$(printf '%s\n' "$DESC_BLOCK" | sed -n 's/.*"mediaType"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
DESC_DIGEST="$(printf '%s\n' "$DESC_BLOCK" | sed -n 's/.*"digest"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"

[ -n "$DESC_MEDIA" ] || { echo "\"containerimage.descriptor\" has no mediaType: $METADATA" >&2; exit 1; }
[ -n "$DESC_DIGEST" ] || { echo "\"containerimage.descriptor\" has no digest: $METADATA" >&2; exit 1; }

_media_type_is_addressable "$DESC_MEDIA" || {
  echo "\"containerimage.descriptor\" mediaType is not an index/manifest media type: $DESC_MEDIA" >&2
  echo "refusing to use its digest as a parity subject" >&2
  exit 1; }

[ "$DESC_DIGEST" = "$TOP_DIGEST" ] || {
  echo "buildx metadata is internally inconsistent: containerimage.digest=$TOP_DIGEST descriptor.digest=$DESC_DIGEST" >&2
  exit 1; }

case "$TOP_DIGEST" in
  sha256:*) ;;
  *) echo "digest is not sha256-prefixed: $TOP_DIGEST" >&2; exit 1 ;;
esac
HEX="${TOP_DIGEST#sha256:}"
[ "${#HEX}" -eq 64 ] || { echo "digest is not 64 hex characters: $TOP_DIGEST" >&2; exit 1; }
case "$HEX" in
  *[!0-9a-f]*) echo "digest contains non-lowercase-hex characters: $TOP_DIGEST" >&2; exit 1 ;;
esac

printf '%s\n' "$TOP_DIGEST"
