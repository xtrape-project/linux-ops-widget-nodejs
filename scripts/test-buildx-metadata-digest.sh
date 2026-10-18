#!/usr/bin/env bash
# Self-test for buildx-metadata-digest.sh.
#
# Two of the fixtures are VERBATIM captures, not hand-written approximations:
#   - runner_shape: `docker buildx build --platform linux/amd64 --load
#     --metadata-file` inside forgejo-runner-dind-engine on host2 (the actual
#     build environment), 2026-09-10.
#   - desktop_shape: the same command on a Docker Desktop host, 2026-09-10.
# Both ran on a `docker` driver and produced DIFFERENT shapes — which is why the
# script proves the layer instead of assuming it from the driver.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SUT="$HERE/buildx-metadata-digest.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok   %-34s → %s\n' "$1" "$2"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %-34s → %s\n' "$1" "$2"; }

# expect_ok <name> <fixture-file> <expected-digest>
expect_ok() {
  local name="$1" f="$2" want="$3" got rc
  got="$("$SUT" "$f" 2>/dev/null)"; rc=$?
  if [ $rc -eq 0 ] && [ "$got" = "$want" ]; then ok "$name" "accepted, correct digest"
  else bad "$name" "rc=$rc got='$got' want='$want'"; fi
}
# expect_fail <name> <fixture-file> <substring-of-reason>
expect_fail() {
  local name="$1" f="$2" needle="$3" err rc
  err="$("$SUT" "$f" 2>&1 >/dev/null)"; rc=$?
  if [ $rc -ne 0 ] && printf '%s' "$err" | grep -qF "$needle"; then ok "$name" "refused ($needle)"
  else bad "$name" "rc=$rc err='$err' expected to contain '$needle'"; fi
}

D_INDEX="sha256:55e0d6b557401b428a5016b4ab0d1bec06c1318fadab0aac1b55b2638c71e3da"
D_CONFIG="sha256:0bb85a557de57b110cb2bd683838211101bd5a5fe2cedf5c7970ab369729f8b5"

# --- 1. VERBATIM runner capture: descriptor present, index media type ---------
cat > "$TMP/runner_shape.json" <<JSON
{
  "buildx.build.ref": "default/default/qjj1klnigcxwzu3becseqrojf",
  "containerimage.descriptor": {
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "digest": "$D_INDEX",
    "size": 855
  },
  "containerimage.digest": "$D_INDEX",
  "image.name": "docker.io/library/mdprobe:local"
}
JSON
expect_ok "runner_shape (verbatim)" "$TMP/runner_shape.json" "$D_INDEX"

# --- 2. VERBATIM desktop capture: no descriptor, digest == CONFIG digest ------
# The dangerous shape. Accepting it would feed a config digest into a parity
# check against a top-level descriptor.
cat > "$TMP/desktop_shape.json" <<JSON
{
  "buildx.build.ref": "desktop-linux/desktop-linux/brovfitelr4pvc24jbrgz6i9s",
  "containerimage.config.digest": "$D_CONFIG",
  "containerimage.digest": "$D_CONFIG",
  "image.name": "docker.io/library/mdtest:probe"
}
JSON
expect_fail "desktop_shape (verbatim)" "$TMP/desktop_shape.json" "carries no \"containerimage.descriptor\""

# --- 3. THE REGRESSION: the exact formatting the old sed could not read -------
# Guards the actual defect. Pretty-printed, space after the colon.
grep -q '"containerimage.digest": "' "$TMP/runner_shape.json" \
  && ok "regression: space after colon" "fixture really has the failing shape" \
  || bad "regression: space after colon" "fixture does not reproduce the defect"
old_sed="$(sed -n 's/.*"containerimage.digest":"\([^"]*\)".*/\1/p' "$TMP/runner_shape.json" | head -n1)"
[ -z "$old_sed" ] \
  && ok "regression: old pattern is blind" "old sed yields empty, as in tasks 7085-7097" \
  || bad "regression: old pattern is blind" "old sed unexpectedly returned '$old_sed'"

# --- 4. Compact JSON must FAIL CLOSED ----------------------------------------
# Note: a compact document is exactly the shape the OLD pattern could read. The
# parser trades that away for top-level-indent anchoring (case 16), so it must
# refuse with an honest reason rather than silently return nothing.
printf '{"containerimage.descriptor":{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"%s","size":855},"containerimage.digest":"%s"}\n' "$D_INDEX" "$D_INDEX" > "$TMP/compact.json"
expect_fail "compact json: honest reason" "$TMP/compact.json" "is not pretty-printed"

# --- 5. Layer traps ----------------------------------------------------------
cat > "$TMP/config_media.json" <<JSON
{
  "containerimage.descriptor": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "$D_CONFIG",
    "size": 855
  },
  "containerimage.digest": "$D_CONFIG"
}
JSON
expect_fail "config mediaType refused" "$TMP/config_media.json" "not an index/manifest media type"

cat > "$TMP/mismatch.json" <<JSON
{
  "containerimage.descriptor": {
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "digest": "$D_INDEX",
    "size": 855
  },
  "containerimage.digest": "$D_CONFIG"
}
JSON
expect_fail "descriptor/digest mismatch" "$TMP/mismatch.json" "internally inconsistent"

# --- 6. Docker (non-OCI) media types are accepted ----------------------------
D_DOCKER="sha256:aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899990"
D_DOCKER="${D_DOCKER:0:71}"
cat > "$TMP/docker_list.json" <<JSON
{
  "containerimage.descriptor": {
    "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
    "digest": "$D_DOCKER",
    "size": 855
  },
  "containerimage.digest": "$D_DOCKER"
}
JSON
expect_ok "docker manifest.list accepted" "$TMP/docker_list.json" "$D_DOCKER"

# --- 6b. The remaining two whitelist media types -----------------------------
D_OCI_MAN="sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
cat > "$TMP/oci_manifest.json" <<JSON
{
  "containerimage.descriptor": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "$D_OCI_MAN",
    "size": 855
  },
  "containerimage.digest": "$D_OCI_MAN"
}
JSON
expect_ok "oci manifest accepted" "$TMP/oci_manifest.json" "$D_OCI_MAN"

D_DOCKER_MAN="sha256:ffffeeeeddddccccbbbbaaaa00009999888877776666555544443333222211110"
D_DOCKER_MAN="${D_DOCKER_MAN:0:71}"
cat > "$TMP/docker_manifest.json" <<JSON
{
  "containerimage.descriptor": {
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "digest": "$D_DOCKER_MAN",
    "size": 855
  },
  "containerimage.digest": "$D_DOCKER_MAN"
}
JSON
expect_ok "docker manifest v2 accepted" "$TMP/docker_manifest.json" "$D_DOCKER_MAN"

# --- 7. Malformed digests ----------------------------------------------------
mk_desc() {  # mk_desc <file> <digest>
  cat > "$1" <<JSON
{
  "containerimage.descriptor": {
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "digest": "$2",
    "size": 855
  },
  "containerimage.digest": "$2"
}
JSON
}
mk_desc "$TMP/short.json" "sha256:abc123"
expect_fail "digest too short" "$TMP/short.json" "not 64 hex characters"
mk_desc "$TMP/upper.json" "sha256:AAAABBBBCCCCDDDDEEEEFFFF00001111222233334444555566667777888899AA"
expect_fail "uppercase hex refused" "$TMP/upper.json" "non-lowercase-hex"
mk_desc "$TMP/sha512.json" "sha512:55e0d6b557401b428a5016b4ab0d1bec06c1318fadab0aac1b55b2638c71e3da"
expect_fail "non-sha256 algorithm" "$TMP/sha512.json" "not sha256-prefixed"

# --- 8. Missing pieces -------------------------------------------------------
cat > "$TMP/nodigest.json" <<JSON
{
  "containerimage.descriptor": {
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "size": 855
  },
  "containerimage.digest": "$D_INDEX"
}
JSON
expect_fail "descriptor without digest" "$TMP/nodigest.json" "has no digest"

cat > "$TMP/nomedia.json" <<JSON
{
  "containerimage.descriptor": {
    "digest": "$D_INDEX",
    "size": 855
  },
  "containerimage.digest": "$D_INDEX"
}
JSON
expect_fail "descriptor without mediaType" "$TMP/nomedia.json" "has no mediaType"

echo '{}' > "$TMP/empty.json"
expect_fail "empty metadata" "$TMP/empty.json" "no top-level"

expect_fail "missing file" "$TMP/does-not-exist.json" "not found"

# --- 9. A nested same-named key must not be mistaken for the top-level one ----
cat > "$TMP/nested_decoy.json" <<JSON
{
  "buildx.build.provenance": {
    "someNested": {
      "containerimage.digest": "$D_CONFIG"
    }
  },
  "containerimage.descriptor": {
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "digest": "$D_INDEX",
    "size": 855
  },
  "containerimage.digest": "$D_INDEX"
}
JSON
expect_ok "nested decoy key ignored" "$TMP/nested_decoy.json" "$D_INDEX"

echo "buildx-metadata-digest self-test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
