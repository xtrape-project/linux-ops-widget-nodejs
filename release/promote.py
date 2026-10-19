"""Same-public-repository promotion of a reviewed 0.8.7 manifest; no build."""
import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MEDIA = ('application/vnd.oci.image.manifest.v1+json',
         'application/vnd.docker.distribution.manifest.v2+json')
INDEX = 'application/vnd.oci.image.index.v1+json'
REPOS = {'xtrape-platform-ce', 'xtrape-panel-ce', 'xtrape-exposure',
         'linux-ops-widget-nodejs', 'forgejo-ops-widget-nodejs'}

class Refusal(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

class Registry:
    def __init__(self, repository):
        self.repository = repository
        self.opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))

    def request(self, path, bearer=None, data=None, media=None, basic=None):
        headers = {'Host': 'forgejo.xtrape.com', 'User-Agent': 'curl/8.0',
                   'Accept': ', '.join((*MEDIA, INDEX))}
        if bearer:
            headers['Authorization'] = 'Bearer ' + bearer
        if basic:
            headers['Authorization'] = 'Basic ' + basic
        if media:
            headers['Content-Type'] = media
        # Existing runner-only trusted LAN endpoint. Never follow redirects/proxies.
        req = urllib.request.Request('http://forgejo.docker' + path, headers=headers,
                                     data=data, method='PUT' if data is not None else 'GET')
        try:
            response = self.opener.open(req, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise Refusal('response too large')
            return response.status, raw

    def token(self, write=False):
        basic = None
        if write:
            user, secret = os.environ.get('REGISTRY_USER'), os.environ.get('REGISTRY_TOKEN')
            if not user or not secret:
                raise Refusal('missing CI registry credential')
            basic = base64.b64encode((user + ':' + secret).encode()).decode()
        query = urllib.parse.urlencode({'service': 'container_registry',
                    'scope': 'repository:' + self.repository + (':pull,push' if write else ':pull')})
        status, raw = self.request('/v2/token?' + query, basic=basic)
        doc = json.loads(raw)
        token = doc.get('token') or doc.get('access_token')
        if status != 200 or not isinstance(token, str) or not token:
            raise Refusal('registry authentication refused')
        return token

    def manifest(self, ref, token):
        status, raw = self.request('/v2/' + self.repository + '/manifests/' + ref, token)
        if status == 200:
            return raw
        errors = json.loads(raw).get('errors')
        if status == 404 and isinstance(errors, list) and errors and all(
                isinstance(e, dict) and e.get('code') == 'MANIFEST_UNKNOWN' for e in errors):
            return None
        raise Refusal('manifest read did not prove existence or absence')

    def blob(self, digest, token):
        status, raw = self.request('/v2/' + self.repository + '/blobs/' + digest, token)
        if status != 200 or sha(raw) != digest:
            raise Refusal('config blob integrity failure')
        return raw

    def put(self, tag, raw, media, token):
        status, _ = self.request('/v2/' + self.repository + '/manifests/' + tag,
                                 token, raw, media)
        if status != 201:
            raise Refusal('manifest publication not confirmed; read back before retry')

def sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()

def validate_image(manifest, registry, token, source, repository):
    if manifest.get('schemaVersion') != 2 or manifest.get('mediaType') not in MEDIA:
        raise Refusal('unsupported image manifest')
    config_descriptor = manifest.get('config', {})
    config_digest = config_descriptor.get('digest', '')
    config_size = config_descriptor.get('size')
    if type(config_size) is not int or config_size <= 0:
        raise Refusal('invalid config size')
    if not re.fullmatch('sha256:[0-9a-f]{64}', config_digest):
        raise Refusal('invalid config digest')
    raw = registry.blob(config_digest, token)
    if sha(raw) != config_digest or len(raw) != config_size:
        raise Refusal('config blob integrity failure')
    labels = json.loads(raw).get('config', {}).get('Labels', {})
    if (labels.get('org.opencontainers.image.revision') != source or
        labels.get('org.opencontainers.image.version') != '0.8.7' or
        labels.get('org.opencontainers.image.source') != 'https://forgejo.xtrape.com/' + repository):
        raise Refusal('source/version labels mismatch')


def validate_candidate(manifest, registry, token, source, repository):
    if manifest.get('schemaVersion') != 2:
        raise Refusal('unsupported manifest schema')
    if manifest.get('mediaType') in MEDIA:
        return validate_image(manifest, registry, token, source, repository)
    if manifest.get('mediaType') != INDEX:
        raise Refusal('unsupported manifest; no conversion allowed')
    # Accepted buildx shape: one linux/amd64 image and its provenance manifest.
    # Preserve the whole index bytes and both children, never flatten or rebuild.
    children = manifest.get('manifests')
    if not isinstance(children, list) or len(children) != 2:
        raise Refusal('unsupported index shape')
    images = [d for d in children if d.get('platform') == {'os': 'linux', 'architecture': 'amd64'}]
    attestations = [d for d in children if d.get('platform') == {'os': 'unknown', 'architecture': 'unknown'}]
    if len(images) != 1 or len(attestations) != 1:
        raise Refusal('unsupported index platforms')
    image, attestation = images[0], attestations[0]
    annotations = attestation.get('annotations', {})
    if (annotations.get('vnd.docker.reference.type') != 'attestation-manifest' or
        annotations.get('vnd.docker.reference.digest') != image.get('digest')):
        raise Refusal('attestation image binding mismatch')
    for descriptor in children:
        digest = descriptor.get('digest', '')
        if (descriptor.get('mediaType') != MEDIA[0] or
            not re.fullmatch('sha256:[0-9a-f]{64}', digest) or
            type(descriptor.get('size')) is not int or descriptor['size'] <= 0):
            raise Refusal('invalid index descriptor')
        raw = registry.manifest(digest, token)
        if raw is None or sha(raw) != digest or len(raw) != descriptor['size']:
            raise Refusal('index child integrity failure')
        child = json.loads(raw)
        if child.get('schemaVersion') != 2 or child.get('mediaType') != descriptor['mediaType']:
            raise Refusal('index child media mismatch')
        if descriptor is image:
            validate_image(child, registry, token, source, repository)
        else:
            # Validate referenced proof/config bytes without treating provenance
            # as a runnable image or requiring product labels on its config.
            blobs = [child.get('config', {})] + child.get('layers', [])
            if len(blobs) < 2:
                raise Refusal('empty attestation')
            for blob in blobs:
                digest = blob.get('digest', '')
                if not re.fullmatch('sha256:[0-9a-f]{64}', digest) or type(blob.get('size')) is not int:
                    raise Refusal('invalid attestation blob descriptor')
                content = registry.blob(digest, token)
                if sha(content) != digest or len(content) != blob['size']:
                    raise Refusal('attestation blob integrity failure')


def promote(record, repository, registry):
    if repository != 'xtrape-project/' + record['repo'] or record['repo'] not in REPOS:
        raise Refusal('repository mismatch')
    source, digest = record['public_source_sha'], record['public_digest']
    if not re.fullmatch('[0-9a-f]{40}', source) or not re.fullmatch('sha256:[0-9a-f]{64}', digest):
        raise Refusal('invalid fixed candidate identity')
    run = record['run_id']
    if type(run) is not int or run <= 0:
        raise Refusal('invalid fixed run')
    anonymous = registry.token()
    candidate = 'candidate-' + source + '-' + str(run) + '-attempt-1'
    raw = registry.manifest(candidate, anonymous)
    if raw is None or sha(raw) != digest or registry.manifest(digest, anonymous) != raw:
        raise Refusal('accepted candidate digest mismatch')
    manifest = json.loads(raw)
    media = manifest.get('mediaType')
    validate_candidate(manifest, registry, anonymous, source, repository)
    targets = ['0.8.7', 'sha-' + source]
    for tag in targets:
        old = registry.manifest(tag, anonymous)
        if old is not None and sha(old) != digest:
            raise Refusal('immutable target conflict')
    writer = registry.token(write=True)
    for tag in targets:
        old = registry.manifest(tag, writer)
        if old is None:
            # Same repository already owns every referenced blob. PUT exact raw
            # manifest bytes; no Docker conversion, layer upload, rebuild or copy.
            registry.put(tag, raw, media, writer)
        elif sha(old) != digest:
            raise Refusal('immutable target conflict on recheck')
        if registry.manifest(tag, anonymous) != raw:
            raise Refusal('anonymous exact-byte readback mismatch')
        print('PUBLIC_RELEASE=' + repository + ':' + tag + '@' + digest)

if __name__ == '__main__':
    try:
        record = json.loads(Path('release/accepted-0.8.7.json').read_text())
        repository = os.environ['GITHUB_REPOSITORY']
        promote(record, repository, Registry(repository))
    except Exception as error:
        # Do not print raw HTTP error bodies, headers or credentials.
        print('public release refused: ' + (str(error) if isinstance(error, Refusal) else type(error).__name__))
        raise SystemExit(1)
