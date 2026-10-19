"""Read-only authentication diagnostics. Never print response bodies or credentials."""
import base64
import json
import http.client
import os
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(path, authorization):
    # Existing trusted runner LAN plane; no external redirect or TLS bypass.
    req = urllib.request.Request(
        'http://forgejo.docker' + path,
        headers={'Authorization': authorization, 'Host': 'forgejo.xtrape.com',
                 'User-Agent': 'curl/8.0'},
    )
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    try:
        response = opener.open(req, timeout=20)
    except urllib.error.HTTPError as exc:
        response = exc
    except (OSError, urllib.error.URLError, ValueError, http.client.HTTPException):
        return {'status': 'transport_error'}, {}
    with response:
        raw = response.read(1048576)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        return {'status': response.code}, data


def granted_actions(token):
    try:
        part = token.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
        return sorted({a for entry in claims.get('access', [])
                       if entry.get('type') == 'repository'
                       and entry.get('name') == 'xtrape-project/linux-ops-widget-nodejs'
                       for a in entry.get('actions', []) if a in ('pull', 'push')})
    except (ValueError, IndexError, TypeError, AttributeError):
        return []


def diagnose(user, secret, fetch=request):
    result = {'user_present': bool(user), 'token_present': bool(secret),
              'user_has_outer_whitespace': user != user.strip(),
              'token_has_outer_whitespace': secret != secret.strip()}
    if not user or not secret:
        return result
    basic = 'Basic ' + base64.b64encode((user + ':' + secret).encode()).decode()
    status, data = fetch('/api/v1/user', 'token ' + secret)
    result['identity_api'] = status
    if status['status'] == 200:
        result['configured_user_matches_token_owner'] = data.get('login', '').casefold() == user.casefold()
    for label, scope in [('login', ''), ('target', 'repository:xtrape-project/linux-ops-widget-nodejs:pull,push')]:
        query = urllib.parse.urlencode({'service': 'container_registry', 'scope': scope})
        status, data = fetch('/v2/token?' + query, basic)
        result[label + '_token_endpoint'] = status
        token = data.get('token') or data.get('access_token')
        if status['status'] == 200 and isinstance(token, str) and token:
            result[label + '_token_issued'] = True
            result[label + '_target_actions'] = granted_actions(token)
            probe, _ = fetch('/v2/', 'Bearer ' + token)
            result[label + '_registry_probe'] = probe
    return result


if __name__ == '__main__':
    print(json.dumps(diagnose(os.environ.get('REGISTRY_USER', ''),
                              os.environ.get('REGISTRY_TOKEN', '')), sort_keys=True))
