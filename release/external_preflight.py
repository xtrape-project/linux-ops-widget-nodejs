"""Read-only fixed-target preflight; no response body or credential is logged."""
import json
import errno
import os
import socket
import ssl
import urllib.error
import urllib.request

REPO = "linux-ops-widget-nodejs"
TARGETS = {
    "github": ("https://api.github.com/repos/xtrape-project/" + REPO, "GH_PUBLISH_TOKEN", "Authorization", "Bearer "),
    "gitlab": ("https://gitlab.com/api/v4/projects/xtrape-project%2F" + REPO, "GITLAB_PUBLISH_TOKEN", "PRIVATE-TOKEN", ""),
    "codeberg": ("https://codeberg.org/api/v1/repos/xtrape-project/" + REPO, "CODEBERG_PUBLISH_TOKEN", "Authorization", "token "),
    "gitee": ("https://gitee.com/api/v5/repos/xtrape-project/" + REPO, "GITEE_PUBLISH_TOKEN", "Authorization", "Bearer "),
}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def classify(code, raw, platform):
    if 300 <= code < 400:
        return "REDIRECT_REFUSED"
    if code == 404:
        return "NOT_FOUND_OR_NOT_VISIBLE"  # never authority to create/overwrite
    if code in (401, 403):
        return "TARGET_ACCESS_REJECTED"
    if code == 429:
        return "RATE_LIMITED"
    if code != 200:
        return "HTTP_FAILURE"
    try:
        data = json.loads(raw)
        field = "path_with_namespace" if platform == "gitlab" else "full_name"
        if not isinstance(data, dict) or data.get(field) != "xtrape-project/" + REPO:
            return "TARGET_IDENTITY_MISMATCH"
        return "TARGET_READABLE_WRITE_UNPROVEN"
    except (ValueError, TypeError):
        return "INVALID_RESPONSE"

def transport_category(error):
    """Return a fixed code only; exception text/URLs are never evidence output."""
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "TLS_CERTIFICATE_VERIFICATION_FAILED"
    if isinstance(reason, ssl.SSLError):
        return "TLS_FAILURE"
    if isinstance(reason, socket.gaierror):
        return "DNS_FAILURE"
    if isinstance(reason, TimeoutError):
        return "TIMEOUT"
    if isinstance(reason, ConnectionRefusedError):
        return "CONNECTION_REFUSED"
    if isinstance(reason, ConnectionResetError):
        return "CONNECTION_RESET"
    if isinstance(reason, OSError) and reason.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        return "NETWORK_UNREACHABLE"
    return "UNCLASSIFIED_TRANSPORT_FAILURE"

def service_error(raw, platform):
    # Exact known API messages only. Never echo arbitrary body/header values.
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return "UNRECOGNIZED"
        message = data.get("message")
        if platform == "github" and message == "Bad credentials":
            return "BAD_CREDENTIALS"
        if platform == "gitlab" and message == "401 Unauthorized":
            return "UNAUTHORIZED"
    except (ValueError, TypeError):
        pass
    return "UNRECOGNIZED"

def probe_details(platform, opener=None):
    result = {"platform": platform if platform in TARGETS else "invalid", "writes_attempted": 0}
    if platform not in TARGETS:
        return dict(result, result="INVALID_PLATFORM")
    url, secret, header, prefix = TARGETS[platform]
    token = os.environ.get(secret, "")
    if not token or any(c in token for c in "\r\n"):
        return dict(result, result="MISSING_OR_INVALID_CREDENTIAL_INPUT")
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(url, headers={header: prefix + token, "User-Agent": "xtrape-public-preflight", "Accept": "application/json"}, method="GET")
    try:
        with opener.open(req, timeout=30) as response:
            if response.geturl() != url:
                return dict(result, result="REDIRECT_REFUSED")
            raw = response.read(1048577)
            if len(raw) > 1048576:
                return dict(result, result="RESPONSE_TOO_LARGE", http_status=response.status)
            return dict(result, result=classify(response.status, raw, platform), http_status=response.status)
    except urllib.error.HTTPError as error:
        detail = dict(result, result=classify(error.code, b"", platform), http_status=error.code)
        try:
            if error.code in (401, 403):
                try:
                    raw = error.read(1048577)
                    detail["service_error"] = service_error(raw, platform) if len(raw) <= 1048576 else "UNRECOGNIZED"
                except Exception:
                    detail["service_error"] = "UNRECOGNIZED"
        finally:
            try:
                error.close()
            except Exception:
                pass  # cleanup failures must not print exception text either
        return detail
    except Exception as error:
        return dict(result, result="TRANSPORT_FAILURE", transport_category=transport_category(error))

def probe(platform, opener=None):
    return probe_details(platform, opener)["result"]

def main():
    platform = os.environ.get("TARGET_PLATFORM", "")
    result = probe_details(platform)
    print(json.dumps(result))
    return 0 if result["result"] == "TARGET_READABLE_WRITE_UNPROVEN" else 1

if __name__ == "__main__":
    raise SystemExit(main())
