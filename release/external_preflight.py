"""Read-only fixed-target preflight; no response body or credential is logged."""
import json
import errno
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = "linux-ops-widget-nodejs"
TARGETS = {
    "github": ("https://api.github.com/repos/xtrape-project/" + REPO, "GH_PUBLISH_TOKEN", "Authorization", "Bearer "),
    "gitlab": ("https://gitlab.com/api/v4/projects/xtrape-project%2F" + REPO, "GITLAB_PUBLISH_TOKEN", "Authorization", "Bearer "),
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
        if platform == "gitlab" and data.get("error") in ("invalid_token", "insufficient_scope", "invalid_grant"):
            return data["error"].upper()
    except (ValueError, TypeError):
        pass
    return "UNRECOGNIZED"

def auth_challenge(headers):
    value = (headers.get("WWW-Authenticate", "") if headers else "").lower()
    if value.startswith("bearer"):
        if 'error="invalid_token"' in value:
            return "BEARER_INVALID_TOKEN"
        if 'error="insufficient_scope"' in value:
            return "BEARER_INSUFFICIENT_SCOPE"
        return "BEARER"
    return "BASIC" if value.startswith("basic") else "OTHER_OR_ABSENT"

def credential_input(value):
    """Only shape booleans; never disclose value, prefix, length or fingerprint."""
    token = value.strip(" \t\r\n")
    info = {
        "injected_nonempty": bool(value),
        "outer_whitespace_removed": token != value,
        "embedded_control_character": any(ord(c) < 33 or ord(c) > 126 for c in token),
        "header_wrapper_present": token.lower().startswith(("bearer ", "token ", "authorization:")),
        "assignment_wrapper_present": any(token.startswith(k + "=") for _, k, _, _ in TARGETS.values()),
        "quoted_value": len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'",
        "placeholder_value": token in ("***", "CHANGEME", "YOUR_TOKEN", *[t[1] for t in TARGETS.values()]),
    }
    return token, info

def temporary_dns_failure(error):
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    return isinstance(reason, socket.gaierror) and reason.errno == socket.EAI_AGAIN

def fixed_target_open(opener, req, sleep=time.sleep):
    # Retry only a resolver's explicit EAI_AGAIN. Never retry any HTTP reply,
    # permanent DNS failure, write, or other transport error.
    for attempt in range(3):
        try:
            return opener.open(req, timeout=30), attempt + 1
        except Exception as error:
            if not temporary_dns_failure(error) or attempt == 2:
                raise
            sleep(attempt + 1)

def dns_diagnostic(platform, resolver=socket.getaddrinfo):
    result = {"platform": platform if platform in TARGETS else "invalid", "writes_attempted": 0}
    if platform not in TARGETS:
        return dict(result, result="INVALID_PLATFORM")
    hostname = urllib.parse.urlsplit(TARGETS[platform][0]).hostname
    try:
        rows = resolver(hostname, 443, type=socket.SOCK_STREAM)
        families = {row[0] for row in rows}
        return dict(result, result="DNS_RESOLVED", ipv4=socket.AF_INET in families, ipv6=socket.AF_INET6 in families)
    except socket.gaierror as error:
        code = "DNS_TEMPORARY_FAILURE" if error.errno == socket.EAI_AGAIN else "DNS_NAME_NOT_FOUND" if error.errno == socket.EAI_NONAME else "DNS_OTHER_FAILURE"
        return dict(result, result=code)
    except Exception:
        return dict(result, result="DNS_OTHER_FAILURE")

def probe_details(platform, opener=None):
    result = {"platform": platform if platform in TARGETS else "invalid", "writes_attempted": 0}
    if platform not in TARGETS:
        return dict(result, result="INVALID_PLATFORM")
    url, secret, header, prefix = TARGETS[platform]
    token, shape = credential_input(os.environ.get(secret, ""))
    result["credential_input"] = shape
    if not token or any(shape[k] for k in ("embedded_control_character", "header_wrapper_present", "assignment_wrapper_present", "quoted_value", "placeholder_value")):
        return dict(result, result="MISSING_OR_INVALID_CREDENTIAL_INPUT")
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(url, headers={header: prefix + token, "User-Agent": "xtrape-public-preflight", "Accept": "application/json"}, method="GET")
    try:
        response, attempts = fixed_target_open(opener, req)
        result["dns_open_attempts"] = attempts
        with response:
            if response.geturl() != url:
                return dict(result, result="REDIRECT_REFUSED")
            raw = response.read(1048577)
            if len(raw) > 1048576:
                return dict(result, result="RESPONSE_TOO_LARGE", http_status=response.status)
            return dict(result, result=classify(response.status, raw, platform), http_status=response.status)
    except urllib.error.HTTPError as error:
        detail = dict(result, result=classify(error.code, b"", platform), http_status=error.code)
        detail["auth_challenge"] = auth_challenge(error.headers)
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
        detail = dict(result, result="TRANSPORT_FAILURE", transport_category=transport_category(error))
        reason = error.reason if isinstance(error, urllib.error.URLError) else error
        if isinstance(reason, socket.gaierror):
            detail["dns_failure_kind"] = "TEMPORARY" if reason.errno == socket.EAI_AGAIN else "NAME_NOT_FOUND" if reason.errno == socket.EAI_NONAME else "OTHER"
        return detail

def probe(platform, opener=None):
    return probe_details(platform, opener)["result"]

def main():
    platform = os.environ.get("TARGET_PLATFORM", "")
    result = dns_diagnostic(platform) if os.environ.get("TARGET_DIAGNOSTIC_MODE") == "dns" else probe_details(platform)
    print(json.dumps(result))
    return 0 if result["result"] in ("TARGET_READABLE_WRITE_UNPROVEN", "DNS_RESOLVED") else 1

if __name__ == "__main__":
    raise SystemExit(main())
