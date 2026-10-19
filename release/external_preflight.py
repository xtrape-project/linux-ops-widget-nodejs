"""Read-only fixed-target preflight; no response body or credential is logged."""
import json
import os
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

def probe(platform, opener=None):
    if platform not in TARGETS:
        return "INVALID_PLATFORM"
    url, secret, header, prefix = TARGETS[platform]
    token = os.environ.get(secret, "")
    if not token or any(c in token for c in "\r\n"):
        return "MISSING_OR_INVALID_CREDENTIAL_INPUT"
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(url, headers={header: prefix + token, "User-Agent": "xtrape-public-preflight", "Accept": "application/json"}, method="GET")
    try:
        with opener.open(req, timeout=30) as response:
            if response.geturl() != url:
                return "REDIRECT_REFUSED"
            raw = response.read(1048577)
            if len(raw) > 1048576:
                return "RESPONSE_TOO_LARGE"
            return classify(response.status, raw, platform)
    except urllib.error.HTTPError as error:
        return classify(error.code, b"", platform)
    except Exception:
        return "TRANSPORT_FAILURE"  # exception text can include credentials

def main():
    platform = os.environ.get("TARGET_PLATFORM", "")
    result = probe(platform)
    print(json.dumps({"platform": platform if platform in TARGETS else "invalid", "result": result, "writes_attempted": 0}))
    return 0 if result == "TARGET_READABLE_WRITE_UNPROVEN" else 1

if __name__ == "__main__":
    raise SystemExit(main())
