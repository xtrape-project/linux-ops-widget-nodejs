"""Fixed-endpoint, GET-only authentication diagnosis. Never emit profiles or secrets."""
import json
import os
import urllib.error
import urllib.request
from external_preflight import credential_input, service_error, auth_challenge, transport_category
from external_source import REPOSITORY, SHA, Refusal, git_environment, execute, source_origin_matches, NoRedirect

TARGETS = {
    "github": ("GH_PUBLISH_TOKEN", "https://api.github.com/user", "https://api.github.com/repos/" + REPOSITORY),
    "gitlab": ("GITLAB_PUBLISH_TOKEN", "https://gitlab.com/api/v4/personal_access_tokens/self", "https://gitlab.com/api/v4/projects/xtrape-project%2Flinux-ops-widget-nodejs"),
}

def fixed_get(url, platform, token, identity=False, opener=None):
    headers = {"User-Agent": "xtrape-public-auth-diagnostic/0.8.7", "Accept": "application/json"}
    headers["PRIVATE-TOKEN" if platform == "gitlab" else "Authorization"] = token if platform == "gitlab" else "Bearer " + token
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(request, timeout=20) as response:
            if response.geturl() != url:
                return {"result": "REDIRECT_REFUSED"}
            raw = response.read(1048577)
            if len(raw) > 1048576:
                return {"result": "RESPONSE_TOO_LARGE"}
            if response.status != 200:
                return {"result": "UNEXPECTED_HTTP_STATUS"}
            try:
                data = json.loads(raw)
            except (ValueError, TypeError):
                return {"result": "INVALID_RESPONSE"}
            if not isinstance(data, dict):
                return {"result": "INVALID_RESPONSE"}
            if identity:
                if type(data.get("id")) is not int or data["id"] <= 0:
                    return {"result": "INVALID_IDENTITY_RESPONSE"}
                if platform == "github":
                    return {"http_status": 200, "result": "CREDENTIAL_ACCEPTED_BY_IDENTITY_ENDPOINT"}
                # Token metadata stays in memory; output only bounded booleans.
                if type(data.get("active")) is not bool or type(data.get("revoked")) is not bool or not isinstance(data.get("scopes"), list):
                    return {"result": "INVALID_TOKEN_METADATA_RESPONSE"}
                return {"http_status": 200, "result": "TOKEN_METADATA_READABLE", "active": data["active"], "revoked": data["revoked"], "git_write_scope": any(scope in ("api", "write_repository") for scope in data["scopes"])}
            field = "full_name" if platform == "github" else "path_with_namespace"
            if data.get(field) != REPOSITORY:
                return {"result": "TARGET_IDENTITY_MISMATCH"}
            return {"http_status": 200, "result": "TARGET_METADATA_READABLE_WRITE_UNPROVEN"}
    except urllib.error.HTTPError as error:
        try:
            raw = error.read(1048577)
            # No 401/403 implies a token-invalid conclusion for GitLab: Git-only
            # tokens need not authorize this REST endpoint. 404 is not absence.
            code = error.code
            result = {"http_status": code, "result": "API_ACCESS_REJECTED" if code in (401, 403) else "NOT_FOUND_OR_NOT_VISIBLE" if code == 404 else "REDIRECT_REFUSED" if 300 <= code < 400 else "HTTP_FAILURE", "auth_challenge": auth_challenge(error.headers)}
            result["service_error"] = service_error(raw, platform) if len(raw) <= 1048576 else "UNRECOGNIZED"
            if platform == "gitlab" and code in (401, 403):
                result["git_credential_validity"] = "NOT_DETERMINED_BY_REST_REJECTION"
            return result
        except Exception:
            return {"result": "HTTP_RESPONSE_UNCONFIRMED"}
        finally:
            try:
                error.close()
            except Exception:
                pass
    except Exception as error:
        return {"result": "TRANSPORT_FAILURE", "transport_category": transport_category(error)}

def diagnose(platform, run=execute, opener=None):
    report = {"platform": platform if platform in TARGETS else "invalid", "writes_attempted": 0}
    try:
        if platform not in TARGETS:
            raise Refusal("INVALID_PLATFORM")
        source = os.environ.get("SOURCE_SHA", "")
        if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or os.environ.get("GITHUB_REF") != "refs/heads/main" or not SHA.fullmatch(source):
            raise Refusal("SOURCE_CONTEXT_REFUSED")
        env = git_environment("https://forgejo.xtrape.com/" + REPOSITORY + ".git")
        if run(["rev-parse", "HEAD"], env) != source or not source_origin_matches(run(["remote", "get-url", "origin"], env), os.environ.get("SOURCE_SERVER_URL", "")):
            raise Refusal("CHECKOUT_SOURCE_REFUSED")
        key, identity_url, target_url = TARGETS[platform]
        token, shape = credential_input(os.environ.get(key, ""))
        if not token or any(shape[k] for k in ("embedded_control_character", "header_wrapper_present", "assignment_wrapper_present", "quoted_value", "placeholder_value")):
            raise Refusal("INVALID_CREDENTIAL_INPUT")
        report["identity"] = fixed_get(identity_url, platform, token, True, opener)
        report["target"] = fixed_get(target_url, platform, token, False, opener)
        report["result"] = "READ_ONLY_DIAGNOSIS_COMPLETED"
    except Refusal as error:
        report["result"] = str(error)
    return report

def main():
    report = diagnose(os.environ.get("TARGET_PLATFORM", ""))
    print(json.dumps(report))
    return 0 if report["result"] == "READ_ONLY_DIAGNOSIS_COMPLETED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
