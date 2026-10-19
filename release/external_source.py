"""Fixed public-source Git delivery. No API scope requirement or forced writes."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse
from external_preflight import credential_input

REPOSITORY = "xtrape-project/linux-ops-widget-nodejs"
TARGETS = {
    "github": ("https://github.com/" + REPOSITORY + ".git", "GH_PUBLISH_TOKEN", "x-access-token"),
    "gitlab": ("https://gitlab.com/" + REPOSITORY + ".git", "GITLAB_PUBLISH_TOKEN", "oauth2"),
    "codeberg": ("https://codeberg.org/" + REPOSITORY + ".git", "CODEBERG_PUBLISH_TOKEN", "x-access-token"),
    "gitee": ("https://gitee.com/" + REPOSITORY + ".git", "GITEE_PUBLISH_TOKEN", "oauth2"),
}
SHA = re.compile(r"^[0-9a-f]{40}$")

class Refusal(Exception):
    pass

def source_origin_matches(origin, server_url):
    canonical = "https://forgejo.xtrape.com/" + REPOSITORY
    if origin in (canonical,canonical+".git"):
        return True
    # The workflow supplies its issuer URL from trusted github.server_url,
    # never a dispatch input. Internal checkout transport can differ from the
    # public canonical. This is an identity check, not an HTTP fetch.
    try:
        if any(ord(c)<33 or ord(c)>126 for c in server_url+origin) or any(c in server_url+origin for c in "?#"):
            return False
        root = urllib.parse.urlsplit(server_url)
        candidate = urllib.parse.urlsplit(origin)
        if root.scheme not in ("http","https") or not root.hostname or root.username is not None or root.password is not None or root.query or root.fragment or root.path not in ("","/"):
            return False
        if candidate.username is not None or candidate.password is not None:
            return False
        _ = root.port, candidate.port  # malformed ports fail closed
        return candidate.scheme==root.scheme and candidate.netloc==root.netloc and candidate.path in ("/"+REPOSITORY,"/"+REPOSITORY+".git")
    except ValueError:
        return False

def git_failure(stderr):
    value=stderr.lower()
    if "could not resolve host" in value or "could not resolve hostname" in value:
        return "GIT_DNS_FAILURE"
    if "ssl certificate problem" in value:
        return "GIT_TLS_FAILURE"
    if "authentication failed" in value or "http basic: access denied" in value:
        return "GIT_AUTHENTICATION_REJECTED"
    if "could not read username" in value or "could not read password" in value or "terminal prompts disabled" in value:
        return "GIT_CREDENTIAL_CHALLENGE"
    if "access token" in value and ("expired" in value or "invalid" in value):
        return "GIT_TOKEN_REJECTED"
    if "requested url returned error: 402" in value:
        return "GIT_HTTP_402"
    if "gnutls_handshake" in value or "tls connection was non-properly terminated" in value:
        return "GIT_TLS_HANDSHAKE_FAILURE"
    if "failed to connect" in value or "connection timed out" in value or "connection reset" in value or "empty reply from server" in value:
        return "GIT_CONNECTION_FAILURE"
    if "http/2 stream" in value or "http2 framing" in value:
        return "GIT_HTTP2_FAILURE"
    if "not allowed to download code" in value or "access denied" in value or "permission denied" in value:
        return "GIT_TARGET_ACCESS_DENIED"
    if "unable to update url base from redirection" in value or re.search(r"returned error: (301|302|303|307|308)\b",value):
        return "GIT_REDIRECT_REFUSED"
    if "not a git repository" in value or "detected dubious ownership" in value:
        return "GIT_LOCAL_CONTEXT_REFUSED"
    if "repository not found" in value or "repository" in value and "not found" in value:
        return "GIT_NOT_FOUND_OR_NOT_VISIBLE"
    match=re.search(r"returned error: (401|403|404|429|5[0-9]{2})\b",value)
    return "GIT_HTTP_"+match[1] if match else "GIT_COMMAND_REJECTED"

def git_environment(url, token=None, username=None):
    secret_keys = {v[1] for v in TARGETS.values()} | {"PUBLISH_TOKEN", "REGISTRY_TOKEN", "GITHUB_TOKEN"}
    env = {k:v for k,v in os.environ.items() if not k.startswith("GIT_") and k not in secret_keys | {"SSH_ASKPASS"}}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0")
    entries = [("credential.helper", ""), ("http.extraHeader", ""), ("core.hooksPath", "/dev/null"), ("http.followRedirects", "false"), ("http.proxy", "")]
    if token is not None:
        header = "Authorization: Basic " + base64.b64encode((username + ":" + token).encode()).decode()
        entries.append(("http." + url + ".extraHeader", header))
    env["GIT_CONFIG_COUNT"] = str(len(entries))
    for n,(key,value) in enumerate(entries):
        env["GIT_CONFIG_KEY_"+str(n)] = key
        env["GIT_CONFIG_VALUE_"+str(n)] = value
    return env

def execute(args, env, cwd=None):
    try:
        p = subprocess.run(["git", *args], env=env, cwd=cwd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    except Exception:
        raise Refusal("GIT_COMMAND_UNCONFIRMED") from None
    if p.returncode:
        # Never print errors: Git can include an authentication value in them.
        raise Refusal(git_failure(p.stderr))
    if len(p.stdout) > 1048576:
        raise Refusal("GIT_RESPONSE_TOO_LARGE")
    return p.stdout.strip()

def remote_head(url, env, run=execute):
    raw = run(["ls-remote", "--heads", url], env)
    refs = {}
    for row in raw.splitlines():
        pieces = row.split("\t")
        if len(pieces) != 2 or not SHA.fullmatch(pieces[0]) or not re.fullmatch(r"refs/heads/[A-Za-z0-9_.+/-]+",pieces[1]) or pieces[1] in refs:
            raise Refusal("INVALID_REMOTE_REFS")
        refs[pieces[1]] = pieces[0]
    if refs and "refs/heads/main" not in refs:
        raise Refusal("TARGET_NONEMPTY_WITHOUT_MAIN")
    return refs.get("refs/heads/main")

def verify_anonymous(url, source, tree, run=execute):
    env = git_environment(url)
    if remote_head(url, env, run) != source:
        raise Refusal("ANONYMOUS_REF_MISMATCH")
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp)/"clone")
        run(["clone", "--quiet", "--no-checkout", "--depth", "1", "--branch", "main", url, path], env)
        if run(["rev-parse", "HEAD^{tree}"], env, path) != tree:
            raise Refusal("ANONYMOUS_TREE_MISMATCH")

def deliver(platform, mode, run=execute):
    report = {"platform": platform if platform in TARGETS else "invalid", "mode": mode if mode in ("probe","publish") else "invalid", "writes_attempted": 0, "phase":"source_validation"}
    try:
        if platform not in TARGETS or mode not in ("probe","publish"):
            raise Refusal("INVALID_INPUT")
        if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or os.environ.get("GITHUB_REF") != "refs/heads/main":
            raise Refusal("SOURCE_CONTEXT_REFUSED")
        source = os.environ.get("SOURCE_SHA", "")
        if not SHA.fullmatch(source):
            raise Refusal("INVALID_SOURCE_SHA")
        url,key,default_user = TARGETS[platform]
        token,shape = credential_input(os.environ.get(key,""))
        if not token or any(shape[k] for k in ("embedded_control_character","header_wrapper_present","assignment_wrapper_present","quoted_value","placeholder_value")):
            raise Refusal("INVALID_CREDENTIAL_INPUT")
        username = os.environ.get("EXTERNAL_GIT_USERNAME",default_user) or default_user
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}",username):
            raise Refusal("INVALID_GIT_USERNAME")
        local_env = git_environment(url)
        if run(["rev-parse", "HEAD"],local_env) != source:
            raise Refusal("CHECKOUT_SOURCE_MISMATCH")
        origin = run(["remote","get-url","origin"],local_env)
        if not source_origin_matches(origin,os.environ.get("SOURCE_SERVER_URL","")):
            raise Refusal("SOURCE_ORIGIN_REFUSED")
        tree = run(["rev-parse", "HEAD^{tree}"],local_env)
        env = git_environment(url,token,username)
        report["phase"]="target_git_probe"
        old = remote_head(url,env,run)
        report.update(source_sha=source, target_head=old)
        if mode == "probe":
            report["result"]="GIT_READABLE_WRITE_UNPROVEN"
            return report
        report["phase"]="anonymous_preflight"
        if remote_head(url,local_env,run) != old:
            raise Refusal("TARGET_REF_CHANGED_BEFORE_WRITE")
        if old and old != source:
            report["phase"]="fast_forward_check"
            try:
                run(["merge-base","--is-ancestor",old,source],local_env)
            except Refusal:
                raise Refusal("TARGET_NOT_FAST_FORWARD") from None
        if old != source:
            report["phase"]="write"
            report["writes_attempted"]=1
            try:
                run(["push","--porcelain",url,source+":refs/heads/main"],env)
            except Refusal:
                # An uncertain write is reconciled read-only, never retried.
                if remote_head(url,env,run) != source:
                    raise Refusal("GIT_WRITE_UNCONFIRMED") from None
        report["phase"]="anonymous_verification"
        verify_anonymous(url,source,tree,run)
        report.update(result="SOURCE_PUBLISHED" if report["writes_attempted"] else "SOURCE_ALREADY_MATCHED", full_tree_verified=True)
    except Refusal as error:
        report["result"]=str(error)
    return report

def main():
    result=deliver(os.environ.get("TARGET_PLATFORM",""),os.environ.get("DELIVERY_MODE","probe"))
    print(json.dumps(result))
    return 0 if result["result"] in ("GIT_READABLE_WRITE_UNPROVEN","SOURCE_PUBLISHED","SOURCE_ALREADY_MATCHED") else 1

if __name__ == "__main__":
    raise SystemExit(main())
