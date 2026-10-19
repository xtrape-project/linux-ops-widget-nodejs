import io
import json
import os
import errno
import socket
import ssl
import unittest
import urllib.error
from unittest.mock import patch
import external_preflight as p

class Response(io.BytesIO):
    status = 200
    def geturl(self): return p.TARGETS["github"][0]

class Tests(unittest.TestCase):
    def test_exact_target(self):
        for platform in p.TARGETS:
            key = "path_with_namespace" if platform == "gitlab" else "full_name"
            self.assertEqual(p.classify(200, json.dumps({key: "xtrape-project/" + p.REPO}), platform), "TARGET_READABLE_WRITE_UNPROVEN")
    def test_reject_other_identity(self):
        self.assertEqual(p.classify(200, b'{"full_name":"other/repo"}', "github"), "TARGET_IDENTITY_MISMATCH")
    def test_status_categories(self):
        for code, expected in [(301,"REDIRECT_REFUSED"),(404,"NOT_FOUND_OR_NOT_VISIBLE"),(401,"TARGET_ACCESS_REJECTED"),(403,"TARGET_ACCESS_REJECTED"),(429,"RATE_LIMITED"),(500,"HTTP_FAILURE")]:
            self.assertEqual(p.classify(code,b"secret response", "github"), expected)
    def test_invalid_payload(self):
        self.assertEqual(p.classify(200,b"<html>","github"),"INVALID_RESPONSE")
    def test_no_redirect(self):
        self.assertIsNone(p.NoRedirect().redirect_request(None,None,302,"",{},"https://evil.example"))
    def test_missing_and_invalid_platform(self):
        with patch.dict(os.environ, {}, clear=True): self.assertEqual(p.probe("github"),"MISSING_OR_INVALID_CREDENTIAL_INPUT")
        self.assertEqual(p.probe("https://evil.example"),"INVALID_PLATFORM")
    def test_get_only_and_no_secret_output(self):
        class Opener:
            def open(self, req, timeout):
                assert req.method == "GET" and req.full_url == p.TARGETS["github"][0]
                return Response(json.dumps({"full_name":"xtrape-project/"+p.REPO}).encode())
        with patch.dict(os.environ,{"GH_PUBLISH_TOKEN":"test-only-value"}):
            self.assertEqual(p.probe("github",Opener()),"TARGET_READABLE_WRITE_UNPROVEN")
    def test_exception_sanitized(self):
        class Opener:
            def open(self,*a,**kw): raise RuntimeError("secret-value")
        with patch.dict(os.environ,{"GH_PUBLISH_TOKEN":"test-only-value"}):
            self.assertEqual(p.probe("github",Opener()),"TRANSPORT_FAILURE")
    def test_http_status_and_known_service_errors(self):
        for platform, code, raw, known in [
            ("github",401,b'{"message":"Bad credentials"}',"BAD_CREDENTIALS"),
            ("gitlab",401,b'{"message":"401 Unauthorized"}',"UNAUTHORIZED"),
            ("github",403,b'{"message":"secret-value"}',"UNRECOGNIZED"),
            ("github",403,b'<html>secret-value</html>',"UNRECOGNIZED"),
        ]:
            class Opener:
                def open(self,req,timeout):
                    raise urllib.error.HTTPError(req.full_url,code,"secret-value",{},io.BytesIO(raw))
            with patch.dict(os.environ,{p.TARGETS[platform][1]:"test-only-value"}):
                result=p.probe_details(platform,Opener())
            self.assertEqual(result["http_status"],code)
            self.assertEqual(result["service_error"],known)
            self.assertEqual(result["result"],"TARGET_ACCESS_REJECTED")
            self.assertNotIn("secret-value",json.dumps(result))
    def test_transport_causes_without_exception_text(self):
        for reason,expected in [
            (ssl.SSLCertVerificationError(1,"secret-value"),"TLS_CERTIFICATE_VERIFICATION_FAILED"),
            (ssl.SSLError(1,"secret-value"),"TLS_FAILURE"),
            (socket.gaierror(-2,"secret-value"),"DNS_FAILURE"),
            (TimeoutError("secret-value"),"TIMEOUT"),
            (ConnectionRefusedError("secret-value"),"CONNECTION_REFUSED"),
            (ConnectionResetError("secret-value"),"CONNECTION_RESET"),
            (OSError(errno.ENETUNREACH,"secret-value"),"NETWORK_UNREACHABLE"),
            (RuntimeError("secret-value"),"UNCLASSIFIED_TRANSPORT_FAILURE"),
        ]:
            class Opener:
                def open(self,*a,**kw): raise urllib.error.URLError(reason)
            with patch.dict(os.environ,{"GH_PUBLISH_TOKEN":"test-only-value"}):
                result=p.probe_details("github",Opener())
            self.assertEqual(result["transport_category"],expected)
            self.assertNotIn("secret-value",json.dumps(result))
    def test_no_error_body_echo_or_unbounded_error_read(self):
        for raw in [b'{"message":"secret-value"}',b'x'*1048577,b'[]']:
            class Opener:
                def open(self,req,timeout):
                    raise urllib.error.HTTPError(req.full_url,401,"secret-value",{},io.BytesIO(raw))
            with patch.dict(os.environ,{"GH_PUBLISH_TOKEN":"test-only-value"}):
                result=p.probe_details("github",Opener())
            self.assertEqual(result["service_error"],"UNRECOGNIZED")
            self.assertNotIn("secret-value",json.dumps(result))
    def test_cli_only_safe_structured_output(self):
        with patch.dict(os.environ,{"TARGET_PLATFORM":"github","GH_PUBLISH_TOKEN":"secret-value"}), patch.object(p,"probe_details",return_value={"platform":"github","result":"TRANSPORT_FAILURE","transport_category":"TIMEOUT","writes_attempted":0}), patch("sys.stdout",new_callable=io.StringIO) as output:
            self.assertEqual(p.main(),1)
            self.assertEqual(json.loads(output.getvalue())["transport_category"],"TIMEOUT")
            self.assertNotIn("secret-value",output.getvalue())

if __name__ == "__main__": unittest.main()
