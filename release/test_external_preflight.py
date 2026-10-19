import io
import json
import os
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

if __name__ == "__main__": unittest.main()
