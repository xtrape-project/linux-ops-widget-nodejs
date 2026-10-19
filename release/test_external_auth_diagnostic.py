import base64
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
import urllib.error
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import external_auth_diagnostic as d
from external_source import git_environment, execute, Refusal

class Response(io.BytesIO):
    status = 200
    def __init__(self, url, raw):
        super().__init__(raw); self.url = url
    def geturl(self): return self.url

class Tests(unittest.TestCase):
    def env(self, platform='github'):
        return {'GITHUB_REPOSITORY':d.REPOSITORY, 'GITHUB_REF':'refs/heads/main', 'SOURCE_SHA':'a'*40, d.TARGETS[platform][0]:'fixture-secret'}
    def run_git(self,args,env):
        return 'a'*40 if args[0]=='rev-parse' else 'https://forgejo.xtrape.com/'+d.REPOSITORY+'.git'
    def test_success_discloses_no_profile_or_token_metadata(self):
        for platform in d.TARGETS:
            calls=[]
            class Opener:
                def open(self,req,timeout):
                    calls.append(req)
                    identity=req.full_url==d.TARGETS[platform][1]
                    data={'id':1,'login':'private-login','name':'private-name','token':'fixture-secret','active':True,'revoked':False,'scopes':['write_repository']} if identity else {'full_name':d.REPOSITORY,'path_with_namespace':d.REPOSITORY,'description':'private-description'}
                    return Response(req.full_url,json.dumps(data).encode())
            with patch.dict(os.environ,self.env(platform),clear=True):
                report=d.diagnose(platform,self.run_git,Opener())
            self.assertEqual(report['result'],'READ_ONLY_DIAGNOSIS_COMPLETED')
            self.assertEqual(report['writes_attempted'],0)
            self.assertEqual([r.full_url for r in calls],list(d.TARGETS[platform][1:]))
            self.assertTrue(all(r.method=='GET' for r in calls))
            for value in ['private-login','private-name','private-description','fixture-secret','write_repository']:
                self.assertNotIn(value,json.dumps(report))
            expected='Bearer fixture-secret' if platform=='github' else 'fixture-secret'
            self.assertEqual(calls[0].get_header('Authorization' if platform=='github' else 'Private-token'),expected)
    def test_valid_identity_plus_target_404_not_invalid_token_or_absence(self):
        class Opener:
            def open(self,req,timeout):
                if req.full_url.endswith('/user'): return Response(req.full_url,b'{"id":1}')
                raise urllib.error.HTTPError(req.full_url,404,'private-error',{},io.BytesIO(b'{"message":"private-error"}'))
        with patch.dict(os.environ,self.env(),clear=True):report=d.diagnose('github',self.run_git,Opener())
        self.assertEqual(report['identity']['result'],'CREDENTIAL_ACCEPTED_BY_IDENTITY_ENDPOINT')
        self.assertEqual(report['target']['result'],'NOT_FOUND_OR_NOT_VISIBLE')
        self.assertNotIn('private-error',json.dumps(report))
    def test_gitlab_rest_401_not_git_token_invalid_conclusion(self):
        class Opener:
            def open(self,req,timeout):raise urllib.error.HTTPError(req.full_url,401,'fixture-secret',{'WWW-Authenticate':'Bearer error="invalid_token"'},io.BytesIO(b'{"error":"invalid_token","extra":"fixture-secret"}'))
        result=d.fixed_get(d.TARGETS['gitlab'][1],'gitlab','fixture-secret',True,Opener())
        self.assertEqual(result['git_credential_validity'],'NOT_DETERMINED_BY_REST_REJECTION')
        self.assertEqual(result['service_error'],'INVALID_TOKEN')
        self.assertNotIn('fixture-secret',json.dumps(result))
    def test_github_bad_credentials_exact_enum_only(self):
        class Opener:
            def open(self,req,timeout):raise urllib.error.HTTPError(req.full_url,401,'fixture-secret',{},io.BytesIO(b'{"message":"Bad credentials"}'))
        result=d.fixed_get(d.TARGETS['github'][1],'github','fixture-secret',True,Opener())
        self.assertEqual(result['service_error'],'BAD_CREDENTIALS')
    def test_source_guard_runs_before_any_authenticated_http(self):
        for changed in [{'GITHUB_REF':'refs/heads/other'},{'GITHUB_REPOSITORY':'private/other'},{'SOURCE_SHA':'invalid'}]:
            env=self.env();env.update(changed)
            with patch.dict(os.environ,env,clear=True),patch.object(d,'fixed_get') as get:
                report=d.diagnose('github',self.run_git)
            self.assertEqual(report['result'],'SOURCE_CONTEXT_REFUSED');get.assert_not_called()
        for result in ['b'*40,'https://evil.example/'+d.REPOSITORY]:
            def bad(args,env):return result
            with patch.dict(os.environ,self.env(),clear=True),patch.object(d,'fixed_get') as get:
                report=d.diagnose('github',bad)
            self.assertEqual(report['result'],'CHECKOUT_SOURCE_REFUSED');get.assert_not_called()
    def test_bad_token_and_invalid_platform_never_sent(self):
        for value in ['', 'Bearer fixture-secret','"fixture-secret"','fixture\nsecret','***']:
            env=self.env();env['GH_PUBLISH_TOKEN']=value
            with patch.dict(os.environ,env,clear=True),patch.object(d,'fixed_get') as get:
                self.assertEqual(d.diagnose('github',self.run_git)['result'],'INVALID_CREDENTIAL_INPUT');get.assert_not_called()
        with patch.object(d,'fixed_get') as get:
            self.assertEqual(d.diagnose('gitee',self.run_git)['result'],'INVALID_PLATFORM');get.assert_not_called()
    def test_redirect_transport_size_and_schema_fail_closed(self):
        for raw in [b'[]',b'<html>fixture-secret</html>',b'x'*1048577,b'{"id":true}',b'{"id":-1}']:
            class Opener:
                def open(self,req,timeout):return Response(req.full_url,raw)
            result=d.fixed_get(d.TARGETS['github'][1],'github','fixture-secret',True,Opener())
            self.assertNotEqual(result['result'],'CREDENTIAL_ACCEPTED_BY_IDENTITY_ENDPOINT')
            self.assertNotIn('fixture-secret',json.dumps(result))
        class Redirect:
            def open(self,req,timeout):return Response('https://evil.example',b'{"id":1}')
        self.assertEqual(d.fixed_get(d.TARGETS['github'][1],'github','fixture-secret',True,Redirect())['result'],'REDIRECT_REFUSED')
        class Failure:
            def open(self,*args,**kw):raise RuntimeError('fixture-secret')
        self.assertNotIn('fixture-secret',json.dumps(d.fixed_get(d.TARGETS['github'][1],'github','fixture-secret',True,Failure())))
    def test_gitlab_metadata_types_and_fixed_scope_boolean(self):
        for data,expected in [({'id':1,'active':True,'revoked':False,'scopes':['write_repository']},True),({'id':1,'active':True,'revoked':False,'scopes':['api']},True),({'id':1,'active':True,'revoked':False,'scopes':['read_repository']},False)]:
            class Opener:
                def open(self,req,timeout):return Response(req.full_url,json.dumps(data).encode())
            report=d.fixed_get(d.TARGETS['gitlab'][1],'gitlab','fixture-secret',True,Opener())
            self.assertEqual(report['git_write_scope'],expected)
        class Invalid:
            def open(self,req,timeout):return Response(req.full_url,b'{"id":1,"active":"true","revoked":false,"scopes":[]}')
        self.assertEqual(d.fixed_get(d.TARGETS['gitlab'][1],'gitlab','fixture-secret',True,Invalid())['result'],'INVALID_TOKEN_METADATA_RESPONSE')
    def test_error_responses_bounded_closed_no_raw_echo(self):
        for code in [302,403,404,429,500]:
            stream=io.BytesIO(b'fixture-secret'*100000)
            class Opener:
                def open(self,req,timeout):raise urllib.error.HTTPError(req.full_url,code,'fixture-secret',{},stream)
            result=d.fixed_get(d.TARGETS['github'][1],'github','fixture-secret',True,Opener())
            self.assertTrue(stream.closed);self.assertEqual(result['http_status'],code)
            self.assertNotIn('fixture-secret',json.dumps(result))
    def test_workflow_only_selected_platform_secret_and_trusted_source(self):
        workflow=(Path(__file__).parents[1]/'.forgejo/workflows/external-auth-diagnostic.yml').read_text()
        self.assertIn('options: [github, gitlab]',workflow)
        for platform,key in [('github','GH_PUBLISH_TOKEN'),('gitlab','GITLAB_PUBLISH_TOKEN')]:
            self.assertIn("inputs.platform == '"+platform+"'",workflow)
            self.assertEqual(workflow.count('secrets.'+key),1)
        self.assertNotIn('CODEBERG_PUBLISH_TOKEN',workflow);self.assertNotIn('GITEE_PUBLISH_TOKEN',workflow)
        self.assertIn('SOURCE_SHA: ${{ github.sha }}',workflow)
        self.assertIn('SOURCE_SERVER_URL: ${{ github.server_url }}',workflow)
        self.assertIn('persist-credentials: false',workflow)
    def test_real_git_target_header_on_authenticated_http_wire(self):
        # Real Git and HTTP, fake token; prove injection rather than inspecting env.
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp)/'fixture.git'
            subprocess.run(['git','init','--bare','--quiet',str(repo)],check=True,capture_output=True)
            subprocess.run(['git','--git-dir',str(repo),'update-server-info'],check=True,capture_output=True)
            seen=[]; expected='Basic '+base64.b64encode(b'fixture-user:fixture-secret').decode()
            class Handler(SimpleHTTPRequestHandler):
                def __init__(self,*args,**kwargs):super().__init__(*args,directory=tmp,**kwargs)
                def do_GET(self):
                    seen.append(self.headers.get('Authorization')==expected)
                    if not seen[-1]:
                        self.send_response(401);self.send_header('WWW-Authenticate','Basic realm="fixture"');self.end_headers();return
                    super().do_GET()
                def log_message(self,*args):pass
            server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                url='http://127.0.0.1:'+str(server.server_port)+'/fixture.git'
                output=execute(['ls-remote','--heads',url],git_environment(url,'fixture-secret','fixture-user'),cwd=tmp)
                self.assertEqual(output,'');self.assertGreater(len(seen),0);self.assertTrue(all(seen))
            finally:
                server.shutdown();server.server_close();thread.join(timeout=5)

if __name__=='__main__':unittest.main()
