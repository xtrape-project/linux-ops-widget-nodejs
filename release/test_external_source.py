import base64
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
import external_source as p

class Tests(unittest.TestCase):
    def test_source_origin_bound_to_issuer_and_exact_public_path(self):
        root='http://ci.example.invalid'
        self.assertTrue(p.source_origin_matches(root+'/'+p.REPOSITORY,root))
        self.assertTrue(p.source_origin_matches(root+'/'+p.REPOSITORY+'.git',root+'/'))
        for origin,issuer in [(root+'/xtrape/linux-ops-widget-nodejs',root),(root+'/'+p.REPOSITORY+'?secret-value',root),(root+'/'+p.REPOSITORY,'https://other.example.invalid'),(root+'/'+p.REPOSITORY,'http://secret-value@ci.example.invalid'),(root+'/'+p.REPOSITORY,root+'/prefix'),(root+'/'+p.REPOSITORY,''),(root+'#/'+p.REPOSITORY,root+'#'),(root+'/'+p.REPOSITORY,root+'\n'),('http://ci.example.invalid:bad/'+p.REPOSITORY,'http://ci.example.invalid:bad')]:
            self.assertFalse(p.source_origin_matches(origin,issuer))
    def test_git_errors_are_fixed_codes_only(self):
        for text,expected in [('secret-value Authentication failed','GIT_AUTHENTICATION_REJECTED'),('secret-value returned error: 403','GIT_HTTP_403'),('Could not resolve host: secret-value','GIT_DNS_FAILURE'),('SSL certificate problem secret-value','GIT_TLS_FAILURE'),('repository secret-value not found','GIT_NOT_FOUND_OR_NOT_VISIBLE'),('secret-value','GIT_COMMAND_REJECTED')]:
            result=p.git_failure(text)
            self.assertEqual(result,expected);self.assertNotIn('secret-value',result)
    def test_credentials_only_in_transient_target_header(self):
        url=p.TARGETS['github'][0]
        with patch.dict(os.environ,{'GH_PUBLISH_TOKEN':'fixture-secret','GIT_TRACE_CURL':'1','GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'credential.helper','GIT_CONFIG_VALUE_0':'store'}):
            env=p.git_environment(url,'fixture-secret','x-access-token')
            anon=p.git_environment(url)
        self.assertNotIn('GH_PUBLISH_TOKEN',env);self.assertNotIn('GH_PUBLISH_TOKEN',anon)
        self.assertNotIn('GIT_TRACE_CURL',env)
        entries={env['GIT_CONFIG_KEY_'+str(i)]:env['GIT_CONFIG_VALUE_'+str(i)] for i in range(int(env['GIT_CONFIG_COUNT']))}
        self.assertEqual(entries['credential.helper'],'');self.assertEqual(entries['http.proxy'],'')
        self.assertEqual(entries['http.followRedirects'],'false')
        self.assertEqual(entries['http.'+url+'.extraHeader'],'Authorization: Basic '+base64.b64encode(b'x-access-token:fixture-secret').decode())
        self.assertNotIn('fixture-secret',json.dumps(anon))
    def test_auth_challenge_uses_real_git_without_prompt_or_secret_output(self):
        class Reject(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(401)
                self.send_header('WWW-Authenticate','Basic realm="fixture"')
                self.end_headers()
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Reject)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            url='http://127.0.0.1:'+str(server.server_port)+'/fixed.git'
            with tempfile.TemporaryDirectory() as cwd, self.assertRaises(p.Refusal) as caught:
                p.execute(['ls-remote','--heads',url],p.git_environment(url,'fixture-secret','oauth2'),cwd)
            self.assertEqual(str(caught.exception),'GIT_CREDENTIAL_CHALLENGE')
            self.assertNotIn('fixture-secret',str(caught.exception))
        finally:
            server.shutdown();server.server_close();thread.join()
    def test_additional_git_failures_never_expose_raw_error(self):
        for raw,expected in [('could not read Username secret-value terminal prompts disabled','GIT_CREDENTIAL_CHALLENGE'),('Access token secret-value has expired','GIT_TOKEN_REJECTED'),('The requested URL returned error: 402 secret-value','GIT_HTTP_402'),('gnutls_handshake() failed secret-value','GIT_TLS_HANDSHAKE_FAILURE'),('Failed to connect secret-value','GIT_CONNECTION_FAILURE'),('HTTP/2 stream secret-value was not closed cleanly','GIT_HTTP2_FAILURE'),('not allowed to download code secret-value','GIT_TARGET_ACCESS_DENIED')]:
            self.assertEqual(p.git_failure(raw),expected)
            self.assertNotIn('secret-value',p.git_failure(raw))
    def test_source_context_and_input_rejections(self):
        with patch.dict(os.environ,{},clear=True):
            self.assertEqual(p.deliver('github','publish')['result'],'SOURCE_CONTEXT_REFUSED')
            self.assertEqual(p.deliver('evil','publish')['result'],'INVALID_INPUT')
            self.assertEqual(p.deliver('github','force')['result'],'INVALID_INPUT')
    def test_redirect_and_local_context_errors_are_fixed_categories(self):
        for raw,expected in [('unable to update url base from redirection secret-value','GIT_REDIRECT_REFUSED'),('The requested URL returned error: 302 secret-value','GIT_REDIRECT_REFUSED'),('not a git repository: secret-value','GIT_LOCAL_CONTEXT_REFUSED'),('detected dubious ownership secret-value','GIT_LOCAL_CONTEXT_REFUSED')]:
            self.assertEqual(p.git_failure(raw),expected)
    def test_refs_fail_closed(self):
        for text,expected in [('garbage','INVALID_REMOTE_REFS'),('a'*40+'\trefs/heads/master','TARGET_NONEMPTY_WITHOUT_MAIN')]:
            with self.assertRaisesRegex(p.Refusal,expected):p.remote_head('https://fixed.invalid',{},lambda *a:text)
    def fixture(self,case):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.mkdir();bare=root/'target.git'
            def git(*args,cwd=source):return subprocess.check_output(['git',*args],cwd=cwd,text=True,stderr=subprocess.DEVNULL).strip()
            git('init','-q','-b','main');git('config','user.name','test');git('config','user.email','test@example.invalid')
            git('remote','add','origin','https://forgejo.xtrape.com/'+p.REPOSITORY+'.git')
            (source/'.gitignore').write_text('logs/\n.env\n');(source/'logs').mkdir();(source/'logs/.gitkeep').touch()
            (source/'tool').write_text('accepted\n');(source/'tool').chmod(0o755)
            git('add','--force','.');git('commit','-qm','accepted');sha=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
            (source/'.env').write_text('runtime-only-value\n')
            git('init','--bare','-q','-b','main',str(bare))
            if case=='fast-forward':
                git('push','-q',str(bare),'HEAD:main')
                (source/'tool').write_text('accepted follow-up\n');git('add','tool');git('commit','-qm','follow-up')
                sha=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
            if case=='diverged':
                other=root/'other';other.mkdir()
                git('init','-q','-b','main',cwd=other);git('-c','user.name=t','-c','user.email=t@example.invalid','commit','--allow-empty','-qm','other',cwd=other)
                git('push','-q',str(bare),'HEAD:main',cwd=other)
            calls=[];pushes=[]
            def run(args,env,cwd=None):
                calls.append(args)
                self.assertNotIn('fixture-secret',' '.join(args))
                self.assertNotIn('--force',args);self.assertNotIn('--mirror',args)
                mapped=[('file://'+str(bare)) if a==p.TARGETS['github'][0] else a for a in args]
                authenticated=any(env.get('GIT_CONFIG_KEY_'+str(i),'').endswith('.extraHeader') and env.get('GIT_CONFIG_VALUE_'+str(i),'') for i in range(int(env['GIT_CONFIG_COUNT'])))
                if case=='private' and args[0]=='ls-remote' and not authenticated:raise p.Refusal('GIT_COMMAND_REJECTED')
                if args[0]=='push':
                    pushes.append(args)
                    if case=='denied':raise p.Refusal('GIT_COMMAND_REJECTED')
                output=p.execute(mapped,env,cwd or str(source))
                if args[0]=='push' and case=='uncertain':raise p.Refusal('GIT_COMMAND_UNCONFIRMED')
                if args[:2]==['rev-parse','HEAD^{tree}'] and cwd and case=='anonymous-mismatch':return '0'*40
                return output
            context={'GITHUB_REPOSITORY':p.REPOSITORY,'GITHUB_REF':'refs/heads/main','SOURCE_SHA':sha,'GH_PUBLISH_TOKEN':'fixture-secret'}
            if case=='ci-alias':
                context['SOURCE_SERVER_URL']='http://ci.example.invalid'
                git('remote','set-url','origin',context['SOURCE_SERVER_URL']+'/'+p.REPOSITORY)
            with patch.dict(os.environ,context):
                result=p.deliver('github','probe' if case=='probe' else 'publish',run)
                if case=='idempotent':
                    result=p.deliver('github','publish',run)
                    self.assertEqual(len(pushes),1)
            self.assertNotIn('fixture-secret',json.dumps(result))
            self.assertNotIn('fixture-secret',(source/'.git/config').read_text())
            if case=='probe':
                self.assertEqual(result['result'],'GIT_READABLE_WRITE_UNPROVEN');self.assertFalse(pushes)
            elif case=='diverged':
                self.assertEqual(result['result'],'TARGET_NOT_FAST_FORWARD');self.assertFalse(pushes)
            elif case=='private':
                self.assertEqual(result['result'],'GIT_COMMAND_REJECTED');self.assertEqual(result['phase'],'anonymous_preflight');self.assertFalse(pushes)
            elif case=='denied':
                self.assertEqual(result['result'],'GIT_WRITE_UNCONFIRMED');self.assertEqual(len(pushes),1)
            elif case=='anonymous-mismatch':
                self.assertEqual(result['result'],'ANONYMOUS_TREE_MISMATCH');self.assertEqual(len(pushes),1)
            else:
                self.assertIn(result['result'],['SOURCE_PUBLISHED','SOURCE_ALREADY_MATCHED'])
                self.assertTrue(result['full_tree_verified'])
                self.assertEqual(git('--git-dir',str(bare),'rev-parse','main'),sha)
                self.assertEqual(git('--git-dir',str(bare),'rev-parse','main^{tree}'),tree)
                self.assertNotIn('.env',git('--git-dir',str(bare),'ls-tree','-r','--name-only','main').splitlines())
                self.assertEqual(len(pushes),1)
    def test_actual_git_delivery(self):self.fixture('success')
    def test_real_git_delivery_with_context_bound_checkout_alias(self):self.fixture('ci-alias')
    def test_fast_forward_of_existing_public_history(self):self.fixture('fast-forward')
    def test_target_must_be_anonymously_readable_before_write(self):self.fixture('private')
    def test_read_only_probe_does_not_write(self):self.fixture('probe')
    def test_denied_write_is_not_retried(self):self.fixture('denied')
    def test_unrelated_target_refused(self):self.fixture('diverged')
    def test_already_equal_is_idempotent(self):self.fixture('idempotent')
    def test_uncertain_write_reconciled_without_retry(self):self.fixture('uncertain')
    def test_anonymous_full_tree_mismatch_fails(self):self.fixture('anonymous-mismatch')

if __name__=='__main__':unittest.main()
