import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock,patch
import urllib.error
import external_codeberg_target as p

META={'full_name':p.REPOSITORY,'private':False,'clone_url':p.GIT_URL,'empty':True}
CONTEXT={'GITHUB_REPOSITORY':p.REPOSITORY,'GITHUB_REF':'refs/heads/main','SOURCE_SHA':'a'*40,'CODEBERG_PUBLISH_TOKEN':'fixture-secret'}

def source_run(args,env,cwd=None):
    if args==['rev-parse','HEAD']:return 'a'*40
    if args==['remote','get-url','origin']:return 'https://forgejo.xtrape.com/'+p.REPOSITORY
    if args[0]=='ls-remote':return ''
    raise AssertionError('unexpected Git command')

class Tests(unittest.TestCase):
    def scenario(self,replies,run=source_run):
        calls=[]
        def call(method,token):
            calls.append(method);self.assertEqual(token,'fixture-secret')
            result=replies.pop(0)
            if isinstance(result,Exception):raise result
            return result
        with patch.dict(os.environ,CONTEXT):result=p.prepare(call,run)
        self.assertNotIn('fixture-secret',json.dumps(result))
        return result,calls
    def test_404_allows_only_one_atomic_create_and_anonymous_readback(self):
        r,c=self.scenario([(404,None),(201,META)])
        self.assertEqual(c,['GET','POST']);self.assertEqual(r['result'],'CREATED_EMPTY_PUBLIC_TARGET')
        self.assertTrue(r['anonymous_git_readable']);self.assertEqual(r['writes_attempted'],1)
    def test_existing_public_repository_is_not_modified(self):
        r,c=self.scenario([(200,META)])
        self.assertEqual(c,['GET']);self.assertEqual(r['writes_attempted'],0)
        self.assertEqual(r['result'],'EXISTING_PUBLIC_TARGET')
    def test_private_wrong_name_or_wrong_clone_url_never_written(self):
        for meta in [dict(META,private=True),dict(META,full_name='private/other'),dict(META,clone_url='https://other.invalid/repo.git')]:
            r,c=self.scenario([(200,meta)])
            self.assertEqual(c,['GET']);self.assertEqual(r['writes_attempted'],0)
            self.assertEqual(r['result'],'CODEBERG_TARGET_IDENTITY_OR_VISIBILITY_REFUSED')
    def test_unauthorized_lookup_never_attempts_create(self):
        for status in [401,403,302,500]:
            r,c=self.scenario([(status,None)])
            self.assertEqual(c,['GET']);self.assertEqual(r['writes_attempted'],0)
    def test_create_auth_refusal_is_not_retried_or_reinterpreted(self):
        for status in [401,403]:
            r,c=self.scenario([(404,None),(status,None)])
            self.assertEqual(c,['GET','POST']);self.assertEqual(r['result'],'CODEBERG_CREATE_ACCESS_REJECTED')
    def test_write_timeout_get_reconciliation_never_repeats_post(self):
        r,c=self.scenario([(404,None),p.Refusal('CODEBERG_TARGET_TRANSPORT_UNCONFIRMED'),(200,META)])
        self.assertEqual(c,['GET','POST','GET'])
        self.assertEqual(r['result'],'CREATE_RECONCILED_EMPTY_PUBLIC_TARGET')
    def test_conflict_does_not_authorize_modifying_existing_content(self):
        r,c=self.scenario([(404,None),(409,None),(200,dict(META,empty=False))])
        self.assertEqual(c,['GET','POST','GET']);self.assertEqual(r['result'],'CODEBERG_CREATE_RECONCILIATION_NOT_EMPTY')
    def test_unconfirmed_create_remains_unconfirmed(self):
        r,c=self.scenario([(404,None),(400,None),(404,None)])
        self.assertEqual(c,['GET','POST','GET']);self.assertEqual(r['result'],'CODEBERG_CREATE_UNCONFIRMED')
    def test_nonempty_create_response_fails_without_another_write(self):
        r,c=self.scenario([(404,None),(201,dict(META,empty=False))])
        self.assertEqual(c,['GET','POST']);self.assertEqual(r['result'],'CODEBERG_CREATED_TARGET_NOT_EMPTY')
    def test_anonymous_visibility_required_after_create(self):
        def run(args,env,cwd=None):
            if args[0]=='ls-remote':raise p.Refusal('GIT_NOT_FOUND_OR_NOT_VISIBLE')
            return source_run(args,env,cwd)
        r,c=self.scenario([(404,None),(201,META)],run)
        self.assertEqual(c,['GET','POST']);self.assertEqual(r['result'],'GIT_NOT_FOUND_OR_NOT_VISIBLE')
    def test_source_context_origin_and_token_validation_precede_any_network(self):
        call=Mock(side_effect=AssertionError('no network allowed'))
        with patch.dict(os.environ,CONTEXT):
            with patch.dict(os.environ,{'GITHUB_REF':'refs/heads/private'}):self.assertEqual(p.prepare(call,source_run)['result'],'SOURCE_CONTEXT_REFUSED')
            with patch.dict(os.environ,{'SOURCE_SHA':'bad'}):self.assertEqual(p.prepare(call,source_run)['result'],'INVALID_SOURCE_SHA')
            with patch.dict(os.environ,{'CODEBERG_PUBLISH_TOKEN':'Bearer fixture-secret'}):self.assertEqual(p.prepare(call,source_run)['result'],'INVALID_CREDENTIAL_INPUT')
            def run(args,env,cwd=None):
                if args[0]=='remote':return 'https://forgejo.xtrape.com/xtrape/private'
                return source_run(args,env,cwd)
            self.assertEqual(p.prepare(call,run)['result'],'SOURCE_ORIGIN_REFUSED')
        call.assert_not_called()
    def test_http_operations_have_fixed_urls_body_and_ephemeral_header(self):
        for method,url,status in [('GET',p.READ_URL,200),('POST',p.CREATE_URL,201)]:
            response=Mock();response.status=status;response.read.return_value=json.dumps(META).encode()
            response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
            opener=Mock();opener.open.return_value=response
            self.assertEqual(p.request(method,'fixture-secret',opener),(status,META))
            req=opener.open.call_args.args[0]
            self.assertEqual(req.full_url,url);self.assertNotIn('fixture-secret',req.full_url)
            self.assertEqual(req.method,method);self.assertEqual(req.get_header('Authorization'),'token fixture-secret')
            self.assertEqual(opener.open.call_args.kwargs,{'timeout':15})
            if method=='POST':self.assertEqual(json.loads(req.data),{'name':'linux-ops-widget-nodejs','private':False,'auto_init':False,'default_branch':'main'})
            self.assertEqual(opener.open.call_count,1);response.read.assert_called_once_with(1048577)
        with self.assertRaises(p.Refusal):p.request('PATCH','fixture-secret',Mock())
    def test_http_errors_are_closed_and_raw_body_never_returned(self):
        body=io.BytesIO(b'fixture-secret');error=urllib.error.HTTPError(p.READ_URL,403,'fixture-secret',{},body)
        opener=Mock();opener.open.side_effect=error
        self.assertEqual(p.request('GET','fixture-secret',opener),(403,None));self.assertTrue(body.closed)
    def test_real_git_reads_new_empty_public_target_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'source';source.mkdir();bare=Path(tmp)/'target.git'
            def git(*args):return subprocess.check_output(['git',*args],cwd=source,text=True,stderr=subprocess.DEVNULL).strip()
            git('init','-q','-b','main');git('-c','user.name=test','-c','user.email=test@example.invalid','commit','--allow-empty','-qm','source')
            git('remote','add','origin','https://forgejo.xtrape.com/'+p.REPOSITORY)
            sha=git('rev-parse','HEAD');calls=[]
            def call(method,token):
                calls.append(method)
                if method=='GET':return 404,None
                git('init','--bare','-q','-b','main',str(bare));return 201,META
            def run(args,env,cwd=None):
                self.assertNotIn('fixture-secret',json.dumps(env))
                mapped=['file://'+str(bare) if a==p.GIT_URL else a for a in args]
                return p.execute(mapped,env,cwd or str(source))
            with patch.dict(os.environ,dict(CONTEXT,SOURCE_SHA=sha)):
                r=p.prepare(call,run)
            self.assertEqual(calls,['GET','POST']);self.assertEqual(r['result'],'CREATED_EMPTY_PUBLIC_TARGET');self.assertTrue(r['anonymous_git_readable'])

if __name__=='__main__':unittest.main()
