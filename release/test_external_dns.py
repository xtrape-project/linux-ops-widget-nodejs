import json
import io
import os
import subprocess
import unittest
from unittest.mock import patch
import external_dns as p

class Tests(unittest.TestCase):
    def test_fixed_inputs_only(self):
        def run(*a,**kw):self.fail('unexpected child')
        self.assertEqual(p.query('evil.example','system',run)['result'],'INVALID_INPUT')
        self.assertEqual(p.query('gitee.com','evil',run)['result'],'INVALID_INPUT')
    def test_tcp_uses_same_resolver_and_no_credentials(self):
        def run(args,**kw):
            self.assertEqual(args[-1],'gitee.com');self.assertEqual(kw['timeout'],12)
            self.assertIn('use-vc',kw['env']['RES_OPTIONS'])
            self.assertIn('ndots:1',kw['env']['RES_OPTIONS'])
            self.assertNotIn('GH_PUBLISH_TOKEN',kw['env']);self.assertNotIn('GIT_TRACE',kw['env'])
            self.assertNotIn('nameserver',kw['env']['RES_OPTIONS'])
            return subprocess.CompletedProcess(args,0,'{"result":"RESOLVED"}')
        with patch.dict(os.environ,{'GH_PUBLISH_TOKEN':'fixture-secret','GIT_TRACE':'1','RES_OPTIONS':'ndots:1'}):
            self.assertEqual(p.query('gitee.com','tcp',run)['result'],'RESOLVED')
            self.assertEqual(os.environ['RES_OPTIONS'],'ndots:1')
    def test_unknown_child_output_not_echoed(self):
        for out in ['secret-value','{"result":"secret-value"}','[]']:
            def run(args,**kw):return subprocess.CompletedProcess(args,0,out)
            result=p.query('gitee.com','system',run)
            self.assertEqual(result['result'],'INVALID_CHILD_RESULT');self.assertNotIn('secret-value',json.dumps(result))
    def test_timeout_is_bounded_and_safe(self):
        def run(*a,**kw):raise subprocess.TimeoutExpired('secret-value',12,output='secret-value')
        result=p.query('gitee.com','system',run)
        self.assertEqual(result['result'],'DNS_QUERY_TIMEOUT');self.assertNotIn('secret-value',json.dumps(result))
    def test_tcp_comparison_does_not_define_default_dns_readiness(self):
        def query(host,profile):return {'host':host,'profile':profile,'result':'RESOLVED' if profile=='system' else 'DNS_QUERY_TIMEOUT'}
        with patch.object(p,'query',side_effect=query),patch('sys.stdout',new_callable=io.StringIO) as out:
            self.assertEqual(p.main(),0)
            self.assertFalse(json.loads(out.getvalue())['resolver_changed'])

if __name__=='__main__':unittest.main()
