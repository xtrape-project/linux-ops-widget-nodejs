import base64
import importlib.util
import json
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('diagnostic', pathlib.Path(__file__).with_name('diagnose-registry-auth.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Diagnostic(unittest.TestCase):
    def test_missing_input_makes_no_request(self):
        self.assertFalse(module.diagnose('', '', lambda *_: self.fail())['token_present'])

    def test_invalid_credentials_never_leak_response_or_input(self):
        secret = 'fixture-secret-not-for-output'
        calls = []
        def fetch(path, auth):
            calls.append(path)
            return {'status': 401}, {'message': secret, 'token': secret}
        result = module.diagnose('fixture-user', secret, fetch)
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn('fixture-user', json.dumps(result))
        self.assertEqual(len(calls), 3)
        self.assertEqual(result['login_token_endpoint']['status'], 401)

    def test_valid_identity_and_scoped_grant(self):
        claims = {'access': [{'type': 'repository', 'name': 'xtrape-project/linux-ops-widget-nodejs', 'actions': ['pull', 'push', 'secret-data']}]}
        token = 'header.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.signature'
        def fetch(path, auth):
            if path == '/api/v1/user': return {'status': 200}, {'login': 'Different'}
            if path.startswith('/v2/token?'): return {'status': 200}, {'token': token}
            return {'status': 200}, {}
        result = module.diagnose('fixture-user', 'fixture-secret', fetch)
        self.assertFalse(result['configured_user_matches_token_owner'])
        self.assertEqual(result['target_target_actions'], ['pull', 'push'])
        self.assertNotIn(token, json.dumps(result))

    def test_redirect_not_followed(self):
        self.assertIsNone(module.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid'))

    def test_invalid_claims(self):
        for token in ['', 'bad', 'a.b.c', 'a.W10.c']:
            self.assertEqual(module.granted_actions(token), [])


unittest.main()
