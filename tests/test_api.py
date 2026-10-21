import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from urllib.parse import urlencode
from service import Application
from models import HistoryStore,StorageError
from tests.support import FixtureNetwork,Client

class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.network=FixtureNetwork().__enter__()
    @classmethod
    def tearDownClass(cls):cls.network.__exit__()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=HistoryStore('sqlite:///'+self.tmp.name+'/history.db')
        self.app=Application(store=self.store,fetcher=self.network.fetcher(),secret='test-secret-not-a-production-credential',rate_limit=200)
        self.client=Client(self.app)
    def test_routes_assets_and_security_headers(self):
        for path in ['/','/about','/results','/history','/static/app.js','/static/style.css','/healthz','/api/model-info']:
            with self.subTest(path=path):
                r=self.client.request(path);self.assertEqual(r['status'],200)
                self.assertEqual(r['headers']['X-Content-Type-Options'],'nosniff')
                self.assertEqual(r['headers']['Cache-Control'],'no-store')
                self.assertIn("frame-ancestors 'none'",r['headers']['Content-Security-Policy'])
        self.assertEqual(self.client.request('/static/../app.py')['status'],404)
    def test_real_prediction_and_history(self):
        r=self.client.request('/api/check','POST',{'url':'http://www.wikipedia.org/legitimate'})
        self.assertEqual(r['status'],200,r['body'])
        data=r['json'];self.assertFalse(data['content_flag']);self.assertEqual(len(data['models']),3)
        saved=self.client.request('/api/results/'+data['id'])
        self.assertEqual(saved['json'],data)
        self.assertEqual(self.client.request('/api/history')['json']['results'][0]['id'],data['id'])
        self.assertEqual(Client(self.app).request('/api/results/'+data['id'])['status'],404)
    def test_real_phishing_content_overrides_low_url_score(self):
        r=self.client.request('/api/check','POST',{'url':'http://www.wikipedia.org/phishing'})
        self.assertEqual(r['status'],200,r['body'])
        self.assertTrue(r['json']['content_flag']);self.assertTrue(r['json']['is_phishing'])
        self.assertIn('external_password_form',[s['code'] for s in r['json']['signals']])
    def test_invalid_json_and_input_types(self):
        for raw in [b'null',b'[]',b'"text"',b'0',b'{bad',b'{"url":NaN}',b'{"url":12}',b'{"url":null}',b'{}',b'{"url":"https://example.org","extra":1}']:
            with self.subTest(raw=raw):
                r=self.client.request('/api/check','POST',raw=raw)
                self.assertEqual(r['status'],400,r['body']);self.assertIn('request_id',r['json']['error'])
    def test_non_json_and_size_limit(self):
        self.assertEqual(self.client.request('/api/check','POST',raw=b'url=x',content_type='text/plain')['status'],415)
        self.assertEqual(self.client.request('/api/check','POST',raw=b'x'*8193)['status'],413)
    def test_fetch_errors_never_saved(self):
        for path,expected in [('nonhtml',422),('loop',422),('private',403),('large',413)]:
            r=self.client.request('/api/check','POST',{'url':'http://www.wikipedia.org/'+path})
            self.assertEqual(r['status'],expected,r['body'])
        self.assertEqual(self.client.request('/api/history')['json']['results'],[])
    def test_missing_artifacts_health_and_scan_fail(self):
        self.app.model=None
        self.assertEqual(self.client.request('/healthz')['status'],503)
        self.assertEqual(self.client.request('/api/check','POST',{'url':'https://example.org'})['status'],503)
    def test_database_failure_is_not_reported_as_success(self):
        with patch.object(self.store,'save',side_effect=StorageError('secret must never escape')):
            r=self.client.request('/api/check','POST',{'url':'http://www.wikipedia.org/legitimate'})
        self.assertEqual(r['status'],503);self.assertNotIn('secret must',r['body'].decode())
    def test_origin_restrictions_and_preflight(self):
        self.assertEqual(self.client.request('/api/check','OPTIONS',headers={'HTTP_ORIGIN':'https://evil.example'})['status'],403)
        self.app.origins.add('chrome-extension://testextension')
        r=self.client.request('/api/check','OPTIONS',headers={'HTTP_ORIGIN':'chrome-extension://testextension'})
        self.assertEqual(r['status'],204)
        self.assertEqual(r['headers']['Access-Control-Allow-Origin'],'chrome-extension://testextension')
        self.assertIn('X-Client-Key',r['headers']['Access-Control-Allow-Headers'])
    def test_extension_owner_key_persists_across_popups(self):
        one=Client(self.app,key='a'*64);r=one.request('/api/check','POST',{'url':'http://www.wikipedia.org/legitimate'})
        self.assertEqual(r['status'],200)
        two=Client(self.app,key='a'*64)
        self.assertEqual(two.request('/api/history')['json']['results'][0]['id'],r['json']['id'])
        self.assertEqual(Client(self.app,key='b'*64).request('/api/history')['json']['results'],[])
    def test_html_form_csrf_and_result_redirect(self):
        import re
        page=self.client.request('/')
        token=re.search(r'name="csrf" value="([a-f0-9]+)"',page['body'].decode()).group(1)
        bad=self.client.request('/analyze','POST',raw=urlencode({'url':'http://www.wikipedia.org/legitimate','csrf':'bad'}).encode(),content_type='application/x-www-form-urlencoded')
        self.assertEqual(bad['status'],403)
        r=self.client.request('/analyze','POST',raw=urlencode({'url':'http://www.wikipedia.org/legitimate','csrf':token}).encode(),content_type='application/x-www-form-urlencoded')
        self.assertEqual(r['status'],303,r['body']);self.assertTrue(r['headers']['Location'].startswith('/results?id='))
    def test_rate_limit(self):
        self.app.rate_limit=2
        for _ in range(2):self.client.request('/api/check','POST',{'url':'bad url'})
        r=self.client.request('/api/check','POST',{'url':'bad url'})
        self.assertEqual(r['status'],429);self.assertEqual(r['headers']['Retry-After'],'60')
    def test_methods_and_unknown_paths(self):
        self.assertEqual(self.client.request('/api/check')['status'],405)
        self.assertEqual(self.client.request('/no-such-page')['status'],404)
    def test_http_head(self):
        r=self.client.request('/healthz','HEAD')
        self.assertEqual(r['status'],200);self.assertEqual(r['body'],b'')
