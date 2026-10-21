"""Real HTTP traffic through the app and Vercel adapter, against local HTML fixtures."""
import http.cookiejar
import json
import socket
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request,build_opener,HTTPCookieProcessor
from urllib.error import HTTPError
from wsgiref.simple_server import make_server,WSGIRequestHandler
from service import Application
from models import HistoryStore
from tests.support import FixtureNetwork

class Quiet(WSGIRequestHandler):
    def log_message(self,*args):pass

class HTTPIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.network=FixtureNetwork().__enter__()
        cls.core=Application(store=HistoryStore('sqlite:///'+cls.tmp.name+'/http.db'),fetcher=cls.network.fetcher(),secret='test-http-session-key-only',rate_limit=100)
        cls.server=make_server('127.0.0.1',0,cls.core,handler_class=Quiet)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base='http://127.0.0.1:'+str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(timeout=2)
        cls.network.__exit__();cls.tmp.cleanup()
    def test_full_http_scan_result_and_history(self):
        client=build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        for path in ['/','/static/app.js','/static/style.css','/healthz']:
            with client.open(self.base+path,timeout=5) as r:self.assertEqual(r.status,200);self.assertGreater(len(r.read()),0)
        request=Request(self.base+'/api/check',data=json.dumps({'url':'http://www.wikipedia.org/phishing'}).encode(),headers={'Content-Type':'application/json'})
        with client.open(request,timeout=5) as r:
            self.assertEqual(r.status,200);scan=json.load(r)
        self.assertTrue(scan['is_phishing']);self.assertTrue(scan['content_flag'])
        with client.open(self.base+'/api/results/'+scan['id'],timeout=5) as r:self.assertEqual(json.load(r),scan)
        with client.open(self.base+'/api/history',timeout=5) as r:self.assertIn(scan['id'],[s['id'] for s in json.load(r)['results']])
        with client.open(self.base+'/history',timeout=5) as r:self.assertIn(b'History',r.read())
    def test_http_invalid_request_and_ssrf(self):
        for url,expected in [('http://127.0.0.1/',403),('file:///etc/passwd',400)]:
            req=Request(self.base+'/api/check',data=json.dumps({'url':url}).encode(),headers={'Content-Type':'application/json'})
            with self.assertRaises(HTTPError) as error:build_opener().open(req,timeout=5)
            self.assertEqual(error.exception.code,expected)
    def test_vercel_http_handler_uses_real_application(self):
        import api.index as vercel
        original=vercel.app;vercel.app=self.core
        server=ThreadingHTTPServer(('127.0.0.1',0),vercel.handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base='http://127.0.0.1:'+str(server.server_port)
        try:
            key='c'*64
            request=Request(base+'/api/check',data=json.dumps({'url':'http://www.wikipedia.org/legitimate'}).encode(),headers={'Content-Type':'application/json','X-Client-Key':key})
            with build_opener().open(request,timeout=5) as r:scan=json.load(r);self.assertEqual(r.status,200)
            with build_opener().open(Request(base+'/api/history',headers={'X-Client-Key':key}),timeout=5) as r:self.assertIn(scan['id'],[s['id'] for s in json.load(r)['results']])
            with build_opener().open(base+'/',timeout=5) as r:self.assertIn(b'Check before',r.read())
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2);vercel.app=original
    def test_runtime_does_not_import_training_stack(self):
        import sys
        self.assertFalse({'numpy','pandas','sklearn','xgboost','nltk'} & set(sys.modules))
