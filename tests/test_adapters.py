import importlib.util
import os
import tempfile
import unittest
from unittest.mock import patch
from service import Application
from models import HistoryStore,StorageError
from tests.support import Client

class AdapterTests(unittest.TestCase):
    def test_missing_serverless_secret_fails_closed(self):
        with patch.dict(os.environ,{'VERCEL':'1','SESSION_SECRET':''}):
            with self.assertRaises(RuntimeError):Application()
    def test_missing_serverless_database_fails_closed(self):
        with patch.dict(os.environ,{'VERCEL':'1','SESSION_SECRET':'a'*64,'DATABASE_URL':''}):
            with self.assertRaises(StorageError):Application()
    def test_legacy_postgres_uri_supported_without_using_credential(self):
        store=HistoryStore('postgres://USERNAME:PASSWORD@HOST/DATABASE',require_postgres=True)
        self.assertTrue(store.postgres)
    @unittest.skipUnless(importlib.util.find_spec('flask'),'Flask package unavailable under registry restriction; WSGI core tested directly')
    def test_real_flask_adapter(self):
        from flask import Flask
        with tempfile.TemporaryDirectory() as tmp:
            core=Application(store=HistoryStore('sqlite:///'+tmp+'/flask.db'),secret='test-flask-secret')
            flask=Flask(__name__);flask.wsgi_app=core
            with flask.test_client() as client:
                self.assertEqual(client.get('/healthz').status_code,200)
                self.assertIn(b'Check before',client.get('/').data)
    def test_local_session_key_persists_and_empty_key_fails_closed(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp,patch('service.ROOT',Path(tmp)),patch.dict(os.environ,{'SESSION_SECRET':''}):
            store=HistoryStore('sqlite:///'+tmp+'/session.db')
            one=Application(store=store)
            two=Application(store=store)
            self.assertEqual(one.secret,two.secret)
            key=Path(tmp)/'instance/session.key'
            self.assertEqual(key.stat().st_mode & 0o777,0o600)
            key.write_text('')
            with self.assertRaises(RuntimeError):Application(store=store)
