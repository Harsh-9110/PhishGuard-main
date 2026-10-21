import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from models import HistoryStore,StorageError

class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=HistoryStore('sqlite:///'+self.tmp.name+'/history.db')
    def test_migration_idempotent_and_connection(self):
        self.store.initialize();self.store.ready=False;self.store.initialize()
        self.assertTrue(self.store.health())
        with self.store.connection() as c:self.assertEqual(c.execute('SELECT count(*) FROM phishguard_migrations').fetchone()[0],1)
    def test_owner_scope_and_persistence(self):
        scan={'id':'scan1','created_at':'2026-10-20T00:00:00+00:00','url':'https://example.org'}
        self.store.save(scan,'alice')
        self.assertEqual(self.store.get('scan1','alice'),scan)
        self.assertIsNone(self.store.get('scan1','bob'))
        self.assertEqual(self.store.history('bob'),[])
        other=HistoryStore('sqlite:///'+self.tmp.name+'/history.db')
        self.assertEqual(other.history('alice'),[scan])
    def test_rollback_recovers_after_duplicate(self):
        scan={'id':'one','created_at':'today'};self.store.save(scan,'alice')
        with self.assertRaises(StorageError):self.store.save(scan,'alice')
        self.store.save({'id':'two','created_at':'tomorrow'},'alice')
        self.assertEqual(len(self.store.history('alice')),2)
    def test_bound_parameters(self):
        owner="x' OR 1=1 --";scan={'id':'test','created_at':'today'}
        self.store.save(scan,owner)
        self.assertEqual(self.store.history('other'),[])
        self.assertEqual(self.store.history(owner),[scan])
    def test_atomic_rate_limit(self):
        self.store.initialize()
        with ThreadPoolExecutor(max_workers=6) as pool:results=list(pool.map(lambda _:self.store.rate_allowed('bucket',5),range(12)))
        self.assertEqual(sum(results),5)
    def test_serverless_requires_persistent_db(self):
        with self.assertRaises(StorageError):HistoryStore('sqlite:///unused.db',require_postgres=True)
    @unittest.skipUnless(os.environ.get('TEST_DATABASE_URL'),'No rotated PostgreSQL test database supplied')
    def test_real_postgres_integration(self):
        pg=HistoryStore(os.environ['TEST_DATABASE_URL'],require_postgres=True)
        self.assertTrue(pg.health())
        import uuid
        owner=uuid.uuid4().hex
        scan={'id':str(uuid.uuid4()),'created_at':'2026-10-20T00:00:00+00:00'}
        pg.save(scan,owner);self.assertEqual(pg.get(scan['id'],owner),scan)
    def test_upgrade_development_rate_column_preserves_data(self):
        with self.store.connection() as c:
            c.execute('CREATE TABLE phishguard_rate_limits(bucket TEXT PRIMARY KEY,"window" BIGINT NOT NULL,hits INTEGER NOT NULL)')
            c.execute('INSERT INTO phishguard_rate_limits VALUES(?,?,?)',('preserved',7,9))
        self.store.initialize()
        with self.store.connection() as c:
            self.assertEqual(c.execute('SELECT window_id,hits FROM phishguard_rate_limits WHERE bucket=?',('preserved',)).fetchone(),(7,9))
