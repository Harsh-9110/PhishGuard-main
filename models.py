"""Transactional SQLite/PostgreSQL history with an explicit, additive migration."""
import contextlib
import json
import os
import sqlite3
import threading
import time
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).parent
SCHEMA=ROOT/'migrations'/'001_history.sql'

class StorageError(RuntimeError):
    pass


class HistoryStore:
    def __init__(self,url=None,require_postgres=False):
        self.url=url or os.environ.get('DATABASE_URL')
        self.postgres=bool(self.url and self.url.startswith(('postgres://','postgresql://')))
        if require_postgres and not self.postgres:
            raise StorageError('Vercel requires a persistent PostgreSQL DATABASE_URL.')
        if self.url and not self.postgres and not self.url.startswith('sqlite:///'):
            raise StorageError('Unsupported database URL.')
        if not self.postgres:
            value=self.url.removeprefix('sqlite:///') if self.url else str(ROOT/'instance'/'phishguard.db')
            self.path=Path(value)
            if not self.path.is_absolute():
                self.path=ROOT/self.path
            self.path.parent.mkdir(parents=True,exist_ok=True)
        self.ready=False
        self.lock=threading.Lock()

    @contextlib.contextmanager
    def connection(self):
        conn=None
        try:
            if self.postgres:
                try:
                    import psycopg
                except ImportError:
                    raise StorageError('PostgreSQL driver missing; install requirements-postgres.txt.') from None
                options={'connect_timeout':5,'options':'-c statement_timeout=5000 -c lock_timeout=3000'}
                if os.environ.get('VERCEL'):
                    options['sslmode']='require'
                conn=psycopg.connect(self.url,**options)
            else:
                conn=sqlite3.connect(self.path,timeout=5)
                conn.execute('PRAGMA busy_timeout=5000')
            yield conn
            conn.commit()
        except StorageError:
            if conn:
                with contextlib.suppress(Exception):
                    conn.rollback()
            raise
        except Exception:
            if conn:
                with contextlib.suppress(Exception):
                    conn.rollback()
            raise StorageError('History database unavailable; analysis was not saved.') from None
        finally:
            if conn:
                with contextlib.suppress(Exception):
                    conn.close()

    def execute(self,conn,sql,args=()):
        cursor=conn.cursor()
        cursor.execute(sql.replace('?','%s') if self.postgres else sql,args)
        return cursor

    def initialize(self):
        if self.ready:
            return
        with self.lock:
            if self.ready:
                return
            with self.connection() as conn:
                if not self.postgres:
                    columns=[row[1] for row in self.execute(conn,'PRAGMA table_info(phishguard_rate_limits)').fetchall()]
                    if 'window' in columns and 'window_id' not in columns:
                        self.execute(conn,'ALTER TABLE phishguard_rate_limits RENAME COLUMN "window" TO window_id')
                for statement in SCHEMA.read_text().split(';'):
                    if statement.strip():
                        self.execute(conn,statement)
                self.execute(conn,'INSERT INTO phishguard_migrations(version,applied_at) VALUES(?,?) ON CONFLICT(version) DO NOTHING',(1,datetime.now(timezone.utc).isoformat()))
            self.ready=True

    def health(self):
        self.initialize()
        with self.connection() as conn:
            return self.execute(conn,'SELECT 1').fetchone()[0]==1

    def save(self,scan,owner):
        self.initialize()
        with self.connection() as conn:
            self.execute(conn,'INSERT INTO phishguard_scans(id,owner,created_at,result_json) VALUES(?,?,?,?)',
                         (scan['id'],owner,scan['created_at'],json.dumps(scan,allow_nan=False)))

    def get(self,scan_id,owner):
        self.initialize()
        with self.connection() as conn:
            row=self.execute(conn,'SELECT result_json FROM phishguard_scans WHERE id=? AND owner=?',(scan_id,owner)).fetchone()
            return json.loads(row[0]) if row else None

    def history(self,owner,limit=50):
        self.initialize()
        with self.connection() as conn:
            rows=self.execute(conn,'SELECT result_json FROM phishguard_scans WHERE owner=? ORDER BY created_at DESC LIMIT ?',(owner,min(50,max(1,int(limit))))).fetchall()
            return [json.loads(row[0]) for row in rows]

    def rate_allowed(self,bucket,limit=20,window_seconds=60):
        self.initialize()
        window=int(time.time())//window_seconds
        with self.connection() as conn:
            row=self.execute(conn,'INSERT INTO phishguard_rate_limits(bucket,window_id,hits) VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET hits=CASE WHEN phishguard_rate_limits.window_id=excluded.window_id THEN phishguard_rate_limits.hits+1 ELSE 1 END,window_id=excluded.window_id RETURNING hits',(bucket,window)).fetchone()
            return row[0]<=limit
