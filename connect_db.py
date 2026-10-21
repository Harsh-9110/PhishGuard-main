"""Initialize/check the configured database without revealing connection secrets."""
import argparse
import sys
from models import HistoryStore,StorageError

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--check',action='store_true',help='Check connectivity after applying additive schema migration')
    parser.parse_args()
    try:
        store=HistoryStore()
        store.initialize()
        if not store.health():
            raise StorageError('Database health check failed.')
        print('Database ready ('+('PostgreSQL' if store.postgres else 'SQLite')+'); migration 001 applied/idempotent.')
    except StorageError as exc:
        print(str(exc),file=sys.stderr)
        sys.exit(1)
