"""Explicit test-only server for browser QA. Never deployed or used by main.py."""
import argparse
import tempfile
from wsgiref.simple_server import make_server
from service import Application
from models import HistoryStore
from tests.support import FixtureNetwork

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=5061);args=parser.parse_args()
    with FixtureNetwork() as network,tempfile.TemporaryDirectory() as tmp:
        core=Application(store=HistoryStore('sqlite:///'+tmp+'/browser.db'),fetcher=network.fetcher(),secret='test-browser-only-session-secret-32bytes')
        with make_server('127.0.0.1',args.port,core) as server:
            print(f'Fixture UI http://127.0.0.1:{args.port}; test transport maps public host to local HTML fixtures.',flush=True)
            server.serve_forever()
