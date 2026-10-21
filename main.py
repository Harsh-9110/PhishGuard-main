"""Local server; no training, package downloads or debug reloader on startup."""
import argparse
import logging
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer,WSGIRequestHandler,make_server
from app import app,RUNTIME_ADAPTER

class ThreadingServer(ThreadingMixIn,WSGIServer):
    daemon_threads=True

class QuietHandler(WSGIRequestHandler):
    def log_message(self,format,*args):
        pass

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=5000)
    args=parser.parse_args()
    logging.basicConfig(level=logging.INFO,format='%(message)s')
    print(f'PhishGuard listening on http://{args.host}:{args.port} ({RUNTIME_ADAPTER})',flush=True)
    with make_server(args.host,args.port,app,server_class=ThreadingServer,handler_class=QuietHandler) as server:
        server.serve_forever()
