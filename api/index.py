"""Vercel Python HTTP entrypoint using the exact locally tested WSGI application."""
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit,unquote
import os
from app import app

class handler(BaseHTTPRequestHandler):
    def dispatch(self):
        path=urlsplit(self.path)
        environ={
            'SCRIPT_NAME':'','REQUEST_METHOD':self.command,'PATH_INFO':unquote(path.path),'QUERY_STRING':path.query,
            'CONTENT_LENGTH':self.headers.get('Content-Length','0'),
            'CONTENT_TYPE':self.headers.get('Content-Type',''),
            'REMOTE_ADDR':self.client_address[0],'SERVER_NAME':self.headers.get('Host','localhost'),
            'SERVER_PORT':'443','SERVER_PROTOCOL':self.request_version,
            'wsgi.version':(1,0),'wsgi.url_scheme':'https' if os.environ.get('VERCEL') else 'http','wsgi.input':self.rfile,
            'wsgi.errors':__import__('sys').stderr,'wsgi.multithread':True,'wsgi.multiprocess':False,'wsgi.run_once':False,
        }
        for name,value in self.headers.items():
            environ['HTTP_'+name.upper().replace('-','_')]=value
        def start_response(status,headers,exc_info=None):
            self.send_response(int(status.split()[0]))
            for name,value in headers:
                self.send_header(name,value)
            self.end_headers()
        result=app(environ,start_response)
        try:
            for data in result:
                self.wfile.write(data)
        finally:
            if hasattr(result,'close'):
                result.close()
    do_GET=do_POST=do_OPTIONS=do_HEAD=do_PUT=do_DELETE=dispatch
    def log_message(self,format,*args):
        pass
