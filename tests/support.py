import io
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from web_scraper import SafeFetcher

PUBLIC='93.184.216.34'
FIXTURES=Path(__file__).parent/'fixtures'

class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path=self.path.split('?')[0]
        if path in {'/loop','/redirect','/private','/bad-redirect','/downgrade'} or path.startswith('/chain'):
            destination={'/loop':'/loop','/redirect':'/legitimate','/private':'http://169.254.169.254/latest/meta-data/','/bad-redirect':'file:///etc/passwd','/downgrade':'http://www.wikipedia.org/legitimate'}.get(path)
            if path.startswith('/chain'):
                destination='/chain'+str(int(path.removeprefix('/chain'))+1)
            self.send_response(302);self.send_header('Location',destination);self.end_headers();return
        if path=='/timeout':
            time.sleep(.3)
        self.send_response(500 if path=='/500' else 200)
        self.send_header('Content-Type','application/pdf' if path=='/nonhtml' else 'text/html; charset='+('bad-charset-no-such-codec' if path=='/charset' else 'utf-8'))
        if path=='/large':
            self.send_header('Content-Length','1000001')
        if path=='/gzip':
            self.send_header('Content-Encoding','gzip')
        self.end_headers()
        try:
            if path=='/stream-large':
                self.wfile.write(b'x'*1_000_001)
            elif path=='/trickle':
                for _ in range(20):
                    self.wfile.write(b'x');self.wfile.flush();time.sleep(.03)
            elif path=='/empty' or path=='/large':
                pass
            else:
                self.wfile.write((FIXTURES/('phishing.html' if path=='/phishing' else 'legitimate.html')).read_bytes())
        except (BrokenPipeError,ConnectionResetError):
            pass
    def log_message(self,format,*args):
        pass

class FixtureNetwork:
    def __enter__(self):
        self.server=ThreadingHTTPServer(('127.0.0.1',0),FixtureHandler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.resolved=[]
        self.connected=[]
        return self
    def __exit__(self,*args):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
    def resolver(self,host,port,**kwargs):
        self.resolved.append(host)
        try:
            __import__('ipaddress').ip_address(host)
            return socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
        except ValueError:
            return [(socket.AF_INET,socket.SOCK_STREAM,6,'',(PUBLIC,port))]
    def connector(self,address,port,timeout):
        if address!=PUBLIC:
            raise AssertionError('An unvalidated destination reached the test connector.')
        self.connected.append((address,port))
        return socket.create_connection(('127.0.0.1',self.server.server_port),timeout)
    def fetcher(self,timeout=2,**kwargs):
        return SafeFetcher(timeout=timeout,resolver=self.resolver,connector=self.connector,**kwargs)

class Client:
    def __init__(self,app,key=None):
        self.app=app
        self.cookie=''
        self.key=key
    def request(self,path='/',method='GET',data=None,raw=None,headers=None,content_type='application/json'):
        from urllib.parse import urlsplit
        p=urlsplit(path)
        body=(json.dumps(data).encode() if data is not None else b'') if raw is None else raw
        e={'PATH_INFO':p.path,'QUERY_STRING':p.query,'REQUEST_METHOD':method,'wsgi.url_scheme':'http','HTTP_HOST':'localhost',
           'REMOTE_ADDR':'127.0.0.1','CONTENT_TYPE':content_type,'CONTENT_LENGTH':str(len(body)),'wsgi.input':io.BytesIO(body),'HTTP_COOKIE':self.cookie}
        if self.key:
            e['HTTP_X_CLIENT_KEY']=self.key
        e.update(headers or {})
        captured={}
        def start(status,response_headers):
            captured['status']=int(status.split()[0]);captured['headers']=dict(response_headers)
            if 'Set-Cookie' in captured['headers']:
                self.cookie=captured['headers']['Set-Cookie'].split(';')[0]
        captured['body']=b''.join(self.app(e,start))
        try:
            captured['json']=json.loads(captured['body'])
        except (ValueError,UnicodeError):
            captured['json']=None
        return captured
