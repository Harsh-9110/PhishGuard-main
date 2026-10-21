"""HTTP application shared by Flask, standard WSGI, and the Vercel entrypoint."""
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime,timezone
from html import escape
from http.cookies import SimpleCookie
from pathlib import Path
from string import Template
from urllib.parse import parse_qs

from feature_extraction import normalize_url,InvalidURL,lexical_features,content_evidence,warning_signals
from ml_models import ModelBundle,ModelError
from models import HistoryStore,StorageError
from web_scraper import SafeFetcher,ScrapeError

ROOT=Path(__file__).parent
LOG=logging.getLogger('phishguard')

class HTTPError(Exception):
    def __init__(self,code,message,status):
        self.code,self.message,self.status=code,message,status


class Application:
    def __init__(self,store=None,fetcher=None,model_dir=None,secret=None,rate_limit=None):
        value=secret or os.environ.get('SESSION_SECRET') or None
        if value is None and not os.environ.get('VERCEL'):
            directory=ROOT/'instance'
            directory.mkdir(exist_ok=True)
            key_file=directory/'session.key'
            try:
                fd=os.open(key_file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            except FileExistsError:
                value=key_file.read_text().strip()
            else:
                with os.fdopen(fd,'w') as handle:
                    value=secrets.token_hex(32)
                    handle.write(value)
        if not value:
            raise RuntimeError('Session key is empty or unavailable; configure SESSION_SECRET.')
        self.secret=value.encode()
        if os.environ.get('VERCEL') and (not os.environ.get('SESSION_SECRET') or len(self.secret)<32):
            raise RuntimeError('Configure a SESSION_SECRET of at least 32 characters on Vercel.')
        self.store=store or HistoryStore(require_postgres=bool(os.environ.get('VERCEL')))
        self.fetcher=fetcher or SafeFetcher()
        self.model=None
        try:
            self.model=ModelBundle(model_dir)
        except ModelError:
            pass
        self.rate_limit=int(rate_limit if rate_limit is not None else os.environ.get('RATE_LIMIT_PER_MINUTE','20'))
        if self.rate_limit<1:
            raise ValueError('RATE_LIMIT_PER_MINUTE must be positive.')
        self.origins={s.strip() for s in os.environ.get('ALLOWED_ORIGINS','').split(',') if s.strip()}
        self.counts={'requests':0,'errors':0,'flagged':0,'scans':0}
        self.lock=threading.Lock()

    def sign(self,value,purpose='owner'):
        return hmac.new(self.secret,(purpose+':'+value).encode(),hashlib.sha256).hexdigest()

    def owner(self,environ):
        client_key=environ.get('HTTP_X_CLIENT_KEY','')
        if re.fullmatch('[0-9a-f]{64}',client_key):
            return hashlib.sha256(client_key.encode()).hexdigest(),None
        cookies=SimpleCookie()
        try:
            cookies.load(environ.get('HTTP_COOKIE',''))
        except Exception:
            pass
        value=cookies['pg_owner'].value if 'pg_owner' in cookies else ''
        parts=value.split('.')
        if len(parts)==2 and re.fullmatch('[0-9a-f]{32}',parts[0]) and hmac.compare_digest(parts[1],self.sign(parts[0])):
            return parts[0],None
        owner=uuid.uuid4().hex
        secure=bool(os.environ.get('VERCEL')) or environ.get('wsgi.url_scheme')=='https'
        cookie=f'pg_owner={owner}.{self.sign(owner)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=2592000'
        if secure:
            cookie+='; Secure'
        return owner,cookie

    def json(self,value,status=200):
        return status,'application/json; charset=utf-8',json.dumps(value,ensure_ascii=True,allow_nan=False).encode()

    def document(self,name,owner):
        text=(ROOT/'templates'/name).read_text()
        return 200,'text/html; charset=utf-8',Template(text).substitute(csrf=escape(self.sign(owner,'csrf'),quote=True)).encode()

    def body(self,e):
        try:
            size=int(e.get('CONTENT_LENGTH') or '0')
        except ValueError:
            raise HTTPError('invalid_body','Invalid content length.',400) from None
        if size<0 or size>8192:
            raise HTTPError('request_too_large','Request body must be at most 8 KB.',413)
        if not size:
            raise HTTPError('invalid_body','A request body is required.',400)
        raw=e['wsgi.input'].read(size)
        if len(raw)!=size:
            raise HTTPError('invalid_body','Incomplete request body.',400)
        try:
            return raw.decode('utf-8')
        except UnicodeError:
            raise HTTPError('invalid_body','Request body must be UTF-8.',400) from None

    def analyze(self,url,owner):
        if self.model is None:
            raise HTTPError('models_unavailable','Trained model artifacts are unavailable.',503)
        url=normalize_url(url)
        page=self.fetcher.fetch(url)
        # Analyze the submitted address and the final page independently; redirects
        # must not erase misleading userinfo or other evidence in the original URL.
        features=lexical_features(url)
        result=self.model.predict(features)
        evidence=content_evidence(page.url,page.html)
        signals=warning_signals(url,evidence)
        content_flag=evidence['external_password_form']
        result['model_is_phishing']=result['is_phishing']
        result['is_phishing']=bool(result['is_phishing'] or content_flag)
        result.update({'id':str(uuid.uuid4()),'url':url,'final_url':page.url,
                       'created_at':datetime.now(timezone.utc).isoformat(),'features':features,
                       'content':evidence,'signals':signals,'content_flag':bool(content_flag),
                       'verdict_source':'model_and_content' if content_flag else 'model',
                       'feature_importance':[{'feature':n,'importance':v} for n,v in sorted(self.model.importances.items(),key=lambda p:p[1],reverse=True)[:10]],
                       'page':{'status':page.status,'bytes_read':page.bytes_read,'redirects':page.redirects},
                       'notice':'Model scores use a historical dataset and are not guarantees of safety. Content flags are separate rules.'})
        self.store.save(result,owner)
        # A successful response requires a committed history write.
        with self.lock:
            self.counts['scans']+=1
            self.counts['flagged']+=int(result['is_phishing'])
        return result

    def dispatch(self,e,owner):
        path=e.get('PATH_INFO') or '/'
        method=e.get('REQUEST_METHOD','GET')
        if method=='HEAD':
            method='GET'
        if path=='/healthz' and method=='GET':
            if self.model is None:
                return self.json({'status':'unhealthy','models':False,'database':'unchecked'},503)
            self.store.health()
            return self.json({'status':'ok','models':list(self.model.models),'model_version':self.model.version,
                              'database':'postgresql' if self.store.postgres else 'sqlite'})
        if path in {'/','/about','/history','/results'} and method=='GET':
            return self.document({'/':'index.html','/about':'about.html','/history':'history.html','/results':'results.html'}[path],owner)
        if path.startswith('/static/') and method=='GET':
            name=path.removeprefix('/static/')
            allowed={'app.js':'text/javascript; charset=utf-8','style.css':'text/css; charset=utf-8'}
            if name not in allowed:
                raise HTTPError('not_found','File not found.',404)
            return 200,allowed[name],(ROOT/'static'/name).read_bytes()
        if path=='/api/model-info' and method=='GET':
            if self.model is None:
                raise HTTPError('models_unavailable','Model artifacts unavailable.',503)
            data=json.loads((ROOT/'artifacts'/self.model.version/'metrics.json').read_text())
            return self.json({'test_rows':data['split']['test_rows'],'aggregation':data['aggregation'],'metrics':data['held_out']})
        if path=='/api/history' and method=='GET':
            return self.json({'results':self.store.history(owner)})
        if path.startswith('/api/results/') and method=='GET':
            scan_id=path.removeprefix('/api/results/')
            if not re.fullmatch('[0-9a-f-]{36}',scan_id):
                raise HTTPError('not_found','Analysis not found.',404)
            result=self.store.get(scan_id,owner)
            if result is None:
                raise HTTPError('not_found','Analysis not found.',404)
            return self.json(result)
        if path in {'/api/check','/analyze'} and method=='POST':
            # REMOTE_ADDR comes from the server, never from user-supplied forwarding headers.
            bucket=self.sign(e.get('REMOTE_ADDR') or 'unknown','rate')
            if not self.store.rate_allowed(bucket,self.rate_limit):
                raise HTTPError('rate_limited','Too many scans. Try again in one minute.',429)
            raw=self.body(e)
            if path=='/api/check':
                if e.get('CONTENT_TYPE','').split(';')[0].strip().lower()!='application/json':
                    raise HTTPError('unsupported_media_type','Send application/json.',415)
                try:
                    def invalid_constant(value):
                        raise ValueError(value)
                    data=json.loads(raw,parse_constant=invalid_constant)
                except (ValueError,TypeError):
                    raise HTTPError('invalid_json','Send a valid JSON object containing a URL.',400) from None
                if not isinstance(data,dict) or set(data)!={'url'}:
                    raise HTTPError('invalid_json','Send exactly one JSON field: url.',400)
            else:
                if e.get('CONTENT_TYPE','').split(';')[0]!='application/x-www-form-urlencoded':
                    raise HTTPError('unsupported_media_type','Send a URL form.',415)
                try:
                    values=parse_qs(raw,max_num_fields=5)
                except ValueError:
                    raise HTTPError('invalid_body','Invalid form data.',400) from None
                csrf=values.get('csrf',[''])[0]
                if not hmac.compare_digest(csrf,self.sign(owner,'csrf')):
                    raise HTTPError('csrf_failed','Reload the page and submit again.',403)
                data={'url':values.get('url',[''])[0]}
            result=self.analyze(data.get('url'),owner)
            if path=='/analyze':
                return 303,'text/plain; charset=utf-8',b'', [('Location','/results?id='+result['id'])]
            return self.json(result)
        if path in {'/api/check','/analyze','/api/history','/healthz'}:
            raise HTTPError('method_not_allowed','Method not allowed.',405)
        raise HTTPError('not_found','Page not found.',404)

    @staticmethod
    def log_route(path):
        if path in {'/','/healthz','/api/check','/api/history','/api/model-info','/analyze','/about','/results','/history'}:
            return path
        return '/api/results/:id' if path.startswith('/api/results/') else '/static/:asset' if path.startswith('/static/') else 'unmatched'

    def __call__(self,e,start_response):
        started=time.monotonic()
        request_id=uuid.uuid4().hex
        cookie=None
        extra=[]
        owner,cookie=self.owner(e)
        origin=e.get('HTTP_ORIGIN')
        host=e.get('HTTP_HOST','')
        same_origin=e.get('wsgi.url_scheme','http')+'://'+host
        allowed=not origin or origin==same_origin or origin in self.origins
        try:
            if origin and not allowed:
                raise HTTPError('origin_forbidden','This origin is not allowed.',403)
            if e.get('REQUEST_METHOD')=='OPTIONS':
                if e.get('PATH_INFO')!='/api/check':
                    raise HTTPError('not_found','Page not found.',404)
                output=(204,'text/plain',b'')
                extra += [('Access-Control-Allow-Methods','POST, OPTIONS'),('Access-Control-Allow-Headers','Content-Type, X-Client-Key'),('Access-Control-Max-Age','600')]
            else:
                output=self.dispatch(e,owner)
        except InvalidURL as exc:
            output=self.json({'error':{'code':'invalid_url','message':str(exc),'request_id':request_id}},400)
        except ScrapeError as exc:
            output=self.json({'error':{'code':exc.code,'message':exc.message,'request_id':request_id}},exc.status)
        except HTTPError as exc:
            output=self.json({'error':{'code':exc.code,'message':exc.message,'request_id':request_id}},exc.status)
        except StorageError:
            output=self.json({'error':{'code':'database_unavailable','message':'History database unavailable; scan was not saved.','request_id':request_id}},503)
        except Exception:
            # Never log exceptions that could embed database credentials or page content.
            LOG.error(json.dumps({'event':'internal_error','request_id':request_id}))
            output=self.json({'error':{'code':'internal_error','message':'Analysis could not be completed.','request_id':request_id}},500)
        status,content_type,body,*additional=output
        if additional:
            extra+=additional[0]
        if cookie:
            extra.append(('Set-Cookie',cookie))
        if origin and allowed:
            extra += [('Access-Control-Allow-Origin',origin),('Vary','Origin'),('Access-Control-Allow-Credentials','true')]
        if status==429:
            extra.append(('Retry-After','60'))
        headers=[('Content-Type',content_type),('Content-Length',str(len(body))),('Cache-Control','no-store'),
                 ('X-Request-ID',request_id),('X-Content-Type-Options','nosniff'),('X-Frame-Options','DENY'),
                 ('Referrer-Policy','no-referrer'),('Permissions-Policy','camera=(), microphone=(), geolocation=()'),
                 ('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")]
        if e.get('wsgi.url_scheme')=='https' or os.environ.get('VERCEL'):
            headers.append(('Strict-Transport-Security','max-age=31536000'))
        from http import HTTPStatus
        start_response(f'{status} {HTTPStatus(status).phrase}',headers+extra)
        with self.lock:
            self.counts['requests']+=1
            self.counts['errors']+=int(status>=400)
        LOG.info(json.dumps({'event':'request','request_id':request_id,'method':e.get('REQUEST_METHOD'),
                             'route':self.log_route(e.get('PATH_INFO') or '/'),
                             'status':status,'latency_ms':round((time.monotonic()-started)*1000,2)}))
        return [] if e.get('REQUEST_METHOD')=='HEAD' else [body]
