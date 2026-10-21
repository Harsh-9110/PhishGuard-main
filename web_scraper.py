"""Bounded HTTP(S) fetching with DNS validation, IP pinning, and redirect checks."""
import concurrent.futures
import http.client
import ipaddress
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from urllib.parse import urljoin,urlsplit,urlunsplit
from feature_extraction import normalize_url,InvalidURL,PageParser,content_evidence

_POOL=concurrent.futures.ThreadPoolExecutor(max_workers=4,thread_name_prefix='phishguard-dns')
_DNS_SLOTS=threading.BoundedSemaphore(4)

class ScrapeError(RuntimeError):
    def __init__(self,code,message,status=422):
        super().__init__(message)
        self.code,self.message,self.status=code,message,status


def resolve_public(host,port,timeout,resolver=socket.getaddrinfo):
    if not _DNS_SLOTS.acquire(timeout=max(.001,timeout)):
        raise ScrapeError('timeout','DNS resolution timed out.',504)
    def resolve():
        return resolver(host,port,type=socket.SOCK_STREAM)
    future=_POOL.submit(resolve)
    future.add_done_callback(lambda _: _DNS_SLOTS.release())
    try:
        entries=future.result(timeout=max(.001,timeout))
    except concurrent.futures.TimeoutError:
        raise ScrapeError('timeout','DNS resolution timed out.',504) from None
    except OSError:
        raise ScrapeError('dns_failed','The hostname could not be resolved.') from None
    addresses=sorted({e[4][0] for e in entries})
    if not addresses:
        raise ScrapeError('dns_failed','The hostname has no addresses.')
    for address in addresses:
        try:
            ip=ipaddress.ip_address(address)
        except ValueError:
            raise ScrapeError('blocked_address','DNS returned an invalid address.',403) from None
        if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local:
            raise ScrapeError('blocked_address','Private, local, metadata and reserved destinations are blocked.',403)
        if isinstance(ip,ipaddress.IPv6Address) and ip.ipv4_mapped and not ip.ipv4_mapped.is_global:
            raise ScrapeError('blocked_address','Mapped private addresses are blocked.',403)
    return addresses


def connect_pinned(address,port,timeout):
    return socket.create_connection((address,port),timeout=timeout)


class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self,host,port,address,timeout,connector):
        super().__init__(host,port,timeout=timeout)
        self.address,self.connector=address,connector
    def connect(self):
        self.sock=self.connector(self.address,self.port,self.timeout)


class PinnedHTTPS(PinnedHTTP):
    def connect(self):
        raw=self.connector(self.address,self.port,self.timeout)
        try:
            self.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=self.host)
        except Exception:
            raw.close()
            raise


@dataclass(frozen=True)
class Page:
    url:str
    html:str
    status:int
    bytes_read:int
    redirects:int


class SafeFetcher:
    def __init__(self,timeout=8,max_bytes=1_000_000,max_redirects=3,resolver=socket.getaddrinfo,connector=connect_pinned):
        self.timeout,self.max_bytes,self.max_redirects=timeout,max_bytes,max_redirects
        self.resolver,self.connector=resolver,connector

    def fetch(self,value):
        url=normalize_url(value)
        deadline=time.monotonic()+self.timeout
        visited=set()
        for redirects in range(self.max_redirects+1):
            if url in visited:
                raise ScrapeError('redirect_loop','The website has a redirect loop.')
            visited.add(url)
            remaining=deadline-time.monotonic()
            if remaining<=0:
                raise ScrapeError('timeout','Website request timed out.',504)
            p=urlsplit(url)
            port=p.port or (443 if p.scheme=='https' else 80)
            if port not in {80,443}:
                raise ScrapeError('blocked_port','Only web ports 80 and 443 are supported.',403)
            addresses=resolve_public(p.hostname,port,remaining,self.resolver)
            remaining=deadline-time.monotonic()
            if remaining<=0:
                raise ScrapeError('timeout','Website request timed out.',504)
            connection=(PinnedHTTPS if p.scheme=='https' else PinnedHTTP)(p.hostname,port,addresses[0],remaining,self.connector)
            try:
                path=urlunsplit(('','',p.path or '/',p.query,''))
                connection.request('GET',path,headers={'User-Agent':'PhishGuard/1.0 (+website risk analysis)','Accept':'text/html,application/xhtml+xml','Accept-Encoding':'identity','Connection':'close'})
                transport_socket=connection.sock
                response=connection.getresponse()
                if response.status in {301,302,303,307,308}:
                    if redirects==self.max_redirects:
                        raise ScrapeError('too_many_redirects','The website exceeded the redirect limit.')
                    location=response.getheader('Location')
                    if not location:
                        raise ScrapeError('bad_redirect','The website returned an empty redirect.')
                    try:
                        next_url=normalize_url(urljoin(url,location))
                    except InvalidURL:
                        raise ScrapeError('bad_redirect','The website redirected to an invalid URL.') from None
                    if p.scheme=='https' and urlsplit(next_url).scheme!='https':
                        raise ScrapeError('https_downgrade','An HTTPS website redirected to insecure HTTP.')
                    url=next_url
                    continue
                if not 200<=response.status<300:
                    raise ScrapeError('upstream_status',f'The website returned HTTP {response.status}.')
                content_type=response.headers.get_content_type()
                if content_type not in {'text/html','application/xhtml+xml'}:
                    raise ScrapeError('non_html','The URL must return an HTML page.')
                if (response.getheader('Content-Encoding') or 'identity').lower()!='identity':
                    raise ScrapeError('unsupported_encoding','The website ignored the uncompressed response request.')
                size=response.getheader('Content-Length')
                if size and (not size.isdigit() or int(size)>self.max_bytes):
                    raise ScrapeError('page_too_large','The HTML page exceeds the size limit.',413)
                chunks=[]
                total=0
                while True:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:
                        raise ScrapeError('timeout','Website request timed out.',504)
                    if transport_socket:
                        transport_socket.settimeout(remaining)
                    chunk=response.read1(min(65536,self.max_bytes+1-total))
                    if not chunk:
                        break
                    total+=len(chunk)
                    if total>self.max_bytes:
                        raise ScrapeError('page_too_large','The HTML page exceeds the size limit.',413)
                    chunks.append(chunk)
                encoding=response.headers.get_content_charset() or 'utf-8'
                try:
                    html=b''.join(chunks).decode(encoding,errors='replace')
                except LookupError:
                    raise ScrapeError('bad_charset','The website specified an unsupported character set.') from None
                if not html.strip():
                    raise ScrapeError('empty_page','The website returned an empty page.')
                return Page(url,html,response.status,total,redirects)
            except (TimeoutError,socket.timeout):
                raise ScrapeError('timeout','Website request timed out.',504) from None
            except ssl.SSLError:
                raise ScrapeError('tls_error','The website failed TLS certificate verification.') from None
            except (OSError,http.client.HTTPException):
                raise ScrapeError('fetch_failed','The website could not be fetched.') from None
            finally:
                connection.close()
        raise ScrapeError('too_many_redirects','The website exceeded the redirect limit.')


def get_website_text_content(url,timeout=8):
    page=SafeFetcher(timeout=timeout).fetch(url)
    parser=PageParser(page.url)
    parser.feed(page.html)
    return ' '.join(parser.text)


def extract_html_features(url,timeout=8):
    page=SafeFetcher(timeout=timeout).fetch(url)
    return content_evidence(page.url,page.html)
