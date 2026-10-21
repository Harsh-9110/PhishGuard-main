"""Shared lexical ML schema. HTML evidence is separate from labeled URL features."""
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit, quote

CHARACTERS = dict(zip(
    ('dot','hyphen','underline','slash','questionmark','equal','at','and','exclamation','space','tilde','comma','plus','asterisk','hashtag','dollar','percent'),
    ('.','-','_','/','?','=','@','&','!',' ','~',',','+','*','#','$','%'),
))
SCHEMA_VERSION = 'lexical-v1'
FEATURE_NAMES = [f'qty_{n}_url' for n in CHARACTERS] + [
    'length_url','qty_dot_domain','qty_hyphen_domain','qty_underline_domain',
    'qty_vowels_domain','domain_length','domain_in_ip','server_client_domain',
]
WORDS = {'login','signin','verify','password','account','banking','confirm','urgent'}

class InvalidURL(ValueError):
    pass


def normalize_url(value):
    if not isinstance(value,str) or not value.strip():
        raise InvalidURL('Enter a website URL.')
    value = value.strip()
    if len(value)>2048 or any(ord(c)<33 or ord(c)==127 for c in value) or '\\' in value:
        raise InvalidURL('URL is too long or contains whitespace/control characters.')
    if '://' not in value:
        value = 'https://' + value
    try:
        p = urlsplit(value)
        if p.scheme.lower() not in {'http','https'} or not p.hostname:
            raise InvalidURL('Only HTTP and HTTPS website URLs are supported.')
        if p.password is not None:
            raise InvalidURL('URLs containing passwords are not accepted.')
        host = p.hostname.encode('idna').decode('ascii').lower().rstrip('.')
        if len(host)>253 or '%' in host or not host:
            raise InvalidURL('Invalid hostname.')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',s) for s in host.split('.')):
                raise InvalidURL('Invalid hostname.') from None
        port = p.port
        if port is not None and not 1<=port<=65535:
            raise InvalidURL('Invalid port.')
        authority = f'[{host}]' if ':' in host else host
        if port is not None:
            authority += f':{port}'
        if p.username is not None:
            authority = quote(p.username,safe="%._~-!$&'()*+,;=") + '@' + authority
        safe="/%:@!$&'()*+,;=-._~"
        result=urlunsplit((p.scheme.lower(),authority,quote(p.path,safe=safe),quote(p.query,safe=safe+'?'),quote(p.fragment,safe=safe+'?')))
        if len(result)>2048:
            raise InvalidURL('Encoded URL exceeds the length limit.')
        return result
    except (ValueError,UnicodeError) as exc:
        if isinstance(exc,InvalidURL):
            raise
        raise InvalidURL('Malformed website URL.') from None


def lexical_features(url):
    host = urlsplit(url).hostname or ''
    try:
        ipaddress.ip_address(host)
        in_ip = 1
    except ValueError:
        in_ip = 0
    values = {f'qty_{n}_url':url.count(c) for n,c in CHARACTERS.items()}
    values.update({'length_url':len(url),'qty_dot_domain':host.count('.'),
                   'qty_hyphen_domain':host.count('-'),'qty_underline_domain':host.count('_'),
                   'qty_vowels_domain':sum(c in 'aeiou' for c in host.lower()),
                   'domain_length':len(host),'domain_in_ip':in_ip,
                   'server_client_domain':int('server' in host or 'client' in host)})
    return values


class PageParser(HTMLParser):
    def __init__(self,url):
        super().__init__(convert_charrefs=True)
        self.url=url
        self.forms=[]
        self.password_field=False
        self.current=None
        self.resources=[]
        self.text=[]
        self.scripts=[]
        self.ignored=0
        self.script_depth=0
        self.iframe_count=0
        self.meta_redirect=False
        self.base_url=url

    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag in {'script','style','noscript'}:
            self.ignored+=1
        if tag=='script':
            self.script_depth+=1
        if tag=='base' and a.get('href'):
            self.base_url=urljoin(self.url,a['href'])
        if tag=='form':
            self.current={'action':a.get('action',''),'password':False,'overrides':[]}
            self.forms.append(self.current)
        if tag=='input' and (a.get('type') or '').lower()=='password':
            self.password_field=True
            if self.current is not None:
                self.current['password']=True
        if tag in {'input','button'} and a.get('formaction') and self.current is not None:
            self.current['overrides'].append(a['formaction'])
        if tag=='iframe':
            self.iframe_count+=1
        if tag in {'script','img','link','iframe'}:
            ref=a.get('src') or a.get('href')
            if ref:
                self.resources.append(ref)
        if tag=='meta' and (a.get('http-equiv') or '').lower()=='refresh':
            self.meta_redirect=True

    def handle_startendtag(self,tag,attrs):
        self.handle_starttag(tag,attrs)
        self.handle_endtag(tag)

    def handle_endtag(self,tag):
        if tag=='form':
            self.current=None
        if tag=='script':
            self.script_depth=max(0,self.script_depth-1)
        if tag in {'script','style','noscript'}:
            self.ignored=max(0,self.ignored-1)

    def handle_data(self,data):
        if self.script_depth:
            self.scripts.append(data)
        if not self.ignored:
            self.text.append(data)


def content_evidence(url,html):
    p=PageParser(url)
    p.feed(html)
    host=urlsplit(url).hostname
    external=[f for f in p.forms if f['password'] and any(urlsplit(urljoin(p.base_url,target or url)).hostname!=host for target in [f['action']]+f['overrides'])]
    text=' '.join(p.text)
    tokens=re.findall(r'[a-z]+',text.lower())
    scripts=' '.join(p.scripts)
    return {'form_count':len(p.forms),'has_password_field':p.password_field,
            'external_password_form':bool(external),'iframe_count':p.iframe_count,
            'external_resources_count':sum(urlsplit(urljoin(p.base_url,r)).hostname!=host for r in p.resources),
            'has_meta_redirect':p.meta_redirect,'has_suspicious_script':bool(re.search(r'eval\s*\(|unescape\s*\(|window\.status',scripts)),
            'text_length':len(text),'word_count':len(tokens),
            'unique_word_ratio':len(set(tokens))/len(tokens) if tokens else 0.,
            'suspicious_word_count':sum(t in WORDS for t in tokens)}


def warning_signals(url,evidence):
    p=urlsplit(url)
    features=lexical_features(url)
    cases=[
        (p.scheme!='https','missing_https','The URL does not use HTTPS.'),
        (features['domain_in_ip'],'ip_host','The hostname is an IP address.'),
        (p.username is not None,'userinfo','The URL contains a misleading @ user-information section.'),
        (any(s.startswith('xn--') for s in (p.hostname or '').split('.')),'punycode','An internationalized hostname uses punycode; check its spelling.'),
        ((p.hostname or '').count('.')>=4,'many_subdomains','The hostname has a long subdomain chain.'),
        (len(url)>150,'long_url','The URL is unusually long.'),
        (evidence.get('external_password_form'),'external_password_form','A password form submits to a different hostname.'),
        (evidence.get('has_meta_redirect'),'meta_redirect','The page contains an HTML redirect.'),
        (evidence.get('has_suspicious_script'),'script_obfuscation','The page contains potentially suspicious script patterns.'),
    ]
    return [{'code':name,'message':message} for flag,name,message in cases if flag]


def extract_features_from_url(url,html=''):
    values=lexical_features(normalize_url(url))
    return [[values[n] for n in FEATURE_NAMES]],values
