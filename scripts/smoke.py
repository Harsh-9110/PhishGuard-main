"""Network-safe smoke check of a running PhishGuard service; never visits a target page."""
import argparse
import json
from urllib.request import urlopen,Request
from urllib.error import HTTPError

parser=argparse.ArgumentParser()
parser.add_argument('--base',default='http://127.0.0.1:5000')
args=parser.parse_args()
base=args.base.rstrip('/')
for path in ['/healthz','/','/static/app.js','/static/style.css','/api/model-info']:
    with urlopen(base+path,timeout=10) as response:
        data=response.read()
        if response.status!=200:raise RuntimeError('Smoke check failed: '+path)
        print(path,response.status,len(data),'bytes')
request=Request(base+'/api/check',data=json.dumps({'url':'file:///etc/passwd'}).encode(),headers={'Content-Type':'application/json'})
try:
    urlopen(request,timeout=10)
except HTTPError as error:
    if error.code!=400:raise
    print('/api/check rejects non-web URL:',error.code)
else:
    raise RuntimeError('A non-web URL was accepted.')
