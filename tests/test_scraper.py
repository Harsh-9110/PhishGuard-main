import socket
import time
import unittest
from unittest.mock import patch
from tests.support import FixtureNetwork,PUBLIC
from web_scraper import SafeFetcher,ScrapeError,resolve_public

class ScraperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.network=FixtureNetwork().__enter__()
    @classmethod
    def tearDownClass(cls):cls.network.__exit__()
    def test_real_http_fixture_and_pinning(self):
        before=len(self.network.connected)
        page=self.network.fetcher().fetch('http://www.wikipedia.org/legitimate')
        self.assertIn('Community encyclopedia',page.html)
        self.assertEqual(page.status,200)
        self.assertEqual(self.network.connected[before],(PUBLIC,80))
    def test_redirect_checked_and_content_fetched(self):
        before=len(self.network.resolved)
        page=self.network.fetcher().fetch('http://www.wikipedia.org/redirect')
        self.assertEqual(page.redirects,1)
        self.assertEqual(len(self.network.resolved)-before,2)
    def test_private_redirect_denied(self):
        with self.assertRaises(ScrapeError) as c:self.network.fetcher().fetch('http://www.wikipedia.org/private')
        self.assertEqual(c.exception.code,'blocked_address')
    def test_error_cases(self):
        cases={'loop':'redirect_loop','chain0':'too_many_redirects','nonhtml':'non_html','large':'page_too_large',
               'stream-large':'page_too_large','empty':'empty_page','500':'upstream_status','gzip':'unsupported_encoding','charset':'bad_charset','bad-redirect':'bad_redirect'}
        for path,code in cases.items():
            with self.subTest(path=path):
                with self.assertRaises(ScrapeError) as c:self.network.fetcher().fetch('http://www.wikipedia.org/'+path)
                self.assertEqual(c.exception.code,code)
    def test_timeout_and_slow_drip_bound(self):
        for path in ['timeout','trickle']:
            start=time.monotonic()
            with self.assertRaises(ScrapeError) as c:self.network.fetcher(timeout=.12).fetch('http://www.wikipedia.org/'+path)
            self.assertEqual(c.exception.code,'timeout')
            self.assertLess(time.monotonic()-start,.4)
    def test_deny_private_reserved_and_mapped(self):
        for ip in ['127.0.0.1','10.0.0.1','172.16.0.1','192.168.1.1','169.254.169.254','0.0.0.0','224.0.0.1','::1','fe80::1','fc00::1','::ffff:127.0.0.1','2001:db8::1']:
            with self.subTest(ip=ip):
                resolver=lambda *a,**k:[(0,0,0,'',(ip,80))]
                with self.assertRaises(ScrapeError):resolve_public('example.org',80,1,resolver)
    def test_mixed_dns_answers(self):
        resolver=lambda *a,**k:[(0,0,0,'',(PUBLIC,80)),(0,0,0,'',('127.0.0.1',80))]
        with self.assertRaises(ScrapeError):resolve_public('example.org',80,1,resolver)
    def test_dns_rebinding_on_redirect(self):
        calls=[]
        def resolver(*args,**kwargs):
            calls.append(1)
            return [(0,0,0,'',((PUBLIC if len(calls)==1 else '127.0.0.1'),80))]
        fetcher=SafeFetcher(resolver=resolver,connector=self.network.connector)
        with self.assertRaises(ScrapeError) as c:fetcher.fetch('http://www.wikipedia.org/redirect')
        self.assertEqual(c.exception.code,'blocked_address')
        self.assertEqual(len(calls),2)
    def test_dns_errors_and_timeout(self):
        def failure(*a,**k):raise socket.gaierror('fixture')
        with self.assertRaises(ScrapeError) as c:resolve_public('example.org',80,.2,failure)
        self.assertEqual(c.exception.code,'dns_failed')
        def slow(*a,**k):time.sleep(.15);return []
        with self.assertRaises(ScrapeError) as c:resolve_public('example.org',80,.02,slow)
        self.assertEqual(c.exception.code,'timeout')
    def test_nonweb_port(self):
        with self.assertRaises(ScrapeError) as c:self.network.fetcher().fetch('http://www.wikipedia.org:22/')
        self.assertEqual(c.exception.code,'blocked_port')
    def test_https_downgrade(self):
        # TLS plumbing is mocked here, never disabled in the shipped fetcher.
        from web_scraper import PinnedHTTP
        with patch('web_scraper.PinnedHTTPS',PinnedHTTP):
            with self.assertRaises(ScrapeError) as c:self.network.fetcher().fetch('https://www.wikipedia.org/downgrade')
        self.assertEqual(c.exception.code,'https_downgrade')
