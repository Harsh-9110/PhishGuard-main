import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from ml_models import ModelBundle,ModelError,tree_value
from feature_extraction import lexical_features,FEATURE_NAMES

class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.bundle=ModelBundle()
    def test_real_three_models(self):
        self.assertEqual(set(self.bundle.models),{'decision_tree','random_forest','gradient_boosting'})
        r=self.bundle.predict(lexical_features('https://www.wikipedia.org'))
        self.assertEqual(len(r['models']),3)
        for m in r['models'].values():
            self.assertGreaterEqual(m['confidence'],.5)
            self.assertLessEqual(m['confidence'],1)
            self.assertAlmostEqual(m['confidence'],max(m['phishing_probability'],1-m['phishing_probability']))
    def test_verdict_aggregation(self):
        r=self.bundle.predict(lexical_features('http://verify.account.login.example.net/banking?x=1'))
        expected=sum(v>=1 for v in r['predictions'].values())>1 if r['aggregation']=='majority_vote' else r['risk_score']>=.5
        self.assertEqual(r['is_phishing'],expected)
    def test_feature_contract(self):
        self.assertEqual(len(FEATURE_NAMES),25)
        with self.assertRaises(KeyError):self.bundle.predict({})
        features=lexical_features('https://example.org');features[FEATURE_NAMES[0]]=float('nan')
        with self.assertRaises(ModelError):self.bundle.predict(features)
    def test_missing_and_tampered_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ModelError):ModelBundle(directory)
            p=Path(directory);(p/'model.json').write_text('{}')
            (p/'current.json').write_text(json.dumps({'version':'bad','file':'model.json','sha256':'0'*64}))
            with self.assertRaises(ModelError):ModelBundle(directory)
    def test_schema_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);raw=json.dumps({'schema_version':'wrong','feature_names':[]}).encode();(p/'model.json').write_bytes(raw)
            (p/'current.json').write_text(json.dumps({'version':'bad','file':'model.json','sha256':hashlib.sha256(raw).hexdigest()}))
            with self.assertRaises(ModelError):ModelBundle(directory)
    def test_recorded_export_parity_and_split(self):
        m=json.loads(Path('artifacts/url-v1/metrics.json').read_text())
        self.assertEqual(m['split']['overlapping_feature_groups'],0)
        self.assertEqual(m['cross_validation']['folds'],3)
        self.assertEqual(m['split']['test_rows'],17441)
        self.assertTrue(all(e<1e-10 for e in m['json_export_max_absolute_probability_error'].values()))
        for v in m['held_out'].values():self.assertEqual(sum(map(sum,v['confusion_matrix'])),17441)
