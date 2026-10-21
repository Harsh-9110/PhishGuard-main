"""Verified JSON tree inference; no training, pickle or ML packages at runtime."""
import hashlib
import json
import math
from pathlib import Path
from feature_extraction import FEATURE_NAMES,SCHEMA_VERSION

class ModelError(RuntimeError):
    pass


def tree_value(tree,row):
    node=0
    while tree['left'][node]!=-1:
        node=tree['left'][node] if row[tree['feature'][node]]<=tree['threshold'][node] else tree['right'][node]
    return tree['value'][node]


def probability(model,row):
    values=[tree_value(t,row) for t in model['trees']]
    if model['kind']=='gradient_boosting':
        raw=model['initial_log_odds']+model['learning_rate']*sum(values)
        return 1./(1.+math.exp(-max(-700,min(700,raw))))
    return sum(values)/len(values)


class ModelBundle:
    def __init__(self,directory=None):
        root=Path(directory or Path(__file__).parent/'artifacts').resolve()
        try:
            manifest=json.loads((root/'current.json').read_text())
            path=(root/manifest['file']).resolve()
            if not path.is_relative_to(root):
                raise ModelError('Invalid artifact path.')
            raw=path.read_bytes()
            if hashlib.sha256(raw).hexdigest()!=manifest['sha256']:
                raise ModelError('Model artifact integrity check failed.')
            data=json.loads(raw)
            if data['schema_version']!=SCHEMA_VERSION or data['feature_names']!=FEATURE_NAMES:
                raise ModelError('Model/extractor feature schema mismatch.')
            self.models=data['models']
            self.version=manifest['version']
            self.method=data['aggregation']
            self.importances=data['feature_importances']
            if not self.models or self.method not in {'soft_vote','majority_vote'}:
                raise ModelError('Unsupported model bundle.')
        except (OSError,KeyError,TypeError,ValueError) as exc:
            raise ModelError('Model artifacts unavailable or invalid; run train.py offline.') from exc

    def predict(self,features):
        row=[float(features[n]) for n in FEATURE_NAMES]
        if any(not math.isfinite(v) for v in row):
            raise ModelError('Nonfinite inference features.')
        scores={name:probability(m,row) for name,m in self.models.items()}
        results={name:{'prediction':int(p>=.5),'phishing_probability':p,'confidence':max(p,1-p),'label':self.models[name]['label']} for name,p in scores.items()}
        score=sum(scores.values())/len(scores)
        verdict=score>=.5 if self.method=='soft_vote' else sum(p>=.5 for p in scores.values())>len(scores)/2
        return {'is_phishing':bool(verdict),'risk_score':score,
                'confidence':{n:r['confidence'] for n,r in results.items()},
                'predictions':{n:r['prediction'] for n,r in results.items()},
                'models':results,'model_version':self.version,'aggregation':self.method}
