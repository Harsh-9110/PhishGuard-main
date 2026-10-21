"""Offline grouped stratified evaluation and artifact export. Never imported by app."""
import argparse
import hashlib
import json
import time
from pathlib import Path
from feature_extraction import FEATURE_NAMES,SCHEMA_VERSION


def metrics(y,p):
    from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,roc_auc_score,confusion_matrix
    pred=p>=.5
    return {'accuracy':float(accuracy_score(y,pred)),
            'precision':float(precision_score(y,pred,zero_division=0)),
            'recall':float(recall_score(y,pred,zero_division=0)),
            'f1':float(f1_score(y,pred,zero_division=0)),
            'roc_auc':float(roc_auc_score(y,p)),
            'confusion_matrix':confusion_matrix(y,pred,labels=[0,1]).tolist()}


def export_tree(tree,classifier):
    values=tree.value[:,0,:]
    values=values[:,1]/values.sum(axis=1) if classifier else values[:,0]
    return {'left':tree.children_left.tolist(),'right':tree.children_right.tolist(),
            'feature':tree.feature.tolist(),'threshold':tree.threshold.tolist(),'value':values.tolist()}


def export_model(name,model):
    if name=='decision_tree':
        return {'kind':name,'label':'Decision Tree','trees':[export_tree(model.tree_,True)]}
    if name=='random_forest':
        return {'kind':name,'label':'Random Forest','trees':[export_tree(t.tree_,True) for t in model.estimators_]}
    import math
    prior=model.init_.class_prior_
    return {'kind':'gradient_boosting','label':'Gradient Boosting (scikit-learn)',
            'initial_log_odds':math.log(prior[1]/prior[0]),'learning_rate':model.learning_rate,
            'trees':[export_tree(t[0].tree_,False) for t in model.estimators_]}


def main():
    import numpy as np
    import pandas as pd
    import sklearn
    import joblib
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.ensemble import RandomForestClassifier,GradientBoostingClassifier
    from sklearn.model_selection import StratifiedGroupKFold
    from sklearn.base import clone
    from threadpoolctl import threadpool_limits
    from ml_models import probability
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',default='phishing_dataset.csv')
    parser.add_argument('--output',default='artifacts')
    parser.add_argument('--version',default='url-v1')
    args=parser.parse_args()
    if not args.version or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in args.version):
        parser.error('Use an ASCII artifact version identifier.')
    output=Path(args.output)/args.version
    if output.exists():
        raise FileExistsError('Use a new --version; existing artifacts are not overwritten.')
    started=time.monotonic()
    df=pd.read_csv(args.dataset)
    before=len(df)
    duplicates=int(df.duplicated().sum())
    df=df.drop_duplicates().reset_index(drop=True)
    if set(df.phishing.unique())!={0,1} or df[FEATURE_NAMES].isna().any().any():
        raise ValueError('Dataset requires complete features and binary labels.')
    X=df[FEATURE_NAMES].astype(float)
    y=df.phishing.to_numpy(dtype=int)
    if not np.isfinite(X.to_numpy()).all():
        raise ValueError('Nonfinite dataset features.')
    groups=pd.util.hash_pandas_object(X,index=False).to_numpy()
    group_stats=df.assign(_group=groups).groupby('_group').phishing.agg(['size','nunique'])
    train,test=next(StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=42).split(X,y,groups))
    assert not set(groups[train]) & set(groups[test])
    cv=list(StratifiedGroupKFold(n_splits=3,shuffle=True,random_state=43).split(X.iloc[train],y[train],groups[train]))
    models={
        'decision_tree':DecisionTreeClassifier(max_depth=10,min_samples_leaf=8,random_state=42),
        'random_forest':RandomForestClassifier(n_estimators=64,max_depth=12,min_samples_leaf=4,random_state=42,n_jobs=2),
        'gradient_boosting':GradientBoostingClassifier(n_estimators=80,max_depth=3,min_samples_leaf=10,learning_rate=.08,subsample=.8,random_state=42),
    }
    oof=np.zeros((len(train),len(models)))
    cv_results={}
    with threadpool_limits(limits=2):
        for j,(name,model) in enumerate(models.items()):
            folds=[]
            for k,(a,b) in enumerate(cv):
                assert not set(groups[train[a]]) & set(groups[train[b]])
                candidate=clone(model).fit(X.iloc[train[a]],y[train[a]])
                pred=candidate.predict_proba(X.iloc[train[b]])[:,1]
                oof[b,j]=pred
                folds.append(metrics(y[train[b]],pred))
                print(json.dumps({'model':name,'cv_fold':k+1,'f1':folds[-1]['f1']}),flush=True)
            cv_results[name]={'folds':folds,'out_of_fold':metrics(y[train],oof[:,j])}
        soft=metrics(y[train],oof.mean(axis=1))
        hard=metrics(y[train],(oof>=.5).mean(axis=1))
        method='soft_vote' if soft['f1']>=hard['f1'] else 'majority_vote'
        test_probabilities=[]
        exported={}
        measured={}
        export_error={}
        for name,model in models.items():
            model.fit(X.iloc[train],y[train])
            p=model.predict_proba(X.iloc[test])[:,1]
            measured[name]=metrics(y[test],p)
            test_probabilities.append(p)
            exported[name]=export_model(name,model)
            interpreted=np.array([probability(exported[name],row) for row in X.iloc[test].to_numpy()])
            error=float(np.max(np.abs(interpreted-p)))
            if error>1e-10:
                raise ValueError(f'Export parity failed for {name}: {error}')
            export_error[name]=error
            print(json.dumps({'held_out':name,**measured[name],'json_export_max_error':error}),flush=True)
    probs=np.stack(test_probabilities)
    ensemble=metrics(y[test],probs.mean(axis=0))
    if method=='majority_vote':
        hard_metrics=metrics(y[test],(probs>=.5).mean(axis=0))
        hard_metrics['roc_auc']=ensemble['roc_auc']
        ensemble=hard_metrics
    measured['ensemble']=ensemble
    best=max(models,key=lambda n:measured[n]['f1'])
    importance=np.mean([m.feature_importances_ for m in models.values()],axis=0)
    data={'schema_version':SCHEMA_VERSION,'feature_names':FEATURE_NAMES,'models':exported,
          'aggregation':method,'feature_importances':dict(zip(FEATURE_NAMES,importance.tolist()))}
    output.mkdir(parents=True)
    raw=json.dumps(data,separators=(',',':'),allow_nan=False).encode()
    (output/'models.json').write_bytes(raw)
    result={
        'dataset':{'file':str(args.dataset),'sha256':hashlib.sha256(Path(args.dataset).read_bytes()).hexdigest(),
                   'source':'https://github.com/GregaVrbancic/Phishing-Dataset','original_rows':before,
                   'removed_exact_duplicates':duplicates,'retained_rows':len(df),'selected_features':FEATURE_NAMES,
                   'selected_feature_count':len(FEATURE_NAMES),'class_counts':{str(k):int((y==k).sum()) for k in [0,1]},
                   'unique_feature_groups':len(group_stats),'conflicting_label_groups':int((group_stats['nunique']>1).sum()),
                   'rows_in_conflicting_groups':int(group_stats.loc[group_stats['nunique']>1,'size'].sum())},
        'split':{'method':'stratified grouped 5-fold outer split, first fold held out','seed':42,
                 'train_rows':len(train),'test_rows':len(test),'test_class_counts':{str(k):int((y[test]==k).sum()) for k in [0,1]},
                 'overlapping_feature_groups':0,'preprocessing':'none; finite numeric tree inputs',
                 'test_index_sha256':hashlib.sha256(np.sort(test).tobytes()).hexdigest()},
        'cross_validation':{'folds':3,'seed':43,'grouping':'identical selected feature vectors remain in one fold',
                            'models':cv_results,'soft_vote':soft,'majority_vote':hard},
        'aggregation':method,'held_out':measured,'best_single_by_test_f1':best,
        'ensemble_beats_best_single_f1':ensemble['f1']>measured[best]['f1'],
        'json_export_max_absolute_probability_error':export_error,'artifact_bytes':len(raw),
        'sklearn_version':sklearn.__version__,'elapsed_seconds':time.monotonic()-started,
        'limitations':['Historical 2020 dataset; raw URLs unavailable, no temporal or original-domain split.',
                       'Conflicting labels for identical selected feature profiles are retained and grouped.',
                       'Scores are uncalibrated dataset-based estimates, not guarantees of safety.',
                       'HTML/text evidence is rule-based and is outside held-out ML metrics.',
                       'GradientBoostingClassifier replaces unavailable XGBoost; it is not XGBoost.'],
    }
    (output/'metrics.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    training=Path(args.output)/'training'
    training.mkdir(exist_ok=True)
    joblib.dump({'models':models,'features':FEATURE_NAMES,'train_indices':train,'test_indices':test},training/(args.version+'.joblib'))
    (Path(args.output)/'current.json').write_text(json.dumps({'version':args.version,'file':f'{args.version}/models.json','sha256':hashlib.sha256(raw).hexdigest()},indent=2)+'\n')
    print(json.dumps({'aggregation':method,'held_out':measured,'artifact_bytes':len(raw),'elapsed_seconds':result['elapsed_seconds']},indent=2),flush=True)

if __name__=='__main__':
    main()
