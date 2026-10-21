"""Regenerate the README's metric table from the active offline evaluation."""
import json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
current=json.loads((root/'artifacts/current.json').read_text())
m=json.loads((root/'artifacts'/current['version']/'metrics.json').read_text())
lines=[f"Measured on **{m['split']['test_rows']:,} held-out rows**, with {m['split']['train_rows']:,} training rows and three grouped CV folds. Aggregation selected on training CV: **{m['aggregation']}**.",'',
       '| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |','| --- | ---: | ---: | ---: | ---: | ---: |']
for name,v in m['held_out'].items():
    lines.append(f"| {name.replace('_',' ')} | {v['accuracy']:.2%} | {v['precision']:.4f} | {v['recall']:.4f} | {v['f1']:.4f} | {v['roc_auc']:.4f} |")
lines+=['',f"Ensemble confusion matrix `[ [TN, FP], [FN, TP] ]`: `{m['held_out']['ensemble']['confusion_matrix']}`.",
        f"The ensemble {'exceeds' if m['ensemble_beats_best_single_f1'] else 'does not exceed'} the best single model's held-out F1; no statistical significance is claimed.",
        f"Maximum JSON inference probability error against scikit-learn across every held-out row: `{max(m['json_export_max_absolute_probability_error'].values()):.3g}`.",
        'Full per-fold metrics, split details and limitations: `artifacts/'+current['version']+'/metrics.json`.']
p=root/'README.md';text=p.read_text();start='<!-- METRICS:START -->';end='<!-- METRICS:END -->'
after=text.split(start,1)[1].split(end,1)[1]
p.write_text(text.split(start,1)[0]+start+'\n'+'\n'.join(lines)+'\n'+end+after)
print('README metrics generated from',current['version'])
