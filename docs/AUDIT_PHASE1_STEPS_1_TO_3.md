# PhishGuard — Phase 1, steps 1–3 checkpoint

## Outcome

Source inspection and local credential exclusion are complete. Dependency
manifests were consolidated, but installation and runtime verification are
blocked by HTTP 403 from PyPI in this environment. The clean virtual environment
contains only pip. **The app has not been demonstrated working. No tests passed,
no models ran, and no model metrics were measured.** Phase 1 is not complete;
steps 4–8 and all of Phases 2–3 remain unstarted.

The input was the user-supplied `PhishGuard-main.zip`. Direct GitHub cloning was
previously denied with HTTP 403. The ZIP contains 19 files and no Git history.
Local commits are review commits based on this snapshot, not descendants of the
upstream GitHub commit. Nothing was pushed or deployed. No leaked credential was
used, and no external database or malicious website was contacted.

## How it really works in the supplied source

`main.py` imports `app.py`. That initializes SQLAlchemy, imports `models.py`, and
calls `db.create_all()`. It then calls `utils.load_dataset()` and trains all
three models during module import. This is startup training in each process,
not artifact loading. There is no offline trainer or saved model artifact.

For `/analyze` or `POST /api/check`, the intended code path is:

1. Read a form value or JSON `url`; prepend `http://` if missing.
2. `utils.is_valid_url()` checks only that parsing produces a scheme and netloc.
3. `check_url_accessibility()` performs a HEAD request, following redirects;
   a 405 response triggers a GET.
4. `extract_features_from_url()` builds 29 ordered URL/text features. Text comes
   from `web_scraper.get_website_text_content()`: Trafilatura fetch/extract,
   followed by Requests/BeautifulSoup as a fallback. NLTK tokenization and
   stopwords supply the text features. Ten HTML feature slots remain defaults:
   the separate `extract_html_features()` function is never called.
5. `predict_phishing()` calls Decision Tree, Random Forest, and XGBoost
   `predict()`/`predict_proba()`. Confidence is the probability of each model's
   predicted class. A majority of class-1 predictions produces the phishing
   verdict; confidence is not an aggregated ensemble probability.
6. Both routes attempt to save three predictions and three confidence values
   in `CheckResult`. UI results and a base64 Matplotlib image are placed in the
   client-side session. The API returns JSON. `/history` queries the latest ten
   rows. PostgreSQL is selected by `DATABASE_URL`, otherwise SQLite is used.
7. The UI then requires missing Jinja templates. There is no supplied Chart.js
   implementation or browser extension. This flow is a source trace, not an
   executed end-to-end result.

## Files read and dataset inventory

All supplied text/code/config files were read. `uv.lock` was fully parsed before
removal; every CSV row was read; `generated-icon.png` was fully decoded as a
1024 × 1024 RGB PNG. `.env` was inspected only in memory, without displaying or
extracting its value.

The 19 input files were `.env`, `.gitignore`, `.replit`, `README.md`, `app.py`,
`connect_db.py`, `feature_extraction.py`, `generated-icon.png`, `main.py`,
`ml_models.py`, `models.py`, `phishing_dataset.csv`, `pyproject.toml`,
`requirements-vercel.txt`, `requirements.txt`, `utils.py`, `uv.lock`,
`vercel.json`, and `web_scraper.py`.

| Dataset property | Observed value |
| --- | --- |
| Rows | 88,647 |
| Columns | 112 |
| Input features selected by current loader | 111 |
| Target column | `phishing` (last column) |
| Target 0 | 58,000 rows |
| Target 1 | 30,647 rows |
| Runtime extractor fields, counted from the AST | 29 |

The code treats 1 as phishing. Independent label provenance, label quality,
duplicate analysis, cross-validation, and held-out model evaluation are not
complete at this checkpoint. Counts above are an inventory, not performance
metrics. There is no basis here to claim any accuracy, precision, recall, F1,
ROC-AUC, or confusion matrix.

## Credential work

`DATABASE_URL` is the only key in the supplied `.env`; its non-placeholder URI
contains a PostgreSQL username and password. No API key was present there.
The working tree and its local Git history exclude the file entirely.
`.gitignore` already listed `.env`; it now also excludes environment variants,
virtual environments, caches, local DB files, and audit intermediates while
allowing `.env.example`.

Manual action: rotate the database-role password, update deployed connection
strings, and configure a fresh `SESSION_SECRET` instead of the public fallback.
Exact git-filter-repo and BFG history-cleanup commands are in
[`CREDENTIAL_CLEANUP.md`](CREDENTIAL_CLEANUP.md). Remote history was unavailable
and has not been purged. Prior uploads/copies can still contain the old value.

## Dependency changes

`requirements.txt` is now the canonical UTF-8 runtime pin list.
`requirements-vercel.txt` delegates to it, and `pyproject.toml` reads the same
file using setuptools dynamic metadata. Python 3.11+ remains the project
requirement. The audit interpreter is Python 3.12.14.

The former requirements file was UTF-16 and installed both `psycopg2` and
`psycopg2-binary`. The source distribution was removed; the binary driver
remains. Shared requirements include `flask-cors` and `python-dotenv`, both
missing from the old Vercel list. Existing versions were preserved. The old
lock's Linux conditional NCCL pin was carried into the canonical list, making
62 unique runtime pins. GPU-related packaging has not been optimized or sized
for Vercel in this checkpoint.

The conflicting `uv.lock` was removed. No replacement lock was fabricated:
network access prevented a new resolution. The supported uv route is
`uv pip install -r requirements.txt`, rather than `uv sync`. This consolidation
was checked structurally and parsed by pip, but a successful installation,
package build, vulnerability assessment, and deployment remain unverified.

## Actual execution results

Commands ran from the repository in a newly created `.venv`, with system site
packages disabled. Environment/cache directories were scoped to the repository
for the final command runs, and `DATABASE_URL`/`SESSION_SECRET` were removed from
their process environments. The exposed `.env` was absent.

| Command/check | Actual result |
| --- | --- |
| `python -m venv .venv` | Created successfully; system site packages disabled |
| Original `pip install -r requirements-vercel.txt` | Exit 1; no package candidates |
| Original install with default pip configuration | Exit 1; same failure |
| Verbose install of `beautifulsoup4==4.13.4` | Exit 1; index request returned HTTP 403; full resolver traceback saved |
| Consolidated `pip install -r requirements.txt` | Exit 1 at `babel==2.17.0`; no package candidates |
| `.venv/bin/python main.py` | Exit 1; `ModuleNotFoundError: No module named 'pandas'` |
| `.venv/bin/python connect_db.py` | Exit 1; `ModuleNotFoundError: No module named 'psycopg2'` |
| `.venv/bin/python -m pytest -q` | Exit 1; pytest is not installed; zero existing test files |
| `.venv/bin/python -m gunicorn --bind 127.0.0.1:5000 main:app` | Exit 1; Gunicorn is not installed |
| `.venv/bin/python -m pip list --format=json` | Exit 0; only pip 25.0.1 installed |
| AST syntax parsing | 8 original Python modules parsed successfully; no imports |
| Dependency/ignore/venv structural checks | Passed; these are not app or model tests |

Representative output:

```text
https://pypi.org:443 "GET /simple/beautifulsoup4/ HTTP/1.1" 403 45
ERROR: No matching distribution found for beautifulsoup4==4.13.4

Traceback (most recent call last):
  File "/workspace/scratch/468f8f77bc49/PhishGuard/main.py", line 1, in <module>
    from app import app
  File "/workspace/scratch/468f8f77bc49/PhishGuard/app.py", line 4, in <module>
    import pandas as pd
ModuleNotFoundError: No module named 'pandas'
```

Full captured output, the pip traceback, command exit codes, source-only checks,
and dataset inventory are in [`audit/evidence/`](audit/evidence/). Early audit
diagnostics also record two recovered issues: the original UTF-16 requirements
file rejected an initial UTF-8 read, and preserved CRLF endings caused a first
whitespace check to fail. The modified files were normalized to LF and final
diff checks passed.

To unblock execution, use an environment with PyPI/package-download access or
supply a compatible offline Linux x86-64 / CPython 3.12 wheelhouse. This is a
network restriction; changing package versions is not a demonstrated remedy.

## Bug list and current disposition

The source findings below have not been reproduced as application failures
because dependencies could not be installed. The missing-import startup
failures above are the runtime failures actually observed.

| File/path | Finding | Fix or disposition at this checkpoint |
| --- | --- | --- |
| `.env` | Credential-bearing database URI included in input | Excluded from source, export, and local commits; rotation and upstream purge remain manual |
| `.gitignore` | Existing `.env` rule cannot untrack a previously committed file | Expanded ignores; example remains trackable; cleanup commands documented |
| Dependency manifests | Conflicting versions, Vercel imports missing, duplicate PostgreSQL drivers, stale lock | Consolidated as described above; install verification blocked |
| `templates/`, `static/`, `extension/` | Absent despite README promises | Deferred to Phase 1 step 4 |
| `vercel.json` | Points to absent `api/index.py`; Python 3.9 conflicts with project 3.11+ | Deferred to Phase 1 serverless repair; Vercel deployment not verified |
| `app.py`, `ml_models.py` | Schema creation and model training during import; no persisted model artifacts | Deferred to offline-training repair in step 5 |
| `utils.py`, `feature_extraction.py` | Training receives 111 scaled fields; inference produces 29 raw fields; scaler is discarded | Verified source mismatch; requires a consistent, reproducible training/inference schema |
| `utils.py`, `ml_models.py` | Imputation/scaling fit before split; split is unstratified; no CV | Deferred to leakage/split/training repair |
| `utils.py` | Dataset-load failure silently trains on random synthetic labels | Deferred to removal of misleading fallback; no synthetic results generated here |
| `feature_extraction.py`, `web_scraper.py` | HTML feature function unused; ten fields stay defaults; domain age fixed at -1 | Deferred to feature repair and local-fixture tests |
| `feature_extraction.py` | IP regex searches the whole URL; NLTK downloads during import | Deferred to feature/NLP provisioning repair |
| `web_scraper.py` | Primary Trafilatura fetch ignores the supplied timeout; no explicit response-size/SSRF controls | Deferred to scraper error handling; full SSRF hardening belongs to Phase 2 |
| `app.py` | JSON `null`/non-object input can reach unguarded `.get()` outside try block | Deferred to API input repair/tests |
| `app.py` | Failed DB commits are caught without rollback; analysis can report success without history | Deferred to DB repair/tests; no live PostgreSQL verification performed |
| `app.py` | Chart ranks raw feature magnitudes, not learned importance; image stored in client-side session | Deferred to UI/feature-importance repair |
| `app.py`, `main.py` | Public session fallback, wildcard API CORS, debug launch | Session configuration documented; remaining hardening tracked for subsequent authorized work |
| Tests, `/healthz`, CI | Absent | Tests/health deferred to Phase 1 step 8; CI is Phase 2 |

## Review and stop gate

The export includes source, this report, full evidence, small review patches,
and a sanitized local-history Git bundle. It excludes `.env`, installed
environments, caches, local databases, and private audit intermediates.
See `review/README.txt` for applying changes to the actual upstream checkout.

**STOP: this is the requested steps 1–3 checkpoint.** Phase 1 still needs its
remaining repairs and successful runtime verification before its phase gate can
be passed. No Phase 2 enhancements or AWS resources were created.
