# PhishGuard

PhishGuard checks a public website for phishing risk using real trained URL
classifiers and separately reported HTML/text evidence. The API, web form,
per-browser history, and Manifest V3 extension share the same analysis service.

**Verified locally:** real fixture HTTP fetch → feature extraction → three trained
models → content warnings → committed SQLite history → saved-result API and UI.
See `docs/verification/` for actual test, startup, and training output.

## Run locally — Python 3.12 only

The shipped JSON inference, HTTP core, HTML parser, and SQLite storage need no
third-party packages. Network access is not needed to start the app or run its
test suite. Public website scans naturally require outbound DNS/HTTP access.

From the unpacked repository directory:

```bash
py -3.12 -m venv .venv
.venv/bin/python connect_db.py --check
.venv/bin/python main.py --port 5000
```

Open **http://127.0.0.1:5000**. The local server binds to loopback by default;
Vercel uses the separate production HTTP entrypoint. On Windows, substitute
`.venv\Scripts\python.exe` for `.venv/bin/python`.

SQLite is created at `instance/phishguard.db`; an ignored, private
`instance/session.key` keeps browser history accessible across local restarts.
Exported environment variables take precedence. `.env` is not loaded implicitly.

```bash
.venv/bin/python -m unittest discover -s tests -v
# In another terminal while the app is running:
.venv/bin/python scripts/smoke.py --base http://127.0.0.1:5000
```

The tests exercise real loopback HTTP HTML fixtures using an injected test
transport. Production address validation is never relaxed. No live malicious
sites are visited by tests. Browser click QA and live PostgreSQL checks require
external dependencies/services; skipped tests identify those requirements.

## Architecture and dependency choices

- `feature_extraction.py`: the same 25 documented lexical features in training
  and inference. No padding, synthetic labels, or discarded scaler.
- `train.py`: offline grouped stratified evaluation and versioned JSON/joblib
  export. The app never imports it or trains on startup/request.
- `ml_models.py`: JSON-only tree inference, verified against scikit-learn on
  every held-out row. No pickle/joblib deserialization at runtime.
- `web_scraper.py`: one bounded page fetch, public-address validation, DNS pinning,
  verified HTTPS, redirect revalidation, 8-second total deadline, 1 MB size cap,
  three-redirect limit, and HTML-only responses. Only ports 80/443 are fetched.
- `service.py`: shared WSGI application, validation, structured JSON errors,
  browser sessions, form CSRF checks, exact CORS allowlist, request IDs, security
  headers, and database-backed scan rate limiting (default 20/minute per server
  remote address). No trust in client-supplied forwarding headers.
- `models.py` and `migrations/001_history.sql`: transactional history and atomic
  rate limits for SQLite or PostgreSQL. A scan is successful only after commit.
- `app.py`: uses the real Flask adapter when Flask is installed, otherwise the
  same WSGI application runs directly. The missing Flask package is not mocked.
- `api/index.py`: Vercel Python HTTP handler delegating to that same application.
- `templates/`, `static/`: responsive form, verdict, actual per-model scores,
  learned global-importance chart, saved results and private history.

Restricted registries prevented Flask/XGBoost/NLTK/Trafilatura installation here.
To deliver a runnable product, GradientBoostingClassifier replaces XGBoost and
is labeled accurately. The standard-library HTML parser/tokenizer replaces
NLTK/Trafilatura, and a native chart replaces the missing Chart.js integration.
Content is inspected but scripts are never executed. These are deliberate
component replacements, not claims that unavailable packages were executed.

`requirements.txt` pins the optional Flask/PostgreSQL production adapters;
`pyproject.toml`, `requirements-vercel.txt`, and the PostgreSQL compatibility
entrypoint reference that list. Training and optional pytest dependencies are
separate. Runtime excludes NumPy, pandas, sklearn, XGBoost, and NLTK. No new
`uv.lock` was fabricated while registry access was blocked.

## Model evaluation and retraining

The supplied CSV matches the documented shape/class counts of the
[Vrbančič phishing dataset](https://github.com/GregaVrbancic/Phishing-Dataset).
Its 88,647 rows contain 1,438 full duplicate rows, removed before splitting.
Identical selected feature profiles remain in one fold; 1,070 profiles have
conflicting labels and were retained, not relabeled. Raw URLs and a reliable
chronological/domain split are unavailable. Features with unavailable online
measurements or ambiguous extraction semantics are excluded.

<!-- METRICS:START -->
Measured on **17,441 held-out rows**, with 69,768 training rows and three grouped CV folds. Aggregation selected on training CV: **majority_vote**.

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| decision tree | 91.65% | 0.8821 | 0.8785 | 0.8803 | 0.9687 |
| random forest | 91.73% | 0.8758 | 0.8895 | 0.8826 | 0.9734 |
| gradient boosting | 91.04% | 0.8572 | 0.8924 | 0.8744 | 0.9701 |
| ensemble | 91.83% | 0.8771 | 0.8913 | 0.8841 | 0.9732 |

Ensemble confusion matrix `[ [TN, FP], [FN, TP] ]`: `[[10580, 762], [663, 5436]]`.
The ensemble exceeds the best single model's held-out F1; no statistical significance is claimed.
Maximum JSON inference probability error against scikit-learn across every held-out row: `6.66e-16`.
Full per-fold metrics, split details and limitations: `artifacts/url-v1/metrics.json`.
<!-- METRICS:END -->

The shipped artifact stays fitted on its training partition. Its probabilities
are uncalibrated estimates, not guarantees of safety. Content rules are not
included in the ML metrics: a password form submitting to another hostname can
flag a page even when URL model scores are low. Legitimate single sign-on can
also trigger this rule. No claims are made about live modern-web accuracy.

To reproduce training in an environment with registry access:

```bash
python3.12 -m venv .train-venv
.train-venv/bin/python -m pip install -r requirements-train.txt
.train-venv/bin/python train.py --version url-v2
.train-venv/bin/python scripts/update_metrics.py
```

Existing artifact versions are never overwritten. Review the new metrics and
`artifacts/current.json` before committing. Both JSON deployment artifacts and
versioned joblib training checkpoints are provided. Runtime reads only the
SHA-256 checked JSON artifact; training data/checkpoints are excluded on Vercel.

## API

```bash
curl -sS -X POST http://127.0.0.1:5000/api/check \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.wikipedia.org"}'
```

Use an accessible **public** HTML website. Invalid URLs return 400, blocked
addresses/origins 403, unsupported request types 415, oversized pages/requests
413, unsupported pages/redirect failures 422, rate limits 429, fetch timeouts
504, and unavailable models/history 503. Errors have the shape
`{"error":{"code":"...","message":"...","request_id":"..."}}`.

Successful responses include `is_phishing`, `model_is_phishing`, the mean ML
`risk_score`, actual per-model `confidence`, `predictions`, `models`, observed
`signals` and `content`, learned `feature_importance`, and a saved scan `id`.
The verdict uses the CV-selected vote plus the separately identified content
rule. The mean model score does not include a fabricated content probability.

`GET /healthz` checks the loaded artifacts and database; `/api/model-info` exposes
recorded evaluation metrics. `/api/history` and `/api/results/<id>` are scoped
to a signed browser cookie or a secret 64-hex `X-Client-Key` generated by the
extension. Knowing a scan ID alone grants no access. This is anonymous scoped
history, not an account/login system. Queries/HTML/credentials are not logged.

## PostgreSQL and Vercel

The Vercel configuration disables framework autodetection and routes through
`api/index.py` on Python 3.12. It excludes the dataset, tests, offline trainer,
joblib checkpoints, caches, and old review files. The JSON model is about
1.48 MB. Actual deployed dependency size and a Vercel cloud build have not been
measured in this environment.

1. **Rotate the exposed PostgreSQL password first.** See
   `docs/CREDENTIAL_CLEANUP.md`; no remote Git history was rewritten or pushed.
2. Import the updated repository into Vercel. Set the root directory to the
   folder containing `vercel.json`; use the **Other** preset and leave custom
   build/output commands unset. Do not upload `.env` or `instance/`.
3. In Vercel project environment settings, configure:
   - `DATABASE_URL`: your rotated PostgreSQL URI, including `sslmode=require`.
   - `SESSION_SECRET`: a fresh random secret of at least 32 characters.
   - `ALLOWED_ORIGINS`: exact extension origin(s), comma-separated, if used.
   - `RATE_LIMIT_PER_MINUTE`: optional positive integer (default 20).
4. Deploy. Check `/healthz`; it must return 200 with `database: "postgresql"`.
   A missing secret/database fails closed; Vercel never silently uses temporary
   SQLite history. The additive migration runs once per instance as needed.
5. Run `scripts/smoke.py --base https://YOUR-DEPLOYMENT.vercel.app` and enable the
   real PostgreSQL integration test with `TEST_DATABASE_URL` before production.

For PostgreSQL locally, install `python -m pip install -r requirements.txt`,
export `DATABASE_URL` and `SESSION_SECRET` using your shell, then run
`python connect_db.py --check` and `python main.py`. `connect_db.py` applies an
idempotent additive migration and exits nonzero on failure without printing the
connection string. Legacy `check_result` tables are preserved untouched; their
unowned rows are not exposed to new anonymous sessions.

Network restrictions prevented installing these production adapters or using a
rotated live database here. Flask adapter and PostgreSQL integration tests are
explicitly skipped locally; CI includes a real ephemeral PostgreSQL service to
exercise them when dependencies are accessible. CI configuration has not been
run on GitHub in this session.

Vercel's standard Python bundle limit and entrypoint support are described in
[its runtime documentation](https://vercel.com/docs/functions/runtimes/python).
Flask's [security-fix release](https://flask.palletsprojects.com/en/stable/changes/)
and [psycopg's package](https://pypi.org/project/psycopg/) inform the adapter pins;
this is not a completed vulnerability scan. Use Vercel's edge controls for
abuse prevention: behind a proxy, the database limiter may group users sharing
one server-reported address. Application fetching is bounded; provider quotas,
concurrency and database capacity still need operational monitoring.

## Browser extension

See `extension/README.md` and `extension/API_TESTING.md`. The popup supports a
configurable API base URL, grants only that host on demand, checks the active
HTTP(S) tab, shows actual scores/evidence, and retrieves its own history.
It does not scrape page content locally or grant itself access to all sites.
Chrome installation/click behavior could not be verified without its binary.

## Remaining verification and deployment status

Local WSGI inference, safe fixture HTTP fetches, SQLite persistence, route/API
integration, classic form submission, and the Vercel HTTP adapter are executed
and tested. Browser JavaScript syntax is checked. Browser-rendered interaction,
Flask execution, live PostgreSQL, package vulnerability scanning, and a Vercel
cloud build/deployment remain unverified due unavailable services/downloads.
The project is usable locally; the supplied Vercel setup is ready for a staging
attempt after secrets/database configuration, not a production certification.

Original project by Harsh. Historical audit evidence remains under `docs/audit/`.
