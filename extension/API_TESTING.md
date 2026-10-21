# API testing

From the project root, execute:

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python main.py --port 5000
```

In another terminal:

```bash
.venv/bin/python scripts/smoke.py --base http://127.0.0.1:5000
curl -i http://127.0.0.1:5000/healthz
curl -i -X POST http://127.0.0.1:5000/api/check \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://www.wikipedia.org"}'
```

The last request actually visits a public website and needs outbound network
access. Use the test suite's local HTML fixtures for deterministic verification;
there is no production bypass flag for fetching loopback/private destinations.
Errors return a JSON `error` object with `code`, `message`, and `request_id`.

Test CORS after configuring an exact extension origin:

```bash
curl -i -X OPTIONS http://127.0.0.1:5000/api/check \
  -H 'Origin: chrome-extension://YOUR_EXTENSION_ID' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: Content-Type,X-Client-Key'
```

Expect 204 for an allowlisted origin and 403 otherwise. The popup creates its
own random 64-hex client key and sends it in `X-Client-Key`. Requests using the
same secret key share their own history; another key cannot read it.

To run browser UI QA when Playwright and Chromium are installed:

```bash
.venv/bin/python -m tests.serve_fixtures --port 5061
# In another terminal with Playwright available to Node:
node scripts/browser_check.cjs
```

The explicit test server injects only a test transport mapping a validated public
address to a local fixture server. It is excluded from Vercel and is never used
by `main.py`. This checks real fetching, real model inference and persistence;
it is not a hardcoded verdict or a synthetic trained model.
