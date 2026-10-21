# PhishGuard extension (Manifest V3)

1. Run PhishGuard locally or configure its Vercel deployment.
2. Open `chrome://extensions`, enable Developer mode, choose **Load unpacked**,
   and select this `extension/` directory.
3. Copy the extension's exact origin (`chrome-extension://EXTENSION_ID`, also
   shown in the popup) into the API's `ALLOWED_ORIGINS` environment variable.
   Restart the local app or redeploy after changing environment settings.
4. In the popup, set the API base to `http://127.0.0.1:5000` for local development
   or your HTTPS Vercel URL. Choose **Save API & grant access**; grant just the
   configured API host permission.
5. Open a public HTTP(S) site and choose **Check current page**. Review per-model
   scores and page warnings. Use **Load history** for this extension's history.

The extension generates a secret random `X-Client-Key` in local extension
storage; it is used to scope its history across popups without third-party
cookies. Do not share it. Clearing extension storage changes history identity.
Browser and extension histories are separate anonymous scopes. No global scan
history is exposed. Host access is optional and requested on demand; `activeTab`
reads only the current tab after the user invokes the extension.

The API's private-address protections apply to the website being analyzed, not
to the developer's loopback API base. Internal/private sites cannot be scanned.
Remote APIs must use HTTPS. Requests time out with a clear popup message.
Chrome click behavior is not claimed tested in the restricted environment;
the same API/CORS/key-isolation paths are covered by executed integration tests.
