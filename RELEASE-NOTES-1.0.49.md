freeSIEM Sentinel 1.0.49
=========================

- Add a built-in, pure-PHP ACME v2 client so SSL issuance/renewal works on shared hosting without certbot (no shell exec, no root) - GoDaddy, Hostinger, and similar shared plans. New "Certificate provider" setting (Automatic / Certbot / PHP ACME client) auto-detects certbot and falls back to the PHP client when it's missing, so existing certbot/VPS installs are unaffected.
- HTTP-01 challenge is served through a built-in WordPress request responder (with a best-effort webroot file write as a second delivery path), so it doesn't depend on shell access or a correctly-guessed webroot path.
- Best-effort automatic certificate install into cPanel via UAPI when cPanel credentials are configured (GoDaddy's usual shared-hosting stack); falls back to "issued, install manually" with the cert/key ready to copy from the Certificate panel when no such API is available (e.g. Hostinger's hPanel).
- Auto-renew for the PHP ACME path only re-issues within the existing ~30-day-before-expiry window, matching certbot's own renewal semantics and avoiding Let's Encrypt rate limits.
