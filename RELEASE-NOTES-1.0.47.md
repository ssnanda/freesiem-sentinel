freeSIEM Sentinel 1.0.47
=========================

- Fix SSL auto-renew: wire the Auto-renew toggle to a real daily WP-Cron job that renews the certificate and reloads nginx (previously stored-only, never scheduled); exclude /.well-known/acme-challenge/ from the generated HTTPS redirect so future renewals aren't broken by it; reload nginx opportunistically via passwordless sudo when available, falling back to the existing manual-reload state otherwise.
