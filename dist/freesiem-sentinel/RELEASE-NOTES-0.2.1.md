# freeSIEM Sentinel 0.2.1

## Highlights

- adds a signed `GET /wp-json/freesiem-sentinel/v1/cloud-connect/users` endpoint under the existing `freesiem-sentinel/v1` namespace
- reuses Sentinel's existing `X-freeSIEM-*` HMAC request verification flow for remote user-list reads
- returns only safe user metadata: `id`, `username`, `email`, `display_name`, and `roles`
- advertises `supports_remote_user_listing` in heartbeat metadata for easier Core-side capability detection

## Included tests

- route registration and namespace exposure
- valid signed `GET` request handling
- invalid signature rejection
- response schema and sensitive-field exclusion
- empty user list behavior
