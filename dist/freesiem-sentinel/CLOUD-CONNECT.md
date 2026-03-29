# freeSIEM Cloud Connect MVP

## Local Option Keys

Cloud Connect state is stored inside the existing `freesiem_sentinel_settings` option.

- `plugin_uuid`
- `local_seed`
- `connection_state`
- `connection_id`
- `email`
- `phone`
- `site_id`
- `api_key`
- `hmac_secret`
- `registration_status`
- `last_heartbeat_at`
- `last_heartbeat_result`
- `allow_remote_scan`
- `scan_frequency`
- `user_sync_enabled`
- `connect_expires_at`

Legacy keys such as `phone_number` and `cloud_connection_state` are kept in sync for backward compatibility with older plugin UI paths.

## Flow

1. Activation ensures `plugin_uuid`, `local_seed`, and a default `connection_state`.
2. Admin starts enrollment from the existing `freeSIEM > Cloud` admin page.
3. Plugin posts site metadata, email, and normalized US phone number to `/api/v1/wordpress/connect/start`.
4. Plugin stores the returned `connection_id` and enters `pending_verification`.
5. Admin enters the emailed verification code.
6. Plugin posts verification details to `/api/v1/wordpress/connect/verify`.
7. Plugin stores returned credentials and permissions, then marks the site `connected`.
8. Test Connection sends a signed heartbeat to `/api/v1/wordpress/heartbeat`.
9. Disconnect sends a signed request to `/api/v1/wordpress/disconnect`, then clears remote credentials locally.

## Backend Override

- `cloud_backend_base_url` stores an optional HTTPS override for local or test freeSIEM Core environments.
- `connected_backend_base_url` stores the backend in use when a Cloud Connect session was successfully verified.
- Leaving `cloud_backend_base_url` blank uses production: `https://core.freesiem.com`.

## Signing

Signed requests use HMAC-SHA256 with this canonical string:

```text
HTTP_METHOD
/request/path
sha256(body)
timestamp
nonce
```

The plugin sends these headers for signed calls:

- `X-freeSIEM-Site-ID`
- `X-freeSIEM-Api-Key`
- `X-freeSIEM-Timestamp`
- `X-freeSIEM-Nonce`
- `X-freeSIEM-Signature`

Only HTTPS backend URLs are allowed for production Cloud Connect requests.
