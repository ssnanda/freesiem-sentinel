# freeSIEM Sentinel 0.2.3

- fix explicit-password provisioning to execute from a separate internal execution payload instead of the redacted task snapshot
- preserve the exact submitted raw password for `wp_insert_user()`
- keep UI, audit, REST, and heartbeat payloads redacted
