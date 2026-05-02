# freeSIEM Sentinel 0.3.47

This release fixes the full Sync UI regression where a running full/baseline Sync could fall back to the generic Pending Changes message and stop driving batches after an empty job-status response or page refresh.

## Changes

- Keep the active full Sync/baseline batch plan visible in Pending Changes while a full Sync is running, paused, or resumable.
- Rebuild a running full Sync job in the browser from saved Sync status when the persisted job object is temporarily unavailable.
- Keep polling and browser-driven batch continuation alive when status endpoints return saved running status but no job payload.
- Return saved Sync status from the job-status endpoint so refreshed pages can recover the running state.
- Preserve the active full Sync plan during transient preview clears, while still clearing it on explicit Cancel / Reset Sync.
- Store large full Sync baseline state on disk instead of inside `wp_options`, preventing MariaDB charset/check queries from breaking `synchy_sync_job` persistence.
- Split database batches into smaller 100-row chunks so failed rows are isolated and long runs remain resumable.
- Exclude WordPress/plugin runtime options, plugin transients, activation flags, and Sentinel's own local settings from Options sync to avoid destination-side critical errors.
