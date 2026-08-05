freeSIEM Sentinel 0.3.41
=========================

- Treat destination cURL timeouts during Sync uploads as recoverable by polling the destination Sync status before failing the batch.
- Keep the full Sync UI in a running/retry state when a transient status refresh error happens while the job is still active.
