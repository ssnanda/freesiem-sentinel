freeSIEM Sentinel 0.3.43
=========================

- Refresh the Pending Changes header during resumed full Sync runs instead of leaving stale success messages in that panel.
- Infer the active running batch from the full Sync status message when the numeric current batch field has not refreshed yet.
- Restore saved incomplete full Sync jobs after page reload so admins can resume instead of seeing only baseline setup.
