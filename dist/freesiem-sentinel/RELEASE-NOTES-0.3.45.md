freeSIEM Sentinel 0.3.45
=========================

- Render saved full Sync job state in Pending Changes on the server so refreshes show running/resumable batches before JavaScript loads.
- Make Preview Changes use the batched full Sync planner when selected scopes need a baseline, keeping Start Baseline aligned with Preview Full Sync.
- Pass saved Sync status into the admin JavaScript as a fallback when the full Sync job object is temporarily unavailable.
