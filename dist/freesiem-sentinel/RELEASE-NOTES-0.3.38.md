freeSIEM Sentinel 0.3.38
=========================

- Simplify the Sync action flow so Preview Full Sync turns into Start Full Sync on the same button while Preview Changes keeps the baseline/push action separate.
- Improve full Sync start feedback and keep the page busy while browser-driven batch processing is running.
- Record manual baseline and completed Sync watermarks from current file/post timestamps so immediate previews do not show already-baselined items as pending.
