# freeSIEM Sentinel 1.0.125

- Reduce shared-host load during full scans with smaller, spaced slices and constant-time file queue processing.
- Page large directories through scan state without dropping coverage or storing an oversized queue.
- Recover stale scan continuations, prevent duplicate full scans, and add a Stop Scan control.
- Scan protected backup directories and nested WordPress installations for malware.
- Report PCRE failures as incomplete scan coverage and replace the costly request-proxy expression with bounded checks.
- Preserve critical findings when a scan reaches its result limit and reduce false positives for plain HTML PHP files.
- Add a Security > WP-Cron monitor with scheduled-event inventory, overdue status, execution duration, memory use, fatal/interrupted status, and retained history.
