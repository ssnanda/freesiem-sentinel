freeSIEM Sentinel 0.3.36
=========================

- Fix Update Live Sentinel by avoiding WordPress filesystem prompts when applying remote plugin packages.
- Add a fallback that updates destination Sentinel files through the Sync receiver when older live sites return a server error from the self-update endpoint.
- Show clear in-page progress and error messages while Update Live Sentinel is running.
