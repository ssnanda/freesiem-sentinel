# freeSIEM Sentinel 0.1.7

- Extend the Cloud Connect MVP inside the existing Cloud admin page.
- Add a custom Cloud backend base URL override for local and test Core environments such as `https://localhost:8443`.
- Keep production as the default backend when no override is set.
- Store and display the backend used for the active connection, with a warning when the configured backend changes after enrollment.
- Add signed heartbeat and disconnect support with clearer connection status and management controls.
