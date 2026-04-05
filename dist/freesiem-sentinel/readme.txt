=== freeSIEM Sentinel ===
Contributors: freesiem
Requires at least: 6.4
Tested up to: 6.8
Requires PHP: 8.1
Stable tag: 0.2.7
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

freeSIEM Sentinel connects a WordPress site to freeSIEM Core for ownership verification, local scanning, secure uploads, remote commands, and centralized summary reporting.

== Description ==

freeSIEM Sentinel is the WordPress agent for freeSIEM Core.

Features:

* Site registration with freeSIEM Core
* Secure heartbeat every 15 minutes
* Strictly whitelisted remote command handling
* Signed remote Pending Tasks queue for sensitive user-management actions
* Read-only local security scanning
* Secure HMAC-signed local scan uploads
* Remote scan trigger requests
* Admin dashboard, results view, and About page
* GitHub release-based updates with a "Check for Updates" action link

== Installation ==

1. Upload the `freesiem-sentinel` folder to `/wp-content/plugins/`.
2. Activate the plugin in WordPress.
3. Open `freeSIEM > Portal`.
4. Enter the site owner email address.
5. Click `Register / Save`.

== Frequently Asked Questions ==

= How are plugin updates delivered? =

Publish a GitHub Release and attach a zip asset named `freesiem-sentinel.zip`.

That zip should contain:

`freesiem-sentinel/`
`  freesiem-sentinel.php`
`  includes/`
`  readme.txt`

= Release Packaging =

GitHub Releases are the distribution source for freeSIEM Sentinel.

1. Bump the plugin version in `freesiem-sentinel.php` and `readme.txt`.
2. Commit and push `main`.
3. Create a matching git tag such as `v0.1.1`.
4. Push the tag to GitHub.
5. GitHub Actions will automatically build and publish the ZIP asset for that release.

The release ZIP asset must be named `freesiem-sentinel.zip`.

The ZIP must contain the plugin folder at the top level:

`freesiem-sentinel/`
`  freesiem-sentinel.php`
`  includes/`
`  readme.txt`

Version bumps should always have matching git tags.

GitHub Actions publishes the ZIP automatically when a `v*` tag is pushed.

== Changelog ==

= 0.2.7 =

* Add a Phase 1 SSL / HTTPS admin area with overview, safe preflight checks, future settings storage, and lightweight logs without issuing certificates or changing server behavior

= 0.2.6 =

* Add the Sentinel-side TFA foundation: encrypted per-user TFA state, local TOTP enrollment and enforcement, signed remote `/users/*` TFA endpoints, and a TFA admin page

= 0.2.5 =

* Force-set and verify explicit provisioning passwords after user creation so the stored WordPress password matches the submitted password exactly

= 0.2.4 =

* Correct the packaged release version for the explicit-password provisioning fix

= 0.2.3 =

* Fix Phase 1 explicit-password provisioning so approval-time execution uses the separate internal execution payload instead of the redacted task snapshot
* Protect raw execution passwords internally, log only short SHA-256 fingerprints for troubleshooting, and scrub the internal execution payload after successful provisioning

= 0.2.2 =

* Send an immediate heartbeat back to freeSIEM Core whenever a pending task status changes, including approve, deny, executing, completed, and failed
* Keep the scheduled priority-heartbeat fallback so task status reporting stays resilient if the immediate send cannot complete

= 0.2.1 =

* Add a signed `GET /wp-json/freesiem-sentinel/v1/cloud-connect/users` endpoint for safe remote user listing
* Reuse the existing freeSIEM signed request verification flow for remote user-list reads
* Return only safe user metadata and advertise `supports_remote_user_listing` in heartbeat payloads
* Add smoke coverage for route registration, valid signed reads, invalid signatures, and empty user-list responses

= 0.2.0 =

* Add a signed Pending Tasks approval queue for remote user-management actions from freeSIEM Core
* Add local approve, deny, auto-approve, execution, audit trail, and heartbeat task reporting flows
* Add Pending Tasks wp-admin review UI and configurable approval policy settings
* Add a repo-native smoke test script for queue submission, idempotency, approvals, and heartbeat redaction

= 0.1.15 =

* Prevent Cloud Connect verify from overwriting saved local automation preferences before the post-verify preference sync is sent

= 0.1.14 =

* Preserve Cloud automation preferences across disconnect and reconnect, and send broader legacy-compatible preference payload keys to freeSIEM Core during Cloud sync

= 0.1.13 =

* Preserve saved Cloud automation preferences during Cloud Connect verify, test, and heartbeat flows instead of overwriting them from Cloud heartbeat responses

= 0.1.12 =

* Keep saved Cloud automation preferences checked locally after Save Cloud Preferences instead of letting the Core sync response overwrite them

= 0.1.11 =

* Make Cloud test/disconnect error reporting clearer, use a minimal signed heartbeat for connection tests, and allow safe local disconnect cleanup when Core already rejects the remote session

= 0.1.10 =

* Preserve saved Cloud automation preferences through verification and sync them to freeSIEM Core immediately after connection

= 0.1.9 =

* Fix Cloud preference sync so remote scan and centralized user sync persist in wp-admin and update freeSIEM Core heartbeat metadata and site permissions correctly

= 0.1.8 =

* Refine the Cloud page UX, restore production-only backend behavior, and sync Cloud preferences to Core while simplifying local user-sync controls

= 0.1.7 =

* Extend Cloud Connect MVP with signed heartbeat/disconnect, status management, and local testing support via a custom backend URL override

= 0.1.6 =

* Refine the Portal landing page, Cloud onboarding, Scan layout, and About page update experience

= 0.1.5 =

* Improve About page updates, compact the Scan UI, and fix clear-results behavior

= 0.1.4 =

* Add the freeSIEM Cloud connection flow and automation controls

= 0.1.3 =

* Improve scan metrics, add clear results flow, and make file changes filtering more interactive

= 0.1.2 =

* Redesign the dashboard and merge scan and results into one investigation workflow

= 0.1.1 =

* Automate GitHub Release publishing from version tags and matching plugin ZIP packaging

= 0.1.0 =

* Add final phase 4 hardening, safe scan failure handling, and stability improvements

= 0.0.9 =

* Fix GitHub release ZIP updater support and enable file integrity monitoring for all users

= 0.0.8 =

* Fix null-safe admin URL handling and polish updater and results rendering

= 0.0.7 =

* Add feature gating and restructure the admin UI for productized freeSIEM workflows

= 0.0.6 =

* Polish file integrity summaries and finding details across wp-admin

= 0.0.5 =

* Add file integrity monitoring baseline and diff engine

= 0.0.4 =

* Fix wp-admin deprecation-prone output handling and redesign the Results experience

= 0.0.3 =

* Improve dashboard, results, and About page operator UX

= 0.0.2 =

* Add bounded filesystem scanning heuristics and richer posture findings

= 0.0.1 =

* Initial release of freeSIEM Sentinel
