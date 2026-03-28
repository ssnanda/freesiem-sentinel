=== freeSIEM Sentinel ===
Contributors: freesiem
Requires at least: 6.4
Tested up to: 6.8
Requires PHP: 8.1
Stable tag: 0.0.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

freeSIEM Sentinel connects a WordPress site to freeSIEM Core for ownership verification, local scanning, secure uploads, remote commands, and centralized summary reporting.

== Description ==

freeSIEM Sentinel is the WordPress agent for freeSIEM Core.

Features:

* Site registration with freeSIEM Core
* Secure heartbeat every 15 minutes
* Strictly whitelisted remote command handling
* Read-only local security scanning
* Secure HMAC-signed local scan uploads
* Remote scan trigger requests
* Admin dashboard, results view, and About page
* GitHub release-based updates with a "Check for Updates" action link

== Installation ==

1. Upload the `freesiem-sentinel` folder to `/wp-content/plugins/`.
2. Activate the plugin in WordPress.
3. Open `freeSIEM > Dashboard`.
4. Enter the site owner email address and confirm the backend URL.
5. Click `Register / Save`.

== Frequently Asked Questions ==

= How are plugin updates delivered? =

Publish a GitHub Release and attach a zip asset named `freesiem-sentinel.zip`.

That zip should contain:

`freesiem-sentinel/`
`  freesiem-sentinel.php`
`  includes/`
`  readme.txt`

== Changelog ==

= 0.0.3 =

* Improve dashboard, results, and About page operator UX

= 0.0.2 =

* Add bounded filesystem scanning heuristics and richer posture findings

= 0.0.1 =

* Initial release of freeSIEM Sentinel
