freeSIEM Sentinel 0.3.18

- Preserve the stealth login token across wp-login form submits so protected logins redirect back to the requested admin page instead of falling through to home.
- Replace `null` hidden menu parent slugs with empty strings to avoid PHP 8.1+ deprecation notices during admin menu registration.
