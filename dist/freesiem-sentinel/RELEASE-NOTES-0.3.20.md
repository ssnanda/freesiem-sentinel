freeSIEM Sentinel 0.3.20

- Harden Stealth Mode request handling around wp-login.php, wp-admin redirects, token validation, and login error visibility.
- Add Stealth Mode event visibility through the existing logs system and a small recent-events section on the Stealth Mode page.
- Expose Stealth Mode status to freeSIEM Core heartbeats and add narrow signed Core commands for Stealth Mode management.
