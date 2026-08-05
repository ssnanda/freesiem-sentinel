freeSIEM Sentinel 0.2.6

- adds the Sentinel-side TFA foundation
- stores per-user TFA state and encrypted TOTP secrets locally
- adds local TOTP enrollment, pending setup, and login-time verification
- adds signed remote `/users/provision`, `/users/reset-tfa`, `/users/set-password`, `/users/update-tfa`, and `/users/list` endpoints
- adds a TFA admin page with local/core-managed action restrictions
