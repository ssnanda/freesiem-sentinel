freeSIEM Sentinel 1.0.51
=========================

- Security: automatically write (and self-heal) a `.htaccess` denying all web access to the PHP ACME client's certificate/key storage directory, since it can end up inside the public webroot and previously relied on file permissions alone - which some hosts don't enforce over HTTP the way you'd expect.
- Add an "Activating a PHP ACME Certificate" guide to the SSL Overview tab (shown for the PHP ACME provider) covering: checking whether cPanel auto-install already ran, trying the host's own cPanel AutoSSL first, configuring Sentinel's cPanel auto-install, and the manual cPanel SSL install steps - including the field mapping confirmed against a real GoDaddy cPanel account (Certificate = cert.pem only, not fullchain.pem; CA Bundle left blank so cPanel auto-fetches the intermediate).
