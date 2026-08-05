<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * A self-contained ACME v2 (RFC 8555) client used when certbot is not available
 * on the host (typical shared hosting such as GoDaddy/Hostinger: no shell exec,
 * no root, no package manager). It speaks HTTP-01 directly against Let's
 * Encrypt using nothing but WordPress's own HTTP API and PHP's openssl
 * extension - no Composer/vendor dependency, matching this plugin's flat-file
 * distribution.
 *
 * Callers hand it two closures for delivering the HTTP-01 challenge so this
 * class stays protocol-only and has no opinion about webroot paths or option
 * storage:
 *   $prepare_challenge(string $token, string $key_authorization): void
 *   $cleanup_challenge(string $token): void
 *
 * On success, cert.pem / fullchain.pem / privkey.pem are written under
 * $user_space['config_dir'] . '/live/' . $host / - the exact layout
 * freesiem_sentinel_verify_ssl_certificate() already expects from certbot, so
 * that function (and everything built on it) works unchanged for this path.
 */
class Freesiem_Acme_Client
{
	private const PRODUCTION_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory';
	private const STAGING_DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory';

	private array $ssl_settings;
	private ?array $directory = null;
	private string $last_nonce = '';

	/** @var resource|\OpenSSLAsymmetricKey|false */
	private $account_key_resource = false;
	private string $account_kid = '';
	private string $last_error = '';

	public function __construct(array $ssl_settings)
	{
		$this->ssl_settings = $ssl_settings;
	}

	public function get_last_error(): string
	{
		return $this->last_error;
	}

	/**
	 * Runs the full issue/renew flow for a single hostname and, on success,
	 * writes cert/fullchain/privkey PEM files under $user_space['config_dir'].
	 *
	 * @return array{success:bool,summary:string,error:string}
	 */
	public function run(string $host, array $user_space, string $contact_email, callable $prepare_challenge, callable $cleanup_challenge): array
	{
		if (!function_exists('openssl_pkey_new') || !function_exists('openssl_sign') || !function_exists('openssl_csr_new')) {
			return $this->fail(__('The PHP OpenSSL extension does not expose the functions this client needs (openssl_pkey_new/openssl_sign/openssl_csr_new).', 'freesiem-sentinel'));
		}

		$config_dir = rtrim((string) ($user_space['config_dir'] ?? ''), '/\\');
		$work_dir = rtrim((string) ($user_space['work_dir'] ?? ''), '/\\');
		if ($config_dir === '' || $work_dir === '') {
			return $this->fail(__('No writable configuration directory is available to store the ACME account/certificate files.', 'freesiem-sentinel'));
		}

		if (!$this->fetch_directory()) {
			return $this->fail(sprintf(__('Could not reach the ACME directory endpoint: %s', 'freesiem-sentinel'), $this->last_error));
		}

		if (!$this->load_or_create_account_key($config_dir)) {
			return $this->fail(__('Could not create or load the ACME account private key.', 'freesiem-sentinel'));
		}

		if (!$this->ensure_account($contact_email, $config_dir)) {
			return $this->fail(sprintf(__('ACME account registration failed: %s', 'freesiem-sentinel'), $this->last_error));
		}

		$order = $this->create_order($host);
		if ($order === null) {
			return $this->fail(sprintf(__('Could not create an ACME order: %s', 'freesiem-sentinel'), $this->last_error));
		}

		$order_url = (string) ($order['_location'] ?? '');
		$authz_url = (string) ($order['authorizations'][0] ?? '');
		if ($order_url === '' || $authz_url === '') {
			return $this->fail(__('The ACME order response was missing an order URL or authorization URL.', 'freesiem-sentinel'));
		}

		$challenge = $this->prepare_http_01_challenge($authz_url);
		if ($challenge === null) {
			return $this->fail(sprintf(__('Could not prepare the HTTP-01 challenge: %s', 'freesiem-sentinel'), $this->last_error));
		}

		$token = (string) $challenge['token'];
		$key_authorization = (string) $challenge['key_authorization'];
		$challenge_url = (string) $challenge['url'];

		$prepare_challenge($token, $key_authorization);
		// Give the webserver / opcache a moment to see the newly written file
		// before asking Let's Encrypt to fetch it.
		usleep(500000);

		$triggered = $this->post($challenge_url, new stdClass());
		if (!$triggered['success']) {
			$cleanup_challenge($token);

			return $this->fail(sprintf(__('Could not notify the ACME server that the challenge is ready: %s', 'freesiem-sentinel'), $this->describe_acme_error($triggered)));
		}

		$ready_order = $this->poll_order_status($order_url, ['ready', 'invalid'], 45);
		$cleanup_challenge($token);

		if ($ready_order === null || (string) ($ready_order['status'] ?? '') !== 'ready') {
			return $this->fail(sprintf(__('The ACME challenge did not validate in time: %s', 'freesiem-sentinel'), $this->describe_order_error($ready_order)));
		}

		$csr = $this->generate_csr($host, $work_dir);
		if ($csr === null) {
			return $this->fail(__('Could not generate a certificate signing request (CSR) for this host.', 'freesiem-sentinel'));
		}

		$finalize_url = (string) ($order['finalize'] ?? '');
		$finalized = $this->post($finalize_url, ['csr' => $csr['csr_der_b64']]);
		if (!$finalized['success']) {
			return $this->fail(sprintf(__('Certificate finalization failed: %s', 'freesiem-sentinel'), $this->describe_acme_error($finalized)));
		}

		$final_order = $this->poll_order_status($order_url, ['valid', 'invalid'], 45);
		if ($final_order === null || (string) ($final_order['status'] ?? '') !== 'valid') {
			return $this->fail(sprintf(__('The certificate order did not finish processing in time: %s', 'freesiem-sentinel'), $this->describe_order_error($final_order)));
		}

		$certificate_url = (string) ($final_order['certificate'] ?? '');
		if ($certificate_url === '') {
			return $this->fail(__('The ACME server marked the order valid but did not provide a certificate download URL.', 'freesiem-sentinel'));
		}

		$fullchain_pem = $this->download_certificate($certificate_url);
		if ($fullchain_pem === null) {
			return $this->fail(sprintf(__('Could not download the issued certificate: %s', 'freesiem-sentinel'), $this->last_error));
		}

		$leaf_pem = $this->extract_leaf_certificate($fullchain_pem);
		if ($leaf_pem === '') {
			return $this->fail(__('The downloaded certificate chain did not contain a parseable leaf certificate.', 'freesiem-sentinel'));
		}

		$written = $this->write_certificate_files($config_dir, $host, $leaf_pem, $fullchain_pem, (string) $csr['private_key_pem']);
		if (!$written) {
			return $this->fail(__('The certificate was issued, but Sentinel could not write it to the expected local storage path.', 'freesiem-sentinel'));
		}

		return [
			'success' => true,
			'summary' => __('Certificate issued successfully via the built-in PHP ACME client.', 'freesiem-sentinel'),
			'error' => '',
		];
	}

	private function fail(string $message): array
	{
		return ['success' => false, 'summary' => $message, 'error' => $this->last_error];
	}

	private function fetch_directory(): bool
	{
		$url = !empty($this->ssl_settings['use_staging']) ? self::STAGING_DIRECTORY_URL : self::PRODUCTION_DIRECTORY_URL;
		$response = wp_remote_get($url, ['timeout' => 20]);

		if (is_wp_error($response)) {
			$this->last_error = $response->get_error_message();

			return false;
		}

		$this->capture_nonce($response);
		$decoded = json_decode((string) wp_remote_retrieve_body($response), true);

		if (!is_array($decoded) || empty($decoded['newAccount']) || empty($decoded['newOrder']) || empty($decoded['newNonce'])) {
			$this->last_error = __('The ACME directory response was not in the expected shape.', 'freesiem-sentinel');

			return false;
		}

		$this->directory = $decoded;

		return true;
	}

	private function load_or_create_account_key(string $config_dir): bool
	{
		$path = $config_dir . '/accounts/account_key.pem';
		wp_mkdir_p(dirname($path));

		if (file_exists($path)) {
			$pem = (string) file_get_contents($path);
			$resource = openssl_pkey_get_private($pem);
			if ($resource !== false) {
				$this->account_key_resource = $resource;

				return true;
			}
		}

		$resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
		if ($resource === false) {
			$this->last_error = __('openssl_pkey_new() failed to generate an account key.', 'freesiem-sentinel');

			return false;
		}

		if (!openssl_pkey_export($resource, $pem)) {
			$this->last_error = __('openssl_pkey_export() failed while saving the account key.', 'freesiem-sentinel');

			return false;
		}

		file_put_contents($path, $pem);
		@chmod($path, 0600);
		$this->account_key_resource = $resource;

		return true;
	}

	private function ensure_account(string $contact_email, string $config_dir): bool
	{
		$account_file = $config_dir . '/accounts/account.json';

		if (file_exists($account_file)) {
			$cached = json_decode((string) file_get_contents($account_file), true);
			if (is_array($cached) && !empty($cached['kid'])) {
				$this->account_kid = (string) $cached['kid'];

				return true;
			}
		}

		$payload = ['termsOfServiceAgreed' => true];
		if (is_email($contact_email)) {
			$payload['contact'] = ['mailto:' . $contact_email];
		}

		$response = $this->post((string) $this->directory['newAccount'], $payload, true);
		if (!$response['success']) {
			$this->last_error = $this->describe_acme_error($response);

			return false;
		}

		$location = $this->find_header($response['headers'] ?? [], 'location');
		if ($location === '') {
			$this->last_error = __('The ACME server accepted the account but did not return an account URL.', 'freesiem-sentinel');

			return false;
		}

		$this->account_kid = $location;
		file_put_contents($account_file, wp_json_encode(['kid' => $location]));

		return true;
	}

	private function create_order(string $host): ?array
	{
		$response = $this->post((string) $this->directory['newOrder'], [
			'identifiers' => [['type' => 'dns', 'value' => $host]],
		]);

		if (!$response['success']) {
			$this->last_error = $this->describe_acme_error($response);

			return null;
		}

		$order = $response['body'];
		$order['_location'] = $this->find_header($response['headers'] ?? [], 'location');

		return $order;
	}

	private function prepare_http_01_challenge(string $authz_url): ?array
	{
		$response = $this->post($authz_url, '');
		if (!$response['success']) {
			$this->last_error = $this->describe_acme_error($response);

			return null;
		}

		$challenges = (array) ($response['body']['challenges'] ?? []);
		$http_challenge = null;
		foreach ($challenges as $candidate) {
			if (($candidate['type'] ?? '') === 'http-01') {
				$http_challenge = $candidate;
				break;
			}
		}

		if ($http_challenge === null) {
			$this->last_error = __('The ACME server did not offer an http-01 challenge for this identifier.', 'freesiem-sentinel');

			return null;
		}

		$token = (string) $http_challenge['token'];

		return [
			'token' => $token,
			'url' => (string) $http_challenge['url'],
			'key_authorization' => $token . '.' . $this->jwk_thumbprint(),
		];
	}

	private function poll_order_status(string $order_url, array $accept_statuses, int $max_wait_seconds): ?array
	{
		$deadline = time() + $max_wait_seconds;
		$delay = 1;

		while (time() < $deadline) {
			$response = $this->post($order_url, '');
			if (!$response['success']) {
				$this->last_error = $this->describe_acme_error($response);

				return null;
			}

			$status = (string) ($response['body']['status'] ?? '');
			if (in_array($status, $accept_statuses, true)) {
				$response['body']['_location'] = $order_url;

				return $response['body'];
			}

			sleep($delay);
			$delay = min($delay + 1, 5);
		}

		$this->last_error = __('Timed out waiting for the ACME server to finish processing.', 'freesiem-sentinel');

		return null;
	}

	private function generate_csr(string $host, string $work_dir): ?array
	{
		$key_resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
		if ($key_resource === false) {
			$this->last_error = __('openssl_pkey_new() failed to generate a certificate private key.', 'freesiem-sentinel');

			return null;
		}

		// PHP's openssl_csr_new only emits a SAN extension when pointed at an
		// openssl.cnf that defines one - write a small self-contained config so
		// this doesn't depend on the host's system openssl.cnf being reachable.
		$cnf_contents = "[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = v3_req\n[req_distinguished_name]\n[v3_req]\nsubjectAltName = DNS:" . $host . "\n";
		$cnf_path = rtrim($work_dir, '/') . '/openssl-' . substr(md5($host . microtime()), 0, 12) . '.cnf';
		file_put_contents($cnf_path, $cnf_contents);

		$csr_resource = openssl_csr_new(['commonName' => $host], $key_resource, [
			'digest_alg' => 'sha256',
			'req_extensions' => 'v3_req',
			'config' => $cnf_path,
		]);

		@unlink($cnf_path);

		if ($csr_resource === false || !openssl_csr_export($csr_resource, $csr_pem) || !openssl_pkey_export($key_resource, $key_pem)) {
			$this->last_error = __('Could not generate a certificate signing request for this host.', 'freesiem-sentinel');

			return null;
		}

		return [
			'csr_der_b64' => $this->base64url($this->pem_to_der($csr_pem)),
			'private_key_pem' => $key_pem,
		];
	}

	private function download_certificate(string $certificate_url): ?string
	{
		$response = $this->post($certificate_url, '');
		if (!$response['success']) {
			$this->last_error = $this->describe_acme_error($response);

			return null;
		}

		$pem = trim((string) $response['raw']);
		if (!str_contains($pem, '-----BEGIN CERTIFICATE-----')) {
			$this->last_error = __('The certificate download did not return a PEM certificate chain.', 'freesiem-sentinel');

			return null;
		}

		return $pem;
	}

	private function extract_leaf_certificate(string $fullchain_pem): string
	{
		if (preg_match('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $fullchain_pem, $matches)) {
			return $matches[0] . "\n";
		}

		return '';
	}

	private function write_certificate_files(string $config_dir, string $host, string $leaf_pem, string $fullchain_pem, string $privkey_pem): bool
	{
		$live_dir = $config_dir . '/live/' . $host;
		if (!wp_mkdir_p($live_dir)) {
			return false;
		}

		$ok = file_put_contents($live_dir . '/cert.pem', $leaf_pem) !== false
			&& file_put_contents($live_dir . '/fullchain.pem', $fullchain_pem) !== false
			&& file_put_contents($live_dir . '/privkey.pem', $privkey_pem) !== false;

		if ($ok) {
			@chmod($live_dir . '/privkey.pem', 0600);
		}

		return $ok;
	}

	// -- JWS / JOSE plumbing ------------------------------------------------

	private function jwk(): array
	{
		$details = openssl_pkey_get_details($this->account_key_resource);

		return [
			'kty' => 'RSA',
			'n' => $this->base64url((string) $details['rsa']['n']),
			'e' => $this->base64url((string) $details['rsa']['e']),
		];
	}

	private function jwk_thumbprint(): string
	{
		$jwk = $this->jwk();
		// RFC 7638 requires the exact member set for an RSA key, in
		// lexicographic order, with no extra whitespace.
		$canonical = wp_json_encode(['e' => $jwk['e'], 'kty' => $jwk['kty'], 'n' => $jwk['n']]);

		return $this->base64url(hash('sha256', (string) $canonical, true));
	}

	/**
	 * Signs and POSTs a JWS request. Pass an empty string '' for $payload to
	 * perform an ACME "POST-as-GET" (used for polling authorizations/orders and
	 * downloading the certificate); pass an array (or stdClass for an explicit
	 * empty JSON object, e.g. the challenge-ready notification) for a normal
	 * signed request body.
	 */
	private function post(string $url, $payload, bool $use_jwk = false): array
	{
		$nonce = $this->get_nonce();
		if ($nonce === '') {
			return ['success' => false, 'code' => 0, 'headers' => [], 'body' => [], 'raw' => '', 'error' => __('No ACME replay-nonce is available.', 'freesiem-sentinel')];
		}

		$protected = ($use_jwk || $this->account_kid === '')
			? ['alg' => 'RS256', 'jwk' => $this->jwk(), 'nonce' => $nonce, 'url' => $url]
			: ['alg' => 'RS256', 'kid' => $this->account_kid, 'nonce' => $nonce, 'url' => $url];

		$protected_b64 = $this->base64url((string) wp_json_encode($protected));
		$payload_b64 = ($payload === '') ? '' : $this->base64url((string) wp_json_encode($payload));

		$signature = '';
		openssl_sign($protected_b64 . '.' . $payload_b64, $signature, $this->account_key_resource, OPENSSL_ALGO_SHA256);

		$body = (string) wp_json_encode([
			'protected' => $protected_b64,
			'payload' => $payload_b64,
			'signature' => $this->base64url($signature),
		]);

		$response = wp_remote_post($url, [
			'headers' => ['Content-Type' => 'application/jose+json'],
			'body' => $body,
			'timeout' => 30,
		]);

		if (is_wp_error($response)) {
			return ['success' => false, 'code' => 0, 'headers' => [], 'body' => [], 'raw' => '', 'error' => $response->get_error_message()];
		}

		$this->capture_nonce($response);
		$code = (int) wp_remote_retrieve_response_code($response);
		$raw = (string) wp_remote_retrieve_body($response);
		$decoded = json_decode($raw, true);

		return [
			'success' => $code >= 200 && $code < 400,
			'code' => $code,
			'headers' => wp_remote_retrieve_headers($response),
			'body' => is_array($decoded) ? $decoded : [],
			'raw' => $raw,
			'error' => '',
		];
	}

	private function get_nonce(): string
	{
		if ($this->last_nonce !== '') {
			$nonce = $this->last_nonce;
			$this->last_nonce = '';

			return $nonce;
		}

		$response = wp_remote_head((string) ($this->directory['newNonce'] ?? ''), ['timeout' => 15]);
		if (is_wp_error($response)) {
			return '';
		}

		return (string) wp_remote_retrieve_header($response, 'replay-nonce');
	}

	/** @param array|\Requests_Utility_CaseInsensitiveDictionary|WP_Error $response */
	private function capture_nonce($response): void
	{
		$nonce = wp_remote_retrieve_header($response, 'replay-nonce');
		if (is_string($nonce) && $nonce !== '') {
			$this->last_nonce = $nonce;
		}
	}

	private function find_header($headers, string $name): string
	{
		if (is_object($headers) && method_exists($headers, 'offsetGet')) {
			$value = $headers->offsetGet($name);

			return is_string($value) ? $value : '';
		}

		if (is_array($headers) && isset($headers[$name])) {
			return (string) $headers[$name];
		}

		return '';
	}

	private function describe_acme_error(array $response): string
	{
		if (!empty($response['error'])) {
			return (string) $response['error'];
		}

		$detail = (string) ($response['body']['detail'] ?? '');

		return $detail !== '' ? $detail : sprintf(__('HTTP %d from the ACME server.', 'freesiem-sentinel'), (int) ($response['code'] ?? 0));
	}

	private function describe_order_error(?array $order): string
	{
		if ($order === null) {
			return $this->last_error;
		}

		$error = (string) ($order['error']['detail'] ?? '');

		return $error !== '' ? $error : sprintf(__('order status: %s', 'freesiem-sentinel'), (string) ($order['status'] ?? 'unknown'));
	}

	private function base64url(string $data): string
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}

	private function pem_to_der(string $pem): string
	{
		$pem = preg_replace('/-----BEGIN [^-]+-----|-----END [^-]+-----|\r|\n/', '', $pem);

		return (string) base64_decode((string) $pem, true);
	}
}
