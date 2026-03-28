<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_API_Client
{
	private array $settings;
	private string $base_url;

	public function __construct(?array $settings = null)
	{
		$this->settings = $settings ?: freesiem_sentinel_get_settings();
		$this->base_url = untrailingslashit((string) ($this->settings['backend_url'] ?? FREESIEM_SENTINEL_BACKEND_URL));
	}

	public function register_site(array $payload)
	{
		return $this->post_json('/api/v1/wordpress/register', $payload, false, false);
	}

	public function heartbeat(array $payload)
	{
		return $this->post_json('/api/v1/wordpress/heartbeat', $payload, true, true);
	}

	public function upload_local_scan(array $payload)
	{
		return $this->post_json('/api/v1/wordpress/local-scan', $payload, true, true);
	}

	public function request_remote_scan(array $payload)
	{
		return $this->post_json('/api/v1/wordpress/request-remote-scan', $payload, true, true);
	}

	public function fetch_summary(string $site_id)
	{
		return $this->get_json('/api/v1/wordpress/summary', ['site_id' => $site_id], true, true);
	}

	public function send_command_result(array $payload)
	{
		return $this->post_json('/api/v1/wordpress/command-result', $payload, true, true);
	}

	public function test_connection()
	{
		$site_id = (string) ($this->settings['site_id'] ?? '');

		if ($site_id === '') {
			return [];
		}

		return $this->heartbeat([
			'site_id' => $site_id,
			'plugin_version' => FREESIEM_SENTINEL_VERSION,
			'wp_version' => get_bloginfo('version'),
			'timestamp' => freesiem_sentinel_get_iso8601_time(),
			'last_local_scan_at' => (string) ($this->settings['last_local_scan_at'] ?? ''),
			'last_remote_scan_at' => (string) ($this->settings['last_remote_scan_at'] ?? ''),
		]);
	}

	private function post_json(string $path, array $payload, bool $authenticated, bool $signed)
	{
		$request = $this->build_request($path, $payload, $authenticated, $signed);

		if (is_wp_error($request)) {
			return [];
		}

		$response = wp_remote_post(
			$request['url'],
			[
				'timeout' => 20,
				'headers' => $request['headers'],
				'body' => $request['body'],
				'data_format' => 'body',
			]
		);

		return $this->parse_response($response, $signed);
	}

	private function get_json(string $path, array $query, bool $authenticated, bool $signed)
	{
		$url = add_query_arg(freesiem_sentinel_safe_query_args($query), $this->base_url . $path);
		$headers = $this->build_headers($authenticated, $signed, '');

		if (is_wp_error($headers)) {
			return [];
		}

		$response = wp_remote_get(
			$url,
			[
				'timeout' => 20,
				'headers' => $headers,
			]
		);

		return $this->parse_response($response, $signed);
	}

	private function build_request(string $path, array $payload, bool $authenticated, bool $signed)
	{
		$url = $this->base_url . $path;
		$body = wp_json_encode($payload);

		if (!is_string($body) || $body === '') {
			return [];
		}

		$headers = $this->build_headers($authenticated, $signed, $body);

		if (is_wp_error($headers)) {
			return [];
		}

		return [
			'url' => $url,
			'headers' => $headers,
			'body' => $body,
		];
	}

	private function build_headers(bool $authenticated, bool $signed, string $body)
	{
		$headers = [
			'Accept' => 'application/json',
			'Content-Type' => 'application/json',
			'User-Agent' => 'freeSIEM-Sentinel/' . FREESIEM_SENTINEL_VERSION . '; ' . wp_parse_url(home_url('/'), PHP_URL_HOST),
		];

		if (!$this->is_secure_url($this->base_url)) {
			return new WP_Error('freesiem_insecure_backend', __('freeSIEM Sentinel requires an HTTPS backend URL.', 'freesiem-sentinel'));
		}

		if ($authenticated) {
			$api_key = (string) ($this->settings['api_key'] ?? '');
			$site_id = (string) ($this->settings['site_id'] ?? '');

			if ($api_key === '' || $site_id === '') {
				return new WP_Error('freesiem_missing_credentials', __('freeSIEM Sentinel is missing backend credentials.', 'freesiem-sentinel'));
			}

			$headers['Authorization'] = 'Bearer ' . $api_key;
			$headers['X-FreeSIEM-Site-ID'] = $site_id;
		}

		if ($signed) {
			$secret = (string) ($this->settings['hmac_secret'] ?? '');

			if ($secret === '') {
				return new WP_Error('freesiem_missing_hmac_secret', __('freeSIEM Sentinel is missing the HMAC secret.', 'freesiem-sentinel'));
			}

			$timestamp = (string) time();
			$nonce = wp_generate_password(20, false, false);
			$signature = hash_hmac('sha256', $timestamp . "\n" . $nonce . "\n" . $body, $secret);

			$headers['X-FreeSIEM-Timestamp'] = $timestamp;
			$headers['X-FreeSIEM-Nonce'] = $nonce;
			$headers['X-FreeSIEM-Signature'] = $signature;
		}

		return $headers;
	}

	private function parse_response($response, bool $signed)
	{
		if (is_wp_error($response)) {
			return [];
		}

		$code = (int) wp_remote_retrieve_response_code($response);
		$body = (string) wp_remote_retrieve_body($response);
		$data = json_decode($body, true);

		if ($signed) {
			$validation = $this->validate_response_signature($response, $body);

			if ($validation !== true) {
				return [];
			}
		}

		if ($code !== 200) {
			return [];
		}

		if (!is_array($data)) {
			return [];
		}

		return $data;
	}

	private function validate_response_signature($response, string $body)
	{
		$headers = wp_remote_retrieve_headers($response);
		$signature = '';
		$timestamp = '';
		$nonce = '';

		if (is_object($headers) && method_exists($headers, 'getAll')) {
			$raw = $headers->getAll();
			$signature = (string) ($raw['x-freesiem-signature'] ?? '');
			$timestamp = (string) ($raw['x-freesiem-timestamp'] ?? '');
			$nonce = (string) ($raw['x-freesiem-nonce'] ?? '');
		} elseif (is_array($headers)) {
			$signature = (string) ($headers['x-freesiem-signature'] ?? '');
			$timestamp = (string) ($headers['x-freesiem-timestamp'] ?? '');
			$nonce = (string) ($headers['x-freesiem-nonce'] ?? '');
		}

		if ($signature === '' || $timestamp === '' || $nonce === '') {
			return true;
		}

		$secret = (string) ($this->settings['hmac_secret'] ?? '');

		if ($secret === '') {
			return new WP_Error('freesiem_missing_hmac_secret', __('freeSIEM Sentinel cannot validate the response signature without a secret.', 'freesiem-sentinel'));
		}

		$expected = hash_hmac('sha256', $timestamp . "\n" . $nonce . "\n" . $body, $secret);

		if (!hash_equals($expected, $signature)) {
			return new WP_Error('freesiem_invalid_signature', __('freeSIEM Sentinel rejected a response with an invalid HMAC signature.', 'freesiem-sentinel'));
		}

		return true;
	}

	private function is_secure_url(string $url): bool
	{
		$parts = wp_parse_url($url);
		$scheme = strtolower((string) ($parts['scheme'] ?? ''));
		$host = strtolower((string) ($parts['host'] ?? ''));

		return $scheme === 'https' || in_array($host, ['localhost', '127.0.0.1'], true);
	}
}
