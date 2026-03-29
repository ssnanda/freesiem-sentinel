<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Cloud_Connect_Client
{
	private array $settings;
	private string $base_url;
	private Freesiem_Cloud_Connect_Signer $signer;

	public function __construct(?array $settings = null, ?Freesiem_Cloud_Connect_Signer $signer = null)
	{
		$this->settings = $settings ?: freesiem_sentinel_get_settings();
		$this->base_url = untrailingslashit(freesiem_sentinel_get_effective_cloud_backend_base_url($this->settings));
		$this->signer = $signer ?: new Freesiem_Cloud_Connect_Signer();
	}

	public function start_connection(array $payload)
	{
		return $this->post('/api/v1/wordpress/connect/start', $payload, false);
	}

	public function verify_connection(array $payload)
	{
		return $this->post('/api/v1/wordpress/connect/verify', $payload, false);
	}

	public function heartbeat(array $payload)
	{
		return $this->post('/api/v1/wordpress/heartbeat', $payload, true);
	}

	public function disconnect(array $payload)
	{
		return $this->post('/api/v1/wordpress/disconnect', $payload, true);
	}

	public function sync_preferences(array $payload)
	{
		return $this->post('/api/v1/wordpress/heartbeat', $payload, true);
	}

	private function post(string $path, array $payload, bool $signed)
	{
		if (!$this->is_secure_backend_url()) {
			return new WP_Error('freesiem_cloud_https_required', __('freeSIEM Cloud Connect requires an HTTPS backend URL.', 'freesiem-sentinel'));
		}

		$body = wp_json_encode($payload);

		if (!is_string($body) || $body === '') {
			return new WP_Error('freesiem_cloud_json_failed', __('freeSIEM Cloud Connect could not prepare the request payload.', 'freesiem-sentinel'));
		}

		$headers = [
			'Accept' => 'application/json',
			'Content-Type' => 'application/json',
			'User-Agent' => 'freeSIEM-Sentinel/' . FREESIEM_SENTINEL_VERSION . '; ' . wp_parse_url(home_url('/'), PHP_URL_HOST),
		];

		if ($signed) {
			$signed_headers = $this->signer->build_headers('POST', $path, $body, $this->settings);

			if (is_wp_error($signed_headers)) {
				return $signed_headers;
			}

			$headers = array_merge($headers, $signed_headers);
		}

		$response = wp_remote_post(
			$this->base_url . $path,
			[
				'timeout' => 20,
				'headers' => $headers,
				'body' => $body,
				'data_format' => 'body',
			]
		);

		return $this->parse_response($response);
	}

	private function parse_response($response)
	{
		if (is_wp_error($response)) {
			return new WP_Error('freesiem_cloud_request_failed', __('freeSIEM Cloud Connect could not reach freeSIEM Core.', 'freesiem-sentinel'));
		}

		$status_code = (int) wp_remote_retrieve_response_code($response);
		$body = (string) wp_remote_retrieve_body($response);
		$data = json_decode($body, true);
		$message = '';

		if (is_array($data) && is_string($data['message'] ?? null)) {
			$message = sanitize_text_field((string) $data['message']);
		}

		if ($status_code < 200 || $status_code >= 300) {
			return new WP_Error(
				'freesiem_cloud_remote_error',
				$message !== '' ? $message : __('freeSIEM Core rejected the request.', 'freesiem-sentinel')
			);
		}

		if (!is_array($data)) {
			return new WP_Error('freesiem_cloud_bad_response', __('freeSIEM Core returned an invalid response.', 'freesiem-sentinel'));
		}

		return $data;
	}

	private function is_secure_backend_url(): bool
	{
		$parts = wp_parse_url($this->base_url);
		$scheme = strtolower((string) ($parts['scheme'] ?? ''));
		$host = strtolower((string) ($parts['host'] ?? ''));

		return $scheme === 'https' || in_array($host, ['localhost', '127.0.0.1'], true);
	}
}
