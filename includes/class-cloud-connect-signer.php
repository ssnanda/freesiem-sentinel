<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Cloud_Connect_Signer
{
	public function build_headers(string $method, string $path, string $body, array $settings): array|WP_Error
	{
		$site_id = sanitize_text_field((string) ($settings['site_id'] ?? ''));
		$api_key = sanitize_text_field((string) ($settings['api_key'] ?? ''));
		$secret = sanitize_text_field((string) ($settings['hmac_secret'] ?? ''));

		if ($site_id === '' || $api_key === '' || $secret === '') {
			return new WP_Error('freesiem_cloud_missing_credentials', __('freeSIEM Cloud Connect is missing stored credentials.', 'freesiem-sentinel'));
		}

		$timestamp = (string) time();
		$nonce = freesiem_sentinel_generate_random_token(24);
		$body_hash = hash('sha256', $body);
		$canonical = implode("\n", [
			strtoupper($method),
			$path,
			$body_hash,
			$timestamp,
			$nonce,
		]);
		$signature = hash_hmac('sha256', $canonical, $secret);

		return [
			'X-freeSIEM-Site-ID' => $site_id,
			'X-freeSIEM-Api-Key' => $api_key,
			'X-freeSIEM-Timestamp' => $timestamp,
			'X-freeSIEM-Nonce' => $nonce,
			'X-freeSIEM-Signature' => $signature,
		];
	}
}
