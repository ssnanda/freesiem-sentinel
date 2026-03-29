<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Cloud_Connect_State
{
	public const STATES = ['disconnected', 'pending_verification', 'connected', 'suspended', 'revoked'];

	public static function ensure_initialized(): array
	{
		$updates = [];
		$settings = freesiem_sentinel_get_settings();

		if (empty($settings['plugin_uuid'])) {
			$updates['plugin_uuid'] = wp_generate_uuid4();
		}

		if (empty($settings['local_seed'])) {
			$updates['local_seed'] = freesiem_sentinel_generate_random_token(64);
		}

		if (empty($settings['connection_state']) || !in_array((string) $settings['connection_state'], self::STATES, true)) {
			$updates['connection_state'] = 'disconnected';
		}

		if ($updates === []) {
			return $settings;
		}

		return freesiem_sentinel_update_settings($updates);
	}

	public static function set_pending(array $data): array
	{
		$updates = [
			'connection_state' => 'pending_verification',
			'connection_id' => sanitize_text_field((string) ($data['connection_id'] ?? '')),
			'email' => sanitize_email((string) ($data['email'] ?? '')),
			'phone' => freesiem_sentinel_sanitize_phone_number((string) ($data['phone'] ?? '')),
			'connect_expires_at' => freesiem_sentinel_sanitize_datetime((string) ($data['connect_expires_at'] ?? ($data['expires_at'] ?? ''))),
			'cloud_verification_code' => '',
		];

		return freesiem_sentinel_update_settings($updates);
	}

	public static function set_connected(array $response): array
	{
		$current_settings = freesiem_sentinel_get_settings();
		$permissions = is_array($response['permissions'] ?? null) ? $response['permissions'] : [];
		$allow_remote_scan = self::resolve_boolean_value(
			$response,
			$permissions,
			['allow_remote_scan', 'allow_remote_scans'],
			!empty($current_settings['allow_remote_scan'])
		);
		$user_sync_enabled = self::resolve_boolean_value(
			$response,
			$permissions,
			['user_sync_enabled', 'centralized_user_sync_enabled', 'centralized_user_sync'],
			!empty($current_settings['user_sync_enabled'])
		);
		$scan_frequency = self::resolve_string_value(
			$response,
			$permissions,
			['scan_frequency'],
			(string) ($current_settings['scan_frequency'] ?? 'daily')
		);

		$updates = [
			'connection_state' => self::sanitize_state((string) ($response['connection_state'] ?? 'connected'), 'connected'),
			'site_id' => sanitize_text_field((string) ($response['site_id'] ?? '')),
			'api_key' => sanitize_text_field((string) ($response['api_key'] ?? '')),
			'hmac_secret' => sanitize_text_field((string) ($response['hmac_secret'] ?? '')),
			'connected_backend_base_url' => freesiem_sentinel_get_effective_cloud_backend_base_url(),
			'registration_status' => sanitize_key((string) ($response['registration_status'] ?? 'connected')),
			'allow_remote_scan' => $allow_remote_scan ? 1 : 0,
			'scan_frequency' => sanitize_key($scan_frequency),
			'user_sync_enabled' => $user_sync_enabled ? 1 : 0,
			'connect_expires_at' => '',
			'connection_id' => '',
			'cloud_connected_at' => freesiem_sentinel_get_iso8601_time(),
			'last_heartbeat_result' => '',
		];

		return freesiem_sentinel_update_settings($updates);
	}

	public static function update_from_heartbeat(array $response, bool $success, string $message): array
	{
		$permissions = is_array($response['permissions'] ?? null) ? $response['permissions'] : [];
		$updates = [
			'last_heartbeat_result' => sanitize_text_field($message),
		];

		if ($success) {
			$updates['last_heartbeat_at'] = freesiem_sentinel_get_iso8601_time();
		}

		if (array_key_exists('allow_remote_scan', $response) || array_key_exists('allow_remote_scan', $permissions)) {
			$updates['allow_remote_scan'] = empty($response['allow_remote_scan']) && empty($permissions['allow_remote_scan']) ? 0 : 1;
		}

		if (!empty($response['scan_frequency']) || !empty($permissions['scan_frequency'])) {
			$updates['scan_frequency'] = sanitize_key((string) ($response['scan_frequency'] ?? $permissions['scan_frequency']));
		}

		if (array_key_exists('user_sync_enabled', $response) || array_key_exists('user_sync_enabled', $permissions)) {
			$updates['user_sync_enabled'] = empty($response['user_sync_enabled']) && empty($permissions['user_sync_enabled']) ? 0 : 1;
		}

		if (!empty($response['registration_status'])) {
			$updates['registration_status'] = sanitize_key((string) $response['registration_status']);
		}

		if (!empty($response['connection_state']) || !empty($response['state'])) {
			$updates['connection_state'] = self::sanitize_state((string) ($response['connection_state'] ?? $response['state']), 'connected');
		}

		return freesiem_sentinel_update_settings($updates);
	}

	public static function reset_pending(): array
	{
		return freesiem_sentinel_update_settings([
			'connection_state' => 'disconnected',
			'connection_id' => '',
			'email' => '',
			'phone' => '',
			'connect_expires_at' => '',
			'cloud_verification_code' => '',
		]);
	}

	public static function clear_remote_credentials(): array
	{
		return freesiem_sentinel_update_settings([
			'connection_state' => 'disconnected',
			'connection_id' => '',
			'connected_backend_base_url' => '',
			'site_id' => '',
			'api_key' => '',
			'hmac_secret' => '',
			'registration_status' => 'unregistered',
			'last_heartbeat_at' => '',
			'last_heartbeat_result' => '',
			'connect_expires_at' => '',
			'allow_remote_scan' => 0,
			'scan_frequency' => 'daily',
			'user_sync_enabled' => 0,
			'cloud_verification_code' => '',
			'cloud_connected_at' => '',
		]);
	}

	public static function is_connected(array $settings): bool
	{
		return !empty($settings['site_id'])
			&& !empty($settings['api_key'])
			&& !empty($settings['hmac_secret'])
			&& self::sanitize_state((string) ($settings['connection_state'] ?? ''), 'disconnected') === 'connected';
	}

	private static function sanitize_state(string $state, string $fallback): string
	{
		return in_array($state, self::STATES, true) ? $state : $fallback;
	}

	private static function resolve_boolean_value(array $response, array $permissions, array $keys, bool $fallback): bool
	{
		foreach ([$response, $permissions] as $source) {
			foreach ($keys as $key) {
				if (array_key_exists($key, $source)) {
					return !empty($source[$key]);
				}
			}
		}

		return $fallback;
	}

	private static function resolve_string_value(array $response, array $permissions, array $keys, string $fallback): string
	{
		foreach ([$response, $permissions] as $source) {
			foreach ($keys as $key) {
				if (!empty($source[$key]) && is_string($source[$key])) {
					return $source[$key];
				}
			}
		}

		return $fallback;
	}
}
