<?php

if (!defined('ABSPATH')) {
	exit;
}

function freesiem_sentinel_get_default_settings(): array
{
	return [
		'site_id' => '',
		'plugin_uuid' => '',
		'local_seed' => '',
		'connection_state' => 'disconnected',
		'connection_id' => '',
		'email' => '',
		'phone' => '',
		'phone_number' => '',
		'cloud_users' => [],
		'connect_expires_at' => '',
		'cloud_connection_state' => 'disconnected',
		'cloud_verification_code' => '',
		'cloud_connected_at' => '',
		'allow_remote_scan' => 1,
		'scan_frequency' => 'daily',
		'user_sync_enabled' => 0,
		'plugin_auto_update' => 1,
		'backend_url' => FREESIEM_SENTINEL_BACKEND_URL,
		'api_key' => '',
		'hmac_secret' => '',
		'plan' => 'free',
		'registration_status' => 'unregistered',
		'last_local_scan_at' => '',
		'last_remote_scan_at' => '',
		'last_sync_at' => '',
		'last_heartbeat_at' => '',
		'last_heartbeat_result' => '',
		'fim_enabled' => 1,
		'fim_last_baseline_at' => '',
		'fim_last_diff_at' => '',
		'fim_baseline' => [],
		'fim_diff_cache' => [],
		'scan_preferences' => [
			'scan_wordpress' => 1,
			'scan_filesystem' => 1,
			'scan_fim' => 1,
			'include_uploads' => 0,
			'max_files' => 1000,
			'max_depth' => 5,
		],
		'summary_cache' => [
			'fetched_at' => '',
			'summary' => [],
			'local_findings' => [],
			'local_inventory' => [],
			'severity_counts' => [],
			'top_issues' => [],
			'recommendations' => [],
			'notices' => [],
		],
		'updater_cache' => [],
	];
}

function freesiem_sentinel_safe_string($value): string
{
	if (is_string($value)) {
		return $value;
	}

	if (is_numeric($value)) {
		return (string) $value;
	}

	if (is_bool($value)) {
		return $value ? '1' : '0';
	}

	return '';
}

function safe($value): string
{
	return is_null($value) ? '' : freesiem_sentinel_safe_string($value);
}

function freesiem_sentinel_safe_array($value): array
{
	return is_array($value) ? $value : [];
}

function freesiem_sentinel_safe_json_pretty($value): string
{
	$json = wp_json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

	return is_string($json) ? $json : '';
}

function freesiem_sentinel_get_settings(): array
{
	$saved = get_option(FREESIEM_SENTINEL_OPTION, []);

	if (!is_array($saved)) {
		$saved = [];
	}

	return wp_parse_args($saved, freesiem_sentinel_get_default_settings());
}

function freesiem_sentinel_get_setting(string $key, $default = '')
{
	$settings = freesiem_sentinel_get_settings();

	return $settings[$key] ?? $default;
}

function freesiem_sentinel_update_settings(array $updates): array
{
	$settings = freesiem_sentinel_get_settings();
	$merged = array_replace_recursive($settings, $updates);
	$sanitized = freesiem_sentinel_sanitize_settings($merged);

	if (get_option(FREESIEM_SENTINEL_OPTION, null) === null) {
		add_option(FREESIEM_SENTINEL_OPTION, $sanitized, '', false);
	} else {
		update_option(FREESIEM_SENTINEL_OPTION, $sanitized, false);
	}

	return $sanitized;
}

function freesiem_sentinel_sanitize_settings(array $settings): array
{
	$defaults = freesiem_sentinel_get_default_settings();
	$settings = wp_parse_args($settings, $defaults);
	$valid_connection_states = ['disconnected', 'pending_verification', 'connected', 'suspended', 'revoked'];

	$settings['site_id'] = sanitize_text_field((string) $settings['site_id']);
	$settings['plugin_uuid'] = sanitize_text_field((string) $settings['plugin_uuid']);
	$settings['local_seed'] = sanitize_text_field((string) ($settings['local_seed'] ?? ''));
	$settings['connection_id'] = sanitize_text_field((string) ($settings['connection_id'] ?? ''));
	$settings['email'] = sanitize_email((string) $settings['email']);
	$settings['phone'] = freesiem_sentinel_sanitize_phone_number((string) ($settings['phone'] ?? ($settings['phone_number'] ?? '')));
	$settings['phone_number'] = $settings['phone'];
	$settings['cloud_users'] = array_values(array_filter(array_map('sanitize_email', is_array($settings['cloud_users'] ?? null) ? $settings['cloud_users'] : [])));
	$settings['connection_state'] = in_array((string) ($settings['connection_state'] ?? ($settings['cloud_connection_state'] ?? 'disconnected')), $valid_connection_states, true) ? (string) ($settings['connection_state'] ?? $settings['cloud_connection_state']) : 'disconnected';
	$settings['cloud_connection_state'] = $settings['connection_state'];
	$settings['connect_expires_at'] = freesiem_sentinel_sanitize_datetime((string) ($settings['connect_expires_at'] ?? ''));
	$settings['cloud_verification_code'] = sanitize_text_field((string) ($settings['cloud_verification_code'] ?? ''));
	$settings['cloud_connected_at'] = freesiem_sentinel_sanitize_datetime((string) ($settings['cloud_connected_at'] ?? ''));
	$settings['allow_remote_scan'] = empty($settings['allow_remote_scan']) ? 0 : 1;
	$settings['scan_frequency'] = in_array((string) ($settings['scan_frequency'] ?? 'daily'), ['manual', 'daily', '6hours', 'hourly'], true) ? (string) $settings['scan_frequency'] : 'daily';
	$settings['user_sync_enabled'] = empty($settings['user_sync_enabled']) ? 0 : 1;
	$settings['plugin_auto_update'] = empty($settings['plugin_auto_update']) ? 0 : 1;
	$settings['backend_url'] = freesiem_sentinel_sanitize_backend_url((string) $settings['backend_url']);
	$settings['api_key'] = sanitize_text_field((string) $settings['api_key']);
	$settings['hmac_secret'] = sanitize_text_field((string) $settings['hmac_secret']);
	$settings['plan'] = in_array((string) ($settings['plan'] ?? 'free'), ['free', 'pro'], true) ? (string) $settings['plan'] : 'free';
	$settings['registration_status'] = sanitize_key((string) $settings['registration_status']);
	$settings['last_local_scan_at'] = freesiem_sentinel_sanitize_datetime((string) $settings['last_local_scan_at']);
	$settings['last_remote_scan_at'] = freesiem_sentinel_sanitize_datetime((string) $settings['last_remote_scan_at']);
	$settings['last_sync_at'] = freesiem_sentinel_sanitize_datetime((string) $settings['last_sync_at']);
	$settings['last_heartbeat_at'] = freesiem_sentinel_sanitize_datetime((string) $settings['last_heartbeat_at']);
	$settings['last_heartbeat_result'] = sanitize_text_field((string) ($settings['last_heartbeat_result'] ?? ''));
	$settings['fim_enabled'] = empty($settings['fim_enabled']) ? 0 : 1;
	$settings['fim_last_baseline_at'] = freesiem_sentinel_sanitize_datetime((string) $settings['fim_last_baseline_at']);
	$settings['fim_last_diff_at'] = freesiem_sentinel_sanitize_datetime((string) $settings['fim_last_diff_at']);
	$settings['fim_baseline'] = is_array($settings['fim_baseline']) ? $settings['fim_baseline'] : [];
	$settings['fim_diff_cache'] = is_array($settings['fim_diff_cache']) ? $settings['fim_diff_cache'] : [];
	$settings['scan_preferences'] = is_array($settings['scan_preferences']) ? $settings['scan_preferences'] : $defaults['scan_preferences'];
	$settings['scan_preferences']['scan_wordpress'] = empty($settings['scan_preferences']['scan_wordpress']) ? 0 : 1;
	$settings['scan_preferences']['scan_filesystem'] = empty($settings['scan_preferences']['scan_filesystem']) ? 0 : 1;
	$settings['scan_preferences']['scan_fim'] = empty($settings['scan_preferences']['scan_fim']) ? 0 : 1;
	$settings['scan_preferences']['include_uploads'] = empty($settings['scan_preferences']['include_uploads']) ? 0 : 1;
	$settings['scan_preferences']['max_files'] = max(100, min(5000, (int) ($settings['scan_preferences']['max_files'] ?? 1000)));
	$settings['scan_preferences']['max_depth'] = max(1, min(10, (int) ($settings['scan_preferences']['max_depth'] ?? 5)));

	$settings['summary_cache'] = is_array($settings['summary_cache']) ? $settings['summary_cache'] : $defaults['summary_cache'];
	$settings['updater_cache'] = is_array($settings['updater_cache']) ? $settings['updater_cache'] : [];

	return $settings;
}

function freesiem_sentinel_sanitize_backend_url(string $url): string
{
	$url = trim(freesiem_sentinel_safe_string($url));
	$url = $url === '' ? FREESIEM_SENTINEL_BACKEND_URL : $url;
	$url = esc_url_raw(untrailingslashit($url));

	if ($url === '') {
		return FREESIEM_SENTINEL_BACKEND_URL;
	}

	$parts = wp_parse_url($url);
	$scheme = strtolower((string) ($parts['scheme'] ?? ''));
	$host = strtolower((string) ($parts['host'] ?? ''));

	if ($scheme !== 'https' && !in_array($host, ['localhost', '127.0.0.1'], true)) {
		return FREESIEM_SENTINEL_BACKEND_URL;
	}

	return $url;
}

function freesiem_sentinel_sanitize_phone_number(string $value): string
{
	$digits = preg_replace('/\D+/', '', $value);
	$digits = is_string($digits) ? $digits : '';

	if ($digits === '') {
		return '';
	}

	if (strlen($digits) === 11 && str_starts_with($digits, '1')) {
		$digits = substr($digits, 1);
	}

	if (strlen($digits) !== 10) {
		return '';
	}

	// Basic NANP validation rejects obviously invalid US numbers for MVP.
	if (!preg_match('/^[2-9]\d{2}[2-9]\d{6}$/', $digits)) {
		return '';
	}

	return $digits;
}

function freesiem_sentinel_is_valid_us_phone(string $value): bool
{
	return freesiem_sentinel_sanitize_phone_number($value) !== '';
}

function freesiem_sentinel_format_phone(string $value, bool $masked = false): string
{
	$digits = freesiem_sentinel_sanitize_phone_number($value);

	if ($digits === '') {
		return '';
	}

	if ($masked) {
		return sprintf('+1 XXX-XXX-%s', substr($digits, -4));
	}

	return sprintf('+1 (%s) %s-%s', substr($digits, 0, 3), substr($digits, 3, 3), substr($digits, 6, 4));
}

function freesiem_sentinel_sanitize_datetime(string $value): string
{
	$value = trim(freesiem_sentinel_safe_string($value));

	if ($value === '') {
		return '';
	}

	$timestamp = strtotime($value);

	return $timestamp ? gmdate('c', $timestamp) : '';
}

function freesiem_sentinel_get_iso8601_time(?int $timestamp = null): string
{
	$timestamp = $timestamp ?: time();

	return gmdate('c', $timestamp);
}

function freesiem_sentinel_generate_random_token(int $length = 32): string
{
	$length = max(8, $length);
	$byte_length = (int) ceil($length / 2);

	try {
		$token = bin2hex(random_bytes($byte_length));
	} catch (Throwable $throwable) {
		if (function_exists('openssl_random_pseudo_bytes')) {
			$bytes = openssl_random_pseudo_bytes($byte_length);
			$token = is_string($bytes) ? bin2hex($bytes) : '';
		} else {
			$token = '';

			for ($i = 0; $i < $byte_length; $i++) {
				$token .= str_pad(dechex(mt_rand(0, 255)), 2, '0', STR_PAD_LEFT);
			}
		}
	}

	return substr($token, 0, $length);
}

function freesiem_sentinel_get_timezone_string(): string
{
	if (function_exists('wp_timezone_string')) {
		$timezone = wp_timezone_string();

		if (is_string($timezone) && $timezone !== '') {
			return $timezone;
		}
	}

	$timezone = get_option('timezone_string');

	if (is_string($timezone) && $timezone !== '') {
		return $timezone;
	}

	$offset = (float) get_option('gmt_offset', 0);

	return $offset === 0.0 ? 'UTC' : sprintf('UTC%+g', $offset);
}

function freesiem_sentinel_get_effective_cloud_backend_base_url(?array $settings = null): string
{
	return FREESIEM_SENTINEL_BACKEND_URL;
}

function freesiem_sentinel_is_custom_cloud_backend(?array $settings = null): bool
{
	return false;
}

function freesiem_sentinel_mask_secret(string $value, int $visible = 4): string
{
	$value = trim(freesiem_sentinel_safe_string($value));

	if ($value === '') {
		return '';
	}

	$length = strlen($value);

	if ($length <= $visible) {
		return str_repeat('*', $length);
	}

	return str_repeat('*', max(4, $length - $visible)) . substr($value, -1 * $visible);
}

function freesiem_sentinel_set_notice(string $type, string $message): void
{
	$notices = get_transient('freesiem_sentinel_admin_notices');

	if (!is_array($notices)) {
		$notices = [];
	}

	$notices[] = [
		'type' => $type,
		'message' => $message,
	];

	set_transient('freesiem_sentinel_admin_notices', $notices, MINUTE_IN_SECONDS * 5);
}

function freesiem_sentinel_render_notices(): void
{
	$notices = get_transient('freesiem_sentinel_admin_notices');

	if (!is_array($notices) || $notices === []) {
		return;
	}

	delete_transient('freesiem_sentinel_admin_notices');

	foreach ($notices as $notice) {
		$type = sanitize_html_class((string) ($notice['type'] ?? 'info'));
		$message = (string) ($notice['message'] ?? '');

		if ($message === '') {
			continue;
		}

		printf(
			'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
			esc_attr($type),
			esc_html($message)
		);
	}
}

function freesiem_sentinel_require_admin_post_nonce(): void
{
	check_admin_referer(FREESIEM_SENTINEL_NONCE_ACTION);
}

function freesiem_sentinel_admin_post_url(string $action, array $args = []): string
{
	$url = add_query_arg(
		freesiem_sentinel_safe_query_args(array_merge(['action' => $action], $args)),
		admin_url('admin-post.php')
	);

	return wp_nonce_url($url, FREESIEM_SENTINEL_NONCE_ACTION);
}

function freesiem_sentinel_admin_page_url(string $page, array $args = []): string
{
	$page = sanitize_key($page);
	$url = add_query_arg(
		freesiem_sentinel_safe_query_args(array_merge(['page' => $page], $args)),
		admin_url('admin.php')
	);

	return (string) $url;
}

function freesiem_sentinel_safe_query_args(array $args): array
{
	$safe = [];

	foreach ($args as $key => $value) {
		$key = safe($key);

		if ($key === '' || $value === null) {
			continue;
		}

		if (is_array($value)) {
			$safe[$key] = array_values(array_map(static fn($item): string => safe($item), $value));
			continue;
		}

		$safe[$key] = safe($value);
	}

	return $safe;
}

function freesiem_sentinel_current_user_can_manage(): bool
{
	return current_user_can('manage_options');
}

function freesiem_sentinel_get_plugin_basename(): string
{
	return FREESIEM_SENTINEL_PLUGIN_BASENAME;
}

function freesiem_sentinel_get_plugin_slug(): string
{
	return dirname(FREESIEM_SENTINEL_PLUGIN_BASENAME);
}

function freesiem_sentinel_get_allowed_remote_setting_keys(): array
{
	return [
		'backend_url',
		'email',
		'plan',
	];
}

function freesiem_sentinel_get_allowed_command_types(): array
{
	return [
		'run_local_scan',
		'sync_results',
		'request_remote_scan',
		'send_inventory',
		'reconnect',
		'refresh_update_check',
		'update_settings',
	];
}

function freesiem_sentinel_normalize_severity(string $severity): string
{
	$severity = strtolower(trim($severity));
	$allowed = ['critical', 'high', 'medium', 'low', 'info'];

	return in_array($severity, $allowed, true) ? $severity : 'info';
}

function freesiem_sentinel_get_severity_weight(string $severity): int
{
	return match (freesiem_sentinel_normalize_severity($severity)) {
		'critical' => 25,
		'high' => 15,
		'medium' => 8,
		'low' => 3,
		default => 1,
	};
}

function freesiem_sentinel_score_from_findings(array $findings): int
{
	$penalty = 0;

	foreach ($findings as $finding) {
		if (!is_array($finding)) {
			continue;
		}

		$penalty += freesiem_sentinel_get_severity_weight((string) ($finding['severity'] ?? 'info'));
	}

	return max(0, min(100, 100 - $penalty));
}

function freesiem_sentinel_format_datetime(string $value): string
{
	$value = freesiem_sentinel_safe_string($value);

	if ($value === '') {
		return 'Never';
	}

	$timestamp = strtotime($value);

	if (!$timestamp) {
		return 'Unknown';
	}

	return wp_date('Y-m-d H:i:s T', $timestamp);
}

function freesiem_sentinel_array_get(array $data, string $key, $default = null)
{
	return array_key_exists($key, $data) ? $data[$key] : $default;
}
