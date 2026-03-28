<?php

if (!defined('ABSPATH')) {
	exit;
}

function freesiem_sentinel_get_default_settings(): array
{
	return [
		'site_id' => '',
		'plugin_uuid' => '',
		'email' => '',
		'backend_url' => FREESIEM_SENTINEL_BACKEND_URL,
		'api_key' => '',
		'hmac_secret' => '',
		'registration_status' => 'unregistered',
		'last_local_scan_at' => '',
		'last_remote_scan_at' => '',
		'last_sync_at' => '',
		'last_heartbeat_at' => '',
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

	$settings['site_id'] = sanitize_text_field((string) $settings['site_id']);
	$settings['plugin_uuid'] = sanitize_text_field((string) $settings['plugin_uuid']);
	$settings['email'] = sanitize_email((string) $settings['email']);
	$settings['backend_url'] = freesiem_sentinel_sanitize_backend_url((string) $settings['backend_url']);
	$settings['api_key'] = sanitize_text_field((string) $settings['api_key']);
	$settings['hmac_secret'] = sanitize_text_field((string) $settings['hmac_secret']);
	$settings['registration_status'] = sanitize_key((string) $settings['registration_status']);
	$settings['last_local_scan_at'] = freesiem_sentinel_sanitize_datetime((string) $settings['last_local_scan_at']);
	$settings['last_remote_scan_at'] = freesiem_sentinel_sanitize_datetime((string) $settings['last_remote_scan_at']);
	$settings['last_sync_at'] = freesiem_sentinel_sanitize_datetime((string) $settings['last_sync_at']);
	$settings['last_heartbeat_at'] = freesiem_sentinel_sanitize_datetime((string) $settings['last_heartbeat_at']);

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
	$url = add_query_arg(array_merge(['action' => $action], $args), admin_url('admin-post.php'));

	return wp_nonce_url($url, FREESIEM_SENTINEL_NONCE_ACTION);
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
