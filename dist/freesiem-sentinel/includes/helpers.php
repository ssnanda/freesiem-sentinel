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
		'enable_pending_task_queue' => 1,
		'auto_approve_enabled_default' => 1,
		'auto_approve_after_minutes_default' => 30,
		'require_manual_approval_for_list_users' => 1,
		'require_manual_approval_for_create_user' => 1,
		'require_manual_approval_for_update_user' => 1,
		'require_manual_approval_for_password_reset' => 1,
		'require_manual_approval_for_delete_user' => 1,
		'allow_auto_approve_list_users' => 1,
		'allow_auto_approve_create_user' => 1,
		'allow_auto_approve_update_user' => 1,
		'allow_auto_approve_password_reset' => 1,
		'allow_auto_approve_delete_user' => 0,
		'allow_set_temp_password_task' => 0,
		'roles_allowed_to_approve_tasks' => ['administrator'],
		'notify_admins_on_pending_task' => 1,
		'include_pending_tasks_in_heartbeat' => 1,
		'heartbeat_include_recent_completed_tasks' => 1,
		'pending_tasks_heartbeat_dirty' => 0,
		'last_task_activity_at' => '',
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
	$settings['enable_pending_task_queue'] = empty($settings['enable_pending_task_queue']) ? 0 : 1;
	$settings['auto_approve_enabled_default'] = empty($settings['auto_approve_enabled_default']) ? 0 : 1;
	$settings['auto_approve_after_minutes_default'] = max(1, min(1440, (int) ($settings['auto_approve_after_minutes_default'] ?? 30)));
	$settings['require_manual_approval_for_list_users'] = empty($settings['require_manual_approval_for_list_users']) ? 0 : 1;
	$settings['require_manual_approval_for_create_user'] = empty($settings['require_manual_approval_for_create_user']) ? 0 : 1;
	$settings['require_manual_approval_for_update_user'] = empty($settings['require_manual_approval_for_update_user']) ? 0 : 1;
	$settings['require_manual_approval_for_password_reset'] = empty($settings['require_manual_approval_for_password_reset']) ? 0 : 1;
	$settings['require_manual_approval_for_delete_user'] = empty($settings['require_manual_approval_for_delete_user']) ? 0 : 1;
	$settings['allow_auto_approve_list_users'] = empty($settings['allow_auto_approve_list_users']) ? 0 : 1;
	$settings['allow_auto_approve_create_user'] = empty($settings['allow_auto_approve_create_user']) ? 0 : 1;
	$settings['allow_auto_approve_update_user'] = empty($settings['allow_auto_approve_update_user']) ? 0 : 1;
	$settings['allow_auto_approve_password_reset'] = empty($settings['allow_auto_approve_password_reset']) ? 0 : 1;
	$settings['allow_auto_approve_delete_user'] = empty($settings['allow_auto_approve_delete_user']) ? 0 : 1;
	$settings['allow_set_temp_password_task'] = empty($settings['allow_set_temp_password_task']) ? 0 : 1;
	$settings['notify_admins_on_pending_task'] = empty($settings['notify_admins_on_pending_task']) ? 0 : 1;
	$settings['include_pending_tasks_in_heartbeat'] = empty($settings['include_pending_tasks_in_heartbeat']) ? 0 : 1;
	$settings['heartbeat_include_recent_completed_tasks'] = empty($settings['heartbeat_include_recent_completed_tasks']) ? 0 : 1;
	$settings['pending_tasks_heartbeat_dirty'] = empty($settings['pending_tasks_heartbeat_dirty']) ? 0 : 1;
	$settings['last_task_activity_at'] = freesiem_sentinel_sanitize_datetime((string) ($settings['last_task_activity_at'] ?? ''));
	$settings['roles_allowed_to_approve_tasks'] = array_values(array_unique(array_filter(array_map('sanitize_key', is_array($settings['roles_allowed_to_approve_tasks'] ?? null) ? $settings['roles_allowed_to_approve_tasks'] : ['administrator']))));
	if ($settings['roles_allowed_to_approve_tasks'] === []) {
		$settings['roles_allowed_to_approve_tasks'] = ['administrator'];
	}
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

function freesiem_sentinel_get_default_ssl_settings(): array
{
	return [
		'enable_management_ui' => 1,
		'acme_contact_email' => '',
		'hostname_override' => '',
		'allow_local_override' => 0,
		'challenge_method' => 'webroot-http-01',
		'webroot_path' => '',
		'check_port_80' => 1,
		'check_port_443' => 1,
		'force_https' => 0,
		'hsts_enabled' => 0,
		'auto_renew' => 0,
		'use_staging' => 1,
		'detailed_logs' => 0,
	];
}

function freesiem_sentinel_get_ssl_settings(): array
{
	$saved = get_option(FREESIEM_SENTINEL_SSL_SETTINGS_OPTION, []);

	if (!is_array($saved)) {
		$saved = [];
	}

	return wp_parse_args($saved, freesiem_sentinel_get_default_ssl_settings());
}

function freesiem_sentinel_update_ssl_settings(array $updates): array
{
	$current = freesiem_sentinel_get_ssl_settings();
	$merged = array_replace_recursive($current, $updates);
	$sanitized = freesiem_sentinel_sanitize_ssl_settings($merged);

	if (get_option(FREESIEM_SENTINEL_SSL_SETTINGS_OPTION, null) === null) {
		add_option(FREESIEM_SENTINEL_SSL_SETTINGS_OPTION, $sanitized, '', false);
	} else {
		update_option(FREESIEM_SENTINEL_SSL_SETTINGS_OPTION, $sanitized, false);
	}

	return $sanitized;
}

function freesiem_sentinel_sanitize_ssl_settings(array $settings): array
{
	$defaults = freesiem_sentinel_get_default_ssl_settings();
	$settings = wp_parse_args($settings, $defaults);

	$settings['enable_management_ui'] = empty($settings['enable_management_ui']) ? 0 : 1;
	$settings['acme_contact_email'] = sanitize_email((string) ($settings['acme_contact_email'] ?? ''));
	$settings['hostname_override'] = strtolower(trim(sanitize_text_field((string) ($settings['hostname_override'] ?? ''))));
	$settings['allow_local_override'] = empty($settings['allow_local_override']) ? 0 : 1;
	$settings['challenge_method'] = in_array((string) ($settings['challenge_method'] ?? 'webroot-http-01'), ['webroot-http-01', 'standalone-http-01', 'manual-dns-01'], true)
		? (string) $settings['challenge_method']
		: 'webroot-http-01';
	$settings['webroot_path'] = trim((string) ($settings['webroot_path'] ?? ''));
	$settings['check_port_80'] = empty($settings['check_port_80']) ? 0 : 1;
	$settings['check_port_443'] = empty($settings['check_port_443']) ? 0 : 1;
	$settings['force_https'] = empty($settings['force_https']) ? 0 : 1;
	$settings['hsts_enabled'] = empty($settings['hsts_enabled']) ? 0 : 1;
	$settings['auto_renew'] = empty($settings['auto_renew']) ? 0 : 1;
	$settings['use_staging'] = empty($settings['use_staging']) ? 0 : 1;
	$settings['detailed_logs'] = empty($settings['detailed_logs']) ? 0 : 1;

	return $settings;
}

function freesiem_sentinel_get_ssl_dry_run(): array
{
	$saved = get_option(FREESIEM_SENTINEL_SSL_DRY_RUN_OPTION, []);

	return freesiem_sentinel_sanitize_ssl_dry_run(is_array($saved) ? $saved : []);
}

function freesiem_sentinel_update_ssl_dry_run(array $dry_run): array
{
	$sanitized = freesiem_sentinel_sanitize_ssl_dry_run($dry_run);

	if (get_option(FREESIEM_SENTINEL_SSL_DRY_RUN_OPTION, null) === null) {
		add_option(FREESIEM_SENTINEL_SSL_DRY_RUN_OPTION, $sanitized, '', false);
	} else {
		update_option(FREESIEM_SENTINEL_SSL_DRY_RUN_OPTION, $sanitized, false);
	}

	return $sanitized;
}

function freesiem_sentinel_get_ssl_preflight(): array
{
	$saved = get_option(FREESIEM_SENTINEL_SSL_PREFLIGHT_OPTION, []);

	return freesiem_sentinel_sanitize_ssl_preflight(is_array($saved) ? $saved : []);
}

function freesiem_sentinel_update_ssl_preflight(array $preflight): array
{
	$sanitized = freesiem_sentinel_sanitize_ssl_preflight($preflight);

	if (get_option(FREESIEM_SENTINEL_SSL_PREFLIGHT_OPTION, null) === null) {
		add_option(FREESIEM_SENTINEL_SSL_PREFLIGHT_OPTION, $sanitized, '', false);
	} else {
		update_option(FREESIEM_SENTINEL_SSL_PREFLIGHT_OPTION, $sanitized, false);
	}

	return $sanitized;
}

function freesiem_sentinel_sanitize_ssl_preflight(array $preflight): array
{
	$items = [];

	foreach ((array) ($preflight['items'] ?? []) as $item) {
		if (!is_array($item)) {
			continue;
		}

		$status = strtoupper(sanitize_key((string) ($item['status'] ?? 'WARN')));
		if (!in_array($status, ['PASS', 'WARN', 'FAIL'], true)) {
			$status = 'WARN';
		}

		$items[] = [
			'key' => sanitize_key((string) ($item['key'] ?? '')),
			'label' => sanitize_text_field((string) ($item['label'] ?? '')),
			'status' => $status,
			'message' => sanitize_text_field((string) ($item['message'] ?? '')),
		];
	}

	return [
		'ran_at' => freesiem_sentinel_sanitize_datetime((string) ($preflight['ran_at'] ?? '')),
		'summary' => sanitize_text_field((string) ($preflight['summary'] ?? '')),
		'counts' => [
			'pass' => max(0, (int) (($preflight['counts']['pass'] ?? 0))),
			'warn' => max(0, (int) (($preflight['counts']['warn'] ?? 0))),
			'fail' => max(0, (int) (($preflight['counts']['fail'] ?? 0))),
		],
		'items' => $items,
	];
}

function freesiem_sentinel_sanitize_ssl_dry_run(array $dry_run): array
{
	$items = [];
	$plan = [];
	$preview = [];
	$context = [];

	foreach ((array) ($dry_run['items'] ?? []) as $item) {
		if (!is_array($item)) {
			continue;
		}

		$status = strtoupper(sanitize_key((string) ($item['status'] ?? 'WARN')));
		if (!in_array($status, ['PASS', 'WARN', 'FAIL'], true)) {
			$status = 'WARN';
		}

		$items[] = [
			'key' => sanitize_key((string) ($item['key'] ?? '')),
			'label' => sanitize_text_field((string) ($item['label'] ?? '')),
			'status' => $status,
			'message' => sanitize_text_field((string) ($item['message'] ?? '')),
		];
	}

	foreach ((array) ($dry_run['plan'] ?? []) as $step) {
		$step = sanitize_text_field((string) $step);
		if ($step !== '') {
			$plan[] = $step;
		}
	}

	foreach ((array) ($dry_run['preview'] ?? []) as $key => $value) {
		$key = sanitize_key((string) $key);
		$value = sanitize_text_field((string) $value);

		if ($key !== '' && $value !== '') {
			$preview[$key] = $value;
		}
	}

	foreach ((array) ($dry_run['context'] ?? []) as $key => $value) {
		$key = sanitize_key((string) $key);
		if ($key === '') {
			continue;
		}

		if (is_array($value)) {
			$context[$key] = array_values(array_map(static fn($item): string => sanitize_text_field((string) $item), $value));
			continue;
		}

		$context[$key] = sanitize_text_field((string) $value);
	}

	return [
		'ran_at' => freesiem_sentinel_sanitize_datetime((string) ($dry_run['ran_at'] ?? '')),
		'summary' => sanitize_text_field((string) ($dry_run['summary'] ?? '')),
		'readiness_state' => sanitize_key((string) ($dry_run['readiness_state'] ?? 'not_configured')),
		'readiness_label' => sanitize_text_field((string) ($dry_run['readiness_label'] ?? '')),
		'preview_mode' => sanitize_text_field((string) ($dry_run['preview_mode'] ?? 'simulated / not executed')),
		'counts' => [
			'pass' => max(0, (int) (($dry_run['counts']['pass'] ?? 0))),
			'warn' => max(0, (int) (($dry_run['counts']['warn'] ?? 0))),
			'fail' => max(0, (int) (($dry_run['counts']['fail'] ?? 0))),
		],
		'items' => $items,
		'plan' => $plan,
		'preview' => $preview,
		'context' => $context,
	];
}

function freesiem_sentinel_get_ssl_logs(): array
{
	$saved = get_option(FREESIEM_SENTINEL_SSL_LOGS_OPTION, []);

	if (!is_array($saved)) {
		$saved = [];
	}

	$logs = [];

	foreach ($saved as $entry) {
		if (!is_array($entry)) {
			continue;
		}

		$logs[] = [
			'timestamp' => freesiem_sentinel_sanitize_datetime((string) ($entry['timestamp'] ?? '')),
			'category' => sanitize_key((string) ($entry['category'] ?? 'general')),
			'level' => sanitize_key((string) ($entry['level'] ?? 'info')),
			'message' => sanitize_text_field((string) ($entry['message'] ?? '')),
			'context' => freesiem_sentinel_sanitize_ssl_log_context((array) ($entry['context'] ?? [])),
		];
	}

	return $logs;
}

function freesiem_sentinel_add_ssl_log(string $level, string $message, string $category = 'general', array $context = []): void
{
	$logs = freesiem_sentinel_get_ssl_logs();
	$logs[] = [
		'timestamp' => freesiem_sentinel_get_iso8601_time(),
		'category' => sanitize_key($category),
		'level' => sanitize_key($level),
		'message' => sanitize_text_field($message),
		'context' => freesiem_sentinel_sanitize_ssl_log_context($context),
	];

	if (count($logs) > 50) {
		$logs = array_slice($logs, -50);
	}

	if (get_option(FREESIEM_SENTINEL_SSL_LOGS_OPTION, null) === null) {
		add_option(FREESIEM_SENTINEL_SSL_LOGS_OPTION, $logs, '', false);
	} else {
		update_option(FREESIEM_SENTINEL_SSL_LOGS_OPTION, $logs, false);
	}
}

function freesiem_sentinel_sanitize_ssl_log_context(array $context): array
{
	$sanitized = [];

	foreach ($context as $key => $value) {
		$key = sanitize_key((string) $key);

		if ($key === '') {
			continue;
		}

		if (is_array($value)) {
			$sanitized[$key] = array_values(array_map(static fn($item): string => sanitize_text_field((string) $item), $value));
			continue;
		}

		$sanitized[$key] = sanitize_text_field((string) $value);
	}

	return $sanitized;
}

function freesiem_sentinel_run_ssl_preflight(?array $ssl_settings = null): array
{
	$ssl_settings = is_array($ssl_settings) ? $ssl_settings : freesiem_sentinel_get_ssl_settings();
	$environment = freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
	$challenge_ready = freesiem_sentinel_ssl_challenge_ready($ssl_settings, $environment);
	$items = [
		freesiem_sentinel_make_ssl_preflight_item(
			'urls_present',
			__('Site and home URLs exist', 'freesiem-sentinel'),
			$environment['site_url'] !== '' && $environment['home_url'] !== '',
			__('WordPress returned both `site_url()` and `home_url()` values.', 'freesiem-sentinel'),
			__('WordPress is missing one or both configured site URLs.', 'freesiem-sentinel')
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'host_parse',
			__('Host can be parsed', 'freesiem-sentinel'),
			$environment['configured_host'] !== '',
			sprintf(__('Using host `%s` for SSL preflight.', 'freesiem-sentinel'), $environment['configured_host']),
			__('No valid host could be parsed from the configured URLs or override.', 'freesiem-sentinel')
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'public_host',
			__('Host looks public', 'freesiem-sentinel'),
			$environment['configured_host'] !== '' && !$environment['is_local_host'] && !$environment['is_ip'],
			sprintf(__('Host `%s` looks like a public DNS name.', 'freesiem-sentinel'), $environment['configured_host']),
			!empty($ssl_settings['allow_local_override'])
				? __('A local or IP-based host is configured, but the explicit override is enabled for future testing.', 'freesiem-sentinel')
				: __('The detected host is localhost, private-only, or a raw IP address. Use a public hostname or enable the explicit override if you are intentionally testing.', 'freesiem-sentinel'),
			!empty($ssl_settings['allow_local_override']) && ($environment['is_local_host'] || $environment['is_ip']) ? 'WARN' : 'FAIL'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'https_enabled',
			__('HTTPS currently enabled', 'freesiem-sentinel'),
			$environment['is_https_configured'],
			__('WordPress is already configured with HTTPS on the site or home URL.', 'freesiem-sentinel'),
			__('WordPress is still configured with HTTP URLs, which is fine for this status-only phase.', 'freesiem-sentinel'),
			'WARN'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'execution_functions',
			__('Future execution functions availability', 'freesiem-sentinel'),
			$environment['execution_support'],
			sprintf(
				__('shell_exec:%1$s, exec:%2$s, proc_open:%3$s, passthru:%4$s, system:%5$s', 'freesiem-sentinel'),
				freesiem_sentinel_bool_label($environment['shell_functions']['shell_exec']),
				freesiem_sentinel_bool_label($environment['shell_functions']['exec']),
				freesiem_sentinel_bool_label($environment['shell_functions']['proc_open']),
				freesiem_sentinel_bool_label($environment['shell_functions']['passthru']),
				freesiem_sentinel_bool_label($environment['shell_functions']['system'])
			),
			'',
			'WARN'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'writable_paths',
			__('ABSPATH and wp-content writability', 'freesiem-sentinel'),
			$environment['abspath_writable'] && $environment['wp_content_writable'],
			sprintf(__('ABSPATH and `%s` appear writable for future storage needs.', 'freesiem-sentinel'), $environment['wp_content_dir']),
			sprintf(__('One or more expected paths are not writable. ABSPATH: %1$s, wp-content: %2$s.', 'freesiem-sentinel'), freesiem_sentinel_bool_label($environment['abspath_writable']), freesiem_sentinel_bool_label($environment['wp_content_writable'])),
			'WARN'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'option_storage',
			__('Plugin can store settings/options', 'freesiem-sentinel'),
			$environment['option_probe'],
			__('A temporary SSL probe option was written and removed successfully.', 'freesiem-sentinel'),
			__('WordPress option storage could not be confirmed by the temporary probe.', 'freesiem-sentinel')
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'wp_cron',
			__('WP-Cron available', 'freesiem-sentinel'),
			$environment['wp_cron_enabled'],
			__('WP-Cron appears enabled for future background work.', 'freesiem-sentinel'),
			__('WP-Cron appears disabled. Future renewals would need another scheduler.', 'freesiem-sentinel'),
			'WARN'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'http_support',
			__('Loopback / HTTP request support exists', 'freesiem-sentinel'),
			$environment['http_support'],
			__('WordPress HTTP transport support is available.', 'freesiem-sentinel'),
			__('WordPress HTTP transports do not appear available for loopback-style checks.', 'freesiem-sentinel'),
			'WARN'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'dns_lookup',
			__('DNS lookup succeeds', 'freesiem-sentinel'),
			$environment['dns_result']['ok'],
			$environment['dns_result']['message'],
			$environment['dns_result']['message'],
			$environment['is_local_host'] || $environment['configured_host'] === '' ? 'WARN' : 'FAIL'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'port_intent',
			__('Port 80/443 intent configured', 'freesiem-sentinel'),
			!empty($ssl_settings['check_port_80']) || !empty($ssl_settings['check_port_443']),
			sprintf(__('Configured intent: port 80 %1$s, port 443 %2$s.', 'freesiem-sentinel'), !empty($ssl_settings['check_port_80']) ? __('on', 'freesiem-sentinel') : __('off', 'freesiem-sentinel'), !empty($ssl_settings['check_port_443']) ? __('on', 'freesiem-sentinel') : __('off', 'freesiem-sentinel')),
			__('No future port intent is configured yet.', 'freesiem-sentinel'),
			'WARN'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'challenge_ready',
			__('Challenge method minimum data is configured', 'freesiem-sentinel'),
			$challenge_ready['ok'],
			$challenge_ready['message'],
			$challenge_ready['message'],
			$challenge_ready['ok'] ? 'PASS' : 'WARN'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'contact_email',
			__('ACME contact email populated', 'freesiem-sentinel'),
			is_email((string) ($ssl_settings['acme_contact_email'] ?? '')),
			sprintf(__('ACME contact email is set to `%s`.', 'freesiem-sentinel'), (string) $ssl_settings['acme_contact_email']),
			__('Add a contact email before future certificate issuance is implemented.', 'freesiem-sentinel'),
			'WARN'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'staging_mode',
			__('Staging mode toggle set', 'freesiem-sentinel'),
			!empty($ssl_settings['use_staging']),
			__('Let’s Encrypt staging is enabled for future safe testing.', 'freesiem-sentinel'),
			__('Staging mode is off. Production mode is not active in this release, but staging is safer for the next phase.', 'freesiem-sentinel'),
			'WARN'
		),
	];

	$counts = freesiem_sentinel_count_ssl_status_items($items);
	$summary = sprintf(
		__('Preflight completed: %1$d pass, %2$d warn, %3$d fail.', 'freesiem-sentinel'),
		$counts['pass'],
		$counts['warn'],
		$counts['fail']
	);

	return freesiem_sentinel_update_ssl_preflight([
		'ran_at' => freesiem_sentinel_get_iso8601_time(),
		'summary' => $summary,
		'counts' => $counts,
		'items' => $items,
	]);
}

function freesiem_sentinel_run_ssl_dry_run(?array $ssl_settings = null): array
{
	$ssl_settings = is_array($ssl_settings) ? $ssl_settings : freesiem_sentinel_get_ssl_settings();
	$preflight = freesiem_sentinel_run_ssl_preflight($ssl_settings);
	$environment = freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
	$readiness = freesiem_sentinel_calculate_ssl_readiness($ssl_settings, $environment, $preflight);
	$preview = freesiem_sentinel_get_ssl_command_preview($ssl_settings, $environment);
	$method_items = freesiem_sentinel_get_ssl_method_validation_items($ssl_settings, $environment);
	$dry_run_items = array_merge(
		[
			freesiem_sentinel_make_ssl_preflight_item(
				'readiness_state',
				__('Execution readiness state calculated', 'freesiem-sentinel'),
				in_array($readiness['state'], ['ready_for_dry_run', 'future_ready'], true),
				sprintf(__('Readiness is `%s`.', 'freesiem-sentinel'), $readiness['label']),
				sprintf(__('Readiness is `%s`.', 'freesiem-sentinel'), $readiness['label']),
				$readiness['state'] === 'blocked' ? 'FAIL' : 'WARN'
			),
			freesiem_sentinel_make_ssl_preflight_item(
				'preflight_recheck',
				__('Preflight re-ran successfully', 'freesiem-sentinel'),
				!empty($preflight['ran_at']),
				$preflight['summary'],
				__('Preflight could not be re-run for dry-run validation.', 'freesiem-sentinel')
			),
			freesiem_sentinel_make_ssl_preflight_item(
				'preview_generated',
				__('Simulated command preview generated', 'freesiem-sentinel'),
				!empty($preview['command']),
				__('A simulated certbot command preview was generated and not executed.', 'freesiem-sentinel'),
				__('A simulated command preview could not be built from the current settings.', 'freesiem-sentinel'),
				'WARN'
			),
		],
		$method_items
	);
	$counts = freesiem_sentinel_count_ssl_status_items($dry_run_items);
	$would_attempt = $counts['fail'] === 0 && in_array($readiness['state'], ['ready_for_dry_run', 'future_ready'], true);
	$summary = sprintf(
		__('Dry run completed: %1$d pass, %2$d warn, %3$d fail. Would be ready to attempt issuance: %4$s.', 'freesiem-sentinel'),
		$counts['pass'],
		$counts['warn'],
		$counts['fail'],
		$would_attempt ? __('PASS', 'freesiem-sentinel') : ($counts['fail'] > 0 ? __('FAIL', 'freesiem-sentinel') : __('WARN', 'freesiem-sentinel'))
	);

	return freesiem_sentinel_update_ssl_dry_run([
		'ran_at' => freesiem_sentinel_get_iso8601_time(),
		'summary' => $summary,
		'readiness_state' => $readiness['state'],
		'readiness_label' => $readiness['label'],
		'preview_mode' => __('simulated / not executed', 'freesiem-sentinel'),
		'counts' => $counts,
		'items' => $dry_run_items,
		'plan' => [
			__('Validate stored SSL settings and recompute readiness.', 'freesiem-sentinel'),
			__('Re-run safe preflight checks for the selected challenge method.', 'freesiem-sentinel'),
			__('Generate a simulated certbot command preview only.', 'freesiem-sentinel'),
			__('Record the dry-run summary without issuing a certificate.', 'freesiem-sentinel'),
		],
		'preview' => $preview,
		'context' => [
			'configured_host' => $environment['configured_host'],
			'challenge_method' => (string) ($ssl_settings['challenge_method'] ?? 'webroot-http-01'),
			'would_attempt_status' => $would_attempt ? 'pass' : ($counts['fail'] > 0 ? 'fail' : 'warn'),
			'https_state' => $environment['is_https_configured'] ? 'https' : 'http',
		],
	]);
}

function freesiem_sentinel_make_ssl_preflight_item(
	string $key,
	string $label,
	bool $condition,
	string $pass_message,
	string $non_pass_message,
	string $non_pass_status = 'FAIL'
): array {
	return [
		'key' => sanitize_key($key),
		'label' => $label,
		'status' => $condition ? 'PASS' : strtoupper($non_pass_status),
		'message' => $condition ? $pass_message : $non_pass_message,
	];
}

function freesiem_sentinel_get_ssl_environment_snapshot(?array $ssl_settings = null): array
{
	$ssl_settings = is_array($ssl_settings) ? $ssl_settings : freesiem_sentinel_get_ssl_settings();
	$site_url = site_url('/');
	$home_url = home_url('/');
	$site_scheme = strtolower((string) wp_parse_url($site_url, PHP_URL_SCHEME));
	$home_scheme = strtolower((string) wp_parse_url($home_url, PHP_URL_SCHEME));
	$site_host = strtolower((string) wp_parse_url($site_url, PHP_URL_HOST));
	$home_host = strtolower((string) wp_parse_url($home_url, PHP_URL_HOST));
	$configured_host = $ssl_settings['hostname_override'] !== '' ? strtolower((string) $ssl_settings['hostname_override']) : $home_host;
	$wp_content_dir = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content';
	$shell_functions = [
		'shell_exec' => function_exists('shell_exec'),
		'exec' => function_exists('exec'),
		'proc_open' => function_exists('proc_open'),
		'passthru' => function_exists('passthru'),
		'system' => function_exists('system'),
	];

	return [
		'site_url' => $site_url,
		'home_url' => $home_url,
		'site_scheme' => $site_scheme,
		'home_scheme' => $home_scheme,
		'site_host' => $site_host,
		'home_host' => $home_host,
		'configured_host' => $configured_host,
		'is_local_host' => freesiem_sentinel_is_local_host($configured_host),
		'is_ip' => $configured_host !== '' && (bool) filter_var($configured_host, FILTER_VALIDATE_IP),
		'dns_result' => freesiem_sentinel_lookup_host($configured_host),
		'option_probe' => freesiem_sentinel_can_store_ssl_probe_option(),
		'wp_content_dir' => $wp_content_dir,
		'abspath_writable' => freesiem_sentinel_path_is_writable(ABSPATH),
		'wp_content_writable' => freesiem_sentinel_path_is_writable($wp_content_dir),
		'wp_cron_enabled' => !defined('DISABLE_WP_CRON') || !DISABLE_WP_CRON,
		'http_support' => function_exists('wp_remote_get') && function_exists('wp_http_supports') && (wp_http_supports(['ssl' => false]) || wp_http_supports(['ssl' => true])),
		'shell_functions' => $shell_functions,
		'execution_support' => in_array(true, $shell_functions, true),
		'is_https_configured' => $site_scheme === 'https' || $home_scheme === 'https',
		'is_admin_request_https' => is_ssl(),
		'host_alignment' => $configured_host !== '' && ($configured_host === $home_host || $configured_host === $site_host),
	];
}

function freesiem_sentinel_calculate_ssl_readiness(?array $ssl_settings = null, ?array $environment = null, ?array $preflight = null): array
{
	$ssl_settings = is_array($ssl_settings) ? $ssl_settings : freesiem_sentinel_get_ssl_settings();
	$environment = is_array($environment) ? $environment : freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
	$preflight = is_array($preflight) ? $preflight : freesiem_sentinel_get_ssl_preflight();
	$has_email = is_email((string) ($ssl_settings['acme_contact_email'] ?? ''));
	$has_host = $environment['configured_host'] !== '';
	$has_method = in_array((string) ($ssl_settings['challenge_method'] ?? ''), ['webroot-http-01', 'standalone-http-01', 'manual-dns-01'], true);
	$method_ready = freesiem_sentinel_ssl_challenge_ready($ssl_settings, $environment);
	$required_core = $has_email && $has_host && $has_method;
	$blocked = (!$required_core && !$has_email && !$has_host)
		? false
		: (
			($environment['is_local_host'] || $environment['is_ip']) && empty($ssl_settings['allow_local_override'])
			|| (!$environment['dns_result']['ok'] && !$environment['is_local_host'] && $environment['configured_host'] !== '')
			|| !$environment['option_probe']
		);

	if (!$has_email && !$has_host) {
		$state = 'not_configured';
		$label = __('Not configured', 'freesiem-sentinel');
	} elseif ($blocked) {
		$state = 'blocked';
		$label = __('Blocked', 'freesiem-sentinel');
	} elseif (!$required_core || !$method_ready['ok']) {
		$state = 'partially_configured';
		$label = __('Partially configured', 'freesiem-sentinel');
	} elseif ((int) ($preflight['counts']['fail'] ?? 0) > 0 || (int) ($preflight['counts']['warn'] ?? 0) > 0) {
		$state = 'ready_for_dry_run';
		$label = __('Ready for dry run', 'freesiem-sentinel');
	} else {
		$state = 'future_ready';
		$label = __('Future ready', 'freesiem-sentinel');
	}

	return [
		'state' => $state,
		'label' => $label,
		'description' => match ($state) {
			'not_configured' => __('Add the hostname, contact email, and challenge details before SSL execution planning can proceed.', 'freesiem-sentinel'),
			'partially_configured' => __('The SSL setup has some required values, but it still needs more challenge-specific configuration.', 'freesiem-sentinel'),
			'ready_for_dry_run' => __('The SSL setup is complete enough for safe simulation, but environment warnings should still be reviewed.', 'freesiem-sentinel'),
			'blocked' => __('A blocking condition exists, such as a local-only host, unresolved DNS, or missing storage capability.', 'freesiem-sentinel'),
			default => __('The configuration is fully modeled for a future execution phase, but issuance remains disabled in this version.', 'freesiem-sentinel'),
		},
	];
}

function freesiem_sentinel_get_ssl_command_preview(?array $ssl_settings = null, ?array $environment = null): array
{
	$ssl_settings = is_array($ssl_settings) ? $ssl_settings : freesiem_sentinel_get_ssl_settings();
	$environment = is_array($environment) ? $environment : freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
	$method = (string) ($ssl_settings['challenge_method'] ?? 'webroot-http-01');
	$host = $environment['configured_host'] !== '' ? $environment['configured_host'] : 'example.com';
	$email = is_email((string) ($ssl_settings['acme_contact_email'] ?? '')) ? (string) $ssl_settings['acme_contact_email'] : 'admin@example.com';
	$staging_flag = !empty($ssl_settings['use_staging']) ? ' --staging' : '';
	$base = 'certbot certonly --agree-tos --non-interactive --email ' . escapeshellarg($email) . ' -d ' . escapeshellarg($host);

	$command = match ($method) {
		'standalone-http-01' => $base . ' --standalone --preferred-challenges http' . $staging_flag,
		'manual-dns-01' => $base . ' --manual --preferred-challenges dns --manual-public-ip-logging-ok' . $staging_flag,
		default => $base . ' --webroot -w ' . escapeshellarg((string) ($ssl_settings['webroot_path'] !== '' ? $ssl_settings['webroot_path'] : ABSPATH)) . ' --preferred-challenges http' . $staging_flag,
	};

	return [
		'command' => $command,
		'label' => __('Simulated command preview only. Not executed.', 'freesiem-sentinel'),
		'method' => $method,
	];
}

function freesiem_sentinel_get_ssl_method_validation_items(?array $ssl_settings = null, ?array $environment = null): array
{
	$ssl_settings = is_array($ssl_settings) ? $ssl_settings : freesiem_sentinel_get_ssl_settings();
	$environment = is_array($environment) ? $environment : freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
	$method = (string) ($ssl_settings['challenge_method'] ?? 'webroot-http-01');
	$items = [
		freesiem_sentinel_make_ssl_preflight_item(
			'method_domain',
			__('Domain / host present', 'freesiem-sentinel'),
			$environment['configured_host'] !== '',
			sprintf(__('Host `%s` is available for the selected challenge method.', 'freesiem-sentinel'), $environment['configured_host']),
			__('Add a hostname before attempting challenge-specific planning.', 'freesiem-sentinel'),
			'FAIL'
		),
		freesiem_sentinel_make_ssl_preflight_item(
			'method_email',
			__('Contact email present', 'freesiem-sentinel'),
			is_email((string) ($ssl_settings['acme_contact_email'] ?? '')),
			__('The ACME contact email is present.', 'freesiem-sentinel'),
			__('Add a valid contact email before certificate planning.', 'freesiem-sentinel'),
			'FAIL'
		),
	];

	if ($method === 'webroot-http-01') {
		$webroot = (string) ($ssl_settings['webroot_path'] ?? '');
		$items[] = freesiem_sentinel_make_ssl_preflight_item(
			'webroot_path_present',
			__('Webroot path present', 'freesiem-sentinel'),
			$webroot !== '',
			sprintf(__('Webroot path `%s` is configured.', 'freesiem-sentinel'), $webroot),
			__('Webroot HTTP-01 requires a webroot path.', 'freesiem-sentinel'),
			'FAIL'
		);
		$items[] = freesiem_sentinel_make_ssl_preflight_item(
			'webroot_exists',
			__('Webroot path exists', 'freesiem-sentinel'),
			$webroot !== '' && file_exists($webroot),
			__('The configured webroot path exists.', 'freesiem-sentinel'),
			__('The configured webroot path does not exist.', 'freesiem-sentinel'),
			'FAIL'
		);
		$items[] = freesiem_sentinel_make_ssl_preflight_item(
			'webroot_readable',
			__('Webroot path readable', 'freesiem-sentinel'),
			$webroot !== '' && is_readable($webroot),
			__('The configured webroot path is readable.', 'freesiem-sentinel'),
			__('The configured webroot path is not readable.', 'freesiem-sentinel'),
			'WARN'
		);
		$items[] = freesiem_sentinel_make_ssl_preflight_item(
			'webroot_writable',
			__('Webroot path writable', 'freesiem-sentinel'),
			$webroot !== '' && freesiem_sentinel_path_is_writable($webroot),
			__('The configured webroot path is writable for expected challenge files.', 'freesiem-sentinel'),
			__('The configured webroot path is not writable, so challenge file placement may fail later.', 'freesiem-sentinel'),
			'WARN'
		);
		$items[] = freesiem_sentinel_make_ssl_preflight_item(
			'host_alignment',
			__('Current site host alignment', 'freesiem-sentinel'),
			$environment['host_alignment'],
			__('The selected hostname matches the current WordPress site host.', 'freesiem-sentinel'),
			__('The selected hostname does not match the current WordPress site host.', 'freesiem-sentinel'),
			'WARN'
		);
	} elseif ($method === 'standalone-http-01') {
		$items[] = freesiem_sentinel_make_ssl_preflight_item(
			'standalone_execution_support',
			__('Shell execution capability available', 'freesiem-sentinel'),
			$environment['execution_support'],
			__('At least one future execution-related PHP function is available.', 'freesiem-sentinel'),
			__('No future execution-related PHP functions appear available.', 'freesiem-sentinel'),
			'WARN'
		);
		$items[] = freesiem_sentinel_make_ssl_preflight_item(
			'standalone_port_binding_live',
			__('Port binding / server conflicts tested live', 'freesiem-sentinel'),
			false,
			'',
			__('Live port-binding conflict checks are intentionally deferred to a later phase.', 'freesiem-sentinel'),
			'WARN'
		);
		$items[] = freesiem_sentinel_make_ssl_preflight_item(
			'standalone_runtime_deferred',
			__('Actual standalone runtime check deferred', 'freesiem-sentinel'),
			false,
			'',
			__('Actual standalone runtime validation is deferred to a future phase.', 'freesiem-sentinel'),
			'WARN'
		);
	} else {
		$items[] = freesiem_sentinel_make_ssl_preflight_item(
			'manual_dns_note',
			__('DNS TXT creation remains manual', 'freesiem-sentinel'),
			false,
			'',
			__('Manual DNS-01 requires manual TXT record creation. Automation is not implemented in the current design.', 'freesiem-sentinel'),
			'WARN'
		);
	}

	return $items;
}

function freesiem_sentinel_count_ssl_status_items(array $items): array
{
	$counts = ['pass' => 0, 'warn' => 0, 'fail' => 0];

	foreach ($items as $item) {
		$key = strtolower((string) ($item['status'] ?? 'warn'));
		if (isset($counts[$key])) {
			$counts[$key]++;
		}
	}

	return $counts;
}

function freesiem_sentinel_bool_label(bool $value): string
{
	return $value ? 'yes' : 'no';
}

function freesiem_sentinel_path_is_writable(string $path): bool
{
	if ($path === '') {
		return false;
	}

	if (function_exists('wp_is_writable')) {
		return wp_is_writable($path);
	}

	return is_writable($path);
}

function freesiem_sentinel_is_local_host(string $host): bool
{
	$host = strtolower(trim($host));

	if ($host === '') {
		return true;
	}

	if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
		return true;
	}

	if (str_contains($host, '.local') || str_contains($host, '.test') || str_contains($host, '.invalid')) {
		return true;
	}

	if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false && filter_var($host, FILTER_VALIDATE_IP)) {
		return true;
	}

	return false;
}

function freesiem_sentinel_lookup_host(string $host): array
{
	$host = strtolower(trim($host));

	if ($host === '') {
		return [
			'ok' => false,
			'message' => __('DNS lookup skipped because no host is configured.', 'freesiem-sentinel'),
		];
	}

	if (freesiem_sentinel_is_local_host($host)) {
		return [
			'ok' => false,
			'message' => __('DNS lookup is not meaningful for localhost/private-only hostnames.', 'freesiem-sentinel'),
		];
	}

	if (function_exists('dns_get_record')) {
		$records = @dns_get_record($host, DNS_A + DNS_AAAA + DNS_CNAME);
		if (is_array($records) && $records !== []) {
			return [
				'ok' => true,
				'message' => sprintf(__('DNS returned %d record(s) for `%s`.', 'freesiem-sentinel'), count($records), $host),
			];
		}
	}

	$resolved = gethostbyname($host);

	if ($resolved !== $host && $resolved !== '') {
		return [
			'ok' => true,
			'message' => sprintf(__('Host `%1$s` resolves to `%2$s`.', 'freesiem-sentinel'), $host, $resolved),
		];
	}

	return [
		'ok' => false,
		'message' => sprintf(__('DNS lookup did not resolve `%s`.', 'freesiem-sentinel'), $host),
	];
}

function freesiem_sentinel_can_store_ssl_probe_option(): bool
{
	$key = 'freesiem_sentinel_ssl_probe_' . wp_generate_password(8, false, false);
	$value = freesiem_sentinel_get_iso8601_time();
	$added = add_option($key, $value, '', false);

	if (!$added) {
		return false;
	}

	$stored = get_option($key, '');
	$deleted = delete_option($key);

	return $stored === $value && $deleted;
}

function freesiem_sentinel_ssl_challenge_ready(array $settings, array|string $environment_or_host): array
{
	$method = (string) ($settings['challenge_method'] ?? 'webroot-http-01');
	$environment = is_array($environment_or_host) ? $environment_or_host : ['configured_host' => (string) $environment_or_host];
	$host = (string) ($environment['configured_host'] ?? '');
	$webroot = (string) ($settings['webroot_path'] ?? '');

	return match ($method) {
		'webroot-http-01' => $webroot !== '' && file_exists($webroot) && is_readable($webroot)
			? ['ok' => true, 'message' => __('Webroot HTTP-01 has the minimum path requirements configured.', 'freesiem-sentinel')]
			: ['ok' => false, 'message' => __('Webroot HTTP-01 needs a readable existing webroot path before it can be used in a later phase.', 'freesiem-sentinel')],
		'standalone-http-01' => !empty($settings['check_port_80'])
			? ['ok' => true, 'message' => __('Standalone HTTP-01 has port 80 intent configured. Live port testing remains deferred.', 'freesiem-sentinel')]
			: ['ok' => false, 'message' => __('Standalone HTTP-01 should have port 80 intent enabled.', 'freesiem-sentinel')],
		'manual-dns-01' => $host !== ''
			? ['ok' => true, 'message' => __('Manual DNS-01 has a hostname available for future TXT record instructions.', 'freesiem-sentinel')]
			: ['ok' => false, 'message' => __('Manual DNS-01 needs a hostname before it can be used.', 'freesiem-sentinel')],
		default => ['ok' => false, 'message' => __('Select a supported challenge method.', 'freesiem-sentinel')],
	};
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
