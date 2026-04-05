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

function freesiem_sentinel_get_default_ssl_state(): array
{
	return [
		'provider' => '',
		'domain' => '',
		'challenge_method' => '',
		'last_action_type' => '',
		'last_action_result_code' => '',
		'cert_path' => '',
		'fullchain_path' => '',
		'privkey_path' => '',
		'user_space_base' => '',
		'user_space_config_dir' => '',
		'user_space_work_dir' => '',
		'user_space_logs_dir' => '',
		'nginx_integration_mode' => '',
		'nginx_config_path' => '',
		'nginx_backup_path' => '',
		'nginx_cert_path' => '',
		'nginx_key_path' => '',
		'nginx_last_apply_status' => '',
		'nginx_last_apply_result' => '',
		'nginx_last_apply_at' => '',
		'nginx_last_test_result' => '',
		'nginx_last_reload_result' => '',
		'nginx_redirect_enabled' => 0,
		'issued_at' => '',
		'expires_at' => '',
		'last_issue_status' => '',
		'last_issue_result' => '',
		'last_issue_at' => '',
		'last_renew_status' => '',
		'last_renew_result' => '',
		'last_renew_at' => '',
		'last_verification_status' => '',
		'last_verification_result' => '',
		'certbot_available' => 0,
		'certbot_path' => '',
		'certbot_version' => '',
		'current_ssl_mode' => 'manual-live-actions',
	];
}

function freesiem_sentinel_get_ssl_state(): array
{
	$saved = get_option(FREESIEM_SENTINEL_SSL_STATE_OPTION, []);

	if (!is_array($saved)) {
		$saved = [];
	}

	return wp_parse_args(freesiem_sentinel_sanitize_ssl_state($saved), freesiem_sentinel_get_default_ssl_state());
}

function freesiem_sentinel_update_ssl_state(array $updates): array
{
	$current = freesiem_sentinel_get_ssl_state();
	$merged = array_replace_recursive($current, $updates);
	$sanitized = freesiem_sentinel_sanitize_ssl_state($merged);

	if (get_option(FREESIEM_SENTINEL_SSL_STATE_OPTION, null) === null) {
		add_option(FREESIEM_SENTINEL_SSL_STATE_OPTION, $sanitized, '', false);
	} else {
		update_option(FREESIEM_SENTINEL_SSL_STATE_OPTION, $sanitized, false);
	}

	return $sanitized;
}

function freesiem_sentinel_sanitize_ssl_state(array $state): array
{
	$defaults = freesiem_sentinel_get_default_ssl_state();
	$state = wp_parse_args($state, $defaults);

	$state['provider'] = sanitize_key((string) ($state['provider'] ?? ''));
	$state['domain'] = strtolower(trim(sanitize_text_field((string) ($state['domain'] ?? ''))));
	$state['challenge_method'] = sanitize_key((string) ($state['challenge_method'] ?? ''));
	$state['last_action_type'] = sanitize_key((string) ($state['last_action_type'] ?? ''));
	$state['last_action_result_code'] = sanitize_key((string) ($state['last_action_result_code'] ?? ''));
	$state['cert_path'] = trim((string) ($state['cert_path'] ?? ''));
	$state['fullchain_path'] = trim((string) ($state['fullchain_path'] ?? ''));
	$state['privkey_path'] = trim((string) ($state['privkey_path'] ?? ''));
	$state['user_space_base'] = trim((string) ($state['user_space_base'] ?? ''));
	$state['user_space_config_dir'] = trim((string) ($state['user_space_config_dir'] ?? ''));
	$state['user_space_work_dir'] = trim((string) ($state['user_space_work_dir'] ?? ''));
	$state['user_space_logs_dir'] = trim((string) ($state['user_space_logs_dir'] ?? ''));
	$state['nginx_integration_mode'] = sanitize_key((string) ($state['nginx_integration_mode'] ?? ''));
	$state['nginx_config_path'] = trim((string) ($state['nginx_config_path'] ?? ''));
	$state['nginx_backup_path'] = trim((string) ($state['nginx_backup_path'] ?? ''));
	$state['nginx_cert_path'] = trim((string) ($state['nginx_cert_path'] ?? ''));
	$state['nginx_key_path'] = trim((string) ($state['nginx_key_path'] ?? ''));
	$state['nginx_last_apply_status'] = sanitize_key((string) ($state['nginx_last_apply_status'] ?? ''));
	$state['nginx_last_apply_result'] = sanitize_text_field((string) ($state['nginx_last_apply_result'] ?? ''));
	$state['nginx_last_apply_at'] = freesiem_sentinel_sanitize_datetime((string) ($state['nginx_last_apply_at'] ?? ''));
	$state['nginx_last_test_result'] = sanitize_text_field((string) ($state['nginx_last_test_result'] ?? ''));
	$state['nginx_last_reload_result'] = sanitize_text_field((string) ($state['nginx_last_reload_result'] ?? ''));
	$state['nginx_redirect_enabled'] = empty($state['nginx_redirect_enabled']) ? 0 : 1;
	$state['issued_at'] = freesiem_sentinel_sanitize_datetime((string) ($state['issued_at'] ?? ''));
	$state['expires_at'] = freesiem_sentinel_sanitize_datetime((string) ($state['expires_at'] ?? ''));
	$state['last_issue_status'] = sanitize_key((string) ($state['last_issue_status'] ?? ''));
	$state['last_issue_result'] = sanitize_text_field((string) ($state['last_issue_result'] ?? ''));
	$state['last_issue_at'] = freesiem_sentinel_sanitize_datetime((string) ($state['last_issue_at'] ?? ''));
	$state['last_renew_status'] = sanitize_key((string) ($state['last_renew_status'] ?? ''));
	$state['last_renew_result'] = sanitize_text_field((string) ($state['last_renew_result'] ?? ''));
	$state['last_renew_at'] = freesiem_sentinel_sanitize_datetime((string) ($state['last_renew_at'] ?? ''));
	$state['last_verification_status'] = sanitize_key((string) ($state['last_verification_status'] ?? ''));
	$state['last_verification_result'] = sanitize_text_field((string) ($state['last_verification_result'] ?? ''));
	$state['certbot_available'] = empty($state['certbot_available']) ? 0 : 1;
	$state['certbot_path'] = trim((string) ($state['certbot_path'] ?? ''));
	$state['certbot_version'] = sanitize_text_field((string) ($state['certbot_version'] ?? ''));
	$state['current_ssl_mode'] = sanitize_key((string) ($state['current_ssl_mode'] ?? 'manual-live-actions'));

	return $state;
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
			'certbot_available',
			__('Certbot binary available', 'freesiem-sentinel'),
			!empty($environment['certbot']['available']),
			sprintf(__('Certbot was detected at `%1$s` (%2$s).', 'freesiem-sentinel'), (string) ($environment['certbot']['path'] ?? ''), (string) ($environment['certbot']['version'] ?? __('version unavailable', 'freesiem-sentinel'))),
			__('Certbot was not detected on this server.', 'freesiem-sentinel'),
			'FAIL'
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
	$ssl_state = freesiem_sentinel_get_ssl_state();
	$certbot = freesiem_sentinel_detect_certbot();
	$install_environment = freesiem_sentinel_detect_ssl_install_environment();
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
		'certbot' => $certbot,
		'install_environment' => $install_environment,
		'ssl_state' => $ssl_state,
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
	$blocker_codes = [];
	$blocker_messages = [];
	$warning_codes = [];
	$warning_messages = [];

	if (!$has_email) {
		$blocker_codes[] = 'missing_email';
		$blocker_messages[] = __('A valid ACME contact email is required.', 'freesiem-sentinel');
	}

	if ($environment['configured_host'] === '') {
		$blocker_codes[] = 'missing_host';
		$blocker_messages[] = __('A hostname or domain is required.', 'freesiem-sentinel');
	}

	if ($environment['configured_host'] !== '' && $environment['is_local_host'] && empty($ssl_settings['allow_local_override'])) {
		$blocker_codes[] = 'localhost_host';
		$blocker_messages[] = __('Blocked: The configured host is local-only and cannot be used for public certificate issuance.', 'freesiem-sentinel');
	}

	if ($environment['configured_host'] !== '' && $environment['is_ip'] && empty($ssl_settings['allow_local_override'])) {
		$blocker_codes[] = 'raw_ip_host';
		$blocker_messages[] = __('Blocked: The configured host is a raw IP address and not a supported certificate hostname.', 'freesiem-sentinel');
	}

	if (!$environment['option_probe']) {
		$blocker_codes[] = 'storage_unavailable';
		$blocker_messages[] = __('Blocked: WordPress option storage could not be confirmed for SSL state updates.', 'freesiem-sentinel');
	}

	if (!$environment['execution_support']) {
		$blocker_codes[] = 'command_execution_unavailable';
		$blocker_messages[] = __('Blocked: No supported PHP command execution function is available on this server.', 'freesiem-sentinel');
	}

	if (empty($environment['certbot']['available'])) {
		$blocker_codes[] = 'certbot_missing';
		$blocker_messages[] = __('Blocked: Certbot is not installed or not detectable on this server.', 'freesiem-sentinel');
	}

	if ((string) ($ssl_settings['challenge_method'] ?? '') === 'webroot-http-01') {
		$webroot = (string) ($ssl_settings['webroot_path'] ?? '');

		if ($webroot === '' || !file_exists($webroot) || !is_readable($webroot)) {
			$blocker_codes[] = 'invalid_webroot';
			$blocker_messages[] = __('Blocked: Webroot HTTP-01 requires a readable existing webroot path.', 'freesiem-sentinel');
		}
	}

	if (!$has_method) {
		$warning_codes[] = 'missing_challenge_method';
		$warning_messages[] = __('Select a supported challenge method.', 'freesiem-sentinel');
	}

	if (!$environment['wp_cron_enabled']) {
		$warning_codes[] = 'wp_cron_disabled';
		$warning_messages[] = __('WP-Cron appears disabled. Manual renewal remains available, but background scheduling is not ready.', 'freesiem-sentinel');
	}

	if (!$environment['abspath_writable'] || !$environment['wp_content_writable']) {
		$warning_codes[] = 'storage_paths_limited';
		$warning_messages[] = __('Some storage paths are not writable, which may limit future logging or challenge file workflows.', 'freesiem-sentinel');
	}

	if (!$environment['dns_result']['ok'] && !$environment['is_local_host'] && $environment['configured_host'] !== '') {
		$warning_codes[] = 'dns_lookup_failed';
		$warning_messages[] = __('Warning: DNS lookup could not be confirmed for the configured host.', 'freesiem-sentinel');
	} elseif ($environment['configured_host'] !== '' && !$environment['dns_result']['ok']) {
		$warning_codes[] = 'dns_lookup_uncertain';
		$warning_messages[] = __('Warning: DNS validation is uncertain for the configured host in this environment.', 'freesiem-sentinel');
	}

	if (!$environment['host_alignment'] && $environment['configured_host'] !== '') {
		$warning_codes[] = 'host_alignment_warn';
		$warning_messages[] = __('The selected hostname does not match the current WordPress site host.', 'freesiem-sentinel');
	}

	if (!$environment['is_https_configured']) {
		$warning_codes[] = 'https_not_enabled';
		$warning_messages[] = __('WordPress is still configured for HTTP. This does not block issuance, but HTTPS is not active yet.', 'freesiem-sentinel');
	}

	if (!$method_ready['ok']) {
		$warning_codes[] = 'method_requirements_pending';
		$warning_messages[] = (string) ($method_ready['message'] ?? __('Method-specific requirements are not complete yet.', 'freesiem-sentinel'));
	}

	if (!$has_email && !$has_host) {
		$state = 'not_configured';
		$label = __('Not configured', 'freesiem-sentinel');
	} elseif ($blocker_codes !== []) {
		$state = 'blocked';
		$label = __('Blocked', 'freesiem-sentinel');
	} elseif (!$required_core || !$method_ready['ok']) {
		$state = 'partially_configured';
		$label = __('Partially configured', 'freesiem-sentinel');
	} elseif ((int) ($preflight['counts']['fail'] ?? 0) > 0 || (int) ($preflight['counts']['warn'] ?? 0) > 0 || $warning_codes !== []) {
		$state = 'ready_for_dry_run';
		$label = __('Ready for dry run', 'freesiem-sentinel');
	} else {
		$state = 'future_ready';
		$label = __('Future ready', 'freesiem-sentinel');
	}

	$description = match ($state) {
		'not_configured' => __('Add the hostname, contact email, and challenge details before SSL execution planning can proceed.', 'freesiem-sentinel'),
		'partially_configured' => __('The SSL setup has some required values, but it still needs more challenge-specific configuration.', 'freesiem-sentinel'),
		'ready_for_dry_run' => __('The SSL setup is complete enough for safe simulation, but the warnings below should be reviewed.', 'freesiem-sentinel'),
		'blocked' => $blocker_messages !== [] ? $blocker_messages[0] : __('Blocked by one or more explicit SSL execution requirements.', 'freesiem-sentinel'),
		default => __('The configuration is fully modeled and has certbot available for explicit admin-triggered actions.', 'freesiem-sentinel'),
	};

	return [
		'readiness_state' => $state,
		'state' => $state,
		'label' => $label,
		'description' => $description,
		'blocker_codes' => array_values(array_unique($blocker_codes)),
		'blocker_messages' => array_values(array_unique($blocker_messages)),
		'warning_codes' => array_values(array_unique($warning_codes)),
		'warning_messages' => array_values(array_unique($warning_messages)),
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
	$user_space = freesiem_sentinel_get_ssl_user_space_paths($ssl_settings);
	$dir_flags = ' --config-dir ' . escapeshellarg((string) $user_space['config_dir']) . ' --work-dir ' . escapeshellarg((string) $user_space['work_dir']) . ' --logs-dir ' . escapeshellarg((string) $user_space['logs_dir']);
	$base = 'certbot certonly --agree-tos --non-interactive --email ' . escapeshellarg($email) . ' -d ' . escapeshellarg($host) . $dir_flags;

	$command = match ($method) {
		'standalone-http-01' => $base . ' --standalone --preferred-challenges http' . $staging_flag,
		'manual-dns-01' => $base . ' --manual --preferred-challenges dns --manual-public-ip-logging-ok' . $staging_flag,
		default => $base . ' --webroot -w ' . escapeshellarg((string) ($ssl_settings['webroot_path'] !== '' ? $ssl_settings['webroot_path'] : ABSPATH)) . ' --preferred-challenges http' . $staging_flag,
	};

	return [
		'command' => $command,
		'label' => __('Simulated command preview only. Not executed.', 'freesiem-sentinel'),
		'method' => $method,
		'user_space' => $user_space,
	];
}

function freesiem_sentinel_get_ssl_user_space_paths(?array $ssl_settings = null): array
{
	$ssl_settings = is_array($ssl_settings) ? $ssl_settings : freesiem_sentinel_get_ssl_settings();
	$base_candidates = [];
	$webroot_path = trim((string) ($ssl_settings['webroot_path'] ?? ''));

	if ($webroot_path !== '') {
		$base_candidates[] = $webroot_path;
	}

	if (defined('ABSPATH')) {
		$base_candidates[] = dirname(untrailingslashit((string) ABSPATH));
	}

	if (defined('WP_CONTENT_DIR')) {
		$base_candidates[] = (string) WP_CONTENT_DIR;
	} elseif (defined('ABSPATH')) {
		$base_candidates[] = trailingslashit((string) ABSPATH) . 'wp-content';
	}

	$selected_base = '';
	foreach ($base_candidates as $candidate) {
		$candidate = rtrim((string) $candidate, '/\\');
		if ($candidate !== '') {
			$selected_base = $candidate;
			break;
		}
	}

	if ($selected_base === '' && defined('ABSPATH')) {
		$selected_base = rtrim((string) ABSPATH, '/\\');
	}

	$root_dir = $selected_base !== '' ? $selected_base . '/.freesiem-letsencrypt' : '';
	$config_dir = $root_dir !== '' ? $root_dir . '/config' : '';
	$work_dir = $root_dir !== '' ? $root_dir . '/work' : '';
	$logs_dir = $root_dir !== '' ? $root_dir . '/logs' : '';
	$created = [];

	foreach ([$root_dir, $config_dir, $work_dir, $logs_dir] as $directory) {
		if ($directory === '') {
			continue;
		}

		if (!file_exists($directory) && wp_mkdir_p($directory)) {
			$created[] = $directory;
		}

		if (file_exists($directory) && function_exists('chmod')) {
			@chmod($directory, 0755);
		}
	}

	return [
		'base_path' => $selected_base,
		'root_dir' => $root_dir,
		'config_dir' => $config_dir,
		'work_dir' => $work_dir,
		'logs_dir' => $logs_dir,
		'created' => $created,
		'writable' => [
			'root_dir' => $root_dir !== '' && freesiem_sentinel_path_is_writable($root_dir),
			'config_dir' => $config_dir !== '' && freesiem_sentinel_path_is_writable($config_dir),
			'work_dir' => $work_dir !== '' && freesiem_sentinel_path_is_writable($work_dir),
			'logs_dir' => $logs_dir !== '' && freesiem_sentinel_path_is_writable($logs_dir),
		],
	];
}

function freesiem_sentinel_detect_permission_denied_message(string $stdout, string $stderr): bool
{
	$combined = strtolower(trim($stdout . ' ' . $stderr));

	if ($combined === '') {
		return false;
	}

	return str_contains($combined, 'errno 13')
		|| str_contains($combined, 'permission denied')
		|| str_contains($combined, 'eacces');
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

function freesiem_sentinel_detect_certbot(bool $force = false): array
{
	static $cached = null;

	if (!$force && is_array($cached)) {
		return $cached;
	}

	$path_result = freesiem_sentinel_run_ssl_shell_command('command -v certbot', 'detect_certbot_path', 15, 'command -v certbot');
	$path = trim((string) ($path_result['stdout_summary'] ?? ''));
	$path = $path !== '' && !str_contains($path, "\n") ? $path : strtok($path, "\n");
	$path = is_string($path) ? trim($path) : '';
	$available = $path !== '';
	$version = '';

	if ($available) {
		$version_result = freesiem_sentinel_run_ssl_shell_command(escapeshellarg($path) . ' --version', 'detect_certbot_version', 20, 'certbot --version');
		$version = trim((string) ($version_result['stdout_summary'] ?? ''));
	}

	$cached = [
		'available' => $available,
		'path' => $path,
		'version' => $version,
	];

	return $cached;
}

function freesiem_sentinel_detect_ssl_install_environment(): array
{
	static $cached = null;

	if (is_array($cached)) {
		return $cached;
	}

	$os_name = php_uname('s');
	$os_release = is_readable('/etc/os-release') ? (string) file_get_contents('/etc/os-release') : '';
	$os_family = 'unknown';
	$package_managers = [
		'apt' => freesiem_sentinel_detect_binary('apt'),
		'yum' => freesiem_sentinel_detect_binary('yum'),
		'dnf' => freesiem_sentinel_detect_binary('dnf'),
		'snap' => freesiem_sentinel_detect_binary('snap'),
	];

	if (str_contains(strtolower($os_release), 'ubuntu') || str_contains(strtolower($os_release), 'debian')) {
		$os_family = 'ubuntu_debian';
	} elseif (str_contains(strtolower($os_release), 'rhel') || str_contains(strtolower($os_release), 'centos') || str_contains(strtolower($os_release), 'fedora') || str_contains(strtolower($os_release), 'rocky') || str_contains(strtolower($os_release), 'alma')) {
		$os_family = 'centos_rhel';
	} elseif (strtolower($os_name) === 'linux') {
		$os_family = 'linux_unknown';
	}

	$root_status = function_exists('posix_geteuid') && posix_geteuid() === 0 ? 'root' : 'unknown';

	$install_method = '';
	if (!empty($package_managers['snap']['available'])) {
		$install_method = 'snap';
	} elseif (!empty($package_managers['apt']['available'])) {
		$install_method = 'apt';
	} elseif (!empty($package_managers['dnf']['available'])) {
		$install_method = 'dnf';
	} elseif (!empty($package_managers['yum']['available'])) {
		$install_method = 'yum';
	}

	$cached = [
		'os_name' => sanitize_text_field((string) $os_name),
		'os_family' => $os_family,
		'root_status' => $root_status,
		'package_managers' => $package_managers,
		'install_method' => $install_method,
		'install_supported' => $install_method !== '',
	];

	return $cached;
}

function freesiem_sentinel_detect_binary(string $binary): array
{
	$result = freesiem_sentinel_run_ssl_shell_command('command -v ' . escapeshellarg($binary), 'detect_binary_' . sanitize_key($binary), 15, 'command -v ' . $binary);
	$path = trim((string) ($result['stdout_summary'] ?? ''));

	return [
		'available' => $path !== '',
		'path' => $path,
	];
}

function freesiem_sentinel_get_certbot_install_preview(?array $environment = null): array
{
	$environment = is_array($environment) ? $environment : freesiem_sentinel_detect_ssl_install_environment();

	$commands = match ((string) ($environment['install_method'] ?? '')) {
		'snap' => [
			'snap install core',
			'snap refresh core',
			'snap install --classic certbot',
			'ln -s /snap/bin/certbot /usr/bin/certbot',
		],
		'apt' => [
			'apt update',
			'apt install -y certbot',
		],
		'dnf' => [
			'dnf install -y certbot',
		],
		'yum' => [
			'yum install -y certbot',
		],
		default => [],
	};

	return [
		'method' => (string) ($environment['install_method'] ?? ''),
		'commands' => $commands,
		'preview' => implode("\n", $commands),
	];
}

function freesiem_sentinel_get_certbot_manual_install_instructions(): array
{
	return [
		'ubuntu' => "apt update\napt install -y certbot",
		'centos' => "dnf install -y certbot\n# or\nyum install -y certbot",
		'snap' => "snap install core\nsnap refresh core\nsnap install --classic certbot\nln -s /snap/bin/certbot /usr/bin/certbot",
	];
}

function freesiem_sentinel_can_install_certbot(?array $environment = null, ?array $ssl_environment = null): array
{
	$environment = is_array($environment) ? $environment : freesiem_sentinel_detect_ssl_install_environment();
	$ssl_environment = is_array($ssl_environment) ? $ssl_environment : freesiem_sentinel_get_ssl_environment_snapshot();

	if (!empty($ssl_environment['certbot']['available'])) {
		return ['allowed' => false, 'reason' => __('Certbot is already installed.', 'freesiem-sentinel')];
	}

	if (empty($ssl_environment['execution_support'])) {
		return ['allowed' => false, 'reason' => __('Command execution is not available on this server.', 'freesiem-sentinel')];
	}

	if (empty($environment['install_supported'])) {
		return ['allowed' => false, 'reason' => __('No supported package manager was detected for automatic certbot installation.', 'freesiem-sentinel')];
	}

	if ((string) ($environment['root_status'] ?? 'unknown') !== 'root') {
		return ['allowed' => false, 'reason' => __('Root execution could not be confirmed, so automatic certbot installation is unavailable from this UI.', 'freesiem-sentinel')];
	}

	return ['allowed' => true, 'reason' => ''];
}

function freesiem_sentinel_install_certbot(): array
{
	$ssl_environment = freesiem_sentinel_get_ssl_environment_snapshot();
	$install_environment = freesiem_sentinel_detect_ssl_install_environment();
	$gate = freesiem_sentinel_can_install_certbot($install_environment, $ssl_environment);
	$preview = freesiem_sentinel_get_certbot_install_preview($install_environment);
	$executed_at = freesiem_sentinel_get_iso8601_time();

	if (empty($gate['allowed'])) {
		return [
			'success' => false,
			'status' => 'blocked',
			'summary' => (string) $gate['reason'],
			'preview' => (string) ($preview['preview'] ?? ''),
			'execution' => null,
			'executed_at' => $executed_at,
			'install_environment' => $install_environment,
		];
	}

	$command = implode(' && ', (array) ($preview['commands'] ?? []));
	$execution = freesiem_sentinel_run_ssl_shell_command($command, 'install_certbot', 900, (string) ($preview['preview'] ?? ''));
	$certbot = freesiem_sentinel_detect_certbot(true);
	$success = $execution['success'] && !empty($certbot['available']);

	freesiem_sentinel_update_ssl_state([
		'certbot_available' => !empty($certbot['available']) ? 1 : 0,
		'certbot_path' => (string) ($certbot['path'] ?? ''),
		'certbot_version' => (string) ($certbot['version'] ?? ''),
	]);

	return [
		'success' => $success,
		'status' => $success ? 'success' : 'failed',
		'summary' => $success
			? __('Certbot installation completed successfully and detection has been refreshed.', 'freesiem-sentinel')
			: (!empty($execution['stderr_summary']) ? (string) $execution['stderr_summary'] : __('Certbot installation failed. Review the manual commands below.', 'freesiem-sentinel')),
		'preview' => (string) ($preview['preview'] ?? ''),
		'execution' => $execution,
		'executed_at' => $executed_at,
		'install_environment' => $install_environment,
	];
}


function freesiem_sentinel_run_ssl_shell_command(string $command, string $action, int $timeout = 120, ?string $redacted_command = null): array
{
	$result = [
		'success' => false,
		'exit_code' => null,
		'stdout_summary' => '',
		'stderr_summary' => '',
		'command_preview' => $redacted_command ?? $command,
		'executed_at' => freesiem_sentinel_get_iso8601_time(),
		'action_type' => sanitize_key($action),
		'runner' => 'none',
		'timed_out' => false,
	];

	if (function_exists('proc_open')) {
		$descriptor_spec = [
			0 => ['pipe', 'r'],
			1 => ['pipe', 'w'],
			2 => ['pipe', 'w'],
		];
		$process = @proc_open(['/bin/sh', '-lc', $command], $descriptor_spec, $pipes);

		if (is_resource($process)) {
			fclose($pipes[0]);
			stream_set_blocking($pipes[1], false);
			stream_set_blocking($pipes[2], false);
			$stdout = '';
			$stderr = '';
			$start = time();

			do {
				$stdout .= (string) stream_get_contents($pipes[1]);
				$stderr .= (string) stream_get_contents($pipes[2]);
				$status = proc_get_status($process);

				if (!$status['running']) {
					break;
				}

				if ((time() - $start) >= $timeout) {
					$result['timed_out'] = true;
					@proc_terminate($process, 15);
					usleep(200000);
					$status = proc_get_status($process);
					if (!empty($status['running'])) {
						@proc_terminate($process, 9);
					}
					break;
				}

				usleep(100000);
			} while (true);

			$stdout .= (string) stream_get_contents($pipes[1]);
			$stderr .= (string) stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			$exit_code = proc_close($process);

			$result['runner'] = 'proc_open';
			$result['exit_code'] = $exit_code;
			$result['stdout_summary'] = freesiem_sentinel_summarize_ssl_command_output($stdout);
			$result['stderr_summary'] = freesiem_sentinel_summarize_ssl_command_output($stderr);
			$result['success'] = !$result['timed_out'] && (int) $exit_code === 0;

			return $result;
		}
	}

	if (function_exists('exec')) {
		$output = [];
		$exit_code = 1;
		@exec($command . ' 2>&1', $output, $exit_code);
		$result['runner'] = 'exec';
		$result['exit_code'] = $exit_code;
		$result['stdout_summary'] = freesiem_sentinel_summarize_ssl_command_output(implode("\n", $output));
		$result['success'] = (int) $exit_code === 0;

		return $result;
	}

	if (function_exists('shell_exec')) {
		$output = @shell_exec($command . ' 2>&1');
		$result['runner'] = 'shell_exec';
		$result['exit_code'] = is_string($output) ? 0 : 1;
		$result['stdout_summary'] = freesiem_sentinel_summarize_ssl_command_output((string) $output);
		$result['success'] = is_string($output);

		return $result;
	}

	if (function_exists('system')) {
		ob_start();
		$exit_code = 1;
		@system($command . ' 2>&1', $exit_code);
		$output = (string) ob_get_clean();
		$result['runner'] = 'system';
		$result['exit_code'] = $exit_code;
		$result['stdout_summary'] = freesiem_sentinel_summarize_ssl_command_output($output);
		$result['success'] = (int) $exit_code === 0;

		return $result;
	}

	if (function_exists('passthru')) {
		ob_start();
		$exit_code = 1;
		@passthru($command . ' 2>&1', $exit_code);
		$output = (string) ob_get_clean();
		$result['runner'] = 'passthru';
		$result['exit_code'] = $exit_code;
		$result['stdout_summary'] = freesiem_sentinel_summarize_ssl_command_output($output);
		$result['success'] = (int) $exit_code === 0;
	}

	return $result;
}

function freesiem_sentinel_summarize_ssl_command_output(string $output, int $max_length = 4000): string
{
	$output = trim(preg_replace('/\s+/', ' ', $output) ?? '');

	if ($output === '') {
		return '';
	}

	return strlen($output) > $max_length ? substr($output, 0, $max_length - 3) . '...' : $output;
}

function freesiem_sentinel_can_run_live_ssl_action(string $action, ?array $ssl_settings = null, ?array $environment = null, ?array $readiness = null): array
{
	$ssl_settings = is_array($ssl_settings) ? $ssl_settings : freesiem_sentinel_get_ssl_settings();
	$environment = is_array($environment) ? $environment : freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
	$readiness = is_array($readiness) ? $readiness : freesiem_sentinel_calculate_ssl_readiness($ssl_settings, $environment);
	$method = (string) ($ssl_settings['challenge_method'] ?? 'webroot-http-01');
	$state = freesiem_sentinel_get_ssl_state();

	if (empty($environment['certbot']['available'])) {
		return ['allowed' => false, 'reason' => __('Certbot is not available on this server.', 'freesiem-sentinel')];
	}

	if (in_array($method, ['manual-dns-01'], true)) {
		return ['allowed' => false, 'reason' => __('Manual DNS-01 is not fully automated for live execution in this version.', 'freesiem-sentinel')];
	}

	if (!in_array((string) ($readiness['state'] ?? 'not_configured'), ['ready_for_dry_run', 'future_ready'], true)) {
		return ['allowed' => false, 'reason' => __('SSL readiness requirements are not met yet.', 'freesiem-sentinel')];
	}

	if ($action === 'renew' && empty($state['domain']) && ($environment['configured_host'] === '')) {
		return ['allowed' => false, 'reason' => __('No certificate domain is available for renewal.', 'freesiem-sentinel')];
	}

	return ['allowed' => true, 'reason' => ''];
}

function freesiem_sentinel_execute_ssl_issue(?array $ssl_settings = null): array
{
	$options = [];
	if (!empty($_POST['force_reissue_existing_certificate'])) {
		$options['force_reissue'] = true;
	}

	return freesiem_sentinel_execute_ssl_certbot_action('issue', $ssl_settings, $options);
}

function freesiem_sentinel_execute_ssl_renew(?array $ssl_settings = null): array
{
	return freesiem_sentinel_execute_ssl_certbot_action('renew', $ssl_settings);
}

function freesiem_sentinel_execute_ssl_certbot_action(string $action, ?array $ssl_settings = null, array $options = []): array
{
	$ssl_settings = is_array($ssl_settings) ? $ssl_settings : freesiem_sentinel_get_ssl_settings();
	$environment = freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
	$preflight = freesiem_sentinel_run_ssl_preflight($ssl_settings);
	$readiness = freesiem_sentinel_calculate_ssl_readiness($ssl_settings, $environment, $preflight);
	$gate = freesiem_sentinel_can_run_live_ssl_action($action, $ssl_settings, $environment, $readiness);
	$executed_at = freesiem_sentinel_get_iso8601_time();
	$state = freesiem_sentinel_get_ssl_state();
	$force_reissue = !empty($options['force_reissue']);

	if (empty($gate['allowed'])) {
		$status_key = $action === 'issue' ? 'last_issue_status' : 'last_renew_status';
		$result_key = $action === 'issue' ? 'last_issue_result' : 'last_renew_result';
		$at_key = $action === 'issue' ? 'last_issue_at' : 'last_renew_at';
		freesiem_sentinel_update_ssl_state([
			$status_key => 'blocked',
			$result_key => $gate['reason'],
			$at_key => $executed_at,
			'certbot_available' => !empty($environment['certbot']['available']) ? 1 : 0,
			'certbot_path' => (string) ($environment['certbot']['path'] ?? ''),
			'certbot_version' => (string) ($environment['certbot']['version'] ?? ''),
		]);

		return [
			'success' => false,
			'status' => 'blocked',
			'summary' => $gate['reason'],
			'command_preview' => '',
			'execution' => null,
			'verification' => null,
			'executed_at' => $executed_at,
			'action_type' => $action,
		];
	}

	if ($action === 'issue' && (string) ($ssl_settings['challenge_method'] ?? '') === 'standalone-http-01') {
		$port_check = freesiem_sentinel_detect_local_port_listener(80);
		if ($port_check['listening']) {
			$message = __('Port 80 appears to already be in use locally, so standalone HTTP-01 was not attempted.', 'freesiem-sentinel');
			freesiem_sentinel_update_ssl_state([
				'last_issue_status' => 'failed',
				'last_issue_result' => $message,
				'last_issue_at' => $executed_at,
			]);

			return [
				'success' => false,
				'status' => 'failed',
				'summary' => $message,
				'command_preview' => '',
				'execution' => null,
				'verification' => null,
				'executed_at' => $executed_at,
				'action_type' => $action,
			];
		}
	}

	$command_data = freesiem_sentinel_build_live_ssl_command($action, $ssl_settings, $environment, $state, [
		'force_reissue' => $force_reissue,
	]);
	if (!$command_data['executable']) {
		return [
			'success' => false,
			'status' => 'warn',
			'summary' => $command_data['summary'],
			'command_preview' => (string) ($command_data['preview'] ?? ''),
			'execution' => null,
			'verification' => null,
			'executed_at' => $executed_at,
			'action_type' => $action,
		];
	}

	$execution = freesiem_sentinel_run_ssl_shell_command((string) $command_data['command'], 'ssl_' . $action, 600, (string) $command_data['preview']);
	$permission_denied = freesiem_sentinel_detect_permission_denied_message((string) ($execution['stdout_summary'] ?? ''), (string) ($execution['stderr_summary'] ?? ''));
	$no_action_needed = freesiem_sentinel_detect_ssl_no_action_needed((string) ($execution['stdout_summary'] ?? ''), (string) ($execution['stderr_summary'] ?? ''));
	$verification = ($execution['success'] || $no_action_needed)
		? freesiem_sentinel_verify_ssl_certificate((string) ($environment['configured_host'] ?: $state['domain']), $command_data)
		: ['success' => false, 'status' => 'failed', 'summary' => __('Certificate verification was skipped because certbot did not succeed.', 'freesiem-sentinel')];
	$status = $no_action_needed
		? 'no_action_needed'
		: ($execution['success']
		? ($verification['success'] ? 'success' : 'warning')
		: 'failed');
	$summary = $execution['success']
		? ($verification['summary'] ?? __('Certbot finished successfully.', 'freesiem-sentinel'))
		: (!empty($execution['stderr_summary']) ? (string) $execution['stderr_summary'] : (string) ($execution['stdout_summary'] ?? __('Certbot failed.', 'freesiem-sentinel')));
	if ($no_action_needed) {
		$summary = __('Existing certificate detected; renewal is not due yet.', 'freesiem-sentinel');
	}
	if ($permission_denied) {
		$summary = __('Certbot requires root directories. Sentinel is switching to user-space mode.', 'freesiem-sentinel');
	}
	$result_code = $permission_denied ? 'permission_redirected_user_space' : ($no_action_needed ? 'no_action_needed' : ($execution['success'] ? 'completed' : 'failed'));
	$state_updates = [
		'provider' => 'certbot',
		'domain' => (string) ($environment['configured_host'] ?: $state['domain']),
		'challenge_method' => (string) ($ssl_settings['challenge_method'] ?? ''),
		'last_action_type' => $action,
		'last_action_result_code' => $result_code,
		'certbot_available' => !empty($environment['certbot']['available']) ? 1 : 0,
		'certbot_path' => (string) ($environment['certbot']['path'] ?? ''),
		'certbot_version' => (string) ($environment['certbot']['version'] ?? ''),
		'current_ssl_mode' => 'manual-live-actions',
		'user_space_base' => (string) ($command_data['user_space']['root_dir'] ?? ''),
		'user_space_config_dir' => (string) ($command_data['user_space']['config_dir'] ?? ''),
		'user_space_work_dir' => (string) ($command_data['user_space']['work_dir'] ?? ''),
		'user_space_logs_dir' => (string) ($command_data['user_space']['logs_dir'] ?? ''),
		'last_verification_status' => sanitize_key((string) ($verification['status'] ?? '')),
		'last_verification_result' => sanitize_text_field((string) ($verification['summary'] ?? '')),
	];

	if (!empty($verification['metadata']) && is_array($verification['metadata'])) {
		$state_updates = array_merge($state_updates, $verification['metadata']);
	}

	if ($action === 'issue') {
		$state_updates['last_issue_status'] = $status;
		$state_updates['last_issue_result'] = $summary;
		$state_updates['last_issue_at'] = $executed_at;
		if ($execution['success'] && !empty($verification['metadata']['issued_at'])) {
			$state_updates['issued_at'] = $verification['metadata']['issued_at'];
		}
	} else {
		$state_updates['last_renew_status'] = $status;
		$state_updates['last_renew_result'] = $summary;
		$state_updates['last_renew_at'] = $executed_at;
	}

	freesiem_sentinel_update_ssl_state($state_updates);

	return [
		'success' => ($execution['success'] || $no_action_needed) && !in_array(($verification['status'] ?? ''), ['failed'], true),
		'status' => $status,
		'summary' => $summary,
		'command_preview' => (string) ($command_data['preview'] ?? ''),
		'execution' => $execution,
		'verification' => $verification,
		'executed_at' => $executed_at,
		'action_type' => $action,
		'result_code' => $result_code,
		'force_reissue' => $force_reissue,
	];
}

function freesiem_sentinel_build_live_ssl_command(string $action, array $ssl_settings, array $environment, array $state = [], array $options = []): array
{
	$method = (string) ($ssl_settings['challenge_method'] ?? 'webroot-http-01');
	$host = (string) ($environment['configured_host'] ?? '');
	$email = (string) ($ssl_settings['acme_contact_email'] ?? '');
	$certbot_path = (string) ($environment['certbot']['path'] ?? 'certbot');
	$staging_flag = !empty($ssl_settings['use_staging']) ? ' --staging' : '';
	$user_space = freesiem_sentinel_get_ssl_user_space_paths($ssl_settings);
	$target_host = $host !== '' ? $host : (string) ($state['domain'] ?? '');
	$dir_flags = ' --config-dir ' . escapeshellarg((string) $user_space['config_dir']) . ' --work-dir ' . escapeshellarg((string) $user_space['work_dir']) . ' --logs-dir ' . escapeshellarg((string) $user_space['logs_dir']);
	$force_flag = ($action === 'issue' && !empty($options['force_reissue'])) ? ' --force-renewal' : '';
	$base = $action === 'renew'
		? escapeshellarg($certbot_path) . ' renew --cert-name ' . escapeshellarg($target_host) . $staging_flag . $dir_flags
		: escapeshellarg($certbot_path) . ' certonly --agree-tos --non-interactive --email ' . escapeshellarg($email) . ' -d ' . escapeshellarg($target_host) . $staging_flag . $force_flag . $dir_flags;
	$preview_base = $action === 'renew'
		? 'certbot renew --cert-name ' . escapeshellarg($target_host) . $staging_flag . $dir_flags
		: 'certbot certonly --agree-tos --non-interactive --email ' . escapeshellarg($email) . ' -d ' . escapeshellarg($target_host) . $staging_flag . $force_flag . $dir_flags;

	return match ($method) {
		'standalone-http-01' => [
			'executable' => true,
			'command' => $base . ' --standalone --preferred-challenges http',
			'preview' => $preview_base . ' --standalone --preferred-challenges http',
			'summary' => '',
			'user_space' => $user_space,
			'action_type' => $action,
		],
		'manual-dns-01' => [
			'executable' => false,
			'command' => '',
			'preview' => $preview_base . ' --manual --preferred-challenges dns --manual-public-ip-logging-ok',
			'summary' => __('Manual DNS-01 remains instruction-only in this version and was not executed.', 'freesiem-sentinel'),
			'user_space' => $user_space,
			'action_type' => $action,
		],
		default => [
			'executable' => true,
			'command' => $base . ' --webroot -w ' . escapeshellarg((string) ($ssl_settings['webroot_path'] ?? '')) . ' --preferred-challenges http',
			'preview' => $preview_base . ' --webroot -w ' . escapeshellarg((string) ($ssl_settings['webroot_path'] ?? '')) . ' --preferred-challenges http',
			'summary' => '',
			'user_space' => $user_space,
			'action_type' => $action,
		],
	};
}

function freesiem_sentinel_detect_ssl_no_action_needed(string $stdout, string $stderr): bool
{
	$combined = strtolower(trim($stdout . ' ' . $stderr));

	if ($combined === '') {
		return false;
	}

	return str_contains($combined, 'certificate not yet due for renewal')
		|| str_contains($combined, 'no action taken');
}

function freesiem_sentinel_ssl_lineage_exists(string $host, ?array $command_data = null): bool
{
	$host = strtolower(trim($host));
	if ($host === '') {
		return false;
	}

	$user_space_config = '';
	if (is_array($command_data) && !empty($command_data['user_space']['config_dir'])) {
		$user_space_config = rtrim((string) ($command_data['user_space']['config_dir']), '/\\');
	}

	$candidates = [];
	if ($user_space_config !== '') {
		$candidates[] = $user_space_config . '/live/' . $host;
	}
	$candidates[] = '/etc/letsencrypt/live/' . $host;

	foreach ($candidates as $candidate) {
		if (file_exists($candidate . '/cert.pem') || file_exists($candidate . '/fullchain.pem') || file_exists($candidate . '/privkey.pem')) {
			return true;
		}
	}

	return false;
}

function freesiem_sentinel_is_allowed_nginx_config_path(string $path): bool
{
	$path = trim($path);
	if ($path === '') {
		return false;
	}

	$allowed_prefixes = [
		'/etc/nginx/sites-available/',
		'/etc/nginx/sites-enabled/',
		'/etc/nginx/conf.d/',
	];

	foreach ($allowed_prefixes as $prefix) {
		if (str_starts_with($path, $prefix)) {
			return true;
		}
	}

	return false;
}

function freesiem_sentinel_get_nginx_config_candidates(string $host, array $ssl_state = []): array
{
	$host = strtolower(trim($host));
	$candidates = [];

	if (!empty($ssl_state['nginx_config_path']) && freesiem_sentinel_is_allowed_nginx_config_path((string) $ssl_state['nginx_config_path'])) {
		$candidates[] = (string) $ssl_state['nginx_config_path'];
	}

	if ($host !== '') {
		$candidates[] = '/etc/nginx/sites-available/' . $host;
		$candidates[] = '/etc/nginx/sites-available/' . $host . '.conf';
		$candidates[] = '/etc/nginx/sites-enabled/' . $host;
		$candidates[] = '/etc/nginx/sites-enabled/' . $host . '.conf';
		$candidates[] = '/etc/nginx/conf.d/' . $host . '.conf';
	}

	return array_values(array_unique(array_filter($candidates, 'freesiem_sentinel_is_allowed_nginx_config_path')));
}

function freesiem_sentinel_get_nginx_preview_config(array $integration, bool $enable_redirect = false): string
{
	$host = (string) ($integration['host'] ?? 'example.com');
	$root = (string) ($integration['webroot'] ?? ABSPATH);
	$fullchain = (string) ($integration['fullchain_path'] ?? '');
	$privkey = (string) ($integration['privkey_path'] ?? '');
	$lines = [];

	if ($enable_redirect) {
		$lines[] = 'server {';
		$lines[] = '    listen 80;';
		$lines[] = '    server_name ' . $host . ';';
		$lines[] = '    return 301 https://$host$request_uri;';
		$lines[] = '}';
		$lines[] = '';
	}

	$lines[] = 'server {';
		$lines[] = '    listen 443 ssl;';
		$lines[] = '    server_name ' . $host . ';';
		$lines[] = '    root ' . $root . ';';
		$lines[] = '    index index.php index.html index.htm;';
		$lines[] = '';
		$lines[] = '    ssl_certificate ' . $fullchain . ';';
		$lines[] = '    ssl_certificate_key ' . $privkey . ';';
		$lines[] = '';
		$lines[] = '    location / {';
		$lines[] = '        try_files $uri $uri/ /index.php?$args;';
		$lines[] = '    }';
	$lines[] = '}';

	return implode("\n", $lines);
}

function freesiem_sentinel_detect_nginx_integration(?array $ssl_settings = null, ?array $environment = null, ?array $ssl_state = null): array
{
	$ssl_settings = is_array($ssl_settings) ? $ssl_settings : freesiem_sentinel_get_ssl_settings();
	$environment = is_array($environment) ? $environment : freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
	$ssl_state = is_array($ssl_state) ? $ssl_state : freesiem_sentinel_get_ssl_state();
	$host = (string) ($environment['configured_host'] ?? '');
	$nginx_binary = freesiem_sentinel_detect_binary('nginx');
	$server_software = isset($_SERVER['SERVER_SOFTWARE']) ? strtolower(sanitize_text_field(wp_unslash((string) $_SERVER['SERVER_SOFTWARE']))) : '';
	$server_is_nginx = str_contains($server_software, 'nginx');
	$fullchain_path = (string) ($ssl_state['fullchain_path'] ?? '');
	$privkey_path = (string) ($ssl_state['privkey_path'] ?? '');
	$fullchain_exists = $fullchain_path !== '' && file_exists($fullchain_path);
	$privkey_exists = $privkey_path !== '' && file_exists($privkey_path);
	$candidates = freesiem_sentinel_get_nginx_config_candidates($host, $ssl_state);
	$target_path = '';
	$target_exists = false;
	$target_is_managed = false;
	$mode = 'manual_required';
	$reason = __('Automatic nginx patching is only available for a Sentinel-managed config target.', 'freesiem-sentinel');

	foreach ($candidates as $candidate) {
		if (!file_exists($candidate)) {
			continue;
		}

		$target_path = $candidate;
		$target_exists = true;
		$contents = is_readable($candidate) ? (string) file_get_contents($candidate) : '';
		$target_is_managed = str_contains($contents, '# BEGIN freeSIEM Sentinel Nginx SSL');
		if ($target_is_managed) {
			$mode = 'patch';
			$reason = __('Sentinel-managed nginx config detected and can be updated safely.', 'freesiem-sentinel');
		} else {
			$mode = 'manual_required';
			$reason = __('An existing nginx site config was detected, so Sentinel is staying in preview/manual mode for safety.', 'freesiem-sentinel');
		}
		break;
	}

	if ($target_path === '') {
		$target_path = $host !== '' ? '/etc/nginx/conf.d/' . $host . '.conf' : '';
		if ($target_path !== '' && is_dir(dirname($target_path))) {
			$mode = freesiem_sentinel_path_is_writable(dirname($target_path)) ? 'patch' : 'manual_required';
			$reason = $mode === 'patch'
				? __('Sentinel can create a dedicated nginx config file for this host.', 'freesiem-sentinel')
				: __('A likely nginx config directory was detected, but it is not writable by PHP.', 'freesiem-sentinel');
		}
	}

	$config_writable = $target_path !== '' && ($target_exists ? freesiem_sentinel_path_is_writable($target_path) : freesiem_sentinel_path_is_writable(dirname($target_path)));
	$preview_only = !$fullchain_exists || !$privkey_exists || empty($environment['execution_support']) || empty($nginx_binary['available']) || (!$server_is_nginx && !$target_exists && !is_dir('/etc/nginx'));
	$apply_allowed = !$preview_only && $mode === 'patch' && $config_writable && $target_path !== '';

	return [
		'host' => $host,
		'webroot' => (string) (($ssl_settings['webroot_path'] ?? '') !== '' ? $ssl_settings['webroot_path'] : ABSPATH),
		'fullchain_path' => $fullchain_path,
		'privkey_path' => $privkey_path,
		'fullchain_exists' => $fullchain_exists,
		'privkey_exists' => $privkey_exists,
		'nginx_binary' => $nginx_binary,
		'server_is_nginx' => $server_is_nginx,
		'server_software' => $server_software,
		'target_path' => $target_path,
		'target_exists' => $target_exists,
		'target_is_managed' => $target_is_managed,
		'config_writable' => $config_writable,
		'mode' => $mode,
		'apply_allowed' => $apply_allowed,
		'reason' => $reason,
		'test_command' => (!empty($nginx_binary['path']) ? $nginx_binary['path'] : 'nginx') . ' -t',
		'reload_command' => (!empty($nginx_binary['path']) ? $nginx_binary['path'] : 'nginx') . ' -s reload',
	];
}

function freesiem_sentinel_apply_ssl_to_nginx(bool $enable_redirect = false): array
{
	$ssl_settings = freesiem_sentinel_get_ssl_settings();
	$environment = freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
	$ssl_state = freesiem_sentinel_get_ssl_state();
	$integration = freesiem_sentinel_detect_nginx_integration($ssl_settings, $environment, $ssl_state);
	$executed_at = freesiem_sentinel_get_iso8601_time();
	$preview = freesiem_sentinel_get_nginx_preview_config($integration, $enable_redirect);
	$state_updates = [
		'nginx_integration_mode' => $integration['mode'],
		'nginx_config_path' => (string) ($integration['target_path'] ?? ''),
		'nginx_cert_path' => (string) ($integration['fullchain_path'] ?? ''),
		'nginx_key_path' => (string) ($integration['privkey_path'] ?? ''),
		'nginx_last_apply_at' => $executed_at,
		'nginx_redirect_enabled' => $enable_redirect ? 1 : 0,
	];

	if (empty($integration['apply_allowed'])) {
		$state_updates['nginx_last_apply_status'] = 'manual_required';
		$state_updates['nginx_last_apply_result'] = (string) ($integration['reason'] ?? __('Automatic nginx apply is not available.', 'freesiem-sentinel'));
		freesiem_sentinel_update_ssl_state($state_updates);

		return [
			'success' => false,
			'status' => 'manual_required',
			'summary' => (string) $state_updates['nginx_last_apply_result'],
			'preview' => $preview,
			'integration' => $integration,
			'backup_path' => '',
			'test' => null,
			'reload' => null,
			'executed_at' => $executed_at,
		];
	}

	$target_path = (string) $integration['target_path'];
	$backup_path = '';
	$existing_contents = file_exists($target_path) ? (string) file_get_contents($target_path) : '';
	$had_existing_file = file_exists($target_path);
	$managed_content = "# BEGIN freeSIEM Sentinel Nginx SSL\n" . $preview . "\n# END freeSIEM Sentinel Nginx SSL\n";

	if ($had_existing_file) {
		$backup_path = $target_path . '.freesiem-sentinel.' . gmdate('YmdHis') . '.bak';
		if (!@copy($target_path, $backup_path)) {
			$state_updates['nginx_last_apply_status'] = 'failed';
			$state_updates['nginx_last_apply_result'] = __('Sentinel could not create an nginx config backup before writing.', 'freesiem-sentinel');
			freesiem_sentinel_update_ssl_state($state_updates);

			return [
				'success' => false,
				'status' => 'failed',
				'summary' => (string) $state_updates['nginx_last_apply_result'],
				'preview' => $preview,
				'integration' => $integration,
				'backup_path' => '',
				'test' => null,
				'reload' => null,
				'executed_at' => $executed_at,
			];
		}
	}

	if (@file_put_contents($target_path, $managed_content) === false) {
		if ($backup_path !== '' && file_exists($backup_path)) {
			@copy($backup_path, $target_path);
		}
		$state_updates['nginx_backup_path'] = $backup_path;
		$state_updates['nginx_last_apply_status'] = 'failed';
		$state_updates['nginx_last_apply_result'] = __('Sentinel could not write the nginx config target file.', 'freesiem-sentinel');
		freesiem_sentinel_update_ssl_state($state_updates);

		return [
			'success' => false,
			'status' => 'failed',
			'summary' => (string) $state_updates['nginx_last_apply_result'],
			'preview' => $preview,
			'integration' => $integration,
			'backup_path' => $backup_path,
			'test' => null,
			'reload' => null,
			'executed_at' => $executed_at,
		];
	}

	$test = freesiem_sentinel_run_ssl_shell_command(escapeshellarg((string) ($integration['nginx_binary']['path'] ?: 'nginx')) . ' -t', 'nginx_test', 60, (string) ($integration['test_command'] ?? 'nginx -t'));
	if (empty($test['success'])) {
		if ($had_existing_file && $backup_path !== '') {
			@copy($backup_path, $target_path);
		} elseif (!$had_existing_file && file_exists($target_path)) {
			@unlink($target_path);
		}

		$state_updates['nginx_backup_path'] = $backup_path;
		$state_updates['nginx_integration_mode'] = 'failed_rolled_back';
		$state_updates['nginx_last_apply_status'] = 'failed';
		$state_updates['nginx_last_apply_result'] = __('Nginx syntax test failed, so Sentinel restored the prior config.', 'freesiem-sentinel');
		$state_updates['nginx_last_test_result'] = !empty($test['stderr_summary']) ? (string) $test['stderr_summary'] : (string) ($test['stdout_summary'] ?? '');
		freesiem_sentinel_update_ssl_state($state_updates);

		return [
			'success' => false,
			'status' => 'failed_rolled_back',
			'summary' => (string) $state_updates['nginx_last_apply_result'],
			'preview' => $preview,
			'integration' => $integration,
			'backup_path' => $backup_path,
			'test' => $test,
			'reload' => null,
			'executed_at' => $executed_at,
		];
	}

	$reload = freesiem_sentinel_run_ssl_shell_command(escapeshellarg((string) ($integration['nginx_binary']['path'] ?: 'nginx')) . ' -s reload', 'nginx_reload', 60, (string) ($integration['reload_command'] ?? 'nginx -s reload'));
	if (empty($reload['success'])) {
		if ($had_existing_file && $backup_path !== '') {
			@copy($backup_path, $target_path);
		} elseif (!$had_existing_file && file_exists($target_path)) {
			@unlink($target_path);
		}
		@freesiem_sentinel_run_ssl_shell_command(escapeshellarg((string) ($integration['nginx_binary']['path'] ?: 'nginx')) . ' -t', 'nginx_test_after_restore', 60, (string) ($integration['test_command'] ?? 'nginx -t'));
		@freesiem_sentinel_run_ssl_shell_command(escapeshellarg((string) ($integration['nginx_binary']['path'] ?: 'nginx')) . ' -s reload', 'nginx_reload_after_restore', 60, (string) ($integration['reload_command'] ?? 'nginx -s reload'));

		$state_updates['nginx_backup_path'] = $backup_path;
		$state_updates['nginx_integration_mode'] = 'failed_rolled_back';
		$state_updates['nginx_last_apply_status'] = 'failed';
		$state_updates['nginx_last_apply_result'] = __('Nginx reload failed, so Sentinel restored the prior config.', 'freesiem-sentinel');
		$state_updates['nginx_last_test_result'] = !empty($test['stderr_summary']) ? (string) $test['stderr_summary'] : (string) ($test['stdout_summary'] ?? '');
		$state_updates['nginx_last_reload_result'] = !empty($reload['stderr_summary']) ? (string) $reload['stderr_summary'] : (string) ($reload['stdout_summary'] ?? '');
		freesiem_sentinel_update_ssl_state($state_updates);

		return [
			'success' => false,
			'status' => 'failed_rolled_back',
			'summary' => (string) $state_updates['nginx_last_apply_result'],
			'preview' => $preview,
			'integration' => $integration,
			'backup_path' => $backup_path,
			'test' => $test,
			'reload' => $reload,
			'executed_at' => $executed_at,
		];
	}

	$https_check = function_exists('wp_remote_get')
		? wp_remote_get('https://' . $integration['host'], ['timeout' => 10, 'sslverify' => false])
		: null;
	$https_summary = is_wp_error($https_check)
		? $https_check->get_error_message()
		: (is_array($https_check) ? 'HTTP ' . (string) wp_remote_retrieve_response_code($https_check) : '');

	$state_updates['nginx_backup_path'] = $backup_path;
	$state_updates['nginx_integration_mode'] = 'applied';
	$state_updates['nginx_last_apply_status'] = 'success';
	$state_updates['nginx_last_apply_result'] = __('Nginx SSL config was applied successfully.', 'freesiem-sentinel');
	$state_updates['nginx_last_test_result'] = !empty($test['stderr_summary']) ? (string) $test['stderr_summary'] : (string) ($test['stdout_summary'] ?? __('nginx -t passed.', 'freesiem-sentinel'));
	$state_updates['nginx_last_reload_result'] = !empty($reload['stderr_summary']) ? (string) $reload['stderr_summary'] : (string) ($reload['stdout_summary'] ?? __('nginx reload completed.', 'freesiem-sentinel'));
	freesiem_sentinel_update_ssl_state($state_updates);

	return [
		'success' => true,
		'status' => 'applied',
		'summary' => (string) $state_updates['nginx_last_apply_result'],
		'preview' => $preview,
		'integration' => $integration,
		'backup_path' => $backup_path,
		'test' => $test,
		'reload' => $reload,
		'https_summary' => $https_summary,
		'executed_at' => $executed_at,
	];
}

function freesiem_sentinel_detect_local_port_listener(int $port): array
{
	$error_no = 0;
	$error_message = '';
	$socket = @fsockopen('127.0.0.1', $port, $error_no, $error_message, 1.0);

	if (is_resource($socket)) {
		fclose($socket);

		return [
			'listening' => true,
			'message' => sprintf(__('A local service appears to be listening on port %d.', 'freesiem-sentinel'), $port),
		];
	}

	return [
		'listening' => false,
		'message' => $error_message !== '' ? sanitize_text_field($error_message) : __('No local listener was detected.', 'freesiem-sentinel'),
	];
}

function freesiem_sentinel_verify_ssl_certificate(string $host, ?array $command_data = null): array
{
	$host = strtolower(trim($host));
	$user_space_config = '';
	if (is_array($command_data) && !empty($command_data['user_space']['config_dir'])) {
		$user_space_config = rtrim((string) $command_data['user_space']['config_dir'], '/\\');
	}

	$candidate_bases = [];
	if ($user_space_config !== '') {
		$candidate_bases[] = $user_space_config . '/live/' . $host;
	}
	$candidate_bases[] = '/etc/letsencrypt/live/' . $host;

	$base_path = '';
	foreach ($candidate_bases as $candidate_base) {
		if (file_exists($candidate_base . '/cert.pem') || file_exists($candidate_base . '/fullchain.pem') || file_exists($candidate_base . '/privkey.pem')) {
			$base_path = $candidate_base;
			break;
		}
	}

	if ($base_path === '') {
		$base_path = $candidate_bases[0];
	}

	$metadata = [
		'domain' => $host,
		'cert_path' => $base_path . '/cert.pem',
		'fullchain_path' => $base_path . '/fullchain.pem',
		'privkey_path' => $base_path . '/privkey.pem',
	];
	$has_files = file_exists($metadata['cert_path']) && file_exists($metadata['fullchain_path']) && file_exists($metadata['privkey_path']);

	if (!$has_files) {
		return [
			'success' => false,
			'status' => 'failed',
			'summary' => __('Certbot reported success, but expected certificate files were not found.', 'freesiem-sentinel'),
			'metadata' => $metadata,
		];
	}

	$cert_contents = @file_get_contents($metadata['cert_path']);
	$cert_data = (is_string($cert_contents) && function_exists('openssl_x509_parse')) ? @openssl_x509_parse($cert_contents) : false;
	$expires_at = '';
	$issued_at = '';
	$host_match = false;

	if (is_array($cert_data)) {
		$issued_at = !empty($cert_data['validFrom_time_t']) ? gmdate('c', (int) $cert_data['validFrom_time_t']) : '';
		$expires_at = !empty($cert_data['validTo_time_t']) ? gmdate('c', (int) $cert_data['validTo_time_t']) : '';
		$names = [];
		if (!empty($cert_data['subject']['CN'])) {
			$names[] = strtolower((string) $cert_data['subject']['CN']);
		}
		if (!empty($cert_data['extensions']['subjectAltName'])) {
			foreach (explode(',', (string) $cert_data['extensions']['subjectAltName']) as $san_entry) {
				$san_entry = trim($san_entry);
				if (str_starts_with($san_entry, 'DNS:')) {
					$names[] = strtolower(substr($san_entry, 4));
				}
			}
		}
		$host_match = in_array($host, array_unique($names), true);
	}

	$metadata['issued_at'] = $issued_at;
	$metadata['expires_at'] = $expires_at;

	if (!$host_match && $cert_data !== false) {
		return [
			'success' => false,
			'status' => 'warning',
			'summary' => __('Certificate files exist, but the parsed certificate host names did not clearly match the expected domain.', 'freesiem-sentinel'),
			'metadata' => $metadata,
		];
	}

	return [
		'success' => true,
		'status' => 'success',
		'summary' => $expires_at !== ''
			? sprintf(__('Certificate files verified successfully. Expires at %s.', 'freesiem-sentinel'), $expires_at)
			: __('Certificate files verified successfully.', 'freesiem-sentinel'),
		'metadata' => $metadata,
	];
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
