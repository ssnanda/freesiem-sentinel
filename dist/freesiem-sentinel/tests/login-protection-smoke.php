<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/login-protection-smoke.php');
}

$original_settings = freesiem_sentinel_get_login_protection_settings();
$original_state = get_option(FREESIEM_SENTINEL_LOGIN_PROTECTION_STATE_OPTION, null);
$test_user_id = 0;
$old_server = [
	'REMOTE_ADDR' => $_SERVER['REMOTE_ADDR'] ?? null,
	'SCRIPT_NAME' => $_SERVER['SCRIPT_NAME'] ?? null,
];

$assert = static function (bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException($message);
	}
};

try {
	$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
	$_SERVER['SCRIPT_NAME'] = '/wp-login.php';
	delete_option(FREESIEM_SENTINEL_LOGIN_PROTECTION_STATE_OPTION);

	freesiem_sentinel_update_login_protection_settings([
		'enabled' => 1,
		'max_failed_attempts' => 5,
		'lockout_duration_minutes' => 15,
		'tracking_mode' => 'both',
		'enable_permanent_ban' => 1,
		'permanent_ban_threshold' => 2,
		'track_failed_login_count' => 1,
		'log_successful_logins' => 1,
		'log_failed_logins' => 1,
	]);

	$unknown_username = 'missing-smoke-user';
	for ($index = 0; $index < 5; $index++) {
		do_action('wp_login_failed', $unknown_username, new WP_Error('invalid_username', 'Invalid username.'));
	}

	$record = freesiem_sentinel_get_login_protection_record($unknown_username);
	$assert((int) ($record['attempts'] ?? 0) === 5, 'Expected five failed attempts to be stored.');
	$assert((int) ($record['total_offenses'] ?? 0) === 1, 'Expected the first lockout offense to be recorded.');
	$assert(freesiem_sentinel_get_login_protection_record_status($record) === 'active_lockout', 'Expected an active lockout after the first threshold.');

	$blocked = apply_filters('authenticate', null, $unknown_username, 'bad-password');
	$assert($blocked instanceof WP_Error && $blocked->get_error_code() === 'freesiem_login_locked', 'Expected authenticate() to block during an active lockout.');

	$record['locked_until'] = 0;
	$record = freesiem_sentinel_upsert_login_protection_record($record);
	for ($index = 0; $index < 5; $index++) {
		do_action('wp_login_failed', $unknown_username, new WP_Error('invalid_username', 'Invalid username.'));
	}

	$record = freesiem_sentinel_get_login_protection_record($unknown_username);
	$assert((int) ($record['total_offenses'] ?? 0) >= 2, 'Expected a second offense after repeated failures.');
	$assert(!empty($record['permanently_banned']), 'Expected the record to become permanently banned.');

	$banned = apply_filters('authenticate', null, $unknown_username, 'bad-password');
	$assert($banned instanceof WP_Error && $banned->get_error_code() === 'freesiem_login_banned', 'Expected authenticate() to block permanently banned records.');

	$test_user_id = wp_insert_user([
		'user_login' => 'login-protection-smoke-' . wp_generate_password(6, false, false),
		'user_email' => 'login-protection-smoke+' . wp_generate_password(6, false, false) . '@example.com',
		'user_pass' => 'SmokePassword!123',
		'role' => 'subscriber',
	]);
	$assert(!is_wp_error($test_user_id) && $test_user_id > 0, 'Expected a smoke-test user to be created.');
	$test_user = get_user_by('id', (int) $test_user_id);
	$assert($test_user instanceof WP_User, 'Expected the smoke-test user to load.');

	do_action('wp_login_failed', (string) $test_user->user_login, new WP_Error('incorrect_password', 'Incorrect password.'));
	$known_record = freesiem_sentinel_get_login_protection_record((string) $test_user->user_login);
	$assert((int) ($known_record['attempts'] ?? 0) === 1, 'Expected a known user failure to be tracked.');
	do_action('wp_login', (string) $test_user->user_login, $test_user);
	$known_record = freesiem_sentinel_get_login_protection_record((string) $test_user->user_login);
	$assert((int) ($known_record['attempts'] ?? 0) === 0, 'Expected successful login to clear the tracked record.');

	$ban_logs = freesiem_sentinel_get_filtered_log_rows(['scope' => 'bans'], 20);
	$failure_logs = freesiem_sentinel_get_filtered_log_rows(['scope' => 'failures', 'username' => (string) $test_user->user_login], 20);
	$assert($ban_logs !== [], 'Expected ban log rows to be queryable.');
	$assert($failure_logs !== [], 'Expected username-filtered failure logs to be queryable.');

	echo "login-protection-smoke: ok\n";
} finally {
	require_once ABSPATH . 'wp-admin/includes/user.php';

	if ($test_user_id > 0) {
		wp_delete_user($test_user_id);
	}

	freesiem_sentinel_update_login_protection_settings($original_settings);

	if ($original_state === null) {
		delete_option(FREESIEM_SENTINEL_LOGIN_PROTECTION_STATE_OPTION);
	} else {
		update_option(FREESIEM_SENTINEL_LOGIN_PROTECTION_STATE_OPTION, $original_state, false);
	}

	foreach ($old_server as $key => $value) {
		if ($value === null) {
			unset($_SERVER[$key]);
			continue;
		}

		$_SERVER[$key] = $value;
	}
}
