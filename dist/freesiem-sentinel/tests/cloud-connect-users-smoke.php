<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/cloud-connect-users-smoke.php');
}

$plugin = Freesiem_Plugin::instance();
$tasks = $plugin->get_pending_tasks();
$tasks->install_or_upgrade();
$tasks->register_rest_routes();

$original_settings = freesiem_sentinel_get_settings();
$test_settings = freesiem_sentinel_update_settings([
	'site_id' => 'test-site-id',
	'api_key' => 'test-api-key',
	'hmac_secret' => 'test-hmac-secret',
	'connection_state' => 'connected',
]);

$assert = static function (bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException($message);
	}
};

$make_request = static function (string $route, array $params = [], ?string $signature = null) use ($test_settings): WP_REST_Request {
	$timestamp = (string) time();
	$nonce = wp_generate_password(12, false, false);
	$canonical = implode("\n", [
		'GET',
		$route,
		hash('sha256', ''),
		$timestamp,
		$nonce,
	]);
	$request = new WP_REST_Request('GET', $route);
	$request->set_query_params($params);
	$request->set_header('X-FreeSIEM-Site-ID', (string) $test_settings['site_id']);
	$request->set_header('X-FreeSIEM-Api-Key', (string) $test_settings['api_key']);
	$request->set_header('X-FreeSIEM-Timestamp', $timestamp);
	$request->set_header('X-FreeSIEM-Nonce', $nonce);
	$request->set_header('X-FreeSIEM-Signature', $signature ?: hash_hmac('sha256', $canonical, (string) $test_settings['hmac_secret']));

	return $request;
};

$cleanup_user_ids = [];

try {
	$route = '/freesiem-sentinel/v1/cloud-connect/users';
	$routes = rest_get_server()->get_routes();
	$assert(isset($routes[$route]), 'Expected the signed cloud users route to be registered.');

	$username = 'smoke-remote-user-' . wp_generate_password(6, false, false);
	$email = 'smoke-users-' . wp_generate_password(6, false, false) . '@example.com';
	$user_id = wp_insert_user([
		'user_login' => $username,
		'user_email' => $email,
		'display_name' => 'Smoke Remote User',
		'user_pass' => wp_generate_password(24, true, true),
		'role' => 'subscriber',
	]);
	$assert(!is_wp_error($user_id), 'Expected smoke-test user creation to succeed.');
	$cleanup_user_ids[] = (int) $user_id;

	$response = rest_get_server()->dispatch($make_request($route, ['role' => 'subscriber']));
	$assert($response instanceof WP_REST_Response, 'Expected a REST response for a valid signed users request.');
	$assert($response->get_status() === 200, 'Expected a 200 response for a valid signed users request.');

	$data = $response->get_data();
	$assert(is_array($data), 'Expected the users response payload to be an array.');
	$assert(array_key_exists('users', $data), 'Expected the users response payload to include a users key.');
	$assert(is_array($data['users']), 'Expected the users key to contain an array.');

	$found = null;

	foreach ($data['users'] as $item) {
		if ((int) ($item['id'] ?? 0) === (int) $user_id) {
			$found = $item;
			break;
		}
	}

	$assert(is_array($found), 'Expected the signed users response to include the smoke-test user.');
	$assert(($found['username'] ?? '') === $username, 'Expected the user item to expose the username.');
	$assert(($found['email'] ?? '') === $email, 'Expected the user item to expose the email.');
	$assert(($found['display_name'] ?? '') === 'Smoke Remote User', 'Expected the user item to expose the display name.');
	$assert(($found['roles'] ?? []) === ['subscriber'], 'Expected the user item to expose roles as a flat string array.');

	$expected_keys = ['id', 'username', 'email', 'display_name', 'roles'];
	$actual_keys = array_keys($found);
	sort($expected_keys);
	sort($actual_keys);
	$assert($actual_keys === $expected_keys, 'Expected the user item to expose only safe metadata fields.');
	$assert(!array_key_exists('user_pass', $found), 'Expected the signed users response to omit password hashes.');
	$assert(!array_key_exists('caps', $found), 'Expected the signed users response to omit capabilities data.');

	$invalid = rest_get_server()->dispatch($make_request($route, [], 'bad-signature'));
	$assert($invalid instanceof WP_Error, 'Expected invalid signature requests to be rejected.');
	$assert($invalid->get_error_code() === 'freesiem_invalid_task_signature', 'Expected invalid signature requests to reuse the existing signature error code.');

	$empty = rest_get_server()->dispatch($make_request($route, ['role' => 'role-that-does-not-exist']));
	$assert($empty instanceof WP_REST_Response, 'Expected an empty signed users request to return a REST response.');
	$empty_data = $empty->get_data();
	$assert(isset($empty_data['users']) && $empty_data['users'] === [], 'Expected unmatched role filters to return an empty users array.');

	$heartbeat = $tasks->build_heartbeat_payload(freesiem_sentinel_get_settings());
	$assert(!empty($heartbeat['supports_remote_user_listing']), 'Expected heartbeat metadata to advertise remote user listing support.');

	echo "cloud-connect-users-smoke: ok\n";
} finally {
	require_once ABSPATH . 'wp-admin/includes/user.php';

	foreach ($cleanup_user_ids as $user_id) {
		if ($user_id > 0) {
			wp_delete_user($user_id);
		}
	}

	freesiem_sentinel_update_settings($original_settings);
}
