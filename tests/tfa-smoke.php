<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/tfa-smoke.php');
}

$plugin = Freesiem_Plugin::instance();
$service = $plugin->get_tfa_service();
$auth = $plugin->get_tfa_auth();
$tasks = $plugin->get_pending_tasks();
$remote = new Freesiem_TFA_Remote($plugin, $service, $tasks);
$remote->register_rest_routes();

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

$sign_request = static function (string $method, string $route, array $payload = []) use ($test_settings): WP_REST_Request {
	$body = $method === 'GET' ? '' : wp_json_encode($payload);
	$timestamp = (string) time();
	$nonce = wp_generate_password(12, false, false);
	$canonical = implode("\n", [
		strtoupper($method),
		$route,
		hash('sha256', $body),
		$timestamp,
		$nonce,
	]);
	$signature = hash_hmac('sha256', $canonical, (string) $test_settings['hmac_secret']);
	$request = new WP_REST_Request(strtoupper($method), $route);
	$request->set_header('X-FreeSIEM-Site-ID', (string) $test_settings['site_id']);
	$request->set_header('X-FreeSIEM-Api-Key', (string) $test_settings['api_key']);
	$request->set_header('X-FreeSIEM-Timestamp', $timestamp);
	$request->set_header('X-FreeSIEM-Nonce', $nonce);
	$request->set_header('X-FreeSIEM-Signature', $signature);
	if ($body !== '') {
		$request->set_body($body);
	}

	return $request;
};

$cleanup_user_ids = [];

try {
	$user_id = wp_insert_user([
		'user_login' => 'tfa-smoke-' . wp_generate_password(6, false, false),
		'user_email' => 'tfa-smoke+' . wp_generate_password(6, false, false) . '@example.com',
		'user_pass' => 'SmokePassword!123',
		'role' => 'subscriber',
	]);
	$assert(!is_wp_error($user_id) && $user_id > 0, 'Expected a smoke-test WordPress user.');
	$cleanup_user_ids[] = (int) $user_id;
	$user = get_user_by('id', (int) $user_id);
	$assert($user instanceof WP_User, 'Expected the smoke-test user to load.');

	$secret = $service->generate_secret();
	$assert(strlen($secret) === 32, 'Expected a 32-character TOTP secret.');
	$code = $service->generate_totp_code($secret);
	$assert($service->verify_totp_code($secret, $code), 'Expected the generated TOTP code to validate.');

	$set_secret = $service->set_secret((int) $user_id, $secret);
	$assert(!is_wp_error($set_secret), 'Expected the encrypted secret to store successfully.');
	$stored_secret = $service->get_secret((int) $user_id);
	$assert(!is_wp_error($stored_secret) && $stored_secret === $secret, 'Expected the encrypted secret to decrypt correctly.');

	$service->set_not_enabled((int) $user_id);
	$state = $service->get_user_tfa_state((int) $user_id);
	$assert($state['tfa_status'] === Freesiem_TFA_Service::STATUS_NOT_ENABLED, 'Expected not_enabled state.');

	$pending_result = $service->set_pending_setup((int) $user_id, Freesiem_TFA_Service::SOURCE_LOCAL, Freesiem_TFA_Service::MANAGED_LOCAL, $secret);
	$assert(!is_wp_error($pending_result), 'Expected pending setup transition to succeed.');
	$state = $service->get_user_tfa_state((int) $user_id);
	$assert($state['tfa_status'] === Freesiem_TFA_Service::STATUS_PENDING_SETUP, 'Expected pending_setup state.');
	$assert($auth->get_login_requirement($user) === Freesiem_TFA_Service::STATUS_PENDING_SETUP, 'Expected login requirement to reflect pending setup.');

	$completed = $service->complete_pending_setup((int) $user_id, $service->generate_totp_code($secret));
	$assert(!is_wp_error($completed), 'Expected pending_setup to transition to enabled with a valid code.');
	$state = $service->get_user_tfa_state((int) $user_id);
	$assert($state['tfa_status'] === Freesiem_TFA_Service::STATUS_ENABLED, 'Expected enabled state after successful verification.');

	$core_secret = $service->generate_secret();
	$core_pending = $service->set_pending_setup((int) $user_id, Freesiem_TFA_Service::SOURCE_CORE, Freesiem_TFA_Service::MANAGED_CORE, $core_secret);
	$assert(!is_wp_error($core_pending), 'Expected Core-managed pending setup to store.');
	$assert(!$service->local_actions_allowed((int) $user_id), 'Expected local actions to be disabled for Core-managed users.');

	$invalid_request = new WP_REST_Request('GET', '/freesiem-sentinel/v1/users/list');
	$invalid_response = $remote->handle_list_users($invalid_request);
	$assert(is_wp_error($invalid_response), 'Expected unsigned list-users requests to fail.');

	$provision_password = 'RemotePass!123';
	$provision_secret = $service->generate_secret();
	$provision_request = $sign_request('POST', '/freesiem-sentinel/v1/users/provision', [
		'target' => [
			'username' => 'remote-tfa-' . wp_generate_password(6, false, false),
			'email' => 'remote-tfa+' . wp_generate_password(6, false, false) . '@example.com',
			'display_name' => 'Remote TFA User',
			'role' => 'subscriber',
			'password' => $provision_password,
		],
		'tfa' => [
			'tfa_status' => Freesiem_TFA_Service::STATUS_PENDING_SETUP,
			'tfa_source' => Freesiem_TFA_Service::SOURCE_CORE,
			'tfa_managed' => Freesiem_TFA_Service::MANAGED_CORE,
			'tfa_secret' => $provision_secret,
		],
	]);
	$provision_response = $remote->handle_provision_user($provision_request);
	$assert($provision_response instanceof WP_REST_Response, 'Expected signed provision-user request to succeed.');
	$provision_data = $provision_response->get_data();
	$remote_user_id = (int) ($provision_data['user']['user_id'] ?? 0);
	$cleanup_user_ids[] = $remote_user_id;
	$assert($remote_user_id > 0, 'Expected remote provisioning to create a WordPress user.');
	$assert(wp_authenticate((string) ($provision_data['user']['username'] ?? ''), $provision_password) instanceof WP_User, 'Expected the provisioned user password to authenticate locally.');
	$remote_state = $service->get_user_tfa_state($remote_user_id);
	$assert($remote_state['tfa_status'] === Freesiem_TFA_Service::STATUS_PENDING_SETUP, 'Expected provisioned TFA state to be pending_setup.');
	$assert($remote_state['tfa_managed'] === Freesiem_TFA_Service::MANAGED_CORE, 'Expected provisioned user to be Core-managed.');

	$update_request = $sign_request('POST', '/freesiem-sentinel/v1/users/update-tfa', [
		'target' => [
			'user_id' => $remote_user_id,
		],
		'tfa' => [
			'tfa_status' => Freesiem_TFA_Service::STATUS_ENABLED,
			'tfa_source' => Freesiem_TFA_Service::SOURCE_CORE,
			'tfa_managed' => Freesiem_TFA_Service::MANAGED_CORE,
			'tfa_secret' => $provision_secret,
			'last_verified_at' => freesiem_sentinel_get_iso8601_time(),
		],
	]);
	$update_response = $remote->handle_update_tfa($update_request);
	$assert($update_response instanceof WP_REST_Response, 'Expected signed update-tfa request to succeed.');
	$updated_state = $service->get_user_tfa_state($remote_user_id);
	$assert($updated_state['tfa_status'] === Freesiem_TFA_Service::STATUS_ENABLED, 'Expected update-tfa to switch the user to enabled.');

	$reset_secret = $service->generate_secret();
	$reset_response = $remote->handle_reset_tfa($sign_request('POST', '/freesiem-sentinel/v1/users/reset-tfa', [
		'target' => [
			'user_id' => $remote_user_id,
		],
		'tfa_status' => Freesiem_TFA_Service::STATUS_PENDING_SETUP,
		'tfa_source' => Freesiem_TFA_Service::SOURCE_CORE,
		'tfa_managed' => Freesiem_TFA_Service::MANAGED_CORE,
		'tfa_secret' => $reset_secret,
	]));
	$assert($reset_response instanceof WP_REST_Response, 'Expected signed reset-tfa request to succeed.');
	$reset_state = $service->get_user_tfa_state($remote_user_id);
	$assert($reset_state['tfa_status'] === Freesiem_TFA_Service::STATUS_PENDING_SETUP, 'Expected reset-tfa to move the user back to pending_setup.');

	$list_response = $remote->handle_list_users($sign_request('GET', '/freesiem-sentinel/v1/users/list'));
	$assert($list_response instanceof WP_REST_Response, 'Expected signed list-users request to succeed.');
	$list_data = $list_response->get_data();
	$list_json = wp_json_encode($list_data);
	$assert(is_string($list_json) && !str_contains($list_json, $provision_secret), 'Expected /users/list to omit stored TFA secrets.');
	$assert(is_string($list_json) && !str_contains($list_json, 'tfa_secret'), 'Expected /users/list to omit secret fields.');

	echo "tfa-smoke: ok\n";
} finally {
	require_once ABSPATH . 'wp-admin/includes/user.php';

	foreach ($cleanup_user_ids as $cleanup_user_id) {
		if ($cleanup_user_id > 0) {
			wp_delete_user($cleanup_user_id);
		}
	}

	freesiem_sentinel_update_settings($original_settings);
}
