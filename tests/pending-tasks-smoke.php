<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/pending-tasks-smoke.php');
}

$plugin = Freesiem_Plugin::instance();
$tasks = $plugin->get_pending_tasks();
$tasks->install_or_upgrade();

$original_settings = freesiem_sentinel_get_settings();
$test_settings = freesiem_sentinel_update_settings([
	'site_id' => 'test-site-id',
	'api_key' => 'test-api-key',
	'hmac_secret' => 'test-hmac-secret',
	'connection_state' => 'connected',
	'enable_pending_task_queue' => 1,
	'auto_approve_enabled_default' => 1,
	'auto_approve_after_minutes_default' => 30,
]);

$assert = static function (bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException($message);
	}
};

$make_request = static function (array $payload) use ($test_settings): WP_REST_Request {
	$body = wp_json_encode($payload);
	$route = '/freesiem-sentinel/v1/cloud/task';
	$timestamp = (string) time();
	$nonce = wp_generate_password(12, false, false);
	$canonical = implode("\n", [
		'POST',
		$route,
		hash('sha256', $body),
		$timestamp,
		$nonce,
	]);
	$signature = hash_hmac('sha256', $canonical, (string) $test_settings['hmac_secret']);
	$request = new WP_REST_Request('POST', $route);
	$request->set_header('X-FreeSIEM-Site-ID', (string) $test_settings['site_id']);
	$request->set_header('X-FreeSIEM-Api-Key', (string) $test_settings['api_key']);
	$request->set_header('X-FreeSIEM-Timestamp', $timestamp);
	$request->set_header('X-FreeSIEM-Nonce', $nonce);
	$request->set_header('X-FreeSIEM-Signature', $signature);
	$request->set_body($body);

	return $request;
};

$cleanup_ids = [];
$cleanup_user_ids = [];

try {
	$task_payload = [
		'core_task_id' => 'smoke-create-user',
		'action_type' => 'create_user',
		'source_core_identifier' => 'smoke-core',
		'target' => [
			'username' => 'smoke-user-' . wp_generate_password(6, false, false),
			'email' => 'smoke+' . wp_generate_password(6, false, false) . '@example.com',
			'first_name' => 'Smoke',
			'last_name' => 'Test',
			'role' => 'subscriber',
		],
	];

	$response = $tasks->handle_submit_task($make_request($task_payload));
	$assert($response instanceof WP_REST_Response, 'Expected REST response from task submission.');
	$data = $response->get_data();
	$assert(!empty($data['accepted']), 'Expected task submission to be accepted.');
	$assert((string) ($data['status'] ?? '') === 'pending', 'Expected initial task status to be pending.');
	$cleanup_ids[] = (int) ($data['local_task_id'] ?? 0);

	$duplicate = $tasks->handle_submit_task($make_request($task_payload));
	$assert($duplicate instanceof WP_REST_Response, 'Expected REST response from duplicate submission.');
	$assert(!empty($duplicate->get_data()['idempotent']), 'Expected duplicate task submission to be idempotent.');

	$approved = $tasks->approve_task((int) $data['local_task_id'], 1);
	$assert(!is_wp_error($approved), 'Expected task approval to succeed.');
	$approved_task = $tasks->get_task((int) $data['local_task_id']);
	$assert(in_array((string) ($approved_task['status'] ?? ''), ['completed', 'failed'], true), 'Expected approved task to execute to a terminal state.');
	$assert(!empty($approved_task['execution_result']['password_reset_sent']), 'Expected reset-email create-user flow to remain intact.');
	$created_user_id = (int) ($approved_task['execution_result']['user_id'] ?? 0);
	if ($created_user_id > 0) {
		$cleanup_user_ids[] = $created_user_id;
	}

	$explicit_password = 'SmokePass!' . wp_generate_password(8, false, false);
	$password_username = 'smoke-pass-user-' . wp_generate_password(6, false, false);
	$password_email = 'smoke-pass+' . wp_generate_password(6, false, false) . '@example.com';
	$password_payload = [
		'core_task_id' => 'smoke-password-user',
		'action_type' => 'create_user',
		'source_core_identifier' => 'smoke-core',
		'target' => [
			'username' => $password_username,
			'email' => $password_email,
			'first_name' => 'Password',
			'last_name' => 'Flow',
			'display_name' => 'Password Flow',
			'role' => 'subscriber',
			'mode' => 'explicit_password',
			'password' => $explicit_password,
		],
	];

	$password_response = $tasks->handle_submit_task($make_request($password_payload));
	$assert($password_response instanceof WP_REST_Response, 'Expected password-based task submission to be accepted.');
	$password_data = $password_response->get_data();
	$cleanup_ids[] = (int) ($password_data['local_task_id'] ?? 0);
	$password_task_before = $tasks->get_task((int) ($password_data['local_task_id'] ?? 0));
	$assert(($password_task_before['payload']['target']['password'] ?? '') === '[REDACTED]', 'Expected pending task payload output to redact raw passwords.');
	$assert(!str_contains((string) ($password_task_before['payload_json'] ?? ''), $explicit_password), 'Expected stored task payload JSON to omit the raw password.');
	$assert(!str_contains((string) ($password_task_before['execution_payload_json'] ?? ''), $explicit_password), 'Expected stored execution payload JSON to protect the raw password.');
	$assert(str_contains((string) ($password_task_before['execution_payload_json'] ?? ''), 'execution_password_protected'), 'Expected a separate internal execution payload for explicit-password provisioning.');
	$assert(!str_contains(wp_json_encode($password_task_before), $explicit_password), 'Expected normalized task payloads to omit the raw password.');

	$password_approved = $tasks->approve_task((int) ($password_data['local_task_id'] ?? 0), 1);
	$assert(!is_wp_error($password_approved), 'Expected explicit-password task approval to succeed.');
	$password_task = $tasks->get_task((int) ($password_data['local_task_id'] ?? 0));
	$assert((string) ($password_task['status'] ?? '') === 'completed', 'Expected explicit-password task to complete successfully.');
	$assert(!empty($password_task['execution_result']['local_password_set']), 'Expected explicit-password flow to record local password provisioning.');
	$assert(empty($password_task['execution_result']['password_reset_sent']), 'Expected explicit-password flow to skip reset email.');
	$assert(empty($password_task['execution_payload_json']), 'Expected the internal execution payload to be scrubbed after successful execution.');

	$password_user_id = (int) ($password_task['execution_result']['user_id'] ?? 0);
	$assert($password_user_id > 0, 'Expected explicit-password flow to create a local WordPress user.');
	$cleanup_user_ids[] = $password_user_id;
	$authenticated = wp_authenticate($password_username, $explicit_password);
	$assert($authenticated instanceof WP_User, 'Expected the created WordPress user to authenticate locally with the supplied password.');

	$deny_payload = [
		'core_task_id' => 'smoke-deny-user',
		'action_type' => 'delete_user',
		'source_core_identifier' => 'smoke-core',
		'target' => [
			'user_id' => 999999,
			'username' => 'nobody',
			'email' => 'nobody@example.com',
		],
	];
	$deny_response = $tasks->handle_submit_task($make_request($deny_payload));
	$deny_data = $deny_response instanceof WP_REST_Response ? $deny_response->get_data() : [];
	$cleanup_ids[] = (int) ($deny_data['local_task_id'] ?? 0);
	$denied = $tasks->deny_task((int) ($deny_data['local_task_id'] ?? 0), 1, 'Smoke-test deny.');
	$assert(!is_wp_error($denied), 'Expected task deny flow to succeed.');
	$denied_task = $tasks->get_task((int) ($deny_data['local_task_id'] ?? 0));
	$assert((string) ($denied_task['status'] ?? '') === 'denied', 'Expected denied task to remain denied.');

	$auto_payload = [
		'core_task_id' => 'smoke-auto-list',
		'action_type' => 'list_users',
		'source_core_identifier' => 'smoke-core',
	];
	$auto_response = $tasks->handle_submit_task($make_request($auto_payload));
	$auto_data = $auto_response instanceof WP_REST_Response ? $auto_response->get_data() : [];
	$cleanup_ids[] = (int) ($auto_data['local_task_id'] ?? 0);
	global $wpdb;
	$wpdb->update(
		$tasks->get_task_table_name(),
		['auto_approve_at' => gmdate('Y-m-d H:i:s', time() - 60)],
		['id' => (int) ($auto_data['local_task_id'] ?? 0)],
		['%s'],
		['%d']
	);
	$tasks->process_due_tasks();
	$auto_task = $tasks->get_task((int) ($auto_data['local_task_id'] ?? 0));
	$assert(in_array((string) ($auto_task['status'] ?? ''), ['completed', 'failed'], true), 'Expected auto-approved task to execute to a terminal state.');

	$heartbeat = $tasks->build_heartbeat_payload(freesiem_sentinel_get_settings());
	$heartbeat_json = wp_json_encode($heartbeat);
	$assert(is_string($heartbeat_json), 'Expected the heartbeat payload to encode as JSON.');
	$assert(!str_contains((string) $heartbeat_json, $explicit_password), 'Heartbeat payload must not expose explicit provisioning passwords.');
	$assert(!empty($heartbeat['supports_pending_tasks']), 'Heartbeat must advertise pending task support.');
	$assert(!empty($heartbeat['supports_remote_user_listing']), 'Heartbeat must advertise remote user listing support.');
	$assert(array_key_exists('pending_task_summary', $heartbeat), 'Heartbeat must include pending task summary.');

	echo "pending-tasks-smoke: ok\n";
} finally {
	require_once ABSPATH . 'wp-admin/includes/user.php';

	foreach ($cleanup_user_ids as $user_id) {
		if ($user_id > 0) {
			wp_delete_user($user_id);
		}
	}

	foreach ($cleanup_ids as $task_id) {
		if ($task_id > 0) {
			$GLOBALS['wpdb']->delete($tasks->get_task_table_name(), ['id' => $task_id], ['%d']);
			$GLOBALS['wpdb']->delete($tasks->get_event_table_name(), ['task_id' => $task_id], ['%d']);
		}
	}

	freesiem_sentinel_update_settings($original_settings);
}
