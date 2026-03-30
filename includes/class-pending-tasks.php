<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Pending_Tasks
{
	public const TASK_TABLE_SUFFIX = 'freesiem_sentinel_pending_tasks';
	public const EVENT_TABLE_SUFFIX = 'freesiem_sentinel_task_events';
	public const REST_NAMESPACE = 'freesiem-sentinel/v1';
	public const REST_ROUTE = '/cloud/task';
	public const REST_USERS_ROUTE = '/cloud-connect/users';
	public const NONCE_TRANSIENT_PREFIX = 'freesiem_sentinel_task_nonce_';
	public const HEARTBEAT_THROTTLE_TRANSIENT = 'freesiem_sentinel_task_heartbeat_throttle';
	private const REPORTABLE_STATUSES = ['pending', 'approved', 'denied', 'auto_approved', 'executing', 'completed', 'failed', 'canceled', 'expired'];
	private const PASSWORD_KEYS = ['password', 'user_pass', 'pass', 'password_hash', 'hash', 'temporary_password', 'temp_password'];
	private const CREATE_USER_MODE_RESET = 'send_reset_email';
	private const CREATE_USER_MODE_PASSWORD = 'explicit_password';
	private const PROTECTED_PASSWORD_KEY = 'password_protected';
	private const EXECUTION_PASSWORD_KEY = 'execution_password_protected';
	private const REDACTED_SECRET = '[REDACTED]';

	private Freesiem_Plugin $plugin;

	public function __construct(Freesiem_Plugin $plugin)
	{
		$this->plugin = $plugin;
	}

	public function register(): void
	{
		add_action('rest_api_init', [$this, 'register_rest_routes']);
		add_action(Freesiem_Cron::TASK_PROCESS_HOOK, [$this, 'process_due_tasks']);
		add_action(Freesiem_Cron::TASK_HEARTBEAT_HOOK, [$this, 'send_priority_heartbeat']);
	}

	public function install_or_upgrade(): void
	{
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$task_table = $this->get_task_table_name();
		$event_table = $this->get_event_table_name();

		$task_sql = "CREATE TABLE {$task_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			core_task_id varchar(191) NOT NULL,
			source_core_identifier varchar(191) NOT NULL DEFAULT '',
			source_core_url varchar(255) NOT NULL DEFAULT '',
			action_type varchar(64) NOT NULL,
			object_type varchar(64) NOT NULL DEFAULT 'user',
			target_user_id bigint(20) unsigned DEFAULT NULL,
			target_username varchar(191) NOT NULL DEFAULT '',
			target_email varchar(191) NOT NULL DEFAULT '',
			payload_json longtext NOT NULL,
			execution_payload_json longtext DEFAULT NULL,
			payload_hash char(64) NOT NULL,
			status varchar(32) NOT NULL DEFAULT 'pending',
			approval_mode varchar(32) NOT NULL DEFAULT 'manual',
			auto_approve_enabled tinyint(1) NOT NULL DEFAULT 0,
			auto_approve_after_minutes int(11) NOT NULL DEFAULT 30,
			auto_approve_at datetime DEFAULT NULL,
			requested_at datetime DEFAULT NULL,
			approved_at datetime DEFAULT NULL,
			denied_at datetime DEFAULT NULL,
			executed_at datetime DEFAULT NULL,
			completed_at datetime DEFAULT NULL,
			failed_at datetime DEFAULT NULL,
			decided_by_wp_user_id bigint(20) unsigned DEFAULT NULL,
			deny_reason text DEFAULT NULL,
			execution_result_json longtext DEFAULT NULL,
			error_message text DEFAULT NULL,
			signature_verified tinyint(1) NOT NULL DEFAULT 0,
			heartbeat_reported_at datetime DEFAULT NULL,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY core_task_id (core_task_id),
			KEY status (status),
			KEY auto_approve_at (auto_approve_at),
			KEY heartbeat_reported_at (heartbeat_reported_at)
		) {$charset_collate};";

		$event_sql = "CREATE TABLE {$event_table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			task_id bigint(20) unsigned NOT NULL,
			event_type varchar(64) NOT NULL,
			message text NOT NULL,
			actor_wp_user_id bigint(20) unsigned DEFAULT NULL,
			details_json longtext DEFAULT NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY task_id (task_id),
			KEY event_type (event_type)
		) {$charset_collate};";

		dbDelta($task_sql);
		dbDelta($event_sql);
	}

	public function register_rest_routes(): void
	{
		register_rest_route(
			self::REST_NAMESPACE,
			self::REST_ROUTE,
			[
				'methods' => WP_REST_Server::CREATABLE,
				'callback' => [$this, 'handle_submit_task'],
				'permission_callback' => '__return_true',
			]
		);

		register_rest_route(
			self::REST_NAMESPACE,
			self::REST_USERS_ROUTE,
			[
				'methods' => WP_REST_Server::READABLE,
				'callback' => [$this, 'handle_list_users_request'],
				'permission_callback' => '__return_true',
			]
		);
	}

	public function handle_submit_task(WP_REST_Request $request): WP_REST_Response|WP_Error
	{
		$settings = freesiem_sentinel_get_settings();

		if (empty($settings['enable_pending_task_queue'])) {
			return new WP_Error('freesiem_tasks_disabled', __('Pending Tasks are disabled on this site.', 'freesiem-sentinel'), ['status' => 403]);
		}

		if (!Freesiem_Cloud_Connect_State::is_connected($settings)) {
			return new WP_Error('freesiem_cloud_not_connected', __('This site is not connected to freeSIEM Core.', 'freesiem-sentinel'), ['status' => 403]);
		}

		$verification = $this->verify_signed_request($request, $settings);

		if (is_wp_error($verification)) {
			return $verification;
		}

		$payload = json_decode((string) $request->get_body(), true);

		if (!is_array($payload)) {
			return new WP_Error('freesiem_invalid_task_payload', __('freeSIEM Sentinel could not decode the task payload.', 'freesiem-sentinel'), ['status' => 400]);
		}

		$core_task_id = sanitize_text_field((string) ($payload['core_task_id'] ?? $payload['task_id'] ?? ''));
		$action_type = sanitize_key((string) ($payload['action_type'] ?? $payload['type'] ?? ''));

		if ($core_task_id === '' || !$this->is_supported_action($action_type)) {
			return new WP_Error('freesiem_invalid_task', __('The task request is missing a valid task identifier or action type.', 'freesiem-sentinel'), ['status' => 400]);
		}

		$payload = $this->validate_incoming_task_payload($action_type, $payload);

		if (is_wp_error($payload)) {
			return $payload;
		}

		if ($action_type === 'set_temp_password' || !empty($payload['set_temp_password'])) {
			return new WP_Error('freesiem_temp_password_unsupported', __('Temporary password tasks are not enabled on this site.', 'freesiem-sentinel'), ['status' => 400]);
		}

		$existing = $this->get_task_by_core_task_id($core_task_id);

		if (is_array($existing)) {
			$this->insert_event((int) $existing['id'], 'request_received_duplicate', __('Duplicate task submission acknowledged idempotently.', 'freesiem-sentinel'));

			return new WP_REST_Response([
				'accepted' => true,
				'idempotent' => true,
				'core_task_id' => $core_task_id,
				'local_task_id' => (int) $existing['id'],
				'status' => (string) $existing['status'],
				'message' => __('Task already exists and was not duplicated.', 'freesiem-sentinel'),
			], 200);
		}

		$policy = $this->resolve_policy($action_type, $settings);
		$now = current_time('mysql', true);
		$auto_approve_at = $policy['auto_approve_enabled']
			? gmdate('Y-m-d H:i:s', strtotime('+' . (int) $policy['auto_approve_after_minutes'] . ' minutes', strtotime($now . ' UTC')))
			: null;
		$payload_for_storage = $this->prepare_payload_for_storage($payload, $action_type);

		if (is_wp_error($payload_for_storage)) {
			return $payload_for_storage;
		}

		$execution_payload = $this->prepare_execution_payload($payload, $action_type);

		if (is_wp_error($execution_payload)) {
			return $execution_payload;
		}

		$target = $this->derive_target_fields($action_type, $payload_for_storage);

		global $wpdb;

		$inserted = $wpdb->insert(
			$this->get_task_table_name(),
			[
				'core_task_id' => $core_task_id,
				'source_core_identifier' => sanitize_text_field((string) ($payload['source_core_identifier'] ?? $payload['source'] ?? 'freeSIEM Core')),
				'source_core_url' => esc_url_raw((string) ($payload['source_core_url'] ?? '')),
				'action_type' => $action_type,
				'object_type' => 'user',
				'target_user_id' => $target['target_user_id'],
				'target_username' => $target['target_username'],
				'target_email' => $target['target_email'],
				'payload_json' => wp_json_encode($payload_for_storage),
				'execution_payload_json' => wp_json_encode($execution_payload),
				'payload_hash' => hash('sha256', wp_json_encode($payload_for_storage)),
				'status' => 'pending',
				'approval_mode' => $policy['approval_mode'],
				'auto_approve_enabled' => $policy['auto_approve_enabled'] ? 1 : 0,
				'auto_approve_after_minutes' => (int) $policy['auto_approve_after_minutes'],
				'auto_approve_at' => $auto_approve_at,
				'requested_at' => $now,
				'signature_verified' => 1,
				'created_at' => $now,
				'updated_at' => $now,
			],
			[
				'%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%d', '%s', '%s', '%s',
			]
		);

		if (!$inserted) {
			return new WP_Error('freesiem_task_insert_failed', __('freeSIEM Sentinel could not store the pending task.', 'freesiem-sentinel'), ['status' => 500]);
		}

		$task_id = (int) $wpdb->insert_id;
		$this->insert_event($task_id, 'request_received', __('Signed task request received from freeSIEM Core.', 'freesiem-sentinel'));
		$this->insert_event($task_id, 'signature_verified', __('Task request signature verified successfully.', 'freesiem-sentinel'));
		$this->insert_event($task_id, 'task_created', __('Pending task created locally and queued for approval.', 'freesiem-sentinel'), [
			'approval_mode' => $policy['approval_mode'],
			'auto_approve_enabled' => $policy['auto_approve_enabled'],
			'auto_approve_at' => $auto_approve_at,
		]);

		$this->maybe_notify_admins($task_id);
		$this->mark_heartbeat_dirty();

		return new WP_REST_Response([
			'accepted' => true,
			'idempotent' => false,
			'core_task_id' => $core_task_id,
			'local_task_id' => $task_id,
			'status' => 'pending',
			'approval_mode' => $policy['approval_mode'],
			'auto_approve_enabled' => $policy['auto_approve_enabled'],
			'auto_approve_after_minutes' => (int) $policy['auto_approve_after_minutes'],
			'auto_approve_at' => $this->format_mysql_datetime($auto_approve_at),
			'message' => __('Task received and queued for local approval.', 'freesiem-sentinel'),
		], 202);
	}

	public function handle_list_users_request(WP_REST_Request $request): WP_REST_Response|WP_Error
	{
		$settings = freesiem_sentinel_get_settings();

		if (!Freesiem_Cloud_Connect_State::is_connected($settings)) {
			return new WP_Error('freesiem_cloud_not_connected', __('This site is not connected to freeSIEM Core.', 'freesiem-sentinel'), ['status' => 403]);
		}

		$verification = $this->verify_signed_request($request, $settings);

		if (is_wp_error($verification)) {
			return $verification;
		}

		$role = sanitize_key((string) $request->get_param('role'));
		$users = $this->get_safe_user_list($role);

		return new WP_REST_Response([
			'users' => $users,
		], 200);
	}

	public function verify_signed_request(WP_REST_Request $request, array $settings): bool|WP_Error
	{
		$site_id = sanitize_text_field((string) $request->get_header('x-freesiem-site-id'));
		$api_key = sanitize_text_field((string) $request->get_header('x-freesiem-api-key'));
		$timestamp = sanitize_text_field((string) $request->get_header('x-freesiem-timestamp'));
		$nonce = sanitize_text_field((string) $request->get_header('x-freesiem-nonce'));
		$signature = sanitize_text_field((string) $request->get_header('x-freesiem-signature'));

		if ($site_id === '' || $api_key === '' || $timestamp === '' || $nonce === '' || $signature === '') {
			return new WP_Error('freesiem_missing_signature_headers', __('The task request is missing required signature headers.', 'freesiem-sentinel'), ['status' => 401]);
		}

		if (!hash_equals((string) ($settings['site_id'] ?? ''), $site_id) || !hash_equals((string) ($settings['api_key'] ?? ''), $api_key)) {
			return new WP_Error('freesiem_untrusted_core', __('The task request did not match the trusted freeSIEM Core credentials.', 'freesiem-sentinel'), ['status' => 403]);
		}

		if (!$this->is_recent_timestamp($timestamp)) {
			return new WP_Error('freesiem_task_request_expired', __('The signed task request timestamp is outside the accepted window.', 'freesiem-sentinel'), ['status' => 401]);
		}

		$nonce_key = self::NONCE_TRANSIENT_PREFIX . md5($site_id . '|' . $nonce);

		if (get_transient($nonce_key)) {
			return new WP_Error('freesiem_task_request_replayed', __('The signed task request nonce has already been used.', 'freesiem-sentinel'), ['status' => 409]);
		}

		$body = (string) $request->get_body();
		$canonical = implode("\n", [
			strtoupper((string) $request->get_method()),
			(string) $request->get_route(),
			hash('sha256', $body),
			$timestamp,
			$nonce,
		]);
		$expected = hash_hmac('sha256', $canonical, (string) ($settings['hmac_secret'] ?? ''));

		if (!hash_equals($expected, $signature)) {
			return new WP_Error('freesiem_invalid_task_signature', __('freeSIEM Sentinel rejected the task request signature.', 'freesiem-sentinel'), ['status' => 401]);
		}

		set_transient($nonce_key, '1', 10 * MINUTE_IN_SECONDS);

		return true;
	}

	public function process_due_tasks(): void
	{
		$this->process_auto_approvals();
		$this->process_ready_executions();
	}

	public function maybe_process_due_tasks_fallback(): void
	{
		$due = $this->get_due_task_count();

		if ($due > 0) {
			$this->process_due_tasks();
		}

		$this->schedule_priority_heartbeat();
	}

	public function get_due_task_count(): int
	{
		global $wpdb;

		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$this->get_task_table_name()} WHERE (status = %s AND auto_approve_enabled = 1 AND auto_approve_at IS NOT NULL AND auto_approve_at <= %s) OR status IN (%s, %s)",
				'pending',
				current_time('mysql', true),
				'approved',
				'auto_approved'
			)
		);

		return max(0, (int) $count);
	}

	public function process_auto_approvals(): void
	{
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id FROM {$this->get_task_table_name()} WHERE status = %s AND auto_approve_enabled = 1 AND auto_approve_at IS NOT NULL AND auto_approve_at <= %s ORDER BY requested_at ASC LIMIT 25",
				'pending',
				current_time('mysql', true)
			),
			ARRAY_A
		);

		foreach ($rows as $row) {
			$this->auto_approve_task((int) ($row['id'] ?? 0));
		}
	}

	public function process_ready_executions(): void
	{
		global $wpdb;

		$rows = $wpdb->get_results(
			"SELECT id FROM {$this->get_task_table_name()} WHERE status IN ('approved', 'auto_approved') ORDER BY updated_at ASC LIMIT 25",
			ARRAY_A
		);

		foreach ($rows as $row) {
			$this->execute_task((int) ($row['id'] ?? 0));
		}
	}

	public function approve_task(int $task_id, int $wp_user_id): bool|WP_Error
	{
		$task = $this->get_task($task_id);

		if (!is_array($task)) {
			return new WP_Error('freesiem_task_not_found', __('The requested task could not be found.', 'freesiem-sentinel'));
		}

		if ((string) $task['status'] !== 'pending') {
			return new WP_Error('freesiem_task_not_pending', __('Only pending tasks can be approved.', 'freesiem-sentinel'));
		}

		$updated = $this->conditional_transition_task($task_id, ['pending'], 'approved', [
			'approved_at' => current_time('mysql', true),
			'decided_by_wp_user_id' => $wp_user_id,
			'deny_reason' => null,
		]);

		if (!$updated) {
			return new WP_Error('freesiem_task_approve_failed', __('freeSIEM Sentinel could not approve the task.', 'freesiem-sentinel'));
		}

		$this->insert_event($task_id, 'task_approved', __('Task approved by a local WordPress user.', 'freesiem-sentinel'), [], $wp_user_id);
		$this->mark_heartbeat_dirty(true);

		return $this->execute_task($task_id);
	}

	public function deny_task(int $task_id, int $wp_user_id, string $reason = ''): bool|WP_Error
	{
		$task = $this->get_task($task_id);

		if (!is_array($task)) {
			return new WP_Error('freesiem_task_not_found', __('The requested task could not be found.', 'freesiem-sentinel'));
		}

		if ((string) $task['status'] !== 'pending') {
			return new WP_Error('freesiem_task_not_pending', __('Only pending tasks can be denied.', 'freesiem-sentinel'));
		}

		$updated = $this->conditional_transition_task($task_id, ['pending'], 'denied', [
			'denied_at' => current_time('mysql', true),
			'decided_by_wp_user_id' => $wp_user_id,
			'deny_reason' => sanitize_textarea_field($reason),
		]);

		if (!$updated) {
			return new WP_Error('freesiem_task_deny_failed', __('freeSIEM Sentinel could not deny the task.', 'freesiem-sentinel'));
		}

		$this->insert_event($task_id, 'task_denied', __('Task denied by a local WordPress user.', 'freesiem-sentinel'), ['deny_reason' => sanitize_textarea_field($reason)], $wp_user_id);
		$this->mark_heartbeat_dirty(true);

		return true;
	}

	public function auto_approve_task(int $task_id): bool
	{
		$task = $this->get_task($task_id);

		if (!is_array($task) || (string) $task['status'] !== 'pending') {
			return false;
		}

		$updated = $this->conditional_transition_task($task_id, ['pending'], 'auto_approved', [
			'approved_at' => current_time('mysql', true),
		]);

		if (!$updated) {
			return false;
		}

		$this->insert_event($task_id, 'task_auto_approved', __('Task was auto-approved after the configured timeout.', 'freesiem-sentinel'));
		$this->mark_heartbeat_dirty(true);
		$this->execute_task($task_id);

		return true;
	}

	public function execute_task(int $task_id): bool|WP_Error
	{
		$task = $this->get_task($task_id);

		if (!is_array($task)) {
			return new WP_Error('freesiem_task_not_found', __('The requested task could not be found.', 'freesiem-sentinel'));
		}

		if (!in_array((string) $task['status'], ['approved', 'auto_approved'], true)) {
			return true;
		}

		if (!$this->conditional_transition_task($task_id, ['approved', 'auto_approved'], 'executing')) {
			return new WP_Error('freesiem_task_execute_locked', __('freeSIEM Sentinel could not reserve the task for execution.', 'freesiem-sentinel'));
		}

		$this->insert_event($task_id, 'execution_started', __('Task execution started locally in WordPress.', 'freesiem-sentinel'));
		$this->mark_heartbeat_dirty(true);

		$payload = $this->get_execution_payload($task);

		if (is_wp_error($payload)) {
			$this->transition_task($task_id, 'failed', [
				'executed_at' => current_time('mysql', true),
				'failed_at' => current_time('mysql', true),
				'error_message' => sanitize_text_field($payload->get_error_message()),
				'execution_result_json' => wp_json_encode([]),
			]);
			$this->insert_event($task_id, 'execution_failed', __('Task execution failed locally.', 'freesiem-sentinel'), ['error' => sanitize_text_field($payload->get_error_message())]);
			$this->mark_heartbeat_dirty(true);

			return $payload;
		}

		$result = $this->run_local_action((string) $task['action_type'], is_array($payload) ? $payload : []);
		$now = current_time('mysql', true);

		if (is_wp_error($result)) {
			$this->transition_task($task_id, 'failed', [
				'executed_at' => $now,
				'failed_at' => $now,
				'error_message' => sanitize_text_field($result->get_error_message()),
				'execution_result_json' => wp_json_encode([]),
			]);
			$this->insert_event($task_id, 'execution_failed', __('Task execution failed locally.', 'freesiem-sentinel'), ['error' => sanitize_text_field($result->get_error_message())]);
			$this->mark_heartbeat_dirty(true);

			return $result;
		}

		$this->transition_task($task_id, 'completed', [
			'executed_at' => $now,
			'completed_at' => $now,
			'execution_result_json' => wp_json_encode($this->sanitize_execution_result($result)),
			'execution_payload_json' => null,
			'error_message' => null,
		]);
		$this->insert_event($task_id, 'execution_completed', __('Task execution completed successfully.', 'freesiem-sentinel'));
		$this->mark_heartbeat_dirty(true);

		return true;
	}

	public function build_heartbeat_payload(array $settings): array
	{
		$include_pending = !empty($settings['include_pending_tasks_in_heartbeat']);
		$include_recent = !empty($settings['heartbeat_include_recent_completed_tasks']);
		$pending = $include_pending ? $this->get_pending_tasks_for_heartbeat() : [];
		$recent = $include_recent ? $this->get_recent_task_updates_for_heartbeat() : [];
		$summary = $this->get_task_status_summary();
		$pending_summary = $this->get_pending_task_summary();
		$last_task_activity_at = (string) ($settings['last_task_activity_at'] ?? '');

		return [
			'supports_remote_user_admin' => true,
			'supports_remote_user_listing' => true,
			'supports_remote_tfa_management' => true,
			'supports_local_tfa_enforcement' => true,
			'supports_pending_tasks' => true,
			'supports_task_status_heartbeat' => true,
			'supports_auto_approve' => true,
			'supports_delete_user_task' => true,
			'supports_password_reset_task' => true,
			'pending_task_summary' => $pending_summary,
			'task_status_summary' => $summary,
			'pending_tasks' => $pending,
			'recent_task_updates' => $recent,
			'last_task_activity_at' => $last_task_activity_at,
		];
	}

	public function mark_heartbeat_payload_reported(array $heartbeat_payload): void
	{
		$ids = [];

		foreach ((array) ($heartbeat_payload['pending_tasks'] ?? []) as $task) {
			$ids[] = (int) ($task['local_task_id'] ?? 0);
		}

		foreach ((array) ($heartbeat_payload['recent_task_updates'] ?? []) as $task) {
			$ids[] = (int) ($task['local_task_id'] ?? 0);
		}

		$ids = array_values(array_unique(array_filter($ids)));

		if ($ids !== []) {
			global $wpdb;

			$placeholders = implode(',', array_fill(0, count($ids), '%d'));
			$params = array_merge([current_time('mysql', true)], $ids);
			$query = $wpdb->prepare(
				"UPDATE {$this->get_task_table_name()} SET heartbeat_reported_at = %s WHERE id IN ({$placeholders})",
				$params
			);

			if (is_string($query)) {
				$wpdb->query($query);
			}

			foreach ($ids as $task_id) {
				$this->insert_event($task_id, 'heartbeat_reported', __('Task status reported in a heartbeat payload.', 'freesiem-sentinel'));
			}
		}

		freesiem_sentinel_update_settings([
			'pending_tasks_heartbeat_dirty' => 0,
		]);
	}

	public function mark_heartbeat_dirty(bool $send_immediately = false): void
	{
		freesiem_sentinel_update_settings([
			'pending_tasks_heartbeat_dirty' => 1,
			'last_task_activity_at' => freesiem_sentinel_get_iso8601_time(),
		]);

		if ($send_immediately) {
			$this->plugin->send_priority_heartbeat();
		}

		$this->schedule_priority_heartbeat();
	}

	public function schedule_priority_heartbeat(): void
	{
		if (!empty(get_transient(self::HEARTBEAT_THROTTLE_TRANSIENT))) {
			return;
		}

		if (!wp_next_scheduled(Freesiem_Cron::TASK_HEARTBEAT_HOOK)) {
			wp_schedule_single_event(time() + MINUTE_IN_SECONDS, Freesiem_Cron::TASK_HEARTBEAT_HOOK);
		}
	}

	public function send_priority_heartbeat(): void
	{
		set_transient(self::HEARTBEAT_THROTTLE_TRANSIENT, '1', MINUTE_IN_SECONDS);
		$this->plugin->send_priority_heartbeat();
	}

	public function get_task(int $task_id): ?array
	{
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare("SELECT * FROM {$this->get_task_table_name()} WHERE id = %d", $task_id),
			ARRAY_A
		);

		return is_array($row) ? $this->normalize_task($row) : null;
	}

	public function get_task_by_core_task_id(string $core_task_id): ?array
	{
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare("SELECT * FROM {$this->get_task_table_name()} WHERE core_task_id = %s", $core_task_id),
			ARRAY_A
		);

		return is_array($row) ? $this->normalize_task($row) : null;
	}

	public function get_task_events(int $task_id): array
	{
		global $wpdb;

		$rows = $wpdb->get_results(
			$wpdb->prepare("SELECT * FROM {$this->get_event_table_name()} WHERE task_id = %d ORDER BY created_at ASC, id ASC", $task_id),
			ARRAY_A
		);

		return is_array($rows) ? $rows : [];
	}

	public function list_tasks(array $filters = []): array
	{
		global $wpdb;

		$where = ['1=1'];
		$params = [];

		if (!empty($filters['status'])) {
			$where[] = 'status = %s';
			$params[] = sanitize_key((string) $filters['status']);
		}

		if (!empty($filters['search'])) {
			$search = '%' . $wpdb->esc_like((string) $filters['search']) . '%';
			$where[] = '(core_task_id LIKE %s OR target_username LIKE %s OR target_email LIKE %s)';
			$params[] = $search;
			$params[] = $search;
			$params[] = $search;
		}

		$limit = max(1, min(100, (int) ($filters['limit'] ?? 50)));
		$sql = "SELECT * FROM {$this->get_task_table_name()} WHERE " . implode(' AND ', $where) . ' ORDER BY created_at DESC LIMIT ' . $limit;

		if ($params !== []) {
			$sql = $wpdb->prepare($sql, $params);
		}

		$rows = $wpdb->get_results($sql, ARRAY_A);

		return array_map([$this, 'normalize_task'], is_array($rows) ? $rows : []);
	}

	public function current_user_can_approve_tasks(): bool
	{
		if (current_user_can('manage_options')) {
			return true;
		}

		$settings = freesiem_sentinel_get_settings();
		$allowed_roles = is_array($settings['roles_allowed_to_approve_tasks'] ?? null) ? $settings['roles_allowed_to_approve_tasks'] : [];
		$user = wp_get_current_user();

		if (!$user instanceof WP_User || $allowed_roles === []) {
			return false;
		}

		return array_intersect($allowed_roles, $user->roles) !== [];
	}

	public function get_task_table_name(): string
	{
		global $wpdb;

		return $wpdb->prefix . self::TASK_TABLE_SUFFIX;
	}

	public function get_event_table_name(): string
	{
		global $wpdb;

		return $wpdb->prefix . self::EVENT_TABLE_SUFFIX;
	}

	public function get_status_options(): array
	{
		return self::REPORTABLE_STATUSES;
	}

	private function resolve_policy(string $action_type, array $settings): array
	{
		$default_minutes = max(1, (int) ($settings['auto_approve_after_minutes_default'] ?? 30));
		$manual_flag = match ($action_type) {
			'list_users' => !empty($settings['require_manual_approval_for_list_users']),
			'create_user' => !empty($settings['require_manual_approval_for_create_user']),
			'update_user' => !empty($settings['require_manual_approval_for_update_user']),
			'send_password_reset' => !empty($settings['require_manual_approval_for_password_reset']),
			'delete_user' => !empty($settings['require_manual_approval_for_delete_user']),
			default => true,
		};
		$auto_allowed = match ($action_type) {
			'list_users' => !empty($settings['allow_auto_approve_list_users']),
			'create_user' => !empty($settings['allow_auto_approve_create_user']),
			'update_user' => !empty($settings['allow_auto_approve_update_user']),
			'send_password_reset' => !empty($settings['allow_auto_approve_password_reset']),
			'delete_user' => !empty($settings['allow_auto_approve_delete_user']),
			default => false,
		};
		$auto_enabled = !empty($settings['auto_approve_enabled_default']) && $auto_allowed;

		return [
			'approval_mode' => $auto_enabled ? 'manual_or_auto' : 'manual',
			'auto_approve_enabled' => $auto_enabled,
			'auto_approve_after_minutes' => $manual_flag ? $default_minutes : $default_minutes,
		];
	}

	private function is_supported_action(string $action_type): bool
	{
		return in_array($action_type, ['list_users', 'create_user', 'update_user', 'send_password_reset', 'delete_user'], true);
	}

	private function payload_contains_restricted_secret(array $payload): bool
	{
		foreach ($payload as $key => $value) {
			$key = sanitize_key((string) $key);

			if (in_array($key, self::PASSWORD_KEYS, true)) {
				return true;
			}

			if (is_array($value) && $this->payload_contains_restricted_secret($value)) {
				return true;
			}
		}

		return false;
	}

	private function validate_incoming_task_payload(string $action_type, array $payload): array|WP_Error
	{
		if ($action_type === 'create_user') {
			return $this->validate_create_user_payload($payload);
		}

		if ($this->payload_contains_restricted_secret($payload)) {
			return new WP_Error('freesiem_password_payload_rejected', __('Task payloads must not include raw passwords or password hashes.', 'freesiem-sentinel'), ['status' => 400]);
		}

		return $payload;
	}

	private function validate_create_user_payload(array $payload): array|WP_Error
	{
		if ($this->payload_contains_restricted_secret_except_create_user_password($payload)) {
			return new WP_Error('freesiem_password_payload_rejected', __('Create user tasks may only include a password when using explicit password provisioning.', 'freesiem-sentinel'), ['status' => 400]);
		}

		$mode = $this->resolve_create_user_mode($payload);

		if (!in_array($mode, [self::CREATE_USER_MODE_RESET, self::CREATE_USER_MODE_PASSWORD], true)) {
			return new WP_Error('freesiem_create_user_mode_invalid', __('Create user tasks must use a supported provisioning mode.', 'freesiem-sentinel'), ['status' => 400]);
		}

		$password = $this->extract_create_user_password($payload);

		if ($mode === self::CREATE_USER_MODE_PASSWORD && $password === '') {
			return new WP_Error('freesiem_create_user_password_required', __('Explicit password provisioning requires a non-empty password.', 'freesiem-sentinel'), ['status' => 400]);
		}

		if ($mode === self::CREATE_USER_MODE_RESET && $password !== '') {
			return new WP_Error('freesiem_create_user_password_unexpected', __('Reset-email provisioning must not include a raw password.', 'freesiem-sentinel'), ['status' => 400]);
		}

		return $payload;
	}

	private function payload_contains_restricted_secret_except_create_user_password(array $payload): bool
	{
		foreach ($payload as $key => $value) {
			$key = sanitize_key((string) $key);

			if (in_array($key, self::PASSWORD_KEYS, true)) {
				return !in_array($key, ['password', 'user_pass', 'pass'], true);
			}

			if (is_array($value) && $this->payload_contains_restricted_secret_except_create_user_password($value)) {
				return true;
			}
		}

		return false;
	}

	private function prepare_payload_for_storage(array $payload, string $action_type): array|WP_Error
	{
		$sanitized = $this->sanitize_payload_for_storage($payload);

		if ($action_type !== 'create_user') {
			return $sanitized;
		}

		$mode = $this->resolve_create_user_mode($payload);
		$password = $this->extract_create_user_password($payload);
		$target_key = is_array($payload['target'] ?? null) ? 'target' : '';

		if ($target_key !== '' && (!isset($sanitized[$target_key]) || !is_array($sanitized[$target_key]))) {
			$sanitized[$target_key] = [];
		}

		if ($target_key !== '') {
			$sanitized[$target_key]['provisioning_mode'] = $mode;
		} else {
			$sanitized['provisioning_mode'] = $mode;
		}

		if ($mode === self::CREATE_USER_MODE_PASSWORD) {
			if ($target_key !== '') {
				$sanitized[$target_key]['password'] = self::REDACTED_SECRET;
			} else {
				$sanitized['password'] = self::REDACTED_SECRET;
			}
		}

		return $sanitized;
	}

	private function prepare_execution_payload(array $payload, string $action_type): array|WP_Error
	{
		if ($action_type !== 'create_user') {
			return $payload;
		}

		$execution_payload = $payload;
		$mode = $this->resolve_create_user_mode($payload);
		$password = $this->extract_create_user_password($payload);
		$target_key = is_array($execution_payload['target'] ?? null) ? 'target' : '';

		if ($mode !== self::CREATE_USER_MODE_PASSWORD) {
			return $this->strip_password_keys($execution_payload);
		}

		if ($password === '') {
			return new WP_Error('freesiem_create_user_password_required', __('Explicit password provisioning requires a non-empty password.', 'freesiem-sentinel'));
		}

		$this->log_password_fingerprint('create_user intake', $password);
		$protected_password = $this->protect_secret($password);

		if (is_wp_error($protected_password)) {
			return $protected_password;
		}

		$execution_payload = $this->strip_password_keys($execution_payload);

		if ($target_key !== '') {
			$execution_payload[$target_key][self::EXECUTION_PASSWORD_KEY] = $protected_password;
		} else {
			$execution_payload[self::EXECUTION_PASSWORD_KEY] = $protected_password;
		}

		return $execution_payload;
	}

	private function sanitize_payload_for_storage(array $payload): array
	{
		$sanitized = [];

		foreach ($payload as $key => $value) {
			$key = sanitize_key((string) $key);

			if ($key === '') {
				continue;
			}

			if (in_array($key, self::PASSWORD_KEYS, true) || $key === self::PROTECTED_PASSWORD_KEY) {
				continue;
			}

			if (is_array($value)) {
				$sanitized[$key] = $this->sanitize_payload_for_storage($value);
				continue;
			}

			if (is_bool($value)) {
				$sanitized[$key] = $value;
				continue;
			}

			if (is_numeric($value)) {
				$sanitized[$key] = 0 + $value;
				continue;
			}

			$sanitized[$key] = sanitize_text_field((string) $value);
		}

		return $sanitized;
	}

	private function sanitize_payload_for_output(array $payload): array
	{
		$sanitized = [];

		foreach ($payload as $key => $value) {
			$key = sanitize_key((string) $key);

			if ($key === '' || $key === self::PROTECTED_PASSWORD_KEY || $key === self::EXECUTION_PASSWORD_KEY) {
				continue;
			}

			if (in_array($key, self::PASSWORD_KEYS, true)) {
				$sanitized[$key] = self::REDACTED_SECRET;
				continue;
			}

			if (is_array($value)) {
				$sanitized[$key] = $this->sanitize_payload_for_output($value);
				continue;
			}

			if (is_bool($value)) {
				$sanitized[$key] = $value;
				continue;
			}

			if (is_numeric($value)) {
				$sanitized[$key] = 0 + $value;
				continue;
			}

			$sanitized[$key] = sanitize_text_field((string) $value);
		}

		return $sanitized;
	}

	private function derive_target_fields(string $action_type, array $payload): array
	{
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : $payload;

		return [
			'target_user_id' => !empty($target['user_id']) ? (int) $target['user_id'] : null,
			'target_username' => sanitize_user((string) ($target['username'] ?? $target['user_login'] ?? '')),
			'target_email' => sanitize_email((string) ($target['email'] ?? $target['user_email'] ?? '')),
			'action_type' => $action_type,
		];
	}

	private function transition_task(int $task_id, string $new_status, array $updates = []): bool
	{
		global $wpdb;

		$data = array_merge(
			[
				'status' => $new_status,
				'updated_at' => current_time('mysql', true),
				'heartbeat_reported_at' => null,
			],
			$updates
		);
		$formats = [];

		foreach ($data as $key => $value) {
			$formats[] = is_int($value) ? '%d' : '%s';
		}

		return false !== $wpdb->update(
			$this->get_task_table_name(),
			$data,
			['id' => $task_id],
			$formats,
			['%d']
		);
	}

	private function conditional_transition_task(int $task_id, array $from_statuses, string $new_status, array $updates = []): bool
	{
		global $wpdb;

		$from_statuses = array_values(array_filter(array_map('sanitize_key', $from_statuses)));

		if ($from_statuses === []) {
			return false;
		}

		$data = array_merge(
			[
				'status' => $new_status,
				'updated_at' => current_time('mysql', true),
				'heartbeat_reported_at' => null,
			],
			$updates
		);
		$set_clauses = [];
		$params = [];

		foreach ($data as $column => $value) {
			$set_clauses[] = "{$column} = %s";
			$params[] = is_scalar($value) || $value === null ? (string) $value : wp_json_encode($value);
		}

		$status_placeholders = implode(',', array_fill(0, count($from_statuses), '%s'));
		$params[] = $task_id;
		$params = array_merge($params, $from_statuses);
		$query = $wpdb->prepare(
			"UPDATE {$this->get_task_table_name()} SET " . implode(', ', $set_clauses) . " WHERE id = %d AND status IN ({$status_placeholders})",
			$params
		);

		if (!is_string($query)) {
			return false;
		}

		return $wpdb->query($query) === 1;
	}

	private function insert_event(int $task_id, string $event_type, string $message, array $details = [], int $actor_wp_user_id = 0): void
	{
		global $wpdb;

		$wpdb->insert(
			$this->get_event_table_name(),
			[
				'task_id' => $task_id,
				'event_type' => sanitize_key($event_type),
				'message' => sanitize_text_field($message),
				'actor_wp_user_id' => $actor_wp_user_id > 0 ? $actor_wp_user_id : null,
				'details_json' => $details !== [] ? wp_json_encode($this->sanitize_payload_for_storage($details)) : null,
				'created_at' => current_time('mysql', true),
			],
			['%d', '%s', '%s', '%d', '%s', '%s']
		);
	}

	private function run_local_action(string $action_type, array $payload): array|WP_Error
	{
		return match ($action_type) {
			'list_users' => $this->execute_list_users($payload),
			'create_user' => $this->execute_create_user($payload),
			'update_user' => $this->execute_update_user($payload),
			'send_password_reset' => $this->execute_send_password_reset($payload),
			'delete_user' => $this->execute_delete_user($payload),
			default => new WP_Error('freesiem_task_action_unsupported', __('This task action is not supported.', 'freesiem-sentinel')),
		};
	}

	private function execute_list_users(array $payload): array
	{
		$items = $this->get_safe_user_list(!empty($payload['role']) ? (string) $payload['role'] : '');

		return [
			'user_count' => count($items),
			'users' => $items,
		];
	}

	private function get_safe_user_list(string $role = ''): array
	{
		$args = [];

		if ($role !== '') {
			$args['role'] = sanitize_key($role);
		}

		$users = get_users($args);
		$items = [];

		foreach ($users as $user) {
			if (!$user instanceof WP_User) {
				continue;
			}

			$items[] = [
				'id' => (int) $user->ID,
				'username' => (string) $user->user_login,
				'email' => $user->user_email !== '' ? (string) $user->user_email : null,
				'display_name' => $user->display_name !== '' ? (string) $user->display_name : null,
				'roles' => array_values(array_map('sanitize_key', is_array($user->roles) ? $user->roles : [])),
			];
		}

		return $items;
	}

	private function execute_create_user(array $payload): array|WP_Error
	{
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : $payload;
		$user_login = sanitize_user((string) ($target['username'] ?? $target['user_login'] ?? ''), true);
		$user_email = sanitize_email((string) ($target['email'] ?? $target['user_email'] ?? ''));
		$role = sanitize_key((string) ($target['role'] ?? get_option('default_role', 'subscriber')));
		$mode = $this->resolve_create_user_mode($payload);

		if ($user_login === '' || $user_email === '') {
			return new WP_Error('freesiem_create_user_invalid', __('Create user tasks require both a username and email address.', 'freesiem-sentinel'));
		}

		$password = $mode === self::CREATE_USER_MODE_PASSWORD
			? $this->extract_password_for_execution($payload)
			: wp_generate_password(24, true, true);

		if (is_wp_error($password)) {
			return $password;
		}

		if ($mode === self::CREATE_USER_MODE_PASSWORD) {
			$this->log_password_fingerprint('create_user wp_insert_user', $password);
		}

		$user_id = wp_insert_user([
			'user_login' => $user_login,
			'user_email' => $user_email,
			'first_name' => sanitize_text_field((string) ($target['first_name'] ?? '')),
			'last_name' => sanitize_text_field((string) ($target['last_name'] ?? '')),
			'display_name' => sanitize_text_field((string) ($target['display_name'] ?? $user_login)),
			'role' => $role !== '' ? $role : get_option('default_role', 'subscriber'),
			'user_pass' => $password,
		]);

		if (is_wp_error($user_id)) {
			return $user_id;
		}

		$password_reset_sent = false;
		$password_verified = false;

		if ($mode === self::CREATE_USER_MODE_RESET) {
			$password_reset_sent = (bool) retrieve_password($user_login);
		} else {
			wp_set_password($password, (int) $user_id);
			$verified_user = get_user_by('id', (int) $user_id);
			$password_hash = $verified_user instanceof WP_User ? (string) ($verified_user->data->user_pass ?? '') : '';
			$password_verified = $password_hash !== '' && wp_check_password($password, $password_hash, (int) $user_id);
			error_log('[freeSIEM] create_user wp_set_password verified=' . ($password_verified ? 'yes' : 'no') . ' user_id=' . (int) $user_id);

			if (!$password_verified) {
				return new WP_Error('freesiem_create_user_password_verify_failed', __('WordPress did not persist the requested explicit password as expected.', 'freesiem-sentinel'));
			}
		}

		return [
			'user_id' => (int) $user_id,
			'username' => $user_login,
			'email' => $user_email,
			'role' => $role,
			'provisioning_mode' => $mode,
			'password_reset_sent' => $password_reset_sent,
			'local_password_set' => $mode === self::CREATE_USER_MODE_PASSWORD,
			'password_verified' => $password_verified,
		];
	}

	private function execute_update_user(array $payload): array|WP_Error
	{
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : $payload;
		$user = $this->find_target_user($target);

		if (!$user instanceof WP_User) {
			return new WP_Error('freesiem_update_user_not_found', __('The target user could not be found for this update.', 'freesiem-sentinel'));
		}

		$updates = ['ID' => (int) $user->ID];
		$allowed_fields = ['first_name', 'last_name', 'display_name', 'nickname', 'user_email'];

		foreach ($allowed_fields as $field) {
			if (!array_key_exists($field, $target)) {
				continue;
			}

			$updates[$field] = $field === 'user_email'
				? sanitize_email((string) $target[$field])
				: sanitize_text_field((string) $target[$field]);
		}

		if (count($updates) > 1) {
			$result = wp_update_user($updates);

			if (is_wp_error($result)) {
				return $result;
			}
		}

		if (!empty($target['role'])) {
			$user->set_role(sanitize_key((string) $target['role']));
		}

		$refreshed = get_user_by('id', (int) $user->ID);

		return [
			'user_id' => (int) $user->ID,
			'username' => (string) $user->user_login,
			'email' => $refreshed instanceof WP_User ? (string) $refreshed->user_email : (string) $user->user_email,
			'display_name' => $refreshed instanceof WP_User ? (string) $refreshed->display_name : (string) $user->display_name,
			'roles' => $refreshed instanceof WP_User ? array_values($refreshed->roles) : array_values($user->roles),
		];
	}

	private function execute_send_password_reset(array $payload): array|WP_Error
	{
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : $payload;
		$user = $this->find_target_user($target);

		if (!$user instanceof WP_User) {
			return new WP_Error('freesiem_reset_user_not_found', __('The target user could not be found for password reset.', 'freesiem-sentinel'));
		}

		$sent = retrieve_password((string) $user->user_login);

		if (!$sent) {
			return new WP_Error('freesiem_reset_send_failed', __('WordPress could not start the password reset flow.', 'freesiem-sentinel'));
		}

		return [
			'user_id' => (int) $user->ID,
			'username' => (string) $user->user_login,
			'email' => (string) $user->user_email,
			'password_reset_sent' => true,
		];
	}

	private function execute_delete_user(array $payload): array|WP_Error
	{
		if (!function_exists('wp_delete_user')) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
		}

		$target = is_array($payload['target'] ?? null) ? $payload['target'] : $payload;
		$user = $this->find_target_user($target);

		if (!$user instanceof WP_User) {
			return new WP_Error('freesiem_delete_user_not_found', __('The target user could not be found for deletion.', 'freesiem-sentinel'));
		}

		$reassign = !empty($payload['reassign_to_user_id']) ? (int) $payload['reassign_to_user_id'] : null;
		$deleted = wp_delete_user((int) $user->ID, $reassign);

		if (!$deleted) {
			return new WP_Error('freesiem_delete_user_failed', __('WordPress did not delete the requested user.', 'freesiem-sentinel'));
		}

		return [
			'user_id' => (int) $user->ID,
			'username' => (string) $user->user_login,
			'deleted' => true,
			'reassigned_to_user_id' => $reassign,
		];
	}

	private function find_target_user(array $target): ?WP_User
	{
		$user_id = !empty($target['user_id']) ? (int) $target['user_id'] : 0;

		if ($user_id > 0) {
			$user = get_user_by('id', $user_id);

			if ($user instanceof WP_User) {
				return $user;
			}
		}

		$username = sanitize_user((string) ($target['username'] ?? $target['user_login'] ?? ''));

		if ($username !== '') {
			$user = get_user_by('login', $username);

			if ($user instanceof WP_User) {
				return $user;
			}
		}

		$email = sanitize_email((string) ($target['email'] ?? $target['user_email'] ?? ''));

		if ($email !== '') {
			$user = get_user_by('email', $email);

			if ($user instanceof WP_User) {
				return $user;
			}
		}

		return null;
	}

	private function sanitize_execution_result(array $result): array
	{
		return $this->sanitize_payload_for_storage($result);
	}

	private function get_pending_tasks_for_heartbeat(): array
	{
		global $wpdb;

		$rows = $wpdb->get_results(
			"SELECT * FROM {$this->get_task_table_name()} WHERE status IN ('pending', 'approved', 'auto_approved', 'executing') ORDER BY requested_at ASC LIMIT 25",
			ARRAY_A
		);

		$items = [];

		foreach ((array) $rows as $row) {
			$task = $this->normalize_task($row);
			$items[] = [
				'core_task_id' => (string) $task['core_task_id'],
				'local_task_id' => (int) $task['id'],
				'action_type' => (string) $task['action_type'],
				'status' => (string) $task['status'],
				'target_summary' => $this->get_target_summary($task),
				'requested_at' => $task['requested_at'],
				'auto_approve_enabled' => !empty($task['auto_approve_enabled']),
				'auto_approve_at' => $task['auto_approve_at'],
				'last_updated_at' => $task['updated_at'],
			];
		}

		return $items;
	}

	private function get_recent_task_updates_for_heartbeat(): array
	{
		global $wpdb;

		$rows = $wpdb->get_results(
			"SELECT * FROM {$this->get_task_table_name()} WHERE status IN ('pending', 'approved', 'denied', 'auto_approved', 'executing', 'completed', 'failed', 'canceled', 'expired') AND (heartbeat_reported_at IS NULL OR heartbeat_reported_at < updated_at) ORDER BY updated_at DESC LIMIT 25",
			ARRAY_A
		);

		$items = [];

		foreach ((array) $rows as $row) {
			$task = $this->normalize_task($row);
			$items[] = [
				'core_task_id' => (string) $task['core_task_id'],
				'local_task_id' => (int) $task['id'],
				'action_type' => (string) $task['action_type'],
				'status' => (string) $task['status'],
				'target_summary' => $this->get_target_summary($task),
				'decided_by' => $this->get_decided_by_label((int) ($task['decided_by_wp_user_id'] ?? 0)),
				'deny_reason' => sanitize_text_field((string) ($task['deny_reason'] ?? '')),
				'execution_result_summary' => $this->summarize_execution_result($task),
				'error_message' => sanitize_text_field((string) ($task['error_message'] ?? '')),
				'updated_at' => $task['updated_at'],
				'completed_at' => $task['completed_at'],
				'failed_at' => $task['failed_at'],
			];
		}

		return $items;
	}

	private function get_pending_task_summary(): array
	{
		global $wpdb;

		$summary = [
			'total_pending' => 0,
			'total_approved_waiting_execution' => 0,
			'total_denied_unreported' => 0,
			'total_completed_unreported' => 0,
			'total_failed_unreported' => 0,
			'total_auto_approved' => 0,
			'oldest_pending_at' => '',
			'next_auto_approve_at' => '',
		];

		$counts = $wpdb->get_results("SELECT status, COUNT(*) AS total FROM {$this->get_task_table_name()} GROUP BY status", ARRAY_A);

		foreach ((array) $counts as $row) {
			$status = sanitize_key((string) ($row['status'] ?? ''));
			$total = (int) ($row['total'] ?? 0);

			if ($status === 'pending') {
				$summary['total_pending'] = $total;
			} elseif (in_array($status, ['approved', 'auto_approved', 'executing'], true)) {
				$summary['total_approved_waiting_execution'] += $total;
			}

			if ($status === 'auto_approved') {
				$summary['total_auto_approved'] = $total;
			}
		}

		$summary['total_denied_unreported'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$this->get_task_table_name()} WHERE status = 'denied' AND (heartbeat_reported_at IS NULL OR heartbeat_reported_at < updated_at)");
		$summary['total_completed_unreported'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$this->get_task_table_name()} WHERE status = 'completed' AND (heartbeat_reported_at IS NULL OR heartbeat_reported_at < updated_at)");
		$summary['total_failed_unreported'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$this->get_task_table_name()} WHERE status = 'failed' AND (heartbeat_reported_at IS NULL OR heartbeat_reported_at < updated_at)");
		$summary['oldest_pending_at'] = $this->format_mysql_datetime((string) $wpdb->get_var("SELECT requested_at FROM {$this->get_task_table_name()} WHERE status = 'pending' ORDER BY requested_at ASC LIMIT 1"));
		$summary['next_auto_approve_at'] = $this->format_mysql_datetime((string) $wpdb->get_var("SELECT auto_approve_at FROM {$this->get_task_table_name()} WHERE status = 'pending' AND auto_approve_enabled = 1 AND auto_approve_at IS NOT NULL ORDER BY auto_approve_at ASC LIMIT 1"));

		return $summary;
	}

	private function get_task_status_summary(): array
	{
		$summary = array_fill_keys(self::REPORTABLE_STATUSES, 0);
		global $wpdb;
		$rows = $wpdb->get_results("SELECT status, COUNT(*) AS total FROM {$this->get_task_table_name()} GROUP BY status", ARRAY_A);

		foreach ((array) $rows as $row) {
			$status = sanitize_key((string) ($row['status'] ?? ''));

			if (array_key_exists($status, $summary)) {
				$summary[$status] = (int) ($row['total'] ?? 0);
			}
		}

		return $summary;
	}

	private function get_target_summary(array $task): string
	{
		$parts = [];

		if (!empty($task['target_username'])) {
			$parts[] = '@' . sanitize_user((string) $task['target_username']);
		}

		if (!empty($task['target_email'])) {
			$parts[] = sanitize_email((string) $task['target_email']);
		}

		if (!empty($task['target_user_id'])) {
			$parts[] = '#' . (int) $task['target_user_id'];
		}

		return $parts !== [] ? implode(' ', $parts) : __('Site users', 'freesiem-sentinel');
	}

	private function summarize_execution_result(array $task): string
	{
		$result = json_decode((string) ($task['execution_result_json'] ?? ''), true);

		if (!is_array($result) || $result === []) {
			return '';
		}

		if (!empty($result['user_count'])) {
			return sprintf(__('Returned %d users.', 'freesiem-sentinel'), (int) $result['user_count']);
		}

		if (!empty($result['deleted'])) {
			return __('User deleted locally.', 'freesiem-sentinel');
		}

		if (!empty($result['password_reset_sent'])) {
			return __('Password reset email triggered locally.', 'freesiem-sentinel');
		}

		if (!empty($result['user_id'])) {
			return sprintf(__('WordPress user #%d updated locally.', 'freesiem-sentinel'), (int) $result['user_id']);
		}

		return __('Task executed locally.', 'freesiem-sentinel');
	}

	private function get_decided_by_label(int $wp_user_id): string
	{
		if ($wp_user_id <= 0) {
			return '';
		}

		$user = get_user_by('id', $wp_user_id);

		if (!$user instanceof WP_User) {
			return '';
		}

		return (string) ($user->display_name ?: $user->user_login);
	}

	private function normalize_task(array $task): array
	{
		$task['id'] = (int) ($task['id'] ?? 0);
		$task['target_user_id'] = !empty($task['target_user_id']) ? (int) $task['target_user_id'] : 0;
		$task['decided_by_wp_user_id'] = !empty($task['decided_by_wp_user_id']) ? (int) $task['decided_by_wp_user_id'] : 0;
		$task['auto_approve_enabled'] = !empty($task['auto_approve_enabled']) ? 1 : 0;
		$task['signature_verified'] = !empty($task['signature_verified']) ? 1 : 0;
		$task['payload'] = $this->sanitize_payload_for_output((array) json_decode((string) ($task['payload_json'] ?? ''), true));
		$task['execution_result'] = json_decode((string) ($task['execution_result_json'] ?? ''), true);
		$task['requested_at'] = $this->format_mysql_datetime((string) ($task['requested_at'] ?? ''));
		$task['approved_at'] = $this->format_mysql_datetime((string) ($task['approved_at'] ?? ''));
		$task['denied_at'] = $this->format_mysql_datetime((string) ($task['denied_at'] ?? ''));
		$task['executed_at'] = $this->format_mysql_datetime((string) ($task['executed_at'] ?? ''));
		$task['completed_at'] = $this->format_mysql_datetime((string) ($task['completed_at'] ?? ''));
		$task['failed_at'] = $this->format_mysql_datetime((string) ($task['failed_at'] ?? ''));
		$task['heartbeat_reported_at'] = $this->format_mysql_datetime((string) ($task['heartbeat_reported_at'] ?? ''));
		$task['created_at'] = $this->format_mysql_datetime((string) ($task['created_at'] ?? ''));
		$task['updated_at'] = $this->format_mysql_datetime((string) ($task['updated_at'] ?? ''));

		return $task;
	}

	private function resolve_create_user_mode(array $payload): string
	{
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : [];
		$mode = sanitize_key((string) ($target['provisioning_mode'] ?? $target['mode'] ?? $payload['provisioning_mode'] ?? $payload['mode'] ?? ''));
		$password = $this->extract_create_user_password($payload);

		if ($mode === self::CREATE_USER_MODE_PASSWORD || ($mode === '' && $password !== '')) {
			return self::CREATE_USER_MODE_PASSWORD;
		}

		return self::CREATE_USER_MODE_RESET;
	}

	private function extract_create_user_password(array $payload): string
	{
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : [];

		foreach (['password', 'user_pass', 'pass'] as $key) {
			if (!empty($target[$key]) && is_string($target[$key])) {
				return (string) $target[$key];
			}

			if (!empty($payload[$key]) && is_string($payload[$key])) {
				return (string) $payload[$key];
			}
		}

		return '';
	}

	private function extract_password_for_execution(array $payload): string|WP_Error
	{
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : [];

		if (!empty($target[self::EXECUTION_PASSWORD_KEY]) && is_string($target[self::EXECUTION_PASSWORD_KEY])) {
			return $this->reveal_protected_secret((string) $target[self::EXECUTION_PASSWORD_KEY]);
		}

		if (!empty($payload[self::EXECUTION_PASSWORD_KEY]) && is_string($payload[self::EXECUTION_PASSWORD_KEY])) {
			return $this->reveal_protected_secret((string) $payload[self::EXECUTION_PASSWORD_KEY]);
		}

		$password = $this->extract_create_user_password($payload);

		if ($password === '') {
			return new WP_Error('freesiem_create_user_password_required', __('Explicit password provisioning requires a protected password payload.', 'freesiem-sentinel'));
		}

		return $password;
	}

	private function protect_secret(string $secret): string|WP_Error
	{
		if ($secret === '') {
			return new WP_Error('freesiem_secret_empty', __('freeSIEM Sentinel requires a non-empty secret value.', 'freesiem-sentinel'));
		}

		if (!function_exists('openssl_encrypt') || !function_exists('openssl_decrypt')) {
			return new WP_Error('freesiem_secret_protection_unavailable', __('OpenSSL is required for protected password storage.', 'freesiem-sentinel'));
		}

		$key = $this->get_secret_protection_key();
		$iv = random_bytes(16);
		$ciphertext = openssl_encrypt($secret, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

		if (!is_string($ciphertext) || $ciphertext === '') {
			return new WP_Error('freesiem_secret_protection_failed', __('freeSIEM Sentinel could not protect the supplied password.', 'freesiem-sentinel'));
		}

		$mac = hash_hmac('sha256', $iv . $ciphertext, $key);

		return 'v1:' . base64_encode($iv) . ':' . base64_encode($ciphertext) . ':' . $mac;
	}

	private function reveal_protected_secret(string $protected): string|WP_Error
	{
		if (!function_exists('openssl_decrypt')) {
			return new WP_Error('freesiem_secret_protection_unavailable', __('OpenSSL is required for protected password storage.', 'freesiem-sentinel'));
		}

		$parts = explode(':', $protected, 4);

		if (count($parts) !== 4 || $parts[0] !== 'v1') {
			return new WP_Error('freesiem_secret_payload_invalid', __('freeSIEM Sentinel could not read the protected password payload.', 'freesiem-sentinel'));
		}

		$iv = base64_decode($parts[1], true);
		$ciphertext = base64_decode($parts[2], true);
		$mac = sanitize_text_field((string) $parts[3]);
		$key = $this->get_secret_protection_key();

		if (!is_string($iv) || !is_string($ciphertext) || $iv === '' || $ciphertext === '') {
			return new WP_Error('freesiem_secret_payload_invalid', __('freeSIEM Sentinel could not read the protected password payload.', 'freesiem-sentinel'));
		}

		$expected_mac = hash_hmac('sha256', $iv . $ciphertext, $key);

		if (!hash_equals($expected_mac, $mac)) {
			return new WP_Error('freesiem_secret_payload_invalid', __('freeSIEM Sentinel could not verify the protected password payload.', 'freesiem-sentinel'));
		}

		$secret = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

		if (!is_string($secret) || $secret === '') {
			return new WP_Error('freesiem_secret_payload_invalid', __('freeSIEM Sentinel could not decrypt the protected password payload.', 'freesiem-sentinel'));
		}

		return $secret;
	}

	private function get_execution_payload(array $task): array|WP_Error
	{
		$payload = json_decode((string) ($task['execution_payload_json'] ?? ''), true);

		if (is_array($payload) && $payload !== []) {
			return $payload;
		}

		$fallback = json_decode((string) ($task['payload_json'] ?? ''), true);

		if (is_array($fallback) && $fallback !== []) {
			if ((string) ($task['action_type'] ?? '') === 'create_user' && $this->resolve_create_user_mode($fallback) === self::CREATE_USER_MODE_PASSWORD) {
				return new WP_Error('freesiem_execution_payload_missing', __('freeSIEM Sentinel cannot execute explicit-password provisioning from a redacted task snapshot.', 'freesiem-sentinel'));
			}

			return $fallback;
		}

		return new WP_Error('freesiem_execution_payload_missing', __('freeSIEM Sentinel could not load the internal execution payload for this task.', 'freesiem-sentinel'));
	}

	private function strip_password_keys(array $payload): array
	{
		$stripped = [];

		foreach ($payload as $key => $value) {
			$key = sanitize_key((string) $key);

			if ($key === '' || in_array($key, self::PASSWORD_KEYS, true) || $key === self::PROTECTED_PASSWORD_KEY || $key === self::EXECUTION_PASSWORD_KEY) {
				continue;
			}

			if (is_array($value)) {
				$stripped[$key] = $this->strip_password_keys($value);
				continue;
			}

			$stripped[$key] = $value;
		}

		return $stripped;
	}

	private function log_password_fingerprint(string $context, string $password): void
	{
		$fingerprint = substr(hash('sha256', $password), 0, 12);
		error_log('[freeSIEM] ' . $context . ' password_sha256=' . $fingerprint);
	}

	private function get_secret_protection_key(): string
	{
		return hash('sha256', wp_salt('auth') . '|' . site_url('/') . '|' . FREESIEM_SENTINEL_SLUG, true);
	}

	private function format_mysql_datetime(string $value): string
	{
		if ($value === '') {
			return '';
		}

		$timestamp = strtotime($value . ' UTC');

		return $timestamp ? gmdate('c', $timestamp) : '';
	}

	private function maybe_notify_admins(int $task_id): void
	{
		$settings = freesiem_sentinel_get_settings();

		if (empty($settings['notify_admins_on_pending_task'])) {
			return;
		}

		$task = $this->get_task($task_id);

		if (!is_array($task)) {
			return;
		}

		$admin_email = get_option('admin_email');

		if (!is_email($admin_email)) {
			return;
		}

		$subject = sprintf(__('Pending freeSIEM task on %s', 'freesiem-sentinel'), wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES));
		$message = sprintf(
			"%s\n\n%s: %s\n%s: %s\n%s: %s\n%s",
			__('A new freeSIEM Pending Task is waiting for review.', 'freesiem-sentinel'),
			__('Action', 'freesiem-sentinel'),
			(string) $task['action_type'],
			__('Core Task ID', 'freesiem-sentinel'),
			(string) $task['core_task_id'],
			__('Target', 'freesiem-sentinel'),
			$this->get_target_summary($task),
			freesiem_sentinel_admin_page_url('freesiem-pending-tasks', ['task_id' => (string) $task_id])
		);

		wp_mail($admin_email, $subject, $message);
	}

	private function is_recent_timestamp(string $timestamp): bool
	{
		if (!ctype_digit($timestamp)) {
			return false;
		}

		return abs(time() - (int) $timestamp) <= (5 * MINUTE_IN_SECONDS);
	}
}
