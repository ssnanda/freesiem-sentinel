<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Commands
{
	private Freesiem_Plugin $plugin;

	public function __construct(Freesiem_Plugin $plugin)
	{
		$this->plugin = $plugin;
	}

	public function process_commands(array $commands): array
	{
		$results = [];

		foreach ($commands as $command) {
			if (!is_array($command)) {
				continue;
			}

			$command_id = sanitize_text_field((string) ($command['id'] ?? ''));
			$type = sanitize_key((string) ($command['type'] ?? ''));
			$payload = is_array($command['payload'] ?? null) ? $command['payload'] : [];

			if (!$this->is_allowed_command_type($type)) {
				$this->log_stealth_command_rejection($command_id, $type, __('Rejected unsupported Stealth Mode command.', 'freesiem-sentinel'));
				continue;
			}

			$result = $this->execute($command_id, $type, $payload);

			if ($result === []) {
				continue;
			}

			$results[] = $result;
			$this->plugin->get_api_client()->send_command_result($result);
		}

		return $results;
	}

	public function execute(string $command_id, string $type, array $payload): array
	{
		$response = [
			'command_id' => $command_id,
			'type' => $type,
			'status' => 'failed',
			'message' => '',
			'result' => [],
			'completed_at' => freesiem_sentinel_get_iso8601_time(),
		];

		if (!$this->is_allowed_command_type($type)) {
			return [];
		}

		try {
			switch ($type) {
				case 'run_local_scan':
					$scan = $this->plugin->run_local_scan(true);
					$response['status'] = is_wp_error($scan) || !empty($scan['status']) ? 'failed' : 'completed';
					$response['message'] = is_wp_error($scan) ? $scan->get_error_message() : safe($scan['message'] ?? __('Local scan completed.', 'freesiem-sentinel'));
					$response['result'] = is_wp_error($scan) || !empty($scan['status']) ? [] : ['score' => $scan['score'] ?? null];
					break;

				case 'sync_results':
					$sync = $this->plugin->sync_results();
					$response['status'] = is_wp_error($sync) ? 'failed' : 'completed';
					$response['message'] = is_wp_error($sync) ? $sync->get_error_message() : __('Results synced.', 'freesiem-sentinel');
					$response['result'] = is_wp_error($sync) ? [] : ['synced' => true];
					break;

				case 'request_remote_scan':
					$request = $this->plugin->request_remote_scan();
					$response['status'] = is_wp_error($request) ? 'failed' : 'completed';
					$response['message'] = is_wp_error($request) ? $request->get_error_message() : __('Remote scan requested.', 'freesiem-sentinel');
					$response['result'] = is_wp_error($request) ? [] : (is_array($request) ? $request : []);
					break;

				case 'send_inventory':
					$sync = $this->plugin->send_inventory();
					$response['status'] = is_wp_error($sync) ? 'failed' : 'completed';
					$response['message'] = is_wp_error($sync) ? $sync->get_error_message() : __('Inventory uploaded.', 'freesiem-sentinel');
					$response['result'] = is_wp_error($sync) ? [] : ['sent' => true];
					break;

				case 'reconnect':
					$reconnect = $this->plugin->reconnect();
					$response['status'] = is_wp_error($reconnect) ? 'failed' : 'completed';
					$response['message'] = is_wp_error($reconnect) ? $reconnect->get_error_message() : __('Reconnect completed.', 'freesiem-sentinel');
					$response['result'] = is_wp_error($reconnect) ? [] : ['site_id' => $reconnect['site_id'] ?? ''];
					break;

				case 'refresh_update_check':
					$refresh = $this->plugin->get_updater()->refresh_plugin_update_state();
					$response['status'] = is_wp_error($refresh) ? 'failed' : 'completed';
					$response['message'] = is_wp_error($refresh) ? $refresh->get_error_message() : __('Update check refreshed.', 'freesiem-sentinel');
					$response['result'] = is_wp_error($refresh) ? [] : (is_array($refresh) ? $refresh : []);
					break;

				case 'update_settings':
					$updated = $this->plugin->apply_remote_settings($payload);
					$response['status'] = is_wp_error($updated) ? 'failed' : 'completed';
					$response['message'] = is_wp_error($updated) ? $updated->get_error_message() : __('Settings updated.', 'freesiem-sentinel');
					$response['result'] = is_wp_error($updated) ? [] : (is_array($updated) ? $updated : []);
					break;

				case 'enable_stealth_mode':
				case 'disable_stealth_mode':
				case 'update_stealth_mode_slug':
				case 'enable_stealth_direct_login_block':
				case 'disable_stealth_direct_login_block':
				case 'enable_stealth_admin_redirect':
				case 'disable_stealth_admin_redirect':
					$updated = $this->plugin->apply_remote_stealth_mode_command($type, $payload);
					$response['status'] = is_wp_error($updated) ? 'failed' : 'completed';
					$response['message'] = is_wp_error($updated) ? $updated->get_error_message() : __('Stealth Mode settings updated.', 'freesiem-sentinel');
					$response['result'] = is_wp_error($updated) ? [] : (is_array($updated) ? $updated : []);
					if (is_wp_error($updated)) {
						$this->log_stealth_command_rejection($command_id, $type, $updated->get_error_message());
					}
					break;

				default:
					return [];
					break;
			}
		} catch (Throwable $throwable) {
			$response['message'] = $throwable->getMessage();
		}

		return $response;
	}

	private function is_allowed_command_type(string $type): bool
	{
		return in_array($type, freesiem_sentinel_get_allowed_command_types(), true);
	}

	private function log_stealth_command_rejection(string $command_id, string $type, string $message): void
	{
		if (!str_contains($type, 'stealth')) {
			return;
		}

		freesiem_sentinel_log_event('stealth_command_rejected', __('A Stealth Mode command was rejected.', 'freesiem-sentinel'), '', '', [
			'command_id' => sanitize_text_field($command_id),
			'command_type' => sanitize_key($type),
			'reason' => sanitize_text_field($message),
		]);
	}
}
