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

			$result = $this->execute($command_id, $type, $payload);
			$results[] = $result;
			$this->plugin->get_api_client()->send_command_result($result);
		}

		return $results;
	}

	public function execute(string $command_id, string $type, array $payload): array
	{
		$allowed = freesiem_sentinel_get_allowed_command_types();
		$response = [
			'command_id' => $command_id,
			'type' => $type,
			'status' => 'failed',
			'message' => '',
			'result' => [],
			'completed_at' => freesiem_sentinel_get_iso8601_time(),
		];

		if (!in_array($type, $allowed, true)) {
			$response['message'] = __('Rejected non-whitelisted command.', 'freesiem-sentinel');
			return $response;
		}

		try {
			switch ($type) {
				case 'run_local_scan':
					$scan = $this->plugin->run_local_scan(true);
					$response['status'] = is_wp_error($scan) ? 'failed' : 'completed';
					$response['message'] = is_wp_error($scan) ? $scan->get_error_message() : __('Local scan completed.', 'freesiem-sentinel');
					$response['result'] = is_wp_error($scan) ? [] : ['score' => $scan['score'] ?? null];
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
					$response['result'] = is_wp_error($request) ? [] : $request;
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
					$response['result'] = is_wp_error($refresh) ? [] : $refresh;
					break;

				case 'update_settings':
					$updated = $this->plugin->apply_remote_settings($payload);
					$response['status'] = is_wp_error($updated) ? 'failed' : 'completed';
					$response['message'] = is_wp_error($updated) ? $updated->get_error_message() : __('Settings updated.', 'freesiem-sentinel');
					$response['result'] = is_wp_error($updated) ? [] : $updated;
					break;
			}
		} catch (Throwable $throwable) {
			$response['message'] = $throwable->getMessage();
		}

		return $response;
	}
}
