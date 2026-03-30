<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_TFA_Remote
{
	private Freesiem_Plugin $plugin;
	private Freesiem_TFA_Service $service;
	private Freesiem_Pending_Tasks $pending_tasks;

	public function __construct(Freesiem_Plugin $plugin, Freesiem_TFA_Service $service, Freesiem_Pending_Tasks $pending_tasks)
	{
		$this->plugin = $plugin;
		$this->service = $service;
		$this->pending_tasks = $pending_tasks;
	}

	public function register(): void
	{
		add_action('rest_api_init', [$this, 'register_rest_routes']);
	}

	public function register_rest_routes(): void
	{
		$namespace = 'freesiem-sentinel/v1';

		register_rest_route($namespace, '/users/provision', [
			'methods' => WP_REST_Server::CREATABLE,
			'permission_callback' => '__return_true',
			'callback' => [$this, 'handle_provision_user'],
		]);

		register_rest_route($namespace, '/users/reset-tfa', [
			'methods' => WP_REST_Server::CREATABLE,
			'permission_callback' => '__return_true',
			'callback' => [$this, 'handle_reset_tfa'],
		]);

		register_rest_route($namespace, '/users/set-password', [
			'methods' => WP_REST_Server::CREATABLE,
			'permission_callback' => '__return_true',
			'callback' => [$this, 'handle_set_password'],
		]);

		register_rest_route($namespace, '/users/update-tfa', [
			'methods' => WP_REST_Server::CREATABLE,
			'permission_callback' => '__return_true',
			'callback' => [$this, 'handle_update_tfa'],
		]);

		register_rest_route($namespace, '/users/list', [
			'methods' => WP_REST_Server::READABLE,
			'permission_callback' => '__return_true',
			'callback' => [$this, 'handle_list_users'],
		]);
	}

	public function handle_provision_user(WP_REST_Request $request): WP_REST_Response|WP_Error
	{
		$verified = $this->verify_request($request);

		if (is_wp_error($verified)) {
			return $verified;
		}

		$result = $this->service->provision_user($this->get_request_payload($request));

		if (is_wp_error($result)) {
			return $result;
		}

		$this->plugin->send_priority_heartbeat();

		return new WP_REST_Response([
			'ok' => true,
			'user' => $result,
		], 200);
	}

	public function handle_reset_tfa(WP_REST_Request $request): WP_REST_Response|WP_Error
	{
		$verified = $this->verify_request($request);

		if (is_wp_error($verified)) {
			return $verified;
		}

		$result = $this->service->reset_remote_tfa($this->get_request_payload($request));

		if (is_wp_error($result)) {
			return $result;
		}

		$this->plugin->send_priority_heartbeat();

		return new WP_REST_Response([
			'ok' => true,
			'tfa' => $result,
		], 200);
	}

	public function handle_set_password(WP_REST_Request $request): WP_REST_Response|WP_Error
	{
		$verified = $this->verify_request($request);

		if (is_wp_error($verified)) {
			return $verified;
		}

		$result = $this->service->set_remote_password($this->get_request_payload($request));

		if (is_wp_error($result)) {
			return $result;
		}

		$this->plugin->send_priority_heartbeat();

		return new WP_REST_Response([
			'ok' => true,
			'user' => $result,
		], 200);
	}

	public function handle_update_tfa(WP_REST_Request $request): WP_REST_Response|WP_Error
	{
		$verified = $this->verify_request($request);

		if (is_wp_error($verified)) {
			return $verified;
		}

		$payload = $this->get_request_payload($request);
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : $payload;
		$user = $this->service->find_target_user($target);

		if (!$user instanceof WP_User) {
			return new WP_Error('freesiem_tfa_user_missing', __('The selected user could not be found.', 'freesiem-sentinel'), ['status' => 404]);
		}

		$result = $this->service->apply_remote_tfa_update((int) $user->ID, is_array($payload['tfa'] ?? null) ? $payload['tfa'] : $payload);

		if (is_wp_error($result)) {
			return $result;
		}

		$this->plugin->send_priority_heartbeat();

		return new WP_REST_Response([
			'ok' => true,
			'user_id' => (int) $user->ID,
			'tfa' => $this->service->get_user_tfa_state((int) $user->ID),
		], 200);
	}

	public function handle_list_users(WP_REST_Request $request): WP_REST_Response|WP_Error
	{
		$verified = $this->verify_request($request);

		if (is_wp_error($verified)) {
			return $verified;
		}

		return new WP_REST_Response([
			'users' => $this->service->get_safe_user_list(),
		], 200);
	}

	private function verify_request(WP_REST_Request $request): bool|WP_Error
	{
		return $this->pending_tasks->verify_signed_request($request, freesiem_sentinel_get_settings());
	}

	private function get_request_payload(WP_REST_Request $request): array
	{
		$params = $request->get_json_params();

		return is_array($params) ? $params : [];
	}
}
