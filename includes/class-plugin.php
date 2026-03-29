<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Plugin
{
	private static ?self $instance = null;

	private Freesiem_API_Client $api_client;
	private Freesiem_Scanner $scanner;
	private Freesiem_Results $results;
	private Freesiem_Commands $commands;
	private Freesiem_Cron $cron;
	private Freesiem_Updater $updater;
	private Freesiem_Admin $admin;
	private Freesiem_Cloud_Connect_Client $cloud_connect_client;

	public static function instance(): self
	{
		if (!self::$instance instanceof self) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public function __construct()
	{
		$this->bootstrap_settings();
		$this->api_client = new Freesiem_API_Client();
		$this->cloud_connect_client = new Freesiem_Cloud_Connect_Client();
		$this->scanner = new Freesiem_Scanner();
		$this->results = new Freesiem_Results();
		$this->updater = new Freesiem_Updater();
		$this->commands = new Freesiem_Commands($this);
		$this->cron = new Freesiem_Cron($this);
		$this->admin = new Freesiem_Admin($this);

		add_action('plugins_loaded', [$this, 'register']);
	}

	public function register(): void
	{
		$this->cron->register();
		$this->updater->register();
		$this->admin->register();
	}

	public static function activate(): void
	{
		$instance = self::instance();
		$instance->bootstrap_settings();
		$instance->ensure_plugin_uuid();
		add_filter('cron_schedules', [$instance->cron, 'register_schedule']);
		Freesiem_Cron::schedule_events();
	}

	public static function deactivate(): void
	{
		Freesiem_Cron::clear_events();
	}

	public function register_site(string $email)
	{
		$email = sanitize_email($email);

		if ($email === '') {
			return new WP_Error('freesiem_email_required', __('A valid email address is required for registration.', 'freesiem-sentinel'));
		}

		$settings = $this->ensure_plugin_uuid();
		$payload = [
			'site_url' => site_url('/'),
			'home_url' => home_url('/'),
			'email' => $email,
			'plugin_uuid' => (string) $settings['plugin_uuid'],
			'plugin_version' => FREESIEM_SENTINEL_VERSION,
			'wp_version' => get_bloginfo('version'),
			'site_name' => get_bloginfo('name'),
			'timezone' => wp_timezone_string() ?: 'UTC',
		];

		$response = (new Freesiem_API_Client($settings))->register_site($payload);

		if (!is_array($response) || $response === []) {
			return new WP_Error('freesiem_registration_failed', __('freeSIEM Sentinel could not register with the backend.', 'freesiem-sentinel'));
		}

		$required = ['site_id', 'api_key', 'hmac_secret', 'registration_status'];

		foreach ($required as $key) {
			if (empty($response[$key]) || !is_string($response[$key])) {
				return new WP_Error('freesiem_invalid_registration', __('The backend returned an incomplete registration response.', 'freesiem-sentinel'));
			}
		}

		$updated = freesiem_sentinel_update_settings([
			'email' => $email,
			'site_id' => sanitize_text_field((string) $response['site_id']),
			'api_key' => sanitize_text_field((string) $response['api_key']),
			'hmac_secret' => sanitize_text_field((string) $response['hmac_secret']),
			'registration_status' => sanitize_key((string) $response['registration_status']),
		]);

		$this->refresh_runtime_clients($updated);

		return $updated;
	}

	public function perform_heartbeat()
	{
		$settings = freesiem_sentinel_get_settings();

		if (empty($settings['site_id']) || empty($settings['api_key']) || empty($settings['hmac_secret'])) {
			return new WP_Error('freesiem_not_registered', __('freeSIEM Sentinel is not registered yet.', 'freesiem-sentinel'));
		}

		$response = $this->api_client->heartbeat([
			'site_id' => (string) $settings['site_id'],
			'plugin_version' => FREESIEM_SENTINEL_VERSION,
			'wp_version' => get_bloginfo('version'),
			'timestamp' => freesiem_sentinel_get_iso8601_time(),
			'last_local_scan_at' => (string) $settings['last_local_scan_at'],
			'last_remote_scan_at' => (string) $settings['last_remote_scan_at'],
		]);

		if (!is_array($response) || $response === []) {
			return new WP_Error('freesiem_heartbeat_failed', __('freeSIEM Sentinel heartbeat failed safely.', 'freesiem-sentinel'));
		}

		freesiem_sentinel_update_settings([
			'last_heartbeat_at' => freesiem_sentinel_get_iso8601_time(),
		]);

		if (is_array($response['notices'] ?? null)) {
			$this->results->store_notices($response['notices']);
		}

		if (is_array($response['update_info'] ?? null)) {
			freesiem_sentinel_update_settings(['updater_cache' => $response['update_info']]);
		}

		if (is_array($response['config'] ?? null)) {
			$this->apply_remote_settings((array) $response['config']);
		}

		if (is_array($response['commands'] ?? null) && $response['commands'] !== []) {
			$this->commands->process_commands($response['commands']);
		}

		return $response;
	}

	public function run_local_scan(bool $upload = true)
	{
		return $this->run_local_scan_with_options($upload, []);
	}

	public function run_local_scan_with_options(bool $upload = true, array $options = [])
	{
		error_log('[freeSIEM] local scan started');
		$started_at = microtime(true);

		try {
			$scan = $this->scanner->run($options);
		} catch (Throwable $throwable) {
			error_log('[freeSIEM] local scan failed');

			return [
				'status' => 'error',
				'message' => __('Scan failed safely', 'freesiem-sentinel'),
				'metadata' => [],
				'inventory' => [],
				'findings' => [],
				'scan_timestamps' => [
					'local' => freesiem_sentinel_get_iso8601_time(),
				],
				'score' => 0,
			];
		}

		error_log('[freeSIEM] scan completed');
		$duration_seconds = round(max(0, microtime(true) - $started_at), 2);

		if (!empty($scan['status']) && $scan['status'] === 'error') {
			return $scan;
		}

		$filesystem = is_array($scan['inventory']['filesystem'] ?? null) ? $scan['inventory']['filesystem'] : [];
		$scan_profile = is_array($scan['inventory']['scan_profile'] ?? null) ? $scan['inventory']['scan_profile'] : [];
		$scan['summary'] = [
			'files_discovered' => (int) ($filesystem['discovered_files'] ?? 0),
			'files_analyzed' => (int) ($filesystem['inspected_files'] ?? 0),
			'files_flagged' => (int) ($filesystem['flagged_files'] ?? 0),
			'duration_seconds' => $duration_seconds,
			'scan_modules' => $this->derive_scan_modules($scan_profile),
		];
		$scan['inventory']['scan_metrics'] = $scan['summary'];

		$this->results->store_local_scan($scan);

		if (!$upload) {
			return $scan;
		}

		$settings = freesiem_sentinel_get_settings();

		if (empty($settings['site_id'])) {
			return $scan;
		}

		$payload = [
			'site_id' => (string) $settings['site_id'],
			'metadata' => $scan['metadata'],
			'findings' => $scan['findings'],
			'inventory' => $scan['inventory'],
			'scan_timestamps' => $scan['scan_timestamps'],
		];

		$response = $this->api_client->upload_local_scan($payload);

		if (!is_array($response) || $response === []) {
			return new WP_Error('freesiem_upload_failed', __('freeSIEM Sentinel could not upload the local scan.', 'freesiem-sentinel'));
		}

		freesiem_sentinel_update_settings(['last_sync_at' => freesiem_sentinel_get_iso8601_time()]);

		return $scan;
	}

	public function request_remote_scan()
	{
		$settings = freesiem_sentinel_get_settings();
		$response = $this->api_client->request_remote_scan([
			'site_id' => (string) ($settings['site_id'] ?? ''),
			'timestamp' => freesiem_sentinel_get_iso8601_time(),
		]);

		if (is_array($response) && $response !== []) {
			freesiem_sentinel_update_settings(['last_remote_scan_at' => freesiem_sentinel_get_iso8601_time()]);
			return $response;
		}

		return new WP_Error('freesiem_remote_scan_failed', __('freeSIEM Sentinel could not request a remote scan.', 'freesiem-sentinel'));
	}

	public function sync_results()
	{
		$site_id = (string) freesiem_sentinel_get_setting('site_id', '');

		if ($site_id === '') {
			return new WP_Error('freesiem_missing_site_id', __('freeSIEM Sentinel is not registered yet.', 'freesiem-sentinel'));
		}

		$response = $this->api_client->fetch_summary($site_id);

		if (!is_array($response) || $response === []) {
			return new WP_Error('freesiem_summary_failed', __('freeSIEM Sentinel could not fetch summary results.', 'freesiem-sentinel'));
		}

		$this->results->store_remote_summary($response);

		return $response;
	}

	public function send_inventory()
	{
		$scan = $this->scanner->run();
		$settings = freesiem_sentinel_get_settings();

		$response = $this->api_client->upload_local_scan([
			'site_id' => (string) ($settings['site_id'] ?? ''),
			'metadata' => $scan['metadata'],
			'findings' => [],
			'inventory' => $scan['inventory'],
			'scan_timestamps' => [
				'local' => freesiem_sentinel_get_iso8601_time(),
			],
		]);

		return is_array($response) && $response !== [] ? $response : new WP_Error('freesiem_inventory_failed', __('freeSIEM Sentinel could not upload inventory.', 'freesiem-sentinel'));
	}

	public function reconnect()
	{
		$email = (string) freesiem_sentinel_get_setting('email', '');

		if ($email === '') {
			return new WP_Error('freesiem_email_required', __('Save an email address before reconnecting.', 'freesiem-sentinel'));
		}

		return $this->register_site($email);
	}

	public function test_connection()
	{
		$response = $this->heartbeat_cloud_connect(true);

		return is_array($response) && $response !== [] ? $response : new WP_Error('freesiem_test_connection_failed', __('freeSIEM Sentinel connection test failed safely.', 'freesiem-sentinel'));
	}

	public function start_cloud_connect(string $email, string $phone)
	{
		$settings = Freesiem_Cloud_Connect_State::ensure_initialized();
		$payload = [
			'plugin_uuid' => (string) ($settings['plugin_uuid'] ?? ''),
			'site_url' => site_url(),
			'home_url' => home_url(),
			'site_name' => get_bloginfo('name'),
			'wp_version' => get_bloginfo('version'),
			'plugin_version' => FREESIEM_SENTINEL_VERSION,
			'timezone' => freesiem_sentinel_get_timezone_string(),
			'email' => $email,
			'phone' => $phone,
		];
		$response = $this->cloud_connect_client->start_connection($payload);

		if (is_wp_error($response)) {
			return $response;
		}

		$connection_id = sanitize_text_field((string) ($response['connection_id'] ?? ''));

		if ($connection_id === '') {
			return new WP_Error('freesiem_cloud_missing_connection_id', __('freeSIEM Core did not return a connection identifier.', 'freesiem-sentinel'));
		}

		$updated = Freesiem_Cloud_Connect_State::set_pending([
			'connection_id' => $connection_id,
			'email' => $email,
			'phone' => $phone,
			'connect_expires_at' => (string) ($response['expires_at'] ?? ''),
		]);
		$this->refresh_runtime_clients($updated);

		return $response;
	}

	public function verify_cloud_connect(string $code)
	{
		$settings = freesiem_sentinel_get_settings();
		$connection_id = sanitize_text_field((string) ($settings['connection_id'] ?? ''));
		$plugin_uuid = sanitize_text_field((string) ($settings['plugin_uuid'] ?? ''));

		if ($connection_id === '' || $plugin_uuid === '') {
			return new WP_Error('freesiem_cloud_missing_pending_state', __('Start a Cloud Connect session before verifying the code.', 'freesiem-sentinel'));
		}

		$response = $this->cloud_connect_client->verify_connection([
			'connection_id' => $connection_id,
			'plugin_uuid' => $plugin_uuid,
			'verification_code' => $code,
		]);

		if (is_wp_error($response)) {
			return $response;
		}

		$required = ['site_id', 'api_key', 'hmac_secret'];

		foreach ($required as $key) {
			if (!is_string($response[$key] ?? null) || trim((string) $response[$key]) === '') {
				return new WP_Error('freesiem_cloud_incomplete_credentials', __('freeSIEM Core returned incomplete site credentials.', 'freesiem-sentinel'));
			}
		}

		$updated = Freesiem_Cloud_Connect_State::set_connected($response);
		$this->refresh_runtime_clients($updated);
		$preference_sync = $this->sync_connected_cloud_preferences($updated);

		if (is_array($preference_sync) && $preference_sync !== []) {
			$response = array_merge($response, [
				'preferences_synced' => true,
				'permissions' => $preference_sync['permissions'] ?? ($response['permissions'] ?? []),
				'state' => $preference_sync['state'] ?? ($response['state'] ?? ''),
				'connection_state' => $preference_sync['state'] ?? ($response['connection_state'] ?? ''),
			]);
		}

		return $response;
	}

	public function heartbeat_cloud_connect(bool $minimal = false)
	{
		$settings = freesiem_sentinel_get_settings();

		if (!Freesiem_Cloud_Connect_State::is_connected($settings)) {
			return new WP_Error('freesiem_cloud_not_connected', __('Connect this site to freeSIEM Cloud before sending a heartbeat.', 'freesiem-sentinel'));
		}

		$summary_cache = freesiem_sentinel_safe_array($settings['summary_cache'] ?? []);
		$local_inventory = freesiem_sentinel_safe_array($summary_cache['local_inventory'] ?? []);
		$scan_metrics = freesiem_sentinel_safe_array($local_inventory['scan_metrics'] ?? []);
		$preference_payload = $this->build_cloud_preference_payload($settings);
		$payload = [
			'plugin_version' => FREESIEM_SENTINEL_VERSION,
			'wp_version' => get_bloginfo('version'),
		];

		if (!$minimal) {
			$payload = array_merge($payload, [
				'allow_remote_scan' => $preference_payload['allow_remote_scan'],
				'allow_remote_scans' => $preference_payload['allow_remote_scans'],
				'scan_frequency' => $preference_payload['scan_frequency'],
				'user_sync_enabled' => $preference_payload['user_sync_enabled'],
				'centralized_user_sync_enabled' => $preference_payload['centralized_user_sync_enabled'],
				'site_health_summary' => [
					'wordpress_version' => get_bloginfo('version'),
					'php_version' => PHP_VERSION,
					'last_local_scan_at' => (string) ($settings['last_local_scan_at'] ?? ''),
				],
				'last_scan_metadata' => [
					'last_local_scan_at' => (string) ($settings['last_local_scan_at'] ?? ''),
					'files_discovered' => (int) ($scan_metrics['files_discovered'] ?? 0),
					'files_flagged' => (int) ($scan_metrics['files_flagged'] ?? 0),
				],
				'preferences' => $preference_payload['preferences'],
			]);
		}

		$response = $this->cloud_connect_client->heartbeat($payload);

		if (is_wp_error($response)) {
			Freesiem_Cloud_Connect_State::update_from_heartbeat([], false, $response->get_error_message());
			return $response;
		}

		$updated = Freesiem_Cloud_Connect_State::update_from_heartbeat($response, true, __('Heartbeat successful.', 'freesiem-sentinel'));
		$this->refresh_runtime_clients($updated);

		return $response;
	}

	public function disconnect_cloud_connect()
	{
		$settings = freesiem_sentinel_get_settings();
		$response = null;

		if (Freesiem_Cloud_Connect_State::is_connected($settings)) {
			$response = $this->cloud_connect_client->disconnect([
				'plugin_uuid' => (string) ($settings['plugin_uuid'] ?? ''),
				'site_url' => site_url(),
			]);

			if (is_wp_error($response)) {
				$error_data = $response->get_error_data();
				$status_code = is_array($error_data) ? (int) ($error_data['status_code'] ?? 0) : 0;

				if (in_array($status_code, [401, 403, 404, 409], true)) {
					$updated = Freesiem_Cloud_Connect_State::clear_remote_credentials();
					$this->refresh_runtime_clients($updated);

					return [
						'disconnected' => true,
						'local_only' => true,
						'message' => $response->get_error_message(),
					];
				}

				return $response;
			}
		}

		$updated = Freesiem_Cloud_Connect_State::clear_remote_credentials();
		$this->refresh_runtime_clients($updated);

		return is_array($response) ? $response : ['disconnected' => true];
	}

	public function save_cloud_preferences(array $preferences)
	{
		$settings = freesiem_sentinel_update_settings($preferences);
		$this->refresh_runtime_clients($settings);

		if (!Freesiem_Cloud_Connect_State::is_connected($settings)) {
			return ['saved' => true, 'synced' => false];
		}

		$response = $this->sync_connected_cloud_preferences($settings);

		if (is_wp_error($response)) {
			return new WP_Error('freesiem_cloud_preferences_sync_failed', __('Cloud preferences were saved locally, but freeSIEM Core could not be updated right now.', 'freesiem-sentinel'));
		}

		$updated = Freesiem_Cloud_Connect_State::update_from_heartbeat($response, false, (string) ($settings['last_heartbeat_result'] ?? ''));
		$this->refresh_runtime_clients($updated);

		return ['saved' => true, 'synced' => true];
	}

	private function build_cloud_preference_payload(array $settings): array
	{
		$allow_remote_scan = !empty($settings['allow_remote_scan']);
		$user_sync_enabled = !empty($settings['user_sync_enabled']);
		$scan_frequency = (string) ($settings['scan_frequency'] ?? 'daily');

		return [
			'allow_remote_scan' => $allow_remote_scan,
			'allow_remote_scans' => $allow_remote_scan,
			'scan_frequency' => $scan_frequency,
			'user_sync_enabled' => $user_sync_enabled,
			'centralized_user_sync_enabled' => $user_sync_enabled,
			'preferences' => [
				'allow_remote_scan' => $allow_remote_scan,
				'allow_remote_scans' => $allow_remote_scan,
				'scan_frequency' => $scan_frequency,
				'user_sync_enabled' => $user_sync_enabled,
				'centralized_user_sync_enabled' => $user_sync_enabled,
			],
		];
	}

	private function sync_connected_cloud_preferences(array $settings)
	{
		$preference_payload = $this->build_cloud_preference_payload($settings);
		error_log('[freeSIEM] syncing cloud preferences: ' . wp_json_encode($preference_payload));

		return $this->cloud_connect_client->sync_preferences([
			'plugin_version' => FREESIEM_SENTINEL_VERSION,
			'wp_version' => get_bloginfo('version'),
			'allow_remote_scan' => $preference_payload['allow_remote_scan'],
			'allow_remote_scans' => $preference_payload['allow_remote_scans'],
			'scan_frequency' => $preference_payload['scan_frequency'],
			'user_sync_enabled' => $preference_payload['user_sync_enabled'],
			'centralized_user_sync_enabled' => $preference_payload['centralized_user_sync_enabled'],
			'preferences' => $preference_payload['preferences'],
		]);
	}

	public function apply_remote_settings(array $payload)
	{
		$allowed_keys = freesiem_sentinel_get_allowed_remote_setting_keys();
		$updates = [];

		foreach ($allowed_keys as $key) {
			if (!array_key_exists($key, $payload)) {
				continue;
			}

			$updates[$key] = $key === 'backend_url'
				? freesiem_sentinel_sanitize_backend_url((string) $payload[$key])
				: sanitize_text_field((string) $payload[$key]);
		}

		if ($updates === []) {
			return new WP_Error('freesiem_no_allowed_settings', __('No allowed settings were provided for remote update.', 'freesiem-sentinel'));
		}

		$settings = freesiem_sentinel_update_settings($updates);
		$this->refresh_runtime_clients($settings);

		return $updates;
	}

	public function get_api_client(): Freesiem_API_Client
	{
		return $this->api_client;
	}

	public function get_results(): Freesiem_Results
	{
		return $this->results;
	}

	public function get_updater(): Freesiem_Updater
	{
		return $this->updater;
	}

	public function get_plan(): string
	{
		return Freesiem_Features::get_plan();
	}

	public function clear_scan_results(): array
	{
		return $this->results->clear_scan_results();
	}

	private function bootstrap_settings(): void
	{
		$settings = freesiem_sentinel_get_settings();

		if (get_option(FREESIEM_SENTINEL_OPTION, null) === null) {
			add_option(FREESIEM_SENTINEL_OPTION, freesiem_sentinel_sanitize_settings($settings), '', false);
		}

		Freesiem_Cloud_Connect_State::ensure_initialized();
	}

	private function ensure_plugin_uuid(): array
	{
		return Freesiem_Cloud_Connect_State::ensure_initialized();
	}

	private function refresh_runtime_clients(array $settings): void
	{
		$this->api_client = new Freesiem_API_Client($settings);
		$this->cloud_connect_client = new Freesiem_Cloud_Connect_Client($settings);
	}

	private function derive_scan_modules(array $scan_profile): array
	{
		$modules = [];

		if (!empty($scan_profile['scan_wordpress'])) {
			$modules[] = 'WordPress Config';
		}
		if (!empty($scan_profile['scan_filesystem'])) {
			$modules[] = 'Filesystem';
		}
		if (!empty($scan_profile['scan_fim'])) {
			$modules[] = 'File Integrity';
		}

		return $modules;
	}
}
