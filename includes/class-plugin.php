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

		if (is_wp_error($response)) {
			return $response;
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

		if (is_wp_error($response)) {
			return $response;
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
		$scan = $this->scanner->run();
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

		if (is_wp_error($response)) {
			return $response;
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

		if (!is_wp_error($response)) {
			freesiem_sentinel_update_settings(['last_remote_scan_at' => freesiem_sentinel_get_iso8601_time()]);
		}

		return $response;
	}

	public function sync_results()
	{
		$site_id = (string) freesiem_sentinel_get_setting('site_id', '');

		if ($site_id === '') {
			return new WP_Error('freesiem_missing_site_id', __('freeSIEM Sentinel is not registered yet.', 'freesiem-sentinel'));
		}

		$response = $this->api_client->fetch_summary($site_id);

		if (is_wp_error($response)) {
			return $response;
		}

		$this->results->store_remote_summary($response);

		return $response;
	}

	public function send_inventory()
	{
		$scan = $this->scanner->run();
		$settings = freesiem_sentinel_get_settings();

		return $this->api_client->upload_local_scan([
			'site_id' => (string) ($settings['site_id'] ?? ''),
			'metadata' => $scan['metadata'],
			'findings' => [],
			'inventory' => $scan['inventory'],
			'scan_timestamps' => [
				'local' => freesiem_sentinel_get_iso8601_time(),
			],
		]);
	}

	public function reconnect()
	{
		$email = (string) freesiem_sentinel_get_setting('email', '');

		if ($email === '') {
			return new WP_Error('freesiem_email_required', __('Save an email address before reconnecting.', 'freesiem-sentinel'));
		}

		return $this->register_site($email);
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

	private function bootstrap_settings(): void
	{
		$settings = freesiem_sentinel_get_settings();

		if (get_option(FREESIEM_SENTINEL_OPTION, null) === null) {
			add_option(FREESIEM_SENTINEL_OPTION, freesiem_sentinel_sanitize_settings($settings), '', false);
		}

		$this->ensure_plugin_uuid();
	}

	private function ensure_plugin_uuid(): array
	{
		$settings = freesiem_sentinel_get_settings();

		if (!empty($settings['plugin_uuid'])) {
			return $settings;
		}

		$settings = freesiem_sentinel_update_settings([
			'plugin_uuid' => wp_generate_uuid4(),
		]);

		return $settings;
	}

	private function refresh_runtime_clients(array $settings): void
	{
		$this->api_client = new Freesiem_API_Client($settings);
	}
}
