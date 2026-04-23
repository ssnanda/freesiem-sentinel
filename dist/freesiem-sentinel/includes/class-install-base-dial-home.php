<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Install_Base_Dial_Home
{
	private const ADDON_NAME = 'freeSIEM Sentinel';
	private const ADDON_SLUG = FREESIEM_SENTINEL_SLUG;
	private const ADDON_TYPE = 'wordpress-plugin';
	private const LOCAL_ENDPOINT = 'https://localhost:8443/api/v1/install-base/dial-home';
	private const PRODUCTION_ENDPOINT = 'https://core.freesiem.com/api/v1/install-base/dial-home';
	private const SHARED_SECRET = 'freesiem-sentinel-shared-secret';
	private const HEARTBEAT_INTERVAL = 12 * HOUR_IN_SECONDS;

	public function send(string $event)
	{
		$event = sanitize_key($event);

		if (!in_array($event, ['activation', 'heartbeat', 'upgrade'], true)) {
			return new WP_Error('freesiem_install_base_invalid_event', __('Invalid install-base dial-home event.', 'freesiem-sentinel'));
		}

		if ($event === 'heartbeat' && !$this->should_send_heartbeat()) {
			return ['skipped' => true, 'reason' => 'heartbeat_interval'];
		}

		$endpoint = $this->get_endpoint();
		$body = $this->build_raw_json_body($this->build_payload($event));
		$timestamp = (string) time();
		$signature = $this->sign($timestamp, $body);

		$response = wp_remote_post(
			$endpoint,
			[
				'method' => 'POST',
				'timeout' => 10,
				'sslverify' => !$this->is_local_endpoint($endpoint),
				'headers' => [
					'Content-Type' => 'application/json',
					'X-FS-Addon' => self::ADDON_SLUG,
					'X-FS-Timestamp' => $timestamp,
					'X-FS-Signature' => $signature,
				],
				'body' => $body,
			]
		);

		if (is_wp_error($response)) {
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code($response);
		if ($code < 200 || $code >= 300) {
			return new WP_Error(
				'freesiem_install_base_dial_home_failed',
				sprintf(
					/* translators: %d: HTTP status code */
					__('Install-base dial-home failed with HTTP %d.', 'freesiem-sentinel'),
					$code
				)
			);
		}

		$this->record_success($event);

		return [
			'success' => true,
			'event' => $event,
			'endpoint' => $endpoint,
			'status_code' => $code,
		];
	}

	public function maybe_send_upgrade(): void
	{
		$stored_version = (string) get_option(FREESIEM_SENTINEL_INSTALL_BASE_VERSION_OPTION, '');

		if ($stored_version === FREESIEM_SENTINEL_VERSION) {
			return;
		}

		$result = $this->send('upgrade');

		if (is_wp_error($result)) {
			error_log('[freeSIEM] install-base dial-home failed: ' . $result->get_error_message());
		}

		update_option(FREESIEM_SENTINEL_INSTALL_BASE_VERSION_OPTION, FREESIEM_SENTINEL_VERSION, false);
	}

	public function heartbeat(): void
	{
		$result = $this->send('heartbeat');

		if (is_wp_error($result)) {
			error_log('[freeSIEM] install-base heartbeat failed: ' . $result->get_error_message());
		}
	}

	public function get_install_uuid(): string
	{
		$uuid = (string) get_option(FREESIEM_SENTINEL_INSTALL_UUID_OPTION, '');

		if ($uuid !== '') {
			return $uuid;
		}

		$uuid = wp_generate_uuid4();
		add_option(FREESIEM_SENTINEL_INSTALL_UUID_OPTION, $uuid, '', false);

		return $uuid;
	}

	public function get_endpoint(?string $home_url = null): string
	{
		$home_url = $home_url ?? home_url();
		$host = strtolower((string) wp_parse_url($home_url, PHP_URL_HOST));
		$endpoint = str_ends_with($host, '.ddev.site') ? self::LOCAL_ENDPOINT : self::PRODUCTION_ENDPOINT;

		return (string) apply_filters('freesiem_sentinel_install_base_dial_home_endpoint', $endpoint, $home_url, $host);
	}

	public function build_payload(string $event): array
	{
		global $wpdb;

		$home_url = home_url();
		$site_url = site_url();
		$site_host = (string) wp_parse_url($home_url, PHP_URL_HOST);
		$theme = wp_get_theme();
		$admin_email = strtolower(trim((string) get_option('admin_email', '')));
		$settings = freesiem_sentinel_get_settings();

		return [
			'addon_name' => self::ADDON_NAME,
			'addon_slug' => self::ADDON_SLUG,
			'addon_type' => self::ADDON_TYPE,
			'addon_version' => FREESIEM_SENTINEL_VERSION,
			'install_uuid' => $this->get_install_uuid(),
			'site_url' => $site_url,
			'home_url' => $home_url,
			'site_host' => $site_host,
			'site_name' => get_bloginfo('name'),
			'wp_version' => get_bloginfo('version'),
			'php_version' => PHP_VERSION,
			'db_version' => is_object($wpdb) && method_exists($wpdb, 'db_version') ? (string) $wpdb->db_version() : '',
			'multisite' => is_multisite(),
			'locale' => get_locale(),
			'timezone' => freesiem_sentinel_get_timezone_string(),
			'theme' => [
				'name' => (string) $theme->get('Name'),
				'stylesheet' => (string) $theme->get_stylesheet(),
				'version' => (string) $theme->get('Version'),
			],
			'environment' => function_exists('wp_get_environment_type') ? wp_get_environment_type() : 'production',
			'admin_email_hash' => 'sha256:' . hash('sha256', $admin_email),
			'connected_to_core' => $this->is_connected_to_core($settings),
			'event' => sanitize_key($event),
			'sent_at' => freesiem_sentinel_get_iso8601_time(),
			'meta' => [
				'source' => 'wordpress-plugin',
				'channel' => $this->is_local_endpoint($this->get_endpoint($home_url)) ? 'local-dev' : 'production',
			],
		];
	}

	public function build_raw_json_body(array $payload): string
	{
		$body = wp_json_encode($payload, JSON_UNESCAPED_SLASHES);

		return is_string($body) ? $body : '{}';
	}

	public function sign(string $timestamp, string $raw_json_body): string
	{
		$message = self::ADDON_SLUG . "\n" . $timestamp . "\n" . $raw_json_body;

		return hash_hmac('sha256', $message, $this->get_shared_secret());
	}

	private function get_shared_secret(): string
	{
		if (defined('FREESIEM_SENTINEL_INSTALL_BASE_SHARED_SECRET')) {
			return (string) FREESIEM_SENTINEL_INSTALL_BASE_SHARED_SECRET;
		}

		return (string) apply_filters('freesiem_sentinel_install_base_shared_secret', self::SHARED_SECRET, self::ADDON_SLUG);
	}

	private function should_send_heartbeat(): bool
	{
		$last_sent = (int) get_option(FREESIEM_SENTINEL_INSTALL_BASE_LAST_HEARTBEAT_OPTION, 0);

		return $last_sent <= 0 || (time() - $last_sent) >= self::HEARTBEAT_INTERVAL;
	}

	private function record_success(string $event): void
	{
		update_option(
			FREESIEM_SENTINEL_INSTALL_BASE_LAST_EVENT_OPTION,
			[
				'event' => $event,
				'sent_at' => freesiem_sentinel_get_iso8601_time(),
			],
			false
		);

		if ($event === 'heartbeat') {
			update_option(FREESIEM_SENTINEL_INSTALL_BASE_LAST_HEARTBEAT_OPTION, time(), false);
		}

		if (in_array($event, ['activation', 'upgrade'], true)) {
			update_option(FREESIEM_SENTINEL_INSTALL_BASE_VERSION_OPTION, FREESIEM_SENTINEL_VERSION, false);
		}
	}

	private function is_connected_to_core(array $settings): bool
	{
		if (Freesiem_Cloud_Connect_State::is_connected($settings)) {
			return true;
		}

		return !empty($settings['site_id']) && !empty($settings['api_key']) && !empty($settings['hmac_secret']);
	}

	private function is_local_endpoint(string $endpoint): bool
	{
		return str_starts_with($endpoint, 'https://localhost:8443/');
	}
}
