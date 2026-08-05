<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Cron
{
	public const HEARTBEAT_HOOK = 'freesiem_sentinel_heartbeat';
	public const LOCAL_SCAN_HOOK = 'freesiem_sentinel_local_scan';
	public const SYNC_HOOK = 'freesiem_sentinel_sync_results';
	public const TASK_PROCESS_HOOK = 'freesiem_sentinel_process_pending_tasks';
	public const TASK_HEARTBEAT_HOOK = 'freesiem_sentinel_task_priority_heartbeat';
	public const INSTALL_BASE_HEARTBEAT_HOOK = 'freesiem_sentinel_install_base_heartbeat';
	public const SSL_AUTO_RENEW_HOOK = 'freesiem_sentinel_ssl_auto_renew';

	private Freesiem_Plugin $plugin;

	public function __construct(Freesiem_Plugin $plugin)
	{
		$this->plugin = $plugin;
	}

	public function register(): void
	{
		add_filter('cron_schedules', [$this, 'register_schedule']);
		add_action(self::HEARTBEAT_HOOK, [$this, 'heartbeat']);
		add_action(self::LOCAL_SCAN_HOOK, [$this, 'local_scan']);
		add_action(self::SYNC_HOOK, [$this, 'sync_results']);
		add_action(self::TASK_PROCESS_HOOK, [$this, 'process_pending_tasks']);
		add_action(self::INSTALL_BASE_HEARTBEAT_HOOK, [$this, 'install_base_heartbeat']);
		add_action(self::SSL_AUTO_RENEW_HOOK, [$this, 'ssl_auto_renew']);

		// Self-heal the schedule on every load (not just plugin activation) so
		// upgrading an already-active install picks up newly added hooks like
		// this one without requiring a deactivate/reactivate cycle.
		if (!wp_next_scheduled(self::SSL_AUTO_RENEW_HOOK)) {
			wp_schedule_event(time() + (20 * MINUTE_IN_SECONDS), 'daily', self::SSL_AUTO_RENEW_HOOK);
		}
	}

	public function register_schedule(array $schedules): array
	{
		$schedules['freesiem_sentinel_15_minutes'] = [
			'interval' => 15 * MINUTE_IN_SECONDS,
			'display' => __('Every 15 Minutes (freeSIEM Sentinel)', 'freesiem-sentinel'),
		];
		$schedules['freesiem_sentinel_every_minute'] = [
			'interval' => MINUTE_IN_SECONDS,
			'display' => __('Every Minute (freeSIEM Sentinel)', 'freesiem-sentinel'),
		];

		return $schedules;
	}

	public static function schedule_events(): void
	{
		if (!wp_next_scheduled(self::HEARTBEAT_HOOK)) {
			wp_schedule_event(time() + MINUTE_IN_SECONDS, 'freesiem_sentinel_15_minutes', self::HEARTBEAT_HOOK);
		}

		if (!wp_next_scheduled(self::LOCAL_SCAN_HOOK)) {
			wp_schedule_event(time() + (5 * MINUTE_IN_SECONDS), 'hourly', self::LOCAL_SCAN_HOOK);
		}

		if (!wp_next_scheduled(self::SYNC_HOOK)) {
			wp_schedule_event(time() + (10 * MINUTE_IN_SECONDS), 'hourly', self::SYNC_HOOK);
		}

		if (!wp_next_scheduled(self::TASK_PROCESS_HOOK)) {
			wp_schedule_event(time() + MINUTE_IN_SECONDS, 'freesiem_sentinel_every_minute', self::TASK_PROCESS_HOOK);
		}

		if (!wp_next_scheduled(self::INSTALL_BASE_HEARTBEAT_HOOK)) {
			wp_schedule_event(time() + (15 * MINUTE_IN_SECONDS), 'hourly', self::INSTALL_BASE_HEARTBEAT_HOOK);
		}

		if (!wp_next_scheduled(self::SSL_AUTO_RENEW_HOOK)) {
			wp_schedule_event(time() + (20 * MINUTE_IN_SECONDS), 'daily', self::SSL_AUTO_RENEW_HOOK);
		}
	}

	public static function clear_events(): void
	{
		wp_clear_scheduled_hook(self::HEARTBEAT_HOOK);
		wp_clear_scheduled_hook(self::LOCAL_SCAN_HOOK);
		wp_clear_scheduled_hook(self::SYNC_HOOK);
		wp_clear_scheduled_hook(self::TASK_PROCESS_HOOK);
		wp_clear_scheduled_hook(self::TASK_HEARTBEAT_HOOK);
		wp_clear_scheduled_hook(self::INSTALL_BASE_HEARTBEAT_HOOK);
		wp_clear_scheduled_hook(self::SSL_AUTO_RENEW_HOOK);
	}

	public function heartbeat(): void
	{
		$this->plugin->perform_heartbeat();
	}

	public function local_scan(): void
	{
		$this->plugin->run_local_scan(true);
	}

	public function sync_results(): void
	{
		$this->plugin->sync_results();
	}

	public function process_pending_tasks(): void
	{
		$this->plugin->get_pending_tasks()->process_due_tasks();
	}

	public function install_base_heartbeat(): void
	{
		$this->plugin->send_install_base_heartbeat();
	}

	public function ssl_auto_renew(): void
	{
		$ssl_settings = freesiem_sentinel_get_ssl_settings();

		if (empty($ssl_settings['auto_renew'])) {
			return;
		}

		$result = freesiem_sentinel_execute_ssl_renew($ssl_settings);
		freesiem_sentinel_add_ssl_log(
			freesiem_sentinel_ssl_result_log_level((string) ($result['status'] ?? 'failed')),
			(string) ($result['summary'] ?? __('Scheduled certificate renewal check ran.', 'freesiem-sentinel')),
			'ssl_auto_renew',
			['status' => (string) ($result['status'] ?? 'failed'), 'result_code' => (string) ($result['result_code'] ?? '')]
		);

		// Only touch nginx when certbot actually renewed something. Most daily
		// runs are no-ops (not yet within the renewal window) and should not
		// reload the webserver.
		if ((string) ($result['result_code'] ?? '') !== 'completed') {
			return;
		}

		$reload = freesiem_sentinel_reload_nginx();
		freesiem_sentinel_add_ssl_log(
			freesiem_sentinel_ssl_result_log_level((string) ($reload['status'] ?? 'failed')),
			(string) ($reload['summary'] ?? __('Nginx reload after renewal completed.', 'freesiem-sentinel')),
			'ssl_auto_renew_reload',
			['status' => (string) ($reload['status'] ?? '')]
		);
	}
}
