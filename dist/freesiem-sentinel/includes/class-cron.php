<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Cron
{
	public const HEARTBEAT_HOOK = 'freesiem_sentinel_heartbeat';
	public const LOCAL_SCAN_HOOK = 'freesiem_sentinel_local_scan';
	public const SYNC_HOOK = 'freesiem_sentinel_sync_results';

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
	}

	public function register_schedule(array $schedules): array
	{
		$schedules['freesiem_sentinel_15_minutes'] = [
			'interval' => 15 * MINUTE_IN_SECONDS,
			'display' => __('Every 15 Minutes (freeSIEM Sentinel)', 'freesiem-sentinel'),
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
	}

	public static function clear_events(): void
	{
		wp_clear_scheduled_hook(self::HEARTBEAT_HOOK);
		wp_clear_scheduled_hook(self::LOCAL_SCAN_HOOK);
		wp_clear_scheduled_hook(self::SYNC_HOOK);
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
}
