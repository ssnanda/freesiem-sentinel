<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Lightweight inventory and execution history for every WP-Cron hook.
 * Instrumentation is active only inside wp-cron.php requests.
 */
class Freesiem_Cron_Monitor
{
	private const HISTORY_OPTION = 'freesiem_sentinel_cron_history';
	private const HISTORY_LIMIT = 250;

	private array $due_hooks = [];
	private array $active = [];

	public function register(): void
	{
		if (!$this->is_cron_request()) {
			return;
		}

		$this->due_hooks = $this->get_due_hooks();
		if ($this->due_hooks === []) {
			return;
		}

		add_action('all', [$this, 'observe_hook_start'], PHP_INT_MIN);
		register_shutdown_function([$this, 'record_interrupted_runs']);
	}

	public function observe_hook_start(): void
	{
		$hook = current_filter();
		if ($hook === '' || empty($this->due_hooks[$hook])) {
			return;
		}

		$id = wp_generate_uuid4();
		$this->active[$hook][] = [
			'id' => $id,
			'started_float' => microtime(true),
			'memory_start' => memory_get_usage(true),
		];

		$this->append_history([
			'id' => $id,
			'hook' => $hook,
			'status' => 'running',
			'started_at' => freesiem_sentinel_get_iso8601_time(),
			'finished_at' => '',
			'duration_ms' => 0,
			'memory_delta' => 0,
		]);

		add_action($hook, function () use ($hook, $id): void {
			$this->record_hook_end($hook, $id);
		}, PHP_INT_MAX, 0);
	}

	private function record_hook_end(string $hook, string $id): void
	{
		$runs = $this->active[$hook] ?? [];
		foreach ($runs as $index => $run) {
			if (($run['id'] ?? '') !== $id) {
				continue;
			}

			$this->finish_history($id, 'completed', $run);
			unset($this->active[$hook][$index]);
			return;
		}
	}

	public function record_interrupted_runs(): void
	{
		$error = error_get_last();
		$fatal_types = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];
		$status = is_array($error) && in_array((int) ($error['type'] ?? 0), $fatal_types, true) ? 'fatal' : 'interrupted';

		foreach ($this->active as $runs) {
			foreach ($runs as $run) {
				$this->finish_history((string) ($run['id'] ?? ''), $status, $run, $error);
			}
		}
	}

	public function get_history(): array
	{
		$history = get_option(self::HISTORY_OPTION, []);
		return is_array($history) ? array_values($history) : [];
	}

	public function clear_history(): void
	{
		delete_option(self::HISTORY_OPTION);
	}

	public function get_events(): array
	{
		$cron = function_exists('_get_cron_array') ? _get_cron_array() : [];
		$schedules = wp_get_schedules();
		$events = [];

		foreach (is_array($cron) ? $cron : [] as $timestamp => $hooks) {
			foreach ((array) $hooks as $hook => $instances) {
				foreach ((array) $instances as $signature => $event) {
					$schedule = (string) ($event['schedule'] ?? '');
					$events[] = [
						'hook' => (string) $hook,
						'next_run' => (int) $timestamp,
						'overdue' => (int) $timestamp < time() - 60,
						'schedule' => $schedule === '' ? __('One time', 'freesiem-sentinel') : (string) ($schedules[$schedule]['display'] ?? $schedule),
						'interval' => (int) ($event['interval'] ?? 0),
						'args' => array_values(is_array($event['args'] ?? null) ? $event['args'] : []),
						'signature' => (string) $signature,
					];
				}
			}
		}

		usort($events, static fn (array $a, array $b): int => $a['next_run'] <=> $b['next_run']);
		return $events;
	}

	private function is_cron_request(): bool
	{
		return function_exists('wp_doing_cron') ? wp_doing_cron() : (defined('DOING_CRON') && DOING_CRON);
	}

	private function get_due_hooks(): array
	{
		$cron = function_exists('_get_cron_array') ? _get_cron_array() : [];
		$due = [];
		foreach (is_array($cron) ? $cron : [] as $timestamp => $hooks) {
			if ((int) $timestamp > time() + 60) {
				continue;
			}
			foreach (array_keys((array) $hooks) as $hook) {
				$due[(string) $hook] = true;
			}
		}
		return $due;
	}

	private function append_history(array $row): void
	{
		$history = $this->get_history();
		array_unshift($history, $row);
		update_option(self::HISTORY_OPTION, array_slice($history, 0, self::HISTORY_LIMIT), false);
	}

	private function finish_history(string $id, string $status, array $run, ?array $error = null): void
	{
		if ($id === '') {
			return;
		}

		$history = $this->get_history();
		foreach ($history as &$row) {
			if (($row['id'] ?? '') !== $id || ($row['status'] ?? '') !== 'running') {
				continue;
			}
			$row['status'] = $status;
			$row['finished_at'] = freesiem_sentinel_get_iso8601_time();
			$row['duration_ms'] = (int) round((microtime(true) - (float) ($run['started_float'] ?? microtime(true))) * 1000);
			$row['memory_delta'] = max(0, memory_get_peak_usage(true) - (int) ($run['memory_start'] ?? 0));
			if ($error !== null && $status === 'fatal') {
				$row['error'] = sanitize_text_field((string) ($error['message'] ?? 'Fatal PHP error'));
			}
			break;
		}
		unset($row);
		update_option(self::HISTORY_OPTION, array_slice($history, 0, self::HISTORY_LIMIT), false);
	}
}
