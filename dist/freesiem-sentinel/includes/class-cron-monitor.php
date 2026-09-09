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
	private const SOURCE_OPTION = 'freesiem_sentinel_cron_source';

	/**
	 * How long after the last page request a cron run must arrive before it can
	 * only have come from outside WordPress.
	 *
	 * Traffic-triggered WP-Cron is spawned BY a page request — WordPress fires a
	 * non-blocking loopback to wp-cron.php while serving the page — so those runs
	 * land within a second or two of front-end traffic. A cron request minutes
	 * after the last page view cannot have been spawned that way, so something
	 * external (a real system cron) must have called wp-cron.php.
	 */
	private const UNATTENDED_AFTER_SECONDS = 180;

	/** Page timestamps are only written this often, to keep request overhead nil. */
	private const PAGE_PROBE_THROTTLE = 60;

	/**
	 * How long after a page view a cron run still counts as that page's own
	 * spawn. WordPress fires the loopback while serving the page, so the run
	 * lands a second or two later; anything past this sits in the quiet window.
	 */
	private const SPAWN_GRACE_SECONDS = 30;

	/** Rolling cron timestamps kept for estimating the external cron's interval. */
	private const PERIOD_SAMPLES = 20;

	private array $due_hooks = [];
	private array $active = [];

	public function register(): void
	{
		// Runs on every request, cron or not — this is what tells a system cron
		// apart from a visitor-spawned one.
		$this->probe_source();

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

	/**
	 * Record one data point about how this request reached WordPress: a page
	 * view, or a wp-cron.php run and how far it sat from the last page view.
	 */
	private function probe_source(): void
	{
		$now = time();
		$source = $this->get_source_state();

		if (!$this->is_cron_request()) {
			// WP-CLI is not a browser visitor and never spawns cron, so counting
			// it as traffic would mask a genuinely quiet site.
			if (defined('WP_CLI') && WP_CLI) {
				return;
			}

			if ($now - (int) $source['last_page_at'] < self::PAGE_PROBE_THROTTLE) {
				return; // already recorded a page view this minute
			}

			// A stretch with no traffic just ended. If no cron ran during it,
			// nothing external is calling wp-cron.php — the mirror image of the
			// unattended-run test below, and the only way to prove "traffic-only"
			// on a site busy enough that cron always lands near a page view.
			$last_page = (int) $source['last_page_at'];

			if ($last_page > 0 && ($now - $last_page) >= self::UNATTENDED_AFTER_SECONDS
				&& (int) $source['last_cron_at'] <= $last_page + self::SPAWN_GRACE_SECONDS) {
				$source['quiet_without_cron']++;
			}

			$source['last_page_at'] = $now;
			$this->save_source_state($source);

			return;
		}

		$last_page = (int) $source['last_page_at'];
		$unattended = $last_page > 0 && ($now - $last_page) >= self::UNATTENDED_AFTER_SECONDS;

		if ($unattended) {
			$source['unattended_runs']++;
			$source['last_unattended_at'] = $now;
		} else {
			$source['attended_runs']++;
		}

		$samples = $source['period_samples'];
		$samples[] = $now;
		$source['period_samples'] = array_slice($samples, -self::PERIOD_SAMPLES);
		$source['last_cron_at'] = $now;

		if ((int) $source['since'] === 0) {
			$source['since'] = $now;
		}

		$this->save_source_state($source);
	}

	private function get_source_state(): array
	{
		$stored = get_option(self::SOURCE_OPTION, []);
		$stored = is_array($stored) ? $stored : [];

		return [
			'since' => (int) ($stored['since'] ?? 0),
			'last_page_at' => (int) ($stored['last_page_at'] ?? 0),
			'last_cron_at' => (int) ($stored['last_cron_at'] ?? 0),
			'attended_runs' => (int) ($stored['attended_runs'] ?? 0),
			'unattended_runs' => (int) ($stored['unattended_runs'] ?? 0),
			'last_unattended_at' => (int) ($stored['last_unattended_at'] ?? 0),
			'quiet_without_cron' => (int) ($stored['quiet_without_cron'] ?? 0),
			'period_samples' => array_values(array_filter(
				(array) ($stored['period_samples'] ?? []),
				static fn ($v): bool => is_int($v) || ctype_digit((string) $v)
			)),
		];
	}

	private function save_source_state(array $source): void
	{
		update_option(self::SOURCE_OPTION, $source, false);
	}

	public function reset_source_state(): void
	{
		delete_option(self::SOURCE_OPTION);
	}

	/**
	 * Classify how wp-cron.php is actually being reached on this site.
	 *
	 * 'system'  — cron ran with no front-end traffic anywhere near it, so an
	 *             external scheduler is calling wp-cron.php. Unattended work
	 *             (deep scans, weekly scans) will keep running with no tab open.
	 * 'traffic' — every observed run sat right next to a page view, which is
	 *             WordPress's default visitor-spawned behaviour. Scans stall
	 *             whenever nobody is browsing the site.
	 * 'unknown' — not enough observations yet to say either way.
	 *
	 * @return array{mode:string,label:string,detail:string,interval:int,unattended_runs:int,attended_runs:int,last_unattended_at:int,observing_since:int}
	 */
	public function analyze_source(): array
	{
		$source = $this->get_source_state();
		$interval = $this->estimate_cron_interval($source['period_samples']);
		$total = $source['attended_runs'] + $source['unattended_runs'];

		$result = [
			'mode' => 'unknown',
			'label' => __('Not enough data yet', 'freesiem-sentinel'),
			'detail' => __('freeSIEM has not observed enough wp-cron.php runs yet to tell a real system cron from WordPress\'s visitor-triggered fallback. Leave the site running for a few minutes and check back.', 'freesiem-sentinel'),
			'interval' => $interval,
			'unattended_runs' => $source['unattended_runs'],
			'attended_runs' => $source['attended_runs'],
			'last_unattended_at' => $source['last_unattended_at'],
			'observing_since' => $source['since'],
		];

		if ($source['unattended_runs'] >= 2) {
			$result['mode'] = 'system';
			$result['label'] = __('System cron detected', 'freesiem-sentinel');
			$result['detail'] = $interval > 0
				/* translators: 1: number of runs 2: human-readable interval */
				? sprintf(__('%1$s wp-cron.php run(s) happened with no site traffic nearby, roughly every %2$s. An external scheduler is calling wp-cron.php, so scheduled work continues with no browser tab open.', 'freesiem-sentinel'), number_format_i18n($source['unattended_runs']), human_time_diff(0, $interval))
				/* translators: %s: number of runs */
				: sprintf(__('%s wp-cron.php run(s) happened with no site traffic nearby, so an external scheduler is calling wp-cron.php. Scheduled work continues with no browser tab open.', 'freesiem-sentinel'), number_format_i18n($source['unattended_runs']));

			return $result;
		}

		// "Traffic-only" is asserted from positive evidence too: a stretch of at
		// least UNATTENDED_AFTER_SECONDS with no traffic went by and no cron ran
		// in it. Counting runs instead would misread a busy site that does have a
		// system cron, because there every run happens to sit near a page view.
		if ($source['quiet_without_cron'] >= 2) {
			$result['mode'] = 'traffic';
			$result['label'] = __('Traffic-triggered only', 'freesiem-sentinel');
			$result['detail'] = __('The site went quiet and no wp-cron.php run happened during that time, so nothing external is calling it — this is WordPress\'s default, where cron only fires when someone loads a page. Long jobs such as a full scan pause whenever nobody is browsing. Add a real system cron to run them unattended.', 'freesiem-sentinel');

			return $result;
		}

		if ($total >= 5) {
			$result['label'] = __('Busy site — inconclusive', 'freesiem-sentinel');
			$result['detail'] = __('Every wp-cron.php run so far has landed close to site traffic, which is what both a system cron and WordPress\'s visitor-triggered fallback look like on a busy site. freeSIEM needs a quiet stretch — a few minutes with no page views — before it can tell them apart.', 'freesiem-sentinel');
		}

		return $result;
	}

	/**
	 * Median gap between recent cron runs, as a rough interval for the external
	 * scheduler. Median rather than mean so one long quiet stretch does not skew
	 * an otherwise steady cadence.
	 */
	private function estimate_cron_interval(array $samples): int
	{
		$samples = array_map('intval', $samples);
		sort($samples);

		if (count($samples) < 3) {
			return 0;
		}

		$gaps = [];

		for ($i = 1, $count = count($samples); $i < $count; $i++) {
			$gap = $samples[$i] - $samples[$i - 1];

			if ($gap > 0 && $gap <= DAY_IN_SECONDS) {
				$gaps[] = $gap;
			}
		}

		if ($gaps === []) {
			return 0;
		}

		sort($gaps);
		$middle = (int) floor(count($gaps) / 2);

		return count($gaps) % 2 === 0
			? (int) round(($gaps[$middle - 1] + $gaps[$middle]) / 2)
			: (int) $gaps[$middle];
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
