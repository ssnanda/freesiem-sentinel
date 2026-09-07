<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Resumable, self-throttling deep security scan.
 *
 * The quick scan (Freesiem_Scanner) still runs synchronously for instant WordPress
 * configuration findings. This engine adds the heavy work — reading file contents and
 * matching them against Freesiem_Threat_Signatures, verifying WordPress.org checksums
 * for core and plugins, inspecting drop-ins and wp-config.php, and a bounded database
 * sweep.
 *
 * All of that is done in short "slices": each slice processes a bounded number of files
 * within a wall-clock budget, sleeps between batches, watches memory, then persists its
 * position to an option so the next slice (foreground click or chained cron event) can
 * pick up where it left off. A large site is covered across several passes and never
 * pins the server.
 */
class Freesiem_Deep_Scanner
{
	public const STATE_OPTION = 'freesiem_sentinel_deep_scan_state';
	public const CONTINUE_HOOK = 'freesiem_sentinel_deep_scan_continue';
	private const LOCK_TRANSIENT = 'freesiem_sentinel_deep_scan_lock';

	private const MAX_FINDINGS = 500;
	private const MAX_FINDINGS_FULL = 1500;
	private const DIR_FILE_CAP = 20000;
	private const DIR_FILE_CAP_FULL = 120000;
	private const MAX_READ_BYTES = 5242880; // 5 MB content read cap
	private const PEEK_BYTES = 8192;
	private const STALE_LOCK_SECONDS = 3600; // a slice that hasn't advanced in an hour is treated as crashed
	private const RESCAN_AFTER_SECONDS = 43200; // 12h — scheduled deep scan cadence
	private const CORE_CHECK_BATCH = 40;
	private const PLUGIN_CHECK_BATCH = 30;

	// The deep scan walks the whole tree; a real install nests ~10 deep
	// (plugins/x/vendor/a/b/src/...). The legacy heuristic-pass "depth limit"
	// preference is not allowed to shrink deep coverage below this.
	private const MIN_TRAVERSAL_DEPTH = 15;

	private Freesiem_Plugin $plugin;

	public function __construct(Freesiem_Plugin $plugin)
	{
		$this->plugin = $plugin;
	}

	// ---------------------------------------------------------------------
	// Lifecycle
	// ---------------------------------------------------------------------

	public function get_state(): array
	{
		$state = get_option(self::STATE_OPTION, []);

		return is_array($state) ? $state : [];
	}

	public function is_running(): bool
	{
		$state = $this->get_state();

		return !empty($state) && ($state['phase'] ?? 'done') !== 'done';
	}

	public function is_stalled(): bool
	{
		$state = $this->get_state();

		if (empty($state) || ($state['phase'] ?? 'done') === 'done') {
			return false;
		}

		$updated = strtotime((string) ($state['updated_at'] ?? '')) ?: 0;

		return $updated > 0 && (time() - $updated) > self::STALE_LOCK_SECONDS;
	}

	public function abort(): void
	{
		delete_option(self::STATE_OPTION);
		delete_transient(self::LOCK_TRANSIENT);
	}

	/**
	 * Reset state and seed the work queue for a fresh scan.
	 *
	 * @param array  $options per-run preference overrides
	 * @param string $mode    'deep' (manual / 12-hourly) or 'weekly' (scheduled full sweep)
	 */
	public function start(array $options = [], string $mode = 'deep'): array
	{
		$full = $mode === 'weekly' || !empty($options['full']);

		if ($full) {
			// A full sweep always runs every module and covers uploads, whatever
			// the saved per-module toggles say.
			$options['scan_malware'] = 1;
			$options['scan_core_integrity'] = 1;
			$options['scan_plugin_integrity'] = 1;
			$options['scan_database'] = 1;
			$options['scan_uploads_deep'] = 1;
		}

		$prefs = $this->resolve_preferences($options);
		$now = freesiem_sentinel_get_iso8601_time();

		$state = [
			'run_token' => wp_generate_uuid4(),
			'mode' => in_array($mode, ['deep', 'weekly'], true) ? $mode : 'deep',
			'full' => $full,
			'phase' => 'filesystem',
			'started_at' => $now,
			'updated_at' => $now,
			'finished_at' => '',
			'prefs' => $prefs,
			'dir_stack' => [],
			'file_queue' => [],
			'integrity_cursor' => ['stage' => 'core', 'index' => 0, 'plugin_index' => 0],
			'database_cursor' => ['stage' => 'users', 'offset' => 0],
			'counters' => [
				'files_seen' => 0,
				'files_scanned' => 0,
				'bytes_scanned' => 0,
				'dirs_visited' => 0,
				'skipped_paths' => 0,
				'core_files_checked' => 0,
				'core_files_modified' => 0,
				'plugin_files_checked' => 0,
				'plugin_files_modified' => 0,
				'malware_hits' => 0,
				'database_issues' => 0,
				'vendor_verified' => 0,
			],
			'findings' => [],
			'partial' => false,
			'partial_reason' => '',
		];

		foreach ($this->scan_targets($prefs) as $target) {
			$path = wp_normalize_path($target['path']);

			if ($path === '' || !is_dir($path)) {
				continue;
			}

			$state['dir_stack'][] = ['path' => untrailingslashit($path), 'label' => $target['label'], 'depth' => 0];
		}

		$this->save_state($state);

		return $state;
	}

	/**
	 * Start a full, uncapped sweep (all modules, uploads, higher finding limit)
	 * and queue the first background continuation. Used by the weekly cron and the
	 * "Run Full Scan Now" button.
	 */
	public function start_full(string $mode = 'weekly'): array
	{
		$state = $this->start(['full' => 1], $mode === 'weekly' ? 'weekly' : 'deep');
		$this->schedule_continue(5);

		return $state;
	}

	/**
	 * Weekly cron entry: start a full scan unless one is already running.
	 */
	public function run_weekly_full_scan(): void
	{
		if (!freesiem_sentinel_get_setting('deep_scan_weekly_enabled', 1)) {
			return;
		}

		if ($this->is_running() && !$this->is_stalled()) {
			$this->schedule_continue(10);

			return;
		}

		$this->start_full('weekly');
	}

	public function maybe_start_scheduled(): void
	{
		if ($this->is_running()) {
			// A scan is in progress (possibly with a broken continuation chain, or
			// simply slow between cron ticks). Resume it from its saved position
			// rather than restarting and losing coverage.
			$this->schedule_continue(10);

			return;
		}

		$settings = freesiem_sentinel_get_settings();
		$prefs = freesiem_sentinel_safe_array($settings['scan_preferences'] ?? []);

		if (empty($prefs['scan_malware']) && empty($prefs['scan_core_integrity']) && empty($prefs['scan_plugin_integrity']) && empty($prefs['scan_database'])) {
			return;
		}

		$last = strtotime((string) ($settings['summary_cache']['summary']['last_deep_scan_at'] ?? '')) ?: 0;

		if ($last > 0 && (time() - $last) < self::RESCAN_AFTER_SECONDS) {
			return;
		}

		$this->start();
		$this->schedule_continue(5);
	}

	/**
	 * Cron entry point: run one background slice and either chain the next one or finalize.
	 */
	public function continue_scan(): void
	{
		if (!$this->is_running()) {
			return;
		}

		$result = $this->run_slice($this->resolve_budget('background'));

		if (empty($result['done'])) {
			$this->schedule_continue(20);

			return;
		}

		$this->finalize();
	}

	/**
	 * Browser-driven equivalent of one cron tick: run a slice and finalize if done.
	 * Called from the Scan screen's progress poller so the scan advances even when
	 * WP-Cron is not firing.
	 */
	public function run_tick(): array
	{
		if (!$this->is_running()) {
			return $this->progress();
		}

		$result = $this->run_slice($this->resolve_budget('background'));

		if (!empty($result['done'])) {
			$this->finalize();
		} else {
			// Belt and suspenders: keep a cron continuation queued in case the
			// user navigates away mid-scan.
			$this->schedule_continue(20);
		}

		return $this->progress();
	}

	private function schedule_continue(int $delay): void
	{
		if (function_exists('wp_next_scheduled') && wp_next_scheduled(self::CONTINUE_HOOK)) {
			return;
		}

		wp_schedule_single_event(time() + max(1, $delay), self::CONTINUE_HOOK);

		if (function_exists('spawn_cron')) {
			spawn_cron();
		}
	}

	// ---------------------------------------------------------------------
	// Slice execution
	// ---------------------------------------------------------------------

	/**
	 * Process work until the first budget limit is hit, then persist and return.
	 *
	 * @param array{files:int,seconds:float,throttle_us:int,batch:int} $budget
	 * @return array{done:bool,progress:array}
	 */
	public function run_slice(array $budget): array
	{
		$state = $this->get_state();

		if (empty($state) || ($state['phase'] ?? 'done') === 'done') {
			return ['done' => true, 'progress' => $this->progress()];
		}

		// Prevent a cron event and a browser tick (or two tabs) from running
		// slices concurrently and racing on the state option.
		if (get_transient(self::LOCK_TRANSIENT)) {
			return ['done' => false, 'progress' => $this->progress()];
		}

		set_transient(self::LOCK_TRANSIENT, 1, 120);

		if (function_exists('ignore_user_abort')) {
			ignore_user_abort(true);
		}

		// A cron / ajax slice does not always inherit the admin memory bump, and
		// memory_ceiling() trusts the live limit — raise it before measuring.
		if (function_exists('wp_raise_memory_limit')) {
			wp_raise_memory_limit('admin');
		}

		@set_time_limit(max(60, (int) $budget['seconds'] + 45));

		$deadline = microtime(true) + max(3.0, (float) $budget['seconds']);
		$file_cap = max(25, (int) $budget['files']);
		$throttle = max(0, (int) $budget['throttle_us']);
		$batch = max(1, (int) $budget['batch']);
		$mem_ceiling = $this->memory_ceiling();

		$processed = 0;
		$since_sleep = 0;
		$since_checkpoint = 0;

		while ($processed < $file_cap && microtime(true) < $deadline) {
			if ($mem_ceiling > 0 && memory_get_usage(true) > $mem_ceiling) {
				$state['partial'] = true;
				$state['partial_reason'] = 'memory';
				break;
			}

			$phase = $state['phase'] ?? 'done';

			if ($phase === 'filesystem') {
				$this->step_filesystem($state);
			} elseif ($phase === 'integrity') {
				$this->step_integrity($state);
			} elseif ($phase === 'database') {
				$this->step_database($state);
			} else {
				break;
			}

			$processed++;
			$since_sleep++;
			$since_checkpoint++;

			if ($throttle > 0 && $since_sleep >= $batch) {
				usleep($throttle);
				$since_sleep = 0;
			}

			// Persist periodically so a hard kill (FastCGI timeout, OOM) loses at
			// most a few hundred files of progress rather than the whole slice.
			if ($since_checkpoint >= 400) {
				$state['updated_at'] = freesiem_sentinel_get_iso8601_time();
				$state['progress_floor'] = max((int) ($state['progress_floor'] ?? 0), $this->percent_from_state($state));
				$this->save_state($state);
				$since_checkpoint = 0;
			}
		}

		$state['updated_at'] = freesiem_sentinel_get_iso8601_time();
		$state['progress_floor'] = max((int) ($state['progress_floor'] ?? 0), $this->percent_from_state($state));
		$done = ($state['phase'] ?? 'done') === 'done';

		if ($done) {
			$state['finished_at'] = $state['updated_at'];
		}

		$this->save_state($state);
		delete_transient(self::LOCK_TRANSIENT);

		return ['done' => $done, 'progress' => $this->progress()];
	}

	/**
	 * Run the first foreground slice for the manual button, then hand off to cron.
	 *
	 * @return array{done:bool,progress:array}
	 */
	public function run_foreground_pass(): array
	{
		$result = $this->run_slice($this->resolve_budget('foreground'));

		if (empty($result['done'])) {
			$this->schedule_continue(1);
		} else {
			$this->finalize();
			$result['progress'] = $this->progress();
		}

		return $result;
	}

	// ---------------------------------------------------------------------
	// Phase: filesystem
	// ---------------------------------------------------------------------

	private function step_filesystem(array &$state): void
	{
		if (!empty($state['file_queue'])) {
			$file = array_shift($state['file_queue']);
			$this->scan_file((string) $file, $state);

			return;
		}

		if (empty($state['dir_stack'])) {
			$state['phase'] = 'integrity';

			return;
		}

		$dir = array_pop($state['dir_stack']);
		$this->expand_directory(is_array($dir) ? $dir : ['path' => (string) $dir, 'label' => '', 'depth' => 0], $state);
	}

	private function expand_directory(array $dir, array &$state): void
	{
		$path = (string) ($dir['path'] ?? '');
		$label = (string) ($dir['label'] ?? '');
		$depth = (int) ($dir['depth'] ?? 0);
		$max_depth = max(self::MIN_TRAVERSAL_DEPTH, (int) ($state['prefs']['max_depth'] ?? self::MIN_TRAVERSAL_DEPTH));
		$excludes = is_array($state['prefs']['exclude_paths'] ?? null) ? $state['prefs']['exclude_paths'] : [];

		if (!is_dir($path) || !is_readable($path) || is_link($path)) {
			$state['counters']['skipped_paths']++;

			return;
		}

		$items = @scandir($path);

		if (!is_array($items)) {
			$state['counters']['skipped_paths']++;

			return;
		}

		$state['counters']['dirs_visited']++;
		$queued = [];

		foreach ($items as $item) {
			if ($item === '.' || $item === '..') {
				continue;
			}

			$child = $path . '/' . $item;
			$child_rel = $this->relative_path($child);

			if ($this->is_excluded($child_rel, $excludes)) {
				$state['counters']['skipped_paths']++;

				continue;
			}

			if (is_dir($child)) {
				if ($this->should_skip_directory($item, $child) || $depth + 1 > $max_depth) {
					$state['counters']['skipped_paths']++;

					continue;
				}

				$state['dir_stack'][] = ['path' => $child, 'label' => $label, 'depth' => $depth + 1];

				continue;
			}

			if (is_file($child)) {
				$queued[] = $child;
			}
		}

		// Guard against a single directory with an enormous file count blowing up
		// the serialized state option.
		$dir_cap = empty($state['full']) ? self::DIR_FILE_CAP : self::DIR_FILE_CAP_FULL;

		if (count($queued) > $dir_cap) {
			$queued = array_slice($queued, 0, $dir_cap);
			$state['partial'] = true;
			$state['partial_reason'] = $state['partial_reason'] ?: 'dir_file_cap';
		}

		if ($queued !== []) {
			$state['file_queue'] = $queued;
		}
	}

	private function scan_file(string $path, array &$state): void
	{
		$state['counters']['files_seen']++;

		if (!is_file($path) || !is_readable($path) || is_link($path)) {
			return;
		}

		$rel = $this->relative_path($path);
		$basename = strtolower((string) basename($path));
		$extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
		$size = (int) @filesize($path);

		// A pristine copy of one of freeSIEM Sentinel's own shipped files
		// legitimately contains signature strings ("coinhive", "c99shell", the
		// detection regexes, ...). Verify it against the release checksum manifest
		// and, if it is byte-identical, do not run content signatures against it —
		// but DO still scan it (and flag it hard) if it has been modified.
		$self_rel = $this->self_relative_path($path);

		if ($self_rel !== null) {
			$manifest = $this->self_manifest();
			$expected = $manifest[$self_rel] ?? '';

			if ($expected !== '' && hash_equals($expected, (string) @md5_file($path))) {
				return; // our own file, unchanged since release — nothing to scan
			}
			// Fall through: modified or unrecognized file inside our own plugin.
			// integrity_self_step() reports the tampering; here we still let the
			// signature scan run so an injected payload is caught too.
		}

		// A file that byte-matches its official WordPress.org checksum (core, or a
		// wp.org-hosted plugin) is known-good — running content signatures or
		// filename heuristics against it only produces false positives (WP core
		// docblocks quote `$_POST['x']` in backticks, ship long class filenames,
		// call ini_set('display_errors', 0), embed sandboxed <iframe>s, etc.).
		if ($this->is_vendor_verified($path, $rel)) {
			$state['counters']['vendor_verified']++;

			return;
		}

		$this->check_filename_heuristics($path, $rel, $basename, $extension, $size, $state);

		$mode = Freesiem_Threat_Signatures::scan_mode($basename, $extension);

		if ($mode === 'skip') {
			return;
		}

		if ($mode === 'full' && $size > self::MAX_READ_BYTES) {
			return;
		}

		$length = $mode === 'peek' ? self::PEEK_BYTES : self::MAX_READ_BYTES;
		$contents = @file_get_contents($path, false, null, 0, $length);

		if (!is_string($contents) || $contents === '') {
			return;
		}

		$state['counters']['files_scanned']++;
		$state['counters']['bytes_scanned'] += strlen($contents);

		$class = $mode === 'peek' ? 'peek' : Freesiem_Threat_Signatures::classify($basename, $extension);
		$this->match_signatures($contents, $rel, $class, $state);
	}

	private function match_signatures(string $contents, string $rel, string $class, array &$state, string $category_override = ''): void
	{
		foreach (Freesiem_Threat_Signatures::rules_for_class($class) as $rule) {
			$pattern = (string) ($rule['pattern'] ?? '');

			if ($pattern === '') {
				continue;
			}

			if (@preg_match($pattern, $contents, $match, PREG_OFFSET_CAPTURE) !== 1) {
				continue;
			}

			$offset = (int) ($match[0][1] ?? 0);
			$line = substr_count($contents, "\n", 0, min($offset, strlen($contents))) + 1;
			// preg_match_all builds a full match array; only run it on modestly
			// sized files so a pathological input cannot balloon memory.
			$count = strlen($contents) <= 524288 ? (@preg_match_all($pattern, $contents) ?: 1) : 1;
			$category = $category_override !== '' ? $category_override : (string) ($rule['category'] ?? 'malware');

			$this->add_finding($state, [
				'finding_key' => 'deep_' . $rule['id'] . '_' . md5($rel),
				'category' => $category,
				'severity' => (string) ($rule['severity'] ?? 'high'),
				'title' => (string) ($rule['label'] ?? 'Suspicious code pattern'),
				'description' => sprintf('Signature "%s" matched in %s (line %d).', (string) ($rule['label'] ?? $rule['id']), $rel, $line),
				'recommendation' => (string) ($rule['recommendation'] ?? 'Review this file against a known-good copy and remove any code you cannot account for.'),
				'evidence' => [
					'path' => $rel,
					'signature_id' => (string) $rule['id'],
					'line' => $line,
					'match_count' => (int) $count,
					'snippet' => $this->snippet($contents, $offset),
				],
				'score' => (int) ($rule['score'] ?? 45),
			]);

			if (($rule['category'] ?? 'malware') === 'malware') {
				$state['counters']['malware_hits']++;
			}
		}
	}

	private function check_filename_heuristics(string $path, string $rel, string $basename, string $extension, int $size, array &$state): void
	{
		$uploads_rel = $this->relative_path(WP_CONTENT_DIR . '/uploads');
		$in_uploads = $uploads_rel !== '' && str_starts_with($rel, $uploads_rel);
		$in_content = str_starts_with($rel, $this->relative_path(WP_CONTENT_DIR));
		$in_public_root = !str_contains(trim($rel, '/'), '/');
		$php_like = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'pht'];

		$reasons = [];
		$severity = 'medium';
		$score = 70;

		if (Freesiem_Threat_Signatures::is_webshell_filename($basename)) {
			$reasons[] = 'Filename matches a known web shell or a disguised-executable pattern';
			$severity = 'critical';
			$score = 30;
		}

		if ($in_uploads && in_array($extension, $php_like, true) && !$this->is_directory_index_stub($path, $basename, $size)) {
			$reasons[] = 'Executable PHP file inside the uploads directory';
			$severity = 'critical';
			$score = min($score, 32);
		}

		if ($in_uploads && $extension === 'php' && $size > 512000) {
			$reasons[] = 'Unusually large PHP file inside uploads';
			$severity = 'critical';
			$score = min($score, 30);
		}

		if (in_array($extension, $php_like, true) && Freesiem_Threat_Signatures::looks_random_filename($basename)) {
			$reasons[] = 'Random-looking PHP filename';
			$severity = $severity === 'critical' ? 'critical' : 'high';
			$score = min($score, 55);
		}

		if (in_array($extension, ['zip', 'tar', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'sql', 'bak', 'old', 'orig', 'save', 'swp'], true)
			&& ($in_public_root || $in_uploads)) {
			$reasons[] = 'Publicly reachable archive, backup, or database dump';
			$severity = $severity === 'critical' ? 'critical' : 'high';
			$score = min($score, 58);
		}

		if (in_array($extension, ['sh', 'bash', 'zsh', 'ksh', 'py', 'pl', 'cgi'], true)
			&& ($in_public_root || $in_uploads)) {
			$reasons[] = 'Shell or interpreter script in a web-accessible location';
			$severity = $severity === 'critical' ? 'critical' : 'high';
			$score = min($score, 52);
		}

		if (in_array($basename, ['.env', 'debug.log', 'error_log', 'wp-config.php.bak', 'wp-config.php.save', '.wp-config.php.swp'], true)) {
			$reasons[] = 'Sensitive configuration or log file in a readable location';
			$severity = $severity === 'critical' ? 'critical' : 'medium';
			$score = min($score, 66);
		}

		if ($reasons === []) {
			return;
		}

		// For data / script files, read a head and say in plain language what the
		// file actually does, so the admin is not left guessing from the name.
		$content_summary = '';
		$describe_exts = ['sql', 'sh', 'bash', 'zsh', 'ksh', 'py', 'pl', 'cgi', 'bak', 'old', 'orig', 'save', 'swp', 'zip', 'gz', 'tgz', 'tar', 'bz2', 'xz', '7z', 'rar'];

		if (in_array($extension, $describe_exts, true)) {
			// A .sql dump front-loads its schema + the users table, so read further
			// into it than a script needs.
			$read = $extension === 'sql' ? 786432 : 131072;
			$head = (string) @file_get_contents($path, false, null, 0, $read);
			$desc = Freesiem_Threat_Signatures::describe_data_file($head, $extension, $basename, $size);
			$content_summary = (string) ($desc['summary'] ?? '');
			$desc_flags = (array) ($desc['flags'] ?? []);

			if (!empty($desc['danger'])) {
				$reasons[] = 'Its contents perform high-risk operations';
				$severity = 'critical';
				$score = min($score, 24);
			} elseif (in_array('empty', $desc_flags, true)) {
				// An empty "dump" / "backup" is inert. Note it, but do not cry wolf.
				$severity = $severity === 'critical' ? $severity : 'low';
				$score = max($score, 88);
			} elseif (array_intersect(['contains_credentials', 'contains_secrets'], $desc_flags) !== []) {
				$severity = $severity === 'critical' ? 'critical' : 'high';
				$score = min($score, 40);
			}
		}

		$abspath_root = wp_normalize_path(untrailingslashit(ABSPATH));
		$full_path = wp_normalize_path($path);

		$this->add_finding($state, [
			'finding_key' => 'deep_fsheur_' . md5($rel . implode('|', $reasons)),
			'category' => 'filesystem',
			'severity' => $severity,
			'title' => 'Suspicious file on disk',
			'description' => $content_summary !== ''
				? sprintf('%s: %s. What it contains: %s', $rel, implode('; ', $reasons), $content_summary)
				: sprintf('%s: %s', $rel, implode('; ', $reasons)),
			'recommendation' => sprintf(
				'Full path: %s (WordPress root: %s). Confirm whether this file is expected. If not, remove it and review access logs for how it arrived.',
				$full_path,
				$abspath_root
			),
			'evidence' => [
				'path' => $rel,
				'full_path' => $full_path,
				'extension' => $extension,
				'size' => $size,
				'reasons' => $reasons,
				'content_summary' => $content_summary,
				'writable' => is_writable($path),
			],
			'score' => $score,
		]);
	}

	/**
	 * A harmless directory-listing guard — the tiny index.php that WordPress core
	 * and countless plugins (WPForms, Astra, ...) drop into their own upload
	 * subfolders to stop directory enumeration. Either the empty "Silence is
	 * golden" stub, or one whose only code is a 404 / response-code / exit call.
	 * Malware planted in an uploads index.php wants to run, not to 404.
	 */
	private function is_directory_index_stub(string $path, string $basename, int $size): bool
	{
		if ($basename !== 'index.php' || $size > 512) {
			return false;
		}

		$contents = (string) @file_get_contents($path, false, null, 0, 512);

		// Strip PHP tags, comments, then neutralise quoted strings and whitespace.
		$code = (string) preg_replace(
			['~<\?php~i', '~<\?=?~', '~\?>~', '~//[^\r\n]*~', '~#[^\r\n]*~', '~/\*.*?\*/~s'],
			'',
			$contents
		);
		$code = (string) preg_replace('~([\'"]).*?\1~s', "''", $code);
		$code = (string) preg_replace('~\s+~', '', $code);

		if ($code === '') {
			return true;
		}

		// Remove the handful of calls a listing guard is allowed to make. Each
		// argument list must be paren-free, so a nested call like
		// exit(shell_exec(...)) is deliberately left behind and still flagged.
		$code = (string) preg_replace(
			'~(?:header|http_response_code|status_header|nocache_headers)\([^()]*\);|(?:exit|die)(?:\([^()]*\))?;~',
			'',
			$code
		);
		$code = (string) str_replace(["\$_SERVER['']", '.', ';'], '', $code);

		return $code === '';
	}

	// ---------------------------------------------------------------------
	// Phase: integrity
	// ---------------------------------------------------------------------

	private function step_integrity(array &$state): void
	{
		$cursor = is_array($state['integrity_cursor'] ?? null) ? $state['integrity_cursor'] : ['stage' => 'core', 'index' => 0, 'plugin_index' => 0];
		$stage = (string) ($cursor['stage'] ?? 'core');
		$prefs = is_array($state['prefs'] ?? null) ? $state['prefs'] : [];

		if ($stage === 'core') {
			if (empty($prefs['scan_core_integrity']) || $this->integrity_core_step($state, $cursor)) {
				$cursor = ['stage' => 'core_extra', 'index' => 0, 'plugin_index' => 0];
			}
		} elseif ($stage === 'core_extra') {
			if (empty($prefs['scan_core_integrity'])) {
				$cursor['stage'] = 'plugins';
			} else {
				$this->integrity_core_extra_step($state);
				$cursor['stage'] = 'plugins';
			}
		} elseif ($stage === 'plugins') {
			if (empty($prefs['scan_plugin_integrity']) || $this->integrity_plugins_step($state, $cursor)) {
				$cursor = ['stage' => 'dropins', 'index' => 0, 'plugin_index' => 0];
			}
		} elseif ($stage === 'dropins') {
			$this->integrity_dropins_step($state);
			$cursor['stage'] = 'wpconfig';
		} elseif ($stage === 'wpconfig') {
			$this->integrity_wpconfig_step($state);
			$cursor['stage'] = 'self';
		} elseif ($stage === 'self') {
			$this->integrity_self_step($state);
			$cursor['stage'] = 'done';
		} else {
			$state['phase'] = empty($prefs['scan_database']) ? 'done' : 'database';

			return;
		}

		$state['integrity_cursor'] = $cursor;
	}

	/**
	 * True only for an exact released WordPress version (6.9, 6.8.2). Nightly /
	 * alpha / beta / RC / -src builds have no published checksum manifest, and
	 * comparing against the nearest release's manifest just produces noise
	 * (files that build moved or does not ship reported as "missing" / "modified").
	 */
	private function is_released_version(): bool
	{
		return (bool) preg_match('/^\d+\.\d+(?:\.\d+)?$/', (string) get_bloginfo('version'));
	}

	/**
	 * Is $path a file that byte-matches its official WordPress.org checksum?
	 * Covers WordPress core and wp.org-hosted plugins. Results are memoised per
	 * request; the underlying checksum fetches are transient-cached.
	 */
	private function is_vendor_verified(string $path, string $rel): bool
	{
		// --- WordPress core ---
		if (($rel === 'wp-settings.php' || str_starts_with($rel, 'wp-admin/') || str_starts_with($rel, 'wp-includes/'))
			&& $this->is_released_version()) {
			$sums = $this->core_checksums();

			if (isset($sums[$rel]) && hash_equals((string) $sums[$rel], (string) @md5_file($path))) {
				return true;
			}
		}

		// --- wp.org-hosted plugins ---
		$plugin_root = wp_normalize_path(untrailingslashit(WP_PLUGIN_DIR));
		$norm = wp_normalize_path($path);

		if (str_starts_with($norm, $plugin_root . '/')) {
			$after = substr($norm, strlen($plugin_root) + 1);
			$slash = strpos($after, '/');

			if ($slash !== false) {
				$slug = substr($after, 0, $slash);
				$inner = substr($after, $slash + 1);
				$sums = $this->plugin_checksums_for_slug($slug);

				if ($sums !== null) {
					$hashes = $sums[$inner] ?? null;
					$expected = is_array($hashes) ? (string) ($hashes['md5'] ?? '') : (string) $hashes;

					if ($expected !== '' && hash_equals($expected, (string) @md5_file($path))) {
						return true;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Checksums for an installed plugin by slug, resolving its version from its
	 * header. Memoised per request. Null when the plugin is not on wordpress.org.
	 */
	private function plugin_checksums_for_slug(string $slug): ?array
	{
		static $memo = [];

		if (array_key_exists($slug, $memo)) {
			return $memo[$slug];
		}

		$memo[$slug] = null;

		if ($slug === '' || $slug === FREESIEM_SENTINEL_SLUG) {
			return null;
		}

		$main = WP_PLUGIN_DIR . '/' . $slug . '/' . $slug . '.php';
		$version = '';

		if (is_readable($main) && function_exists('get_file_data')) {
			$data = get_file_data($main, ['Version' => 'Version']);
			$version = (string) ($data['Version'] ?? '');
		}

		if ($version === '') {
			// Fall back: any *.php in the plugin root with a Version header.
			foreach ((array) @glob(WP_PLUGIN_DIR . '/' . $slug . '/*.php') as $candidate) {
				if (function_exists('get_file_data')) {
					$data = get_file_data($candidate, ['Version' => 'Version']);

					if (!empty($data['Version'])) {
						$version = (string) $data['Version'];
						break;
					}
				}
			}
		}

		if ($version === '') {
			return null;
		}

		$memo[$slug] = $this->plugin_checksums($slug, $version);

		return $memo[$slug];
	}

	private function core_checksums(): array
	{
		$version = get_bloginfo('version');
		$locale = function_exists('get_locale') ? get_locale() : 'en_US';
		$key = 'freesiem_core_checksums_' . md5($version . '|' . $locale);
		$cached = get_transient($key);

		if (is_array($cached) && $cached !== []) {
			return $cached;
		}

		if (!function_exists('get_core_checksums') && is_readable(ABSPATH . 'wp-admin/includes/update.php')) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		if (!function_exists('get_core_checksums')) {
			return [];
		}

		$checksums = get_core_checksums($version, $locale);

		if (!is_array($checksums) || $checksums === []) {
			$checksums = function_exists('get_core_checksums') ? get_core_checksums($version, 'en_US') : false;
		}

		$checksums = is_array($checksums) ? $checksums : [];
		set_transient($key, $checksums, $checksums === [] ? 20 * MINUTE_IN_SECONDS : 12 * HOUR_IN_SECONDS);

		return $checksums;
	}

	private function integrity_core_step(array &$state, array &$cursor): bool
	{
		if (!$this->is_released_version()) {
			// Nightly / alpha / beta / RC / -src build — no authoritative manifest.
			return true;
		}

		$checksums = $this->core_checksums();

		if ($checksums === []) {
			return true;
		}

		$files = array_keys($checksums);
		$index = (int) ($cursor['index'] ?? 0);
		$slice = array_slice($files, $index, self::CORE_CHECK_BATCH);

		if ($slice === []) {
			return true;
		}

		$critical_files = ['wp-load.php', 'wp-settings.php', 'wp-blog-header.php', 'index.php', 'xmlrpc.php', 'wp-login.php', 'wp-cron.php', 'wp-mail.php', 'wp-trackback.php'];

		foreach ($slice as $file) {
			$expected = (string) $checksums[$file];
			$full = ABSPATH . $file;

			if (str_contains($file, '..')) {
				continue;
			}

			if (!file_exists($full)) {
				// Only flag a missing file that actually matters. The manifest for a
				// given version routinely lists optional/bundled files (default
				// themes, the php-ai-client vendor tree, locale data) that a slim or
				// slightly-off build legitimately doesn't ship — reporting each one
				// as "missing / possible tampering" is pure noise.
				if (in_array($file, $critical_files, true) || preg_match('#^wp-(admin|includes)/[^/]+\.php$#', $file)) {
					$this->add_finding($state, [
						'finding_key' => 'deep_core_missing_' . md5($file),
						'category' => 'core_integrity',
						'severity' => 'medium',
						'title' => 'A top-level WordPress core file is missing',
						'description' => sprintf('The core file %s is absent. If you did not remove it deliberately, reinstall WordPress %s.', $file, get_bloginfo('version')),
						'recommendation' => 'Reinstall WordPress core of the exact same version to restore the original files.',
						'evidence' => ['path' => $file],
						'score' => 68,
					]);
				}

				continue;
			}

			$state['counters']['core_files_checked']++;
			$actual = @md5_file($full);

			if (!is_string($actual) || hash_equals($expected, $actual)) {
				continue;
			}

			$state['counters']['core_files_modified']++;
			$is_critical = in_array($file, $critical_files, true) || preg_match('#^wp-includes/(load|functions|version|pluggable)\.php$#', $file);

			$this->add_finding($state, [
				'finding_key' => 'deep_core_modified_' . md5($file),
				'category' => 'core_integrity',
				'severity' => $is_critical ? 'critical' : 'high',
				'title' => 'WordPress core file does not match the official checksum',
				'description' => sprintf('%s differs from the official WordPress %s release. Core files should never be edited.', $file, get_bloginfo('version')),
				'recommendation' => 'Compare the file with a clean copy of this WordPress version. If you did not intentionally patch it, reinstall core and investigate for a compromise.',
				'evidence' => [
					'path' => $file,
					'expected_md5' => $expected,
					'actual_md5' => $actual,
				],
				'score' => $is_critical ? 26 : 45,
			]);
		}

		$cursor['index'] = $index + self::CORE_CHECK_BATCH;

		return $cursor['index'] >= count($files);
	}

	private function integrity_core_extra_step(array &$state): void
	{
		if (!$this->is_released_version()) {
			return;
		}

		$checksums = $this->core_checksums();

		if ($checksums === []) {
			return;
		}

		$known = [];

		foreach (array_keys($checksums) as $file) {
			$known[wp_normalize_path(ABSPATH . $file)] = 1;
		}

		$dirs = [
			untrailingslashit(ABSPATH) . '/wp-admin',
			untrailingslashit(ABSPATH) . '/wp-admin/includes',
			untrailingslashit(ABSPATH) . '/wp-includes',
		];

		foreach ($dirs as $dir) {
			if (!is_dir($dir) || !is_readable($dir)) {
				continue;
			}

			$items = @scandir($dir);

			if (!is_array($items)) {
				continue;
			}

			foreach ($items as $item) {
				if (!str_ends_with(strtolower($item), '.php')) {
					continue;
				}

				$full = wp_normalize_path($dir . '/' . $item);

				if (isset($known[$full]) || !is_file($full)) {
					continue;
				}

				$rel = $this->relative_path($full);
				$this->add_finding($state, [
					'finding_key' => 'deep_core_unknown_' . md5($rel),
					'category' => 'core_integrity',
					'severity' => 'critical',
					'title' => 'Unrecognized PHP file in a WordPress core directory',
					'description' => sprintf('%s is not part of the official WordPress distribution. Extra PHP files in wp-admin / wp-includes are a very common backdoor location.', $rel),
					'recommendation' => 'Inspect the file. Legitimate plugins never add files here — if you cannot attribute it, remove it and treat the site as compromised.',
					'evidence' => ['path' => $rel, 'size' => (int) @filesize($full)],
					'score' => 24,
				]);
			}
		}
	}

	private function integrity_plugins_step(array &$state, array &$cursor): bool
	{
		if (!function_exists('get_plugins') && is_readable(ABSPATH . 'wp-admin/includes/plugin.php')) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		if (!function_exists('get_plugins')) {
			return true;
		}

		$plugins = array_keys(get_plugins());
		$plugin_index = (int) ($cursor['plugin_index'] ?? 0);

		if (!isset($plugins[$plugin_index])) {
			return true;
		}

		$file = $plugins[$plugin_index];
		$cursor['plugin_index'] = $plugin_index + 1;

		$slug = strtok($file, '/');

		if (!is_string($slug) || $slug === '' || $slug === $file) {
			return false; // single-file plugin, no reliable slug/checksum
		}

		$data = get_plugin_data(WP_PLUGIN_DIR . '/' . $file, false, false);
		$version = (string) ($data['Version'] ?? '');

		if ($version === '') {
			return false;
		}

		$checksums = $this->plugin_checksums($slug, $version);

		if ($checksums === null) {
			return false; // premium / custom plugin — not on wordpress.org
		}

		$plugin_dir = wp_normalize_path(WP_PLUGIN_DIR . '/' . $slug);
		$modified = [];
		$checked = 0;

		foreach ($checksums as $rel_file => $hashes) {
			if ($checked >= 400) {
				break;
			}

			$expected = is_array($hashes) ? (string) ($hashes['md5'] ?? '') : (string) $hashes;

			if ($expected === '' || str_contains((string) $rel_file, '..')) {
				continue;
			}

			$full = $plugin_dir . '/' . $rel_file;
			$checked++;
			$state['counters']['plugin_files_checked']++;

			if (!is_file($full)) {
				continue;
			}

			$actual = @md5_file($full);

			if (is_string($actual) && !hash_equals($expected, $actual)) {
				$modified[] = (string) $rel_file;
				$state['counters']['plugin_files_modified']++;
			}
		}

		if ($modified !== []) {
			$sample = array_slice($modified, 0, 15);
			$this->add_finding($state, [
				'finding_key' => 'deep_plugin_modified_' . md5($slug . '|' . $version),
				'category' => 'plugin_integrity',
				'severity' => count($modified) > 3 ? 'high' : 'medium',
				'title' => sprintf('Plugin "%s" has modified files', $slug),
				'description' => sprintf('%d file(s) in %s %s do not match the official WordPress.org release.', count($modified), $slug, $version),
				'recommendation' => 'Reinstall the plugin from a clean source. If you did not deliberately customize it, scan those files for injected code.',
				'evidence' => [
					'path' => 'wp-content/plugins/' . $slug,
					'version' => $version,
					'modified_count' => count($modified),
					'modified_files' => $sample,
				],
				'score' => count($modified) > 3 ? 50 : 62,
			]);
		}

		return false;
	}

	private function plugin_checksums(string $slug, string $version): ?array
	{
		$key = 'freesiem_plugin_cs_' . md5($slug . '|' . $version);
		$cached = get_transient($key);

		if ($cached === 'none') {
			return null;
		}

		if (is_array($cached)) {
			return $cached;
		}

		$url = sprintf('https://api.wordpress.org/plugin-checksums/1.0/%s/%s.json', rawurlencode($slug), rawurlencode($version));
		$response = wp_remote_get($url, ['timeout' => 12]);

		if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
			set_transient($key, 'none', DAY_IN_SECONDS);

			return null;
		}

		$body = json_decode((string) wp_remote_retrieve_body($response), true);
		$files = is_array($body['files'] ?? null) ? $body['files'] : null;

		if ($files === null) {
			set_transient($key, 'none', DAY_IN_SECONDS);

			return null;
		}

		set_transient($key, $files, 7 * DAY_IN_SECONDS);

		return $files;
	}

	private function integrity_dropins_step(array &$state): void
	{
		$dropins = [
			'advanced-cache.php', 'object-cache.php', 'db.php', 'db-error.php', 'sunrise.php',
			'maintenance.php', 'fatal-error-handler.php', 'php-error.php', 'install.php',
		];

		foreach ($dropins as $dropin) {
			$full = WP_CONTENT_DIR . '/' . $dropin;

			if (!is_file($full) || !is_readable($full)) {
				continue;
			}

			$rel = $this->relative_path($full);
			$contents = (string) @file_get_contents($full, false, null, 0, self::MAX_READ_BYTES);

			$this->add_finding($state, [
				'finding_key' => 'deep_dropin_present_' . md5($rel),
				'category' => 'core_integrity',
				'severity' => 'low',
				'title' => sprintf('Drop-in present: %s', $dropin),
				'description' => sprintf('%s runs on every request before most of WordPress loads. Drop-ins are legitimate for caching / multisite but are also used for stealth persistence.', $rel),
				'recommendation' => 'Confirm this drop-in was installed by a caching or multisite plugin you trust. If not, remove it.',
				'evidence' => ['path' => $rel, 'size' => (int) @filesize($full), 'modified_time' => gmdate('c', (int) @filemtime($full))],
				'score' => 84,
			]);

			if ($contents !== '') {
				$this->match_signatures($contents, $rel, 'php', $state);
			}
		}
	}

	private function integrity_wpconfig_step(array &$state): void
	{
		$candidates = [ABSPATH . 'wp-config.php', dirname(ABSPATH) . '/wp-config.php'];

		foreach ($candidates as $config) {
			if (!is_file($config) || !is_readable($config)) {
				continue;
			}

			$rel = $this->relative_path($config);
			$contents = (string) @file_get_contents($config, false, null, 0, self::MAX_READ_BYTES);

			if ($contents === '') {
				return;
			}

			$this->match_signatures($contents, $rel === '' ? 'wp-config.php' : $rel, 'php', $state);

			if (preg_match('/\b(?:eval|assert|base64_decode|gzinflate|create_function|str_rot13)\s*\(/i', $contents)
				|| preg_match('/auto_prepend_file/i', $contents)) {
				$this->add_finding($state, [
					'finding_key' => 'deep_wpconfig_suspect_' . md5($rel),
					'category' => 'core_integrity',
					'severity' => 'critical',
					'title' => 'wp-config.php contains executable-code constructs',
					'description' => 'wp-config.php should only define constants and settings. Decoders or eval() here almost always mean the file was backdoored.',
					'recommendation' => 'Compare wp-config.php against wp-config-sample.php and your host backup. Remove any code that is not a define()/setting, and rotate database and salt keys.',
					'evidence' => ['path' => $rel === '' ? 'wp-config.php' : $rel],
					'score' => 20,
				]);
			}

			return;
		}
	}

	/**
	 * Verify freeSIEM Sentinel's own shipped files against checksums.json. A
	 * modified or missing file here means the plugin itself was tampered with —
	 * reported clearly rather than as a pile of signature matches against its own
	 * detection code.
	 */
	private function integrity_self_step(array &$state): void
	{
		$manifest = $this->self_manifest();

		if ($manifest === [] || !defined('FREESIEM_SENTINEL_PLUGIN_DIR')) {
			return;
		}

		$base = untrailingslashit(wp_normalize_path(FREESIEM_SENTINEL_PLUGIN_DIR));
		$modified = [];
		$missing = [];

		foreach ($manifest as $rel_file => $expected) {
			if (!is_string($rel_file) || str_contains($rel_file, '..') || !is_string($expected) || $expected === '') {
				continue;
			}

			$full = $base . '/' . $rel_file;

			if (!is_file($full)) {
				$missing[] = $rel_file;

				continue;
			}

			if (!hash_equals($expected, (string) @md5_file($full))) {
				$modified[] = $rel_file;
			}
		}

		if ($modified === [] && $missing === []) {
			return;
		}

		$state['counters']['plugin_files_modified'] += count($modified);

		$this->add_finding($state, [
			'finding_key' => 'deep_self_integrity_' . md5(FREESIEM_SENTINEL_VERSION),
			'category' => 'plugin_integrity',
			'severity' => 'critical',
			'title' => 'freeSIEM Sentinel\'s own files were modified',
			'description' => sprintf(
				'%d file(s) modified and %d missing versus the released freeSIEM Sentinel %s. If you did not edit the plugin yourself, its code has been tampered with and its scan results can no longer be trusted.',
				count($modified),
				count($missing),
				FREESIEM_SENTINEL_VERSION
			),
			'recommendation' => 'Reinstall freeSIEM Sentinel from a clean copy (Plugins → delete and re-add, or the built-in updater), then re-run the scan. Investigate how the files were changed.',
			'evidence' => [
				'path' => 'wp-content/plugins/' . FREESIEM_SENTINEL_SLUG,
				'version' => FREESIEM_SENTINEL_VERSION,
				'modified_files' => array_slice($modified, 0, 20),
				'missing_files' => array_slice($missing, 0, 20),
			],
			'score' => 18,
		]);
	}

	// ---------------------------------------------------------------------
	// Phase: database
	// ---------------------------------------------------------------------

	private function step_database(array &$state): void
	{
		$cursor = is_array($state['database_cursor'] ?? null) ? $state['database_cursor'] : ['stage' => 'users', 'offset' => 0];
		$stage = (string) ($cursor['stage'] ?? 'users');

		$order = ['users', 'registration', 'options', 'refs', 'cron', 'content'];

		switch ($stage) {
			case 'users':
				$this->db_check_users($state);
				break;
			case 'registration':
				$this->db_check_registration($state);
				break;
			case 'options':
				if (!$this->db_check_autoload_options($state, $cursor)) {
					$state['database_cursor'] = $cursor;

					return;
				}

				break;
			case 'refs':
				$this->db_check_active_refs($state);
				break;
			case 'cron':
				$this->db_check_cron($state);
				break;
			case 'content':
				$this->db_check_recent_content($state);
				break;
		}

		$next = array_search($stage, $order, true);

		if ($next === false || !isset($order[$next + 1])) {
			$state['phase'] = 'done';

			return;
		}

		$state['database_cursor'] = ['stage' => $order[$next + 1], 'offset' => 0];
	}

	private function db_check_users(array &$state): void
	{
		if (!function_exists('get_users')) {
			return;
		}

		$admins = get_users(['role' => 'administrator', 'fields' => ['ID', 'user_login', 'user_email', 'user_registered']]);

		$now = time();
		$cutoff = 30 * DAY_IN_SECONDS;
		$established = false;

		foreach ($admins as $u) {
			$ts = strtotime((string) ($u->user_registered ?? '')) ?: 0;

			if ($ts > 0 && ($now - $ts) >= $cutoff) {
				$established = true;
				break;
			}
		}

		// A recently-added admin only means something on a site that already has
		// an older admin. On a brand-new / freshly-migrated site every admin is
		// "recent" and flagging them all is noise.
		if ($established) {
			$recent = array_filter($admins, static function ($u) use ($now, $cutoff): bool {
				$ts = strtotime((string) ($u->user_registered ?? '')) ?: 0;

				return $ts > 0 && ($now - $ts) < $cutoff;
			});

			foreach (array_slice(array_values($recent), 0, 10) as $u) {
				$state['counters']['database_issues']++;
				$this->add_finding($state, [
					'finding_key' => 'deep_db_recent_admin_' . (int) $u->ID,
					'category' => 'database',
					'severity' => 'medium',
					'title' => 'Administrator account added recently',
					'description' => sprintf('User "%s" (%s) was given the administrator role on %s, on a site that already had an established admin.', $u->user_login, $u->user_email, $u->user_registered),
					'recommendation' => 'Confirm you created this account. Unexpected recent admins are the most common sign of a break-in — remove it and reset all admin passwords.',
					'evidence' => ['user_id' => (int) $u->ID, 'user_login' => (string) $u->user_login, 'registered' => (string) $u->user_registered],
					'score' => 60,
				]);
			}
		}

		foreach ($admins as $u) {
			if (!preg_match('/^[A-Za-z0-9 _.@\-]{1,60}$/', (string) $u->user_login)) {
				$state['counters']['database_issues']++;
				$this->add_finding($state, [
					'finding_key' => 'deep_db_weird_login_' . (int) $u->ID,
					'category' => 'database',
					'severity' => 'high',
					'title' => 'Administrator login name contains unusual characters',
					'description' => sprintf('Admin user ID %d has an unusual login ("%s"). Malware sometimes creates users whose names are hard to spot or type.', (int) $u->ID, $u->user_login),
					'recommendation' => 'Verify this account is legitimate; if not, delete it and audit recent admin activity.',
					'evidence' => ['user_id' => (int) $u->ID, 'user_login' => (string) $u->user_login],
					'score' => 52,
				]);
			}
		}
	}

	private function db_check_registration(array &$state): void
	{
		if ((int) get_option('users_can_register') === 1 && strtolower((string) get_option('default_role')) === 'administrator') {
			$state['counters']['database_issues']++;
			$this->add_finding($state, [
				'finding_key' => 'deep_db_open_admin_registration',
				'category' => 'database',
				'severity' => 'critical',
				'title' => 'Anyone can register as an administrator',
				'description' => 'Open registration is enabled and the default role for new users is "administrator". Any visitor can take full control of the site.',
				'recommendation' => 'Immediately set the default role to Subscriber (Settings → General), or disable open registration. Then review the user list for rogue admins.',
				'evidence' => ['users_can_register' => 1, 'default_role' => 'administrator'],
				'score' => 15,
			]);
		}
	}

	private function db_check_autoload_options(array &$state, array &$cursor): bool
	{
		global $wpdb;

		if (!isset($wpdb)) {
			return true;
		}

		$offset = (int) ($cursor['offset'] ?? 0);
		$limit = 200;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} WHERE autoload = 'yes' ORDER BY option_id ASC LIMIT %d OFFSET %d",
				$limit,
				$offset
			)
		);

		if (!is_array($rows) || $rows === []) {
			return true;
		}

		foreach ($rows as $row) {
			$value = (string) ($row->option_value ?? '');

			if ($value === '' || strlen($value) > 524288) {
				continue;
			}

			if (preg_match('/(?:eval|assert|create_function)\s*\(|base64_decode\s*\(|gzinflate\s*\(|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(|<script\b[^>]*>[^<]{0,400}(?:eval|unescape|fromCharCode)|<\?php/i', $value)) {
				$state['counters']['database_issues']++;
				$this->add_finding($state, [
					'finding_key' => 'deep_db_option_payload_' . md5((string) $row->option_name),
					'category' => 'database',
					'severity' => 'high',
					'title' => 'Autoloaded option contains code-like content',
					'description' => sprintf('The option "%s" loads on every page and contains PHP/JavaScript execution patterns. Options should hold data, not code.', (string) $row->option_name),
					'recommendation' => 'Inspect the option value. If it is an injected payload, delete the option and find how it was written (often a vulnerable plugin).',
					'evidence' => [
						'option_name' => (string) $row->option_name,
						'snippet' => $this->snippet($value, (int) (stripos($value, 'eval') ?: 0)),
						'length' => strlen($value),
					],
					'score' => 45,
				]);
			}
		}

		$cursor['offset'] = $offset + $limit;

		return $cursor['offset'] >= 4000 || count($rows) < $limit;
	}

	private function db_check_active_refs(array &$state): void
	{
		$active = (array) get_option('active_plugins', []);

		foreach ($active as $plugin_file) {
			if (!is_string($plugin_file) || $plugin_file === '') {
				continue;
			}

			if (!is_file(WP_PLUGIN_DIR . '/' . $plugin_file)) {
				$state['counters']['database_issues']++;
				$this->add_finding($state, [
					'finding_key' => 'deep_db_missing_active_plugin_' . md5($plugin_file),
					'category' => 'database',
					'severity' => 'medium',
					'title' => 'Active plugin file is missing from disk',
					'description' => sprintf('"%s" is listed in active_plugins but the file does not exist. This can be leftover corruption or a plugin that was deleted without deactivating.', $plugin_file),
					'recommendation' => 'Deactivate the stale entry from the Plugins screen, or reinstall the plugin if it is still needed.',
					'evidence' => ['plugin_file' => $plugin_file],
					'score' => 66,
				]);
			}
		}

		$template = (string) get_option('template');
		$stylesheet = (string) get_option('stylesheet');

		foreach (array_unique(array_filter([$template, $stylesheet])) as $theme_dir) {
			if (!is_dir(get_theme_root() . '/' . $theme_dir)) {
				$state['counters']['database_issues']++;
				$this->add_finding($state, [
					'finding_key' => 'deep_db_missing_theme_' . md5($theme_dir),
					'category' => 'database',
					'severity' => 'high',
					'title' => 'Active theme directory is missing',
					'description' => sprintf('The site is configured to use the theme "%s" but that directory does not exist under the theme root.', $theme_dir),
					'recommendation' => 'Reinstall the theme or switch to an installed theme. A missing active theme often means files were deleted by an attacker or a failed update.',
					'evidence' => ['theme' => $theme_dir],
					'score' => 55,
				]);
			}
		}
	}

	private function db_check_cron(array &$state): void
	{
		if (!function_exists('_get_cron_array')) {
			return;
		}

		$cron = _get_cron_array();

		if (!is_array($cron)) {
			return;
		}

		$orphans = [];

		foreach ($cron as $events) {
			if (!is_array($events)) {
				continue;
			}

			foreach (array_keys($events) as $hook) {
				$hook = (string) $hook;

				if ($hook === '' || has_action($hook)) {
					continue;
				}

				if (preg_match('/^[a-f0-9]{16,}$/i', $hook)
					|| preg_match('/(eval|base64|assshell|wp_[a-z0-9]{12,})/i', $hook)) {
					$orphans[] = $hook;
				}
			}
		}

		$orphans = array_values(array_unique($orphans));

		if ($orphans !== []) {
			$state['counters']['database_issues']++;
			$this->add_finding($state, [
				'finding_key' => 'deep_db_cron_orphans',
				'category' => 'database',
				'severity' => 'medium',
				'title' => 'Scheduled tasks with no registered handler and suspicious names',
				'description' => sprintf('%d scheduled cron event(s) point at hooks that nothing in the current code registers and whose names look randomly generated. Malware uses WP-Cron to re-infect a site.', count($orphans)),
				'recommendation' => 'Review these events (WP Crontrol plugin or wp-cli). Remove any you cannot tie to an installed plugin, then re-scan the filesystem.',
				'evidence' => ['hooks' => array_slice($orphans, 0, 20)],
				'score' => 56,
			]);
		}
	}

	private function db_check_recent_content(array &$state): void
	{
		global $wpdb;

		if (!isset($wpdb)) {
			return;
		}

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_content FROM {$wpdb->posts} WHERE post_status IN ('publish','draft','private') AND post_type IN ('post','page') ORDER BY post_modified DESC LIMIT %d",
				200
			)
		);

		if (!is_array($rows)) {
			return;
		}

		$hits = 0;

		foreach ($rows as $row) {
			if ($hits >= 10) {
				break;
			}

			$content = (string) ($row->post_content ?? '');

			if ($content === '') {
				continue;
			}

			if (preg_match('/<script[^>]*>[^<]{0,600}(?:eval\s*\(|unescape\s*\(|String\.fromCharCode|document\.write)|<iframe[^>]+src\s*=\s*["\']?(?:https?:)?\/\/[^"\'>\s]+["\']?[^>]*(?:width\s*=\s*["\']?0|style\s*=\s*["\'][^"\']*display\s*:\s*none)|base64_decode\s*\(/i', $content, $m, PREG_OFFSET_CAPTURE)) {
				$hits++;
				$state['counters']['database_issues']++;
				$this->add_finding($state, [
					'finding_key' => 'deep_db_post_injection_' . (int) $row->ID,
					'category' => 'database',
					'severity' => 'medium',
					'title' => 'Post or page content contains injected script markup',
					'description' => sprintf('Post ID %d ("%s") contains obfuscated <script>/<iframe> markup typical of content injection.', (int) $row->ID, (string) $row->post_title),
					'recommendation' => 'Edit the post and remove the injected markup. If several posts are affected, look for a compromised admin account or a vulnerable editor plugin.',
					'evidence' => [
						'post_id' => (int) $row->ID,
						'snippet' => $this->snippet($content, (int) ($m[0][1] ?? 0)),
					],
					'score' => 58,
				]);
			}
		}
	}

	// ---------------------------------------------------------------------
	// Finalize
	// ---------------------------------------------------------------------

	public function finalize(): void
	{
		$state = $this->get_state();

		if (empty($state)) {
			return;
		}

		$findings = array_values(is_array($state['findings'] ?? null) ? $state['findings'] : []);
		$counters = is_array($state['counters'] ?? null) ? $state['counters'] : [];
		$mode = (string) ($state['mode'] ?? 'deep');

		$findings = $this->soften_unverifiable_heuristics($findings, $counters);

		$metrics = [
			'mode' => $mode,
			'full' => !empty($state['full']),
			'files_scanned' => (int) ($counters['files_scanned'] ?? 0),
			'files_seen' => (int) ($counters['files_seen'] ?? 0),
			'bytes_scanned' => (int) ($counters['bytes_scanned'] ?? 0),
			'dirs_visited' => (int) ($counters['dirs_visited'] ?? 0),
			'malware_hits' => (int) ($counters['malware_hits'] ?? 0),
			'core_files_checked' => (int) ($counters['core_files_checked'] ?? 0),
			'core_files_modified' => (int) ($counters['core_files_modified'] ?? 0),
			'plugin_files_modified' => (int) ($counters['plugin_files_modified'] ?? 0),
			'database_issues' => (int) ($counters['database_issues'] ?? 0),
			'partial' => !empty($state['partial']),
			'partial_reason' => (string) ($state['partial_reason'] ?? ''),
			'started_at' => (string) ($state['started_at'] ?? ''),
			'finished_at' => (string) ($state['finished_at'] ?? freesiem_sentinel_get_iso8601_time()),
		];

		$merged_cache = $this->plugin->get_results()->merge_deep_scan($findings, $metrics);

		// Record the run against the FULL merged result set (deep findings +
		// the quick config-scan findings), so the history row and its drill-in
		// match what "Scan Results" shows for this run — not just the deep subset.
		$merged_findings = array_values(freesiem_sentinel_safe_array($merged_cache['local_findings'] ?? $findings));
		$this->plugin->get_results()->record_scan_run($mode === 'weekly' ? 'weekly' : 'deep', $merged_findings, $metrics);
		$this->plugin->push_local_findings_snapshot();

		if ($mode === 'weekly' && !empty(freesiem_sentinel_get_setting('scan_email_on_weekly', 1))) {
			freesiem_sentinel_send_scan_report_email([], 'weekly');
		}

		// Keep a slim record of the last run; drop the bulky work queue + findings.
		$state['phase'] = 'done';
		$state['findings'] = [];
		$state['dir_stack'] = [];
		$state['file_queue'] = [];
		$state['seen_dirs'] = [];
		$state['last_metrics'] = $metrics;
		$state['finished_at'] = $metrics['finished_at'];
		$state['updated_at'] = freesiem_sentinel_get_iso8601_time();

		$this->save_state($state);
	}

	/**
	 * Filename heuristics ("Random-looking PHP filename") exist as a backstop for
	 * files that are NOT checksum-verified. When the scan managed to verify zero
	 * vendor / core files — WordPress.org checksums unreachable, an impossible
	 * core version, an offline box — that backstop instead fires across whole
	 * legitimate third-party trees (jetpack-autoloader, symfony polyfills, ...).
	 *
	 * In that state, drop the purely name-based "high" findings to "low" and
	 * replace them with a single note, so the run does not report hundreds of
	 * highs that are all verification noise. Findings with any harder reason
	 * (executable in uploads, web-shell name, exposed backup) are left alone.
	 */
	private function soften_unverifiable_heuristics(array $findings, array $counters): array
	{
		$verified = (int) ($counters['vendor_verified'] ?? 0);
		$seen = (int) ($counters['files_seen'] ?? 0);

		if ($verified > 0 || $seen < 200) {
			return $findings;
		}

		$softened = 0;
		$soft_reasons = ['Random-looking PHP filename'];

		foreach ($findings as &$finding) {
			if (($finding['category'] ?? '') !== 'filesystem' || ($finding['title'] ?? '') !== 'Suspicious file on disk') {
				continue;
			}

			$reasons = freesiem_sentinel_safe_array($finding['evidence']['reasons'] ?? []);

			if ($reasons === [] || array_diff($reasons, $soft_reasons) !== []) {
				continue;
			}

			$finding['severity'] = 'low';
			$finding['description'] .= ' (Downgraded: vendor file verification was unavailable this scan, so a name-based match alone is not reliable.)';
			$softened++;
		}
		unset($finding);

		if ($softened > 0) {
			$findings[] = [
				'finding_key' => 'deep_verification_unavailable',
				'category' => 'filesystem',
				'severity' => 'info',
				'title' => 'Vendor file verification was unavailable',
				'description' => sprintf('The scan could not verify any core or plugin file against WordPress.org checksums (unreachable, or the reported WordPress version has no published manifest). %d filename-heuristic finding(s) were downgraded because a name-based match cannot be trusted without a known-good baseline.', $softened),
				'recommendation' => 'Confirm the site can reach api.wordpress.org and that its WordPress version is a real release, then run the scan again.',
				'evidence' => ['files_seen' => $seen, 'downgraded' => $softened],
				'score' => 90,
			];
		}

		return $findings;
	}

	// ---------------------------------------------------------------------
	// Progress / presentation
	// ---------------------------------------------------------------------

	public function progress(): array
	{
		$state = $this->get_state();

		if (empty($state)) {
			return ['running' => false, 'phase' => 'idle', 'percent' => 0, 'label' => ''];
		}

		$phase = (string) ($state['phase'] ?? 'done');
		$counters = is_array($state['counters'] ?? null) ? $state['counters'] : [];
		$percent = max($this->percent_from_state($state), (int) ($state['progress_floor'] ?? 0));

		$labels = [
			'filesystem' => __('Scanning file contents', 'freesiem-sentinel'),
			'integrity' => __('Verifying core & plugin checksums', 'freesiem-sentinel'),
			'database' => __('Inspecting the database', 'freesiem-sentinel'),
			'done' => __('Complete', 'freesiem-sentinel'),
		];

		return [
			'running' => $phase !== 'done',
			'stalled' => $this->is_stalled(),
			'phase' => $phase,
			'mode' => (string) ($state['mode'] ?? 'deep'),
			'full' => !empty($state['full']),
			'percent' => (int) max(0, min(100, $percent)),
			'label' => $labels[$phase] ?? $phase,
			'files_scanned' => (int) ($counters['files_scanned'] ?? 0),
			'files_seen' => (int) ($counters['files_seen'] ?? 0),
			'malware_hits' => (int) ($counters['malware_hits'] ?? 0),
			'started_at' => (string) ($state['started_at'] ?? ''),
			'updated_at' => (string) ($state['updated_at'] ?? ''),
			'finished_at' => (string) ($state['finished_at'] ?? ''),
			'partial' => !empty($state['partial']),
		];
	}

	private function percent_from_state(array $state): int
	{
		$phase = (string) ($state['phase'] ?? 'done');

		if ($phase === 'done') {
			return 100;
		}

		if ($phase === 'filesystem') {
			// No reliable total mid-walk, so use a monotonic curve on files seen:
			// it only ever grows and asymptotically approaches the 60% mark.
			$seen = (int) ($state['counters']['files_seen'] ?? 0);

			return (int) round(60 * (1 - 1 / (1 + $seen / 3500)));
		}

		if ($phase === 'integrity') {
			$stage = (string) ($state['integrity_cursor']['stage'] ?? 'core');

			return ['core' => 62, 'core_extra' => 72, 'plugins' => 76, 'dropins' => 82, 'wpconfig' => 84, 'self' => 85, 'done' => 86][$stage] ?? 70;
		}

		$stage = (string) ($state['database_cursor']['stage'] ?? 'users');

		return ['users' => 87, 'registration' => 89, 'options' => 91, 'refs' => 94, 'cron' => 96, 'content' => 98][$stage] ?? 90;
	}

	// ---------------------------------------------------------------------
	// Internals
	// ---------------------------------------------------------------------

	private function add_finding(array &$state, array $finding): void
	{
		$key = (string) ($finding['finding_key'] ?? '');

		if ($key === '') {
			$key = 'deep_' . md5(wp_json_encode($finding));
			$finding['finding_key'] = $key;
		}

		if (isset($state['findings'][$key])) {
			return;
		}

		$cap = empty($state['full']) ? self::MAX_FINDINGS : self::MAX_FINDINGS_FULL;

		if (count($state['findings']) >= $cap) {
			$state['partial'] = true;
			$state['partial_reason'] = $state['partial_reason'] ?: 'finding_cap';

			return;
		}

		$finding['severity'] = freesiem_sentinel_normalize_severity((string) ($finding['severity'] ?? 'info'));
		$finding['detected_at'] = freesiem_sentinel_get_iso8601_time();
		$finding['evidence'] = is_array($finding['evidence'] ?? null) ? $finding['evidence'] : [];
		$state['findings'][$key] = $finding;
	}

	private function snippet(string $contents, int $offset): string
	{
		$start = max(0, $offset - 80);
		$window = (string) substr($contents, $start, 280);
		// Strip control characters (keep tab/newline) and collapse whitespace so the
		// snippet is safe and compact to store and render.
		$window = (string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/', ' ', $window);
		$window = trim((string) preg_replace('/\s+/', ' ', $window));

		// A polyglot / binary match window carries bytes that are not valid UTF-8.
		// Left raw they make the whole scan-state option fail to persist (silently,
		// on a utf8mb4 column), losing every finding in the run. Reduce anything
		// that is not clean UTF-8 to printable ASCII.
		if (!(function_exists('mb_check_encoding') && mb_check_encoding($window, 'UTF-8'))) {
			$window = (string) preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '.', $window);
		}

		return function_exists('mb_substr') && mb_check_encoding($window, 'UTF-8')
			? (string) mb_substr($window, 0, 240, 'UTF-8')
			: substr($window, 0, 240);
	}

	private function save_state(array $state): void
	{
		update_option(self::STATE_OPTION, $this->scrub_utf8($state), false);
	}

	/**
	 * Belt-and-suspenders: guarantee every string in the state is valid UTF-8
	 * before it reaches update_option(). One non-UTF-8 byte (a weird filename, a
	 * binary match snippet) otherwise silently fails the DB write and the scan
	 * loses all progress and findings for the run.
	 *
	 * @param mixed $value
	 * @return mixed
	 */
	private function scrub_utf8($value)
	{
		if (is_array($value)) {
			$out = [];

			foreach ($value as $key => $item) {
				$out[$key] = $this->scrub_utf8($item);
			}

			return $out;
		}

		if (is_string($value) && $value !== ''
			&& !(function_exists('mb_check_encoding') && mb_check_encoding($value, 'UTF-8'))) {
			return (string) preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '.', $value);
		}

		return $value;
	}

	private function memory_ceiling(): int
	{
		$parse = static function ($value): int {
			$value = trim((string) $value);

			if ($value === '' || $value === '-1' || !function_exists('wp_convert_hr_to_bytes')) {
				return 0;
			}

			return (int) wp_convert_hr_to_bytes($value);
		};

		// Guard against the REAL, PHP-enforced limit. The scan runs in an admin /
		// cron request that has already raised the limit toward WP_MAX_MEMORY_LIMIT
		// (256M by default) — NOT the 40M front-end WP_MEMORY_LIMIT, whose 32M
		// guard would abort the scan after a handful of files.
		$limit = $parse(ini_get('memory_limit'));

		if ($limit <= 0 && defined('WP_MAX_MEMORY_LIMIT')) {
			$limit = $parse(WP_MAX_MEMORY_LIMIT);
		}

		if ($limit <= 0) {
			$limit = 256 * MB_IN_BYTES;
		}

		return (int) ($limit * 0.8);
	}

	private function resolve_preferences(array $options): array
	{
		$settings = freesiem_sentinel_get_settings();
		$saved = freesiem_sentinel_safe_array($settings['scan_preferences'] ?? []);
		$prefs = wp_parse_args($options, $saved);

		$intensity = in_array((string) ($prefs['scan_intensity'] ?? 'balanced'), ['gentle', 'balanced', 'thorough'], true)
			? (string) $prefs['scan_intensity']
			: 'balanced';

		$excludes = $prefs['exclude_paths'] ?? [];

		if (is_string($excludes)) {
			$excludes = preg_split('/[\r\n,]+/', $excludes) ?: [];
		}

		$excludes = array_values(array_filter(array_map(static function ($p): string {
			return trim(ltrim((string) $p, '/'));
		}, is_array($excludes) ? $excludes : [])));

		$scan_uploads_deep = !array_key_exists('scan_uploads_deep', $prefs) || !empty($prefs['scan_uploads_deep']);

		if (!$scan_uploads_deep) {
			$uploads = wp_get_upload_dir();
			$uploads_rel = $this->relative_path((string) ($uploads['basedir'] ?? WP_CONTENT_DIR . '/uploads'));

			if ($uploads_rel !== '') {
				$excludes[] = $uploads_rel;
			}
		}

		return [
			'scan_malware' => !empty($prefs['scan_malware']),
			'scan_core_integrity' => !empty($prefs['scan_core_integrity']),
			'scan_plugin_integrity' => !empty($prefs['scan_plugin_integrity']),
			'scan_database' => !empty($prefs['scan_database']),
			'scan_uploads_deep' => $scan_uploads_deep,
			'scan_intensity' => $intensity,
			'throttle_us' => max(-1, min(200000, (int) ($prefs['throttle_us'] ?? -1))),
			'max_depth' => max(1, min(20, (int) ($prefs['max_depth'] ?? 12))),
			'exclude_paths' => $excludes,
		];
	}

	private function resolve_budget(string $context): array
	{
		$state = $this->get_state();
		$prefs = is_array($state['prefs'] ?? null) ? $state['prefs'] : $this->resolve_preferences([]);
		$intensity = (string) ($prefs['scan_intensity'] ?? 'balanced');

		// A full sweep should not crawl at the slowest pace.
		if (!empty($state['full']) && $intensity === 'gentle') {
			$intensity = 'balanced';
		}

		$base = match ($intensity) {
			'gentle' => ['files' => 400, 'seconds' => 8.0, 'throttle_us' => 20000, 'batch' => 10],
			'thorough' => ['files' => 3000, 'seconds' => 25.0, 'throttle_us' => 2000, 'batch' => 50],
			default => ['files' => 1200, 'seconds' => 12.0, 'throttle_us' => 8000, 'batch' => 20],
		};

		if (isset($prefs['throttle_us']) && (int) $prefs['throttle_us'] >= 0) {
			$base['throttle_us'] = (int) $prefs['throttle_us'];
		}

		if ($context === 'foreground') {
			// Just enough to show immediate progress; the Scan screen's poller and
			// WP-Cron carry the rest so the button returns quickly.
			$base['files'] *= 2;
			$base['seconds'] = min(max($base['seconds'], 12.0), 15.0);
		}

		return $base;
	}

	private function scan_targets(array $prefs): array
	{
		// The WordPress root already contains wp-admin / wp-includes / wp-content
		// (and therefore plugins, themes, uploads), so seeding it alone covers a
		// standard install without scanning any subtree twice. Extra entries are
		// added only for directories that can legitimately live outside the root.
		$candidates = [
			['label' => 'WordPress Root', 'path' => untrailingslashit(ABSPATH)],
			['label' => 'wp-content', 'path' => untrailingslashit(WP_CONTENT_DIR)],
			['label' => 'plugins', 'path' => untrailingslashit(WP_PLUGIN_DIR)],
			['label' => 'themes', 'path' => untrailingslashit((string) get_theme_root())],
		];

		if (defined('WPMU_PLUGIN_DIR')) {
			$candidates[] = ['label' => 'mu-plugins', 'path' => untrailingslashit(WPMU_PLUGIN_DIR)];
		}

		$normalized = [];

		foreach ($candidates as $candidate) {
			$path = wp_normalize_path((string) $candidate['path']);

			if ($path === '' || !is_dir($path)) {
				continue;
			}

			$normalized[$path] = (string) $candidate['label'];
		}

		// Drop any path that is contained within another selected path.
		$paths = array_keys($normalized);
		$targets = [];

		foreach ($paths as $path) {
			$contained = false;

			foreach ($paths as $other) {
				if ($other !== $path && str_starts_with($path . '/', $other . '/')) {
					$contained = true;
					break;
				}
			}

			if (!$contained) {
				$targets[] = ['label' => $normalized[$path], 'path' => $path];
			}
		}

		return $targets;
	}

	private function should_skip_directory(string $basename, string $path): bool
	{
		$basename = strtolower($basename);

		if (in_array($basename, ['.git', '.svn', '.hg', '.bzr', 'node_modules'], true)) {
			return true;
		}

		// freeSIEM Sentinel's own directory: only skip the whole subtree when we
		// have NO self-checksum manifest to tell a pristine copy of our own code
		// (which legitimately contains signature strings like "coinhive" and
		// "c99shell") from a tampered one. That is the case for a symlinked dev
		// checkout. A real release ships checksums.json, and scan_file() then
		// verifies each of our files individually instead of skipping them.
		if (defined('FREESIEM_SENTINEL_PLUGIN_DIR') && $this->self_manifest() === []) {
			$self = untrailingslashit(wp_normalize_path(FREESIEM_SENTINEL_PLUGIN_DIR));
			$here = untrailingslashit(wp_normalize_path($path));

			if ($here === $self || str_starts_with($here . '/', $self . '/')) {
				return true;
			}
		}

		$normalized = $this->relative_path($path);

		return str_contains($normalized, 'synchy-backups')
			|| str_contains($normalized, '/backups/')
			|| str_ends_with($normalized, '/backups');
	}

	private function is_excluded(string $relative, array $excludes): bool
	{
		if ($excludes === []) {
			return false;
		}

		$relative = ltrim($relative, '/');

		foreach ($excludes as $needle) {
			$needle = trim(ltrim((string) $needle, '/'), '/');

			if ($needle !== '' && ($relative === $needle || str_starts_with($relative, $needle . '/'))) {
				return true;
			}
		}

		return false;
	}

	private function relative_path(string $path): string
	{
		$path = wp_normalize_path($path);
		$root = untrailingslashit(wp_normalize_path(ABSPATH));

		if ($path === $root) {
			return '';
		}

		if (str_starts_with($path, $root . '/')) {
			return ltrim(substr($path, strlen($root)), '/');
		}

		return ltrim($path, '/');
	}

	/**
	 * If $path is a file inside freeSIEM Sentinel's own plugin directory, return
	 * its path relative to that directory (matching checksums.json keys);
	 * otherwise null.
	 */
	private function self_relative_path(string $path): ?string
	{
		if (!defined('FREESIEM_SENTINEL_PLUGIN_DIR')) {
			return null;
		}

		$base = untrailingslashit(wp_normalize_path(FREESIEM_SENTINEL_PLUGIN_DIR));
		$path = wp_normalize_path($path);

		if (!str_starts_with($path, $base . '/')) {
			return null;
		}

		return ltrim(substr($path, strlen($base)), '/');
	}

	/**
	 * The plugin's own release checksum manifest ({ "includes/foo.php": "<md5>" }),
	 * written into checksums.json by bin/build-release.sh. Absent from a symlinked
	 * dev checkout — callers treat [] as "cannot verify our own files".
	 */
	private function self_manifest(): array
	{
		static $cache = null;

		if (is_array($cache)) {
			return $cache;
		}

		$cache = [];

		if (!defined('FREESIEM_SENTINEL_PLUGIN_DIR')) {
			return $cache;
		}

		$file = untrailingslashit(wp_normalize_path(FREESIEM_SENTINEL_PLUGIN_DIR)) . '/checksums.json';

		if (!is_readable($file)) {
			return $cache;
		}

		$decoded = json_decode((string) @file_get_contents($file), true);

		if (is_array($decoded)) {
			$cache = array_filter($decoded, 'is_string');
		}

		return $cache;
	}
}
