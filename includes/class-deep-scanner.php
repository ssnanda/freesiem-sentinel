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

	/**
	 * Set by scan_file() while scanning a file that lives inside freeSIEM
	 * Sentinel's own plugin directory but is NOT byte-identical to (or is absent
	 * from) the release checksum manifest. add_finding() reads it to reframe any
	 * finding raised against such a file: it is not "injected malware in an
	 * unknown file" — it is an unrecognized file sitting inside our own plugin,
	 * which means either a development copy was deployed (our own tests/ ship
	 * signature-shaped fixtures) or a file was planted in our directory.
	 *
	 * @var array{rel:string,self_rel:string}|null
	 */
	private ?array $self_file_context = null;

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
			$this->self_file_context = null;

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

				if ($this->is_secondary_wp_root($child)) {
					$this->flag_secondary_wp_root($child, $state);
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
		$this->self_file_context = null;

		if ($self_rel !== null) {
			$manifest = $this->self_manifest();
			$expected = $manifest[$self_rel] ?? '';

			if ($expected !== '' && hash_equals($expected, (string) @md5_file($path))) {
				return; // our own file, unchanged since release — nothing to scan
			}

			// Fall through: modified or unrecognized file inside our own plugin.
			// integrity_self_step() reports manifest tampering; here we still let
			// the signature scan run so an injected payload is caught too — but
			// add_finding() reframes whatever it raises, because the honest story
			// is "unrecognized file inside freeSIEM Sentinel", not "malware in a
			// random file". Only meaningful when we actually have a manifest to
			// compare against (a real release, not a symlinked dev checkout).
			if ($manifest !== []) {
				$this->self_file_context = ['rel' => $rel, 'self_rel' => $self_rel];
			}
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
		$this->check_marker_file($path, $rel, $basename, $extension, $size, $state);

		$mode = Freesiem_Threat_Signatures::scan_mode($basename, $extension);

		// A file whose name / extension says "not code" may still be executable
		// PHP — a shell renamed shell.php.bak, avatar.png, license.old, or with no
		// extension at all. Peek the head; if it opens a PHP tag, pull it into the
		// scan as PHP and record why it looked wrong.
		$disguised_php = false;

		if ($mode === 'skip' || $mode === 'peek') {
			$head = (string) @file_get_contents($path, false, null, 0, self::PEEK_BYTES);

			if ($head !== '' && $this->looks_like_php_source($head)) {
				$disguised_php = true;

				// Images already get the polyglot signatures via 'peek'; the
				// extra "not named as PHP" finding is for everything else.
				if (!in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'webp', 'svg'], true)) {
					$this->flag_disguised_php($rel, $basename, $extension, $size, $state);
				}

				if ($mode === 'skip') {
					$mode = 'full';
				}
			}
		}

		if ($mode === 'skip') {
			return;
		}

		$native_class = $mode === 'peek' ? 'peek' : Freesiem_Threat_Signatures::classify($basename, $extension);
		$is_code_class = $disguised_php || in_array($native_class, ['php', 'js', 'html', 'htaccess'], true);

		if ($mode === 'full' && $size > self::MAX_READ_BYTES) {
			// A giant .sql / .xml / .txt is covered by the filename heuristics and
			// describe_data_file(); skipping the content scan is fine. A giant
			// CODE file is a red flag on its own — an attacker pads a shell so the
			// scanner walks past it. Read a head + tail window and scan that.
			if (!$is_code_class) {
				return;
			}

			$contents = $this->read_head_and_tail($path, $size);
			$this->add_finding($state, [
				'finding_key' => 'deep_oversized_code_' . md5($rel),
				'category' => 'malware',
				'severity' => 'low',
				'title' => 'Unusually large code file',
				'description' => sprintf('%s is %s — far larger than hand-written source. Large code files are used to bury a payload past a scanner\'s read limit. Only the first and last portions were signature-scanned.', $rel, size_format($size)),
				'recommendation' => 'Open the file and confirm it is a legitimate generated/minified asset. If you cannot account for its size, treat it as suspicious.',
				'evidence' => ['path' => $rel, 'size' => $size, 'class' => $native_class],
				'score' => 80,
			]);
		} else {
			$length = $mode === 'peek' ? self::PEEK_BYTES : self::MAX_READ_BYTES;

			// A disguised shell hides behind a non-PHP name precisely so it is
			// only peeked; read it in full so the PHP signatures see all of it.
			if ($disguised_php && $mode === 'peek') {
				$length = self::MAX_READ_BYTES;
			}

			$contents = @file_get_contents($path, false, null, 0, $length);
		}

		if (!is_string($contents) || $contents === '') {
			return;
		}

		$state['counters']['files_scanned']++;
		$state['counters']['bytes_scanned'] += strlen($contents);

		// Signature classes to run: the file's native class, plus 'php' whenever
		// the bytes contain a PHP open tag in a file not already classed as PHP.
		$classes = [$native_class];

		if ($native_class !== 'php' && ($disguised_php || str_contains($contents, '<?php') || str_contains($contents, '<?='))) {
			$classes[] = 'php';
		}

		if (in_array('php', $classes, true)) {
			$this->score_obfuscation($contents, $rel, $size, $disguised_php, $state);
		}

		foreach (array_unique($classes) as $class) {
			$this->match_signatures($contents, $rel, $class, $state, '', $size);
		}
	}

	/**
	 * Does this file's head look like PHP source (not just an incidental "<?"
	 * in XML/SVG)? Used to catch a shell hiding behind a non-PHP name.
	 */
	private function looks_like_php_source(string $head): bool
	{
		return (bool) preg_match('~<\?php[\s\r\n(]|<\?=|<\?php$|<script\s+language\s*=\s*[\'"]?php~i', $head);
	}

	/**
	 * Read up to MAX_READ_BYTES from the start of a file plus the last ~512 KB,
	 * joined, so an oversized file is still partly signature-scanned.
	 */
	private function read_head_and_tail(string $path, int $size): string
	{
		$tail_len = 524288;
		$head_len = max(0, self::MAX_READ_BYTES - $tail_len);
		$head = (string) @file_get_contents($path, false, null, 0, $head_len);
		$tail = '';

		if ($size > $head_len + $tail_len) {
			$tail = (string) @file_get_contents($path, false, null, $size - $tail_len, $tail_len);
		}

		return $tail === '' ? $head : $head . "\n/* …freeSIEM: oversized-file gap… */\n" . $tail;
	}

	/**
	 * Executable PHP living in a file that is NOT named as PHP. Severity scales
	 * with how web-reachable and how disguised it is.
	 */
	private function flag_disguised_php(string $rel, string $basename, string $extension, int $size, array &$state): void
	{
		$in_uploads = str_starts_with($rel, $this->relative_path(WP_CONTENT_DIR . '/uploads'));
		$in_public_root = !str_contains(trim($rel, '/'), '/');
		$doc_ext = in_array($extension, ['txt', 'md', 'markdown', 'rst', 'log', 'json', 'xml', 'csv', 'html', 'htm', 'po', 'pot'], true);
		$backupish = in_array($extension, ['bak', 'old', 'orig', 'save', 'sav', 'tmp', 'temp', 'swp', 'suspected', 'disabled', 'off', '_', '1', '2', 'txt2', 'bkp', 'copy'], true)
			|| (bool) preg_match('#\.(?:php\d?|phtml|phar)[._~-]#i', $basename);

		// A doc / data file that merely contains a PHP open tag (a code sample in
		// a changelog, an example in a readme) is common and benign. Don't raise
		// a name-based finding for those — the PHP signature + obfuscation scan
		// still runs on the contents and will flag a real payload with high
		// confidence. Only the disguises that have no innocent explanation get a
		// finding here.
		if ($doc_ext) {
			return;
		}

		if ($backupish || $extension === '') {
			$severity = ($in_uploads || $in_public_root) ? 'critical' : 'high';
			$score = ($in_uploads || $in_public_root) ? 22 : 40;
			$why = $extension === ''
				? 'It has no file extension but its contents are executable PHP.'
				: 'Its extension marks it as a backup / disabled copy, but its contents are executable PHP — a common way to park a shell where a scanner will not look.';
		} else {
			$severity = ($in_uploads || $in_public_root) ? 'high' : 'medium';
			$score = ($in_uploads || $in_public_root) ? 44 : 60;
			$why = sprintf('Its extension (.%s) does not indicate PHP, but its contents are executable PHP.', $extension);
		}

		$this->add_finding($state, [
			'finding_key' => 'deep_disguised_php_' . md5($rel),
			'category' => 'malware',
			'severity' => $severity,
			'title' => 'Executable PHP in a file that is not named as PHP',
			'description' => sprintf('%s: %s', $rel, $why),
			'recommendation' => 'Download and inspect the file offline. If it is not a deliberate, documented code sample, treat it as a planted payload: quarantine it and review access logs.',
			'evidence' => ['path' => $rel, 'extension' => $extension, 'size' => $size],
			'score' => $score,
		]);
	}

	/**
	 * Signature-independent obfuscation scoring. Catches a novel or heavily
	 * disguised shell that trips no specific pattern, by looking at structural
	 * tells: a payload appended after the "real" file, code after
	 * __halt_compiler(), enormous single lines, high non-printable density, and a
	 * concentration of dynamic-dispatch / decoder / superglobal-callable tokens.
	 */
	private function score_obfuscation(string $contents, string $rel, int $size, bool $disguised, array &$state): void
	{
		$len = strlen($contents);

		if ($len < 24) {
			return;
		}

		$reasons = [];

		// --- Execution signals: the code actually runs something hidden. ---
		$exec = 0;

		// A payload appended after the file's final PHP closing tag: the close
		// tag, then only whitespace, then a PHP open tag beginning a single
		// dense line that runs a decoder / eval and nothing else. A normal
		// template's tag transitions carry HTML between the tags, so they do
		// not match this.
		if (preg_match('~\?>[ \t\r\n]{0,40}<\?php[ \t]{0,4}(@?\s*(?:eval|assert|error_reporting|ini_set|@?(?:base64_decode|gzinflate|create_function))\b[^\r\n]{0,4000}?)\s*(?:\?>\s*)?$~i', $contents, $m)) {
			$reasons[] = 'a one-line PHP block appended after the file\'s closing tag';
			$exec += 60;
		}

		// Code after __halt_compiler() — "the data section is really a payload".
		if (preg_match('~__halt_compiler\s*\(\s*\)\s*;(.{200,})~s', $contents, $m)
			&& preg_match('~[A-Za-z0-9+/=]{200,}|\\\\x[0-9a-f]{2}|eval|base64_decode|gzinflate~i', $m[1])) {
			$reasons[] = 'executable-looking data after __halt_compiler()';
			$exec += 60;
		}

		// Token concentration: decoders, dynamic dispatch, superglobal-as-callable,
		// variable-variables, char builders — relative to file size.
		$dyn = preg_match_all('~\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin)\s*\(~i', $contents)
			+ preg_match_all('~\b(?:eval|assert|create_function|preg_replace_callback)\s*\(~i', $contents)
			+ preg_match_all('~\$\{\s*[\'"]|\$\$[a-z_]|\bGLOBALS\s*\[[^\]]*\]\s*\(~i', $contents)
			+ preg_match_all('~\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]]{1,40}\]\s*[({]~', $contents);
		$per_kb = $dyn / max(1, $len / 1024);
		if ($dyn >= 6 && $per_kb > 1.2) {
			$reasons[] = sprintf('%d dynamic-execution / decoder tokens (%.1f per KB)', $dyn, $per_kb);
			$exec += $per_kb > 4 ? 55 : 30;
		}

		// --- Structure signals: it LOOKS packed. Alone, these are just how a
		//     minified asset or a Unicode data table looks — they only count
		//     alongside an execution signal. ---
		$struct = 0;

		$longest = 0;
		foreach (explode("\n", substr($contents, 0, 262144)) as $line) {
			$longest = max($longest, strlen($line));
		}
		if ($longest > 8000) {
			$reasons[] = sprintf('a %s-character line', number_format_i18n($longest));
			$struct += $longest > 40000 ? 30 : 18;
		}

		$sample = substr($contents, 0, 131072);
		$nonprint = strlen((string) preg_replace('~[\x09\x0A\x0D\x20-\x7E]~', '', $sample));
		if (strlen($sample) > 512 && $nonprint / strlen($sample) > 0.15) {
			$reasons[] = sprintf('%d%% non-text bytes', (int) round(100 * $nonprint / strlen($sample)));
			$struct += 30;
		}

		if (preg_match('~\'[^\'\r\n]{6000,}\'|"[^"\r\n]{6000,}"~', $contents)) {
			$reasons[] = 'a multi-kilobyte inline string literal';
			$struct += 15;
		}

		if ($disguised) {
			$exec += 15;
		}

		// Fire on a strong execution signal on its own, or a moderate one that is
		// also structurally packed. Never on structure alone.
		if ($exec < 40 && !($exec >= 25 && $struct >= 25)) {
			return;
		}

		$score = $exec + $struct;
		$severity = $score >= 110 ? 'critical' : ($score >= 75 ? 'high' : 'medium');

		$this->add_finding($state, [
			'finding_key' => 'deep_obfuscated_php_' . md5($rel),
			'category' => 'malware',
			'severity' => $severity,
			'title' => 'Heavily obfuscated PHP',
			'description' => sprintf('%s shows the structure of obfuscated / packed code (%s) without matching a specific known signature. Legitimate source is rarely built this way.', $rel, implode('; ', $reasons)),
			'recommendation' => 'Reconstruct what the file does (de-obfuscate the payload in a sandbox). If you cannot attribute it to a plugin you trust, treat it as a backdoor.',
			'evidence' => ['path' => $rel, 'size' => $size, 'reasons' => $reasons, 'obfuscation_score' => $score],
			'score' => max(10, 70 - (int) ($score / 3)),
		]);
	}

	/**
	 * A tiny file whose entire body is a digit, an absolute filesystem path, a
	 * bare domain / hostname, or nothing — dropped in the web root or a random
	 * top-level directory. This is what an attacker or a mass-exploit scanner
	 * leaves behind to confirm write access and fingerprint the box.
	 */
	private function check_marker_file(string $path, string $rel, string $basename, string $extension, int $size, array &$state): void
	{
		if ($size > 512 || $size < 0) {
			return;
		}

		$depth = substr_count(trim($rel, '/'), '/');
		$top = strtok(trim($rel, '/'), '/');
		$random_top_dir = $depth === 1 && (bool) preg_match('~^(?:[0-9]{3,}|[a-f0-9]{8,}|[a-z0-9]{1,4})$~i', (string) $top)
			&& !in_array(strtolower((string) $top), ['wp-admin', 'wp-includes', 'wp-content', 'cgi-bin'], true);
		$in_public_root = $depth === 0;

		if (!$in_public_root && !$random_top_dir) {
			return;
		}

		if (in_array($extension, ['php', 'phtml', 'phar', 'js', 'css', 'html', 'htm', 'json', 'xml', 'map', 'lock', 'md'], true)) {
			return; // handled by other checks / normal project files
		}

		if (in_array($basename, ['index.php', 'index.html', '.htaccess', 'robots.txt', 'favicon.ico', 'ads.txt', 'security.txt', 'llms.txt', 'sitemap.xml', '.well-known'], true)) {
			return;
		}

		$body = trim((string) @file_get_contents($path, false, null, 0, 512));
		$looks_marker = $body === ''
			|| preg_match('~^[0-9]{1,4}$~', $body)
			|| preg_match('~^(?:/[A-Za-z0-9._-]+){2,}/?$~', $body)                       // absolute unix path
			|| preg_match('~^[a-z0-9-]+\.[a-z0-9-]+(?:\.[a-z]{2,})+$~i', $body)          // bare domain
			|| preg_match('~^[A-Za-z0-9+/=]{6,32}$~', $body) && !str_contains($body, ' '); // short token

		if (!$looks_marker) {
			return;
		}

		$this->add_finding($state, [
			'finding_key' => 'deep_recon_marker_' . md5($rel),
			'category' => 'malware',
			'severity' => 'high',
			'title' => 'Attacker reconnaissance marker file',
			'description' => sprintf('%s is a tiny file (%d byte(s)) %s whose content is %s. Automated exploit tools and attackers drop files like this to confirm they can write to the server and to fingerprint it.', $rel, $size, $in_public_root ? 'in the web root' : 'in a random-named directory', $body === '' ? 'empty' : '"' . mb_substr($body, 0, 80) . '"'),
			'recommendation' => 'If you did not create this file, delete it and the directory it sits in, and check access logs for the request that wrote it — it marks a successful write from an exploit attempt.',
			'evidence' => ['path' => $rel, 'size' => $size, 'body' => mb_substr($body, 0, 120)],
			'score' => 46,
		]);
	}

	private function match_signatures(string $contents, string $rel, string $class, array &$state, string $category_override = '', int $file_size = -1): void
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

			$added = $this->add_finding($state, [
				'finding_key' => 'deep_' . $rule['id'] . '_' . md5($rel),
				'category' => $category,
				'severity' => (string) ($rule['severity'] ?? 'high'),
				'title' => (string) ($rule['label'] ?? 'Suspicious code pattern'),
				'description' => sprintf('Signature "%s" matched in %s (line %d).', (string) ($rule['label'] ?? $rule['id']), $rel, $line),
				'recommendation' => (string) ($rule['recommendation'] ?? 'Review this file against a known-good copy and remove any code you cannot account for.'),
				'evidence' => array_filter([
					'path' => $rel,
					'signature_id' => (string) $rule['id'],
					'line' => $line,
					'match_count' => (int) $count,
					'size' => $file_size >= 0 ? $file_size : null,
					'snippet' => $this->snippet($contents, $offset),
				], static fn ($v): bool => $v !== null),
				'score' => (int) ($rule['score'] ?? 45),
			]);

			// Not counted as a malware hit when the "finding" was really a
			// reframed unrecognized-own-file notice, or a dedupe no-op.
			if ($added && $this->self_file_context === null && ($rule['category'] ?? 'malware') === 'malware') {
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

				// A credentials-bearing backup that a backup tool has sealed off
				// with its own "deny all" .htaccess is a lower (defence-in-depth,
				// not front-door) risk — say so instead of screaming.
				if ($this->directory_denies_web_access(dirname($path))) {
					$reasons[] = 'The containing folder has a deny-all rule (Apache); still verify nginx / LiteSpeed block it too';
					$severity = 'medium';
					$score = max($score, 55);
				}
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
	 * True when the directory carries an .htaccess that blanket-denies web
	 * access ("Require all denied" / "Deny from all"). Apache-only signal — nginx
	 * and LiteSpeed ignore .htaccess — but enough to distinguish a backup tool's
	 * sealed folder from a credentials file dropped straight in the doc root.
	 */
	private function directory_denies_web_access(string $dir): bool
	{
		$htaccess = rtrim(wp_normalize_path($dir), '/') . '/.htaccess';

		if (!is_file($htaccess) || !is_readable($htaccess)) {
			return false;
		}

		$contents = (string) @file_get_contents($htaccess, false, null, 0, 4096);

		return (bool) preg_match('~require\s+all\s+denied|deny\s+from\s+all~i', $contents);
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
			$cursor = ['stage' => 'extcode', 'index' => 0, 'plugin_index' => 0];
		} elseif ($stage === 'extcode') {
			if (empty($prefs['scan_plugin_integrity']) || $this->integrity_extcode_step($state, $cursor)) {
				$cursor['stage'] = 'done';
			}
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

	/**
	 * The only .php files WordPress core places directly in the web root. Used to
	 * flag a stray root-level PHP file (a loader / backdoor mimicking a core
	 * name, e.g. wp-header.php) even when no checksum manifest is available.
	 */
	private const CORE_ROOT_PHP = [
		'index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php',
		'wp-config.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php',
		'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php',
		'wp-trackback.php', 'xmlrpc.php',
	];

	private function integrity_core_extra_step(array &$state): void
	{
		$checksums = $this->is_released_version() ? $this->core_checksums() : [];
		$have_manifest = $checksums !== [];

		// --- Web root: a stray top-level .php file (no checksum manifest needed) ---
		$root = untrailingslashit(ABSPATH);
		$root_items = @scandir($root);

		if (is_array($root_items)) {
			foreach ($root_items as $item) {
				if (!str_ends_with(strtolower($item), '.php')) {
					continue;
				}

				$lower = strtolower($item);

				if (in_array($lower, self::CORE_ROOT_PHP, true)) {
					continue;
				}

				$full = wp_normalize_path($root . '/' . $item);

				if (!is_file($full) || is_link($full)) {
					continue;
				}

				// A few hosts / installers legitimately drop one loader in the root.
				// Keep the severity a notch below wp-admin/wp-includes but still loud.
				$rel = $this->relative_path($full);
				$mimics_core = (bool) preg_match('~^wp[-_].*\.php$~i', $item);

				$this->add_finding($state, [
					'finding_key' => 'deep_core_unknown_' . md5($rel),
					'category' => 'core_integrity',
					'severity' => $mimics_core ? 'high' : 'medium',
					'title' => 'Unrecognized PHP file in the WordPress web root',
					'description' => sprintf('%s sits in the site root but is not one of the files WordPress core places there.%s Loader files with core-looking names (wp-*.php) are a common backdoor / staging pattern.', $rel, $mimics_core ? ' Its name mimics a core file.' : ''),
					'recommendation' => 'Open the file. If it is not something your host or a deliberate customization added, remove it and review access logs.',
					'evidence' => ['path' => $rel, 'size' => (int) @filesize($full), 'mimics_core_name' => $mimics_core],
					'score' => $mimics_core ? 44 : 62,
				]);
			}
		}

		if (!$have_manifest) {
			return;
		}

		// --- wp-admin/** and wp-includes/**: anything not in the manifest ---
		$known = [];

		foreach (array_keys($checksums) as $file) {
			$known[wp_normalize_path(ABSPATH . $file)] = 1;
		}

		foreach (['wp-admin', 'wp-includes'] as $top) {
			$this->scan_core_tree_for_unknowns(untrailingslashit(ABSPATH) . '/' . $top, $known, 0, $state);
		}
	}

	/**
	 * Recursively flag every .php file under a core directory that the checksum
	 * manifest does not list. Bounded depth; no plugin/theme code lives here, so
	 * an unknown .php is a strong compromise signal wherever in the tree it is.
	 */
	private function scan_core_tree_for_unknowns(string $dir, array $known, int $depth, array &$state): void
	{
		if ($depth > 8 || !is_dir($dir) || !is_readable($dir) || is_link($dir)) {
			return;
		}

		$items = @scandir($dir);

		if (!is_array($items)) {
			return;
		}

		foreach ($items as $item) {
			if ($item === '.' || $item === '..') {
				continue;
			}

			$full = wp_normalize_path($dir . '/' . $item);

			if (is_link($full)) {
				continue;
			}

			if (is_dir($full)) {
				$this->scan_core_tree_for_unknowns($full, $known, $depth + 1, $state);

				continue;
			}

			if (!str_ends_with(strtolower($item), '.php') || isset($known[$full]) || !is_file($full)) {
				continue;
			}

			$rel = $this->relative_path($full);
			$this->add_finding($state, [
				'finding_key' => 'deep_core_unknown_' . md5($rel),
				'category' => 'core_integrity',
				'severity' => 'critical',
				'title' => 'Unrecognized PHP file in a WordPress core directory',
				'description' => sprintf('%s is not part of the official WordPress distribution. Extra PHP files anywhere under wp-admin / wp-includes are a very common backdoor location.', $rel),
				'recommendation' => 'Inspect the file. Legitimate plugins never add files here — if you cannot attribute it, remove it and treat the site as compromised.',
				'evidence' => ['path' => $rel, 'size' => (int) @filesize($full)],
				'score' => 24,
			]);
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

		$extra = $this->find_unrecognized_self_files($base, $manifest, $state);

		if ($modified === [] && $missing === [] && $extra === []) {
			return;
		}

		$state['counters']['plugin_files_modified'] += count($modified);

		$tampered = $modified !== [] || $missing !== [];

		if ($tampered) {
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

		if ($extra !== []) {
			$dev_only = array_values(array_filter(
				$extra,
				static fn (string $r): bool => (bool) preg_match('~(^|/)(tests?|dist|node_modules|\.github)(/|$)~', $r) || str_ends_with($r, '.md')
			));
			$all_dev = count($dev_only) === count($extra);

			$this->add_finding($state, [
				'finding_key' => 'deep_self_extra_files_' . md5(FREESIEM_SENTINEL_VERSION),
				'category' => 'plugin_integrity',
				'severity' => $all_dev ? 'medium' : 'high',
				'title' => __('Unrecognized files in freeSIEM Sentinel\'s directory', 'freesiem-sentinel'),
				'description' => sprintf(
					/* translators: 1: count, 2: version */
					_n(
						'%1$d file that the official freeSIEM Sentinel %2$s release does not ship is present in our plugin directory.',
						'%1$d files that the official freeSIEM Sentinel %2$s release does not ship are present in our plugin directory.',
						count($extra),
						'freesiem-sentinel'
					),
					count($extra),
					FREESIEM_SENTINEL_VERSION
				) . ' ' . ($all_dev
					? 'They all live under paths the release build strips (tests/, dist/, *.md), so this install was copied from a development tree rather than the release zip. Our own test fixtures deliberately contain malware-shaped strings.'
					: 'Some are not development-only paths. A file that freeSIEM Sentinel neither ships nor recognises inside its own directory can be a planted shell.'),
				'recommendation' => $all_dev
					? sprintf('Reinstall freeSIEM Sentinel from the release zip, or delete the development-only files under wp-content/plugins/%s/.', FREESIEM_SENTINEL_SLUG)
					: 'Review each file below. If you did not add it deliberately, quarantine it and reinstall freeSIEM Sentinel from a clean copy.',
				'evidence' => [
					'path' => 'wp-content/plugins/' . FREESIEM_SENTINEL_SLUG,
					'version' => FREESIEM_SENTINEL_VERSION,
					'unrecognized_files' => array_slice($extra, 0, 50),
					'development_only' => $all_dev,
				],
				'score' => $all_dev ? 62 : 44,
			]);
		}
	}

	/**
	 * Files inside our own plugin directory that are not in the release manifest.
	 * Limited to the extensions the manifest actually covers (.php/.js/.css) so
	 * language files, images and readme.txt are not mistaken for intruders, and
	 * skips VCS/build directories. Any path already reported as a reframed
	 * per-file "unrecognized file" finding is left out to avoid double-counting.
	 *
	 * @param array<string,string> $manifest
	 * @return list<string> repo-relative paths (wp-content/plugins/<slug>/...)
	 */
	private function find_unrecognized_self_files(string $base, array $manifest, array $state): array
	{
		if (!is_dir($base)) {
			return [];
		}

		$slug = defined('FREESIEM_SENTINEL_SLUG') ? (string) FREESIEM_SENTINEL_SLUG : 'freesiem-sentinel';
		$prefix = 'wp-content/plugins/' . $slug . '/';
		$extra = [];
		$seen = 0;

		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveCallbackFilterIterator(
					new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS),
					static function ($current): bool {
						$name = strtolower($current->getFilename());

						// dist/ is a full nested copy of the plugin in dev trees —
						// skip it so it does not drown the report in its own files.
						return !in_array($name, ['.git', '.svn', '.hg', 'node_modules', 'dist'], true);
					}
				)
			);

			foreach ($it as $file) {
				if (!$file->isFile() || $file->isLink()) {
					continue;
				}

				if (++$seen > 5000) {
					break;
				}

				$ext = strtolower($file->getExtension());

				if (!in_array($ext, ['php', 'js', 'css'], true)) {
					continue;
				}

				$rel_self = ltrim(substr(wp_normalize_path($file->getPathname()), strlen($base)), '/');

				if ($rel_self === '' || $rel_self === 'checksums.json' || isset($manifest[$rel_self])) {
					continue;
				}

				if (isset($state['findings']['deep_self_unrecognized_' . md5($prefix . $rel_self)])) {
					continue;
				}

				$extra[] = $prefix . $rel_self;
			}
		} catch (\Throwable $e) {
			return $extra;
		}

		sort($extra);

		return $extra;
	}

	// ---------------------------------------------------------------------
	// Phase: integrity — external (premium / custom) plugin & theme baseline
	// ---------------------------------------------------------------------

	public const EXTCODE_BASELINE_OPTION = 'freesiem_sentinel_extcode_baseline';
	private const EXTCODE_MAX_FILES = 30000;
	private const EXTCODE_BATCH = 250;

	/**
	 * WordPress.org checksums only cover core and wp.org-hosted plugins/themes.
	 * A backdoor injected into an existing file of a PREMIUM or CUSTOM plugin
	 * (Hostinger's, a page builder's pro add-on, a bespoke plugin) matches no
	 * checksum and only trips a content signature if it is written carelessly.
	 *
	 * This step keeps its own hash baseline of every .php / .js file under
	 * plugins, themes and mu-plugins that is not already wp.org-verified. On the
	 * first run it just records the baseline; on later runs it flags any file
	 * whose bytes changed while its component's version stayed the same, and any
	 * brand-new file appearing in a component that was not updated — regardless
	 * of whether the change looks malicious.
	 *
	 * @return bool true when the step is complete for this run
	 */
	private function integrity_extcode_step(array &$state, array &$cursor): bool
	{
		// --- Phase 1: build the candidate file list (once) ---
		if (!isset($cursor['files'])) {
			$roots = array_values(array_filter([
				untrailingslashit(WP_PLUGIN_DIR),
				untrailingslashit((string) get_theme_root()),
				defined('WPMU_PLUGIN_DIR') ? untrailingslashit(WPMU_PLUGIN_DIR) : '',
			]));

			$files = [];

			foreach ($roots as $root) {
				if ($root === '' || !is_dir($root)) {
					continue;
				}

				$this->collect_extcode_files($root, 0, $files);

				if (count($files) >= self::EXTCODE_MAX_FILES) {
					break;
				}
			}

			sort($files);
			$cursor['files'] = array_slice($files, 0, self::EXTCODE_MAX_FILES);
			$cursor['index'] = 0;
			$cursor['map'] = [];
			$cursor['truncated'] = count($files) > self::EXTCODE_MAX_FILES ? count($files) : 0;

			return false;
		}

		// --- Phase 2: hash a batch ---
		$files = $cursor['files'];
		$index = (int) $cursor['index'];
		$end = min($index + self::EXTCODE_BATCH, count($files));

		for (; $index < $end; $index++) {
			$abs = (string) $files[$index];

			if (!is_file($abs) || is_link($abs)) {
				continue;
			}

			$rel = $this->relative_path($abs);

			if ($this->is_vendor_verified($abs, $rel) || $this->self_relative_path($abs) !== null) {
				continue; // core / wp.org checksums and our own integrity step own these
			}

			$md5 = (string) @md5_file($abs);

			if ($md5 !== '') {
				$cursor['map'][$rel] = $md5 . '|' . (int) @filesize($abs);
			}
		}

		$cursor['index'] = $index;

		if ($index < count($files)) {
			return false;
		}

		// --- Phase 3: diff against the stored baseline and persist ---
		$this->finalize_extcode_baseline($cursor['map'], (int) ($cursor['truncated'] ?? 0), $state);
		unset($cursor['files'], $cursor['map']);

		return true;
	}

	private function collect_extcode_files(string $dir, int $depth, array &$out): void
	{
		if ($depth > 12 || count($out) >= self::EXTCODE_MAX_FILES || !is_dir($dir) || !is_readable($dir) || is_link($dir)) {
			return;
		}

		$items = @scandir($dir);

		if (!is_array($items)) {
			return;
		}

		foreach ($items as $item) {
			if ($item === '.' || $item === '..') {
				continue;
			}

			$lc = strtolower($item);

			if (in_array($lc, ['.git', '.svn', '.hg', 'node_modules'], true)) {
				continue;
			}

			$full = $dir . '/' . $item;

			if (is_link($full)) {
				continue;
			}

			if (is_dir($full)) {
				$this->collect_extcode_files($full, $depth + 1, $out);

				continue;
			}

			if (preg_match('~\.(php|phtml|php\d|inc|js|mjs|cjs)$~i', $lc)) {
				$out[] = wp_normalize_path($full);

				if (count($out) >= self::EXTCODE_MAX_FILES) {
					return;
				}
			}
		}
	}

	private function finalize_extcode_baseline(array $map, int $truncated, array &$state): void
	{
		$now = freesiem_sentinel_get_iso8601_time();
		$versions = $this->extcode_component_versions();

		$stored = get_option(self::EXTCODE_BASELINE_OPTION, []);
		$stored = is_array($stored) ? $stored : [];
		$base_map = is_array($stored['map'] ?? null) ? $stored['map'] : [];
		$base_versions = is_array($stored['versions'] ?? null) ? $stored['versions'] : [];

		$save = [
			'built_at' => $now,
			'versions' => $versions,
			'map' => $map,
			'truncated' => $truncated,
		];

		if ($base_map === []) {
			update_option(self::EXTCODE_BASELINE_OPTION, $save, false);
			$this->add_finding($state, [
				'finding_key' => 'deep_extcode_baseline_new',
				'category' => 'plugin_integrity',
				'severity' => 'info',
				'title' => 'Plugin / theme file baseline established',
				'description' => sprintf('freeSIEM Sentinel recorded a hash of %s plugin, theme and mu-plugin file(s) that WordPress.org cannot verify. From the next scan on, any change to one of these files that is not explained by a version update will be reported.', number_format_i18n(count($map))),
				'recommendation' => 'No action needed. Re-run the scan after you update plugins or themes so the baseline follows the new versions.',
				'evidence' => ['files' => count($map), 'truncated' => $truncated],
				'score' => 95,
			]);

			return;
		}

		$modified_by_component = [];
		$new_by_component = [];

		foreach ($map as $rel => $sig) {
			$component = $this->extcode_component_for($rel);
			$ver_now = (string) ($versions[$component] ?? '');
			$ver_was = (string) ($base_versions[$component] ?? '');
			$version_changed = $ver_was !== '' && $ver_now !== '' && $ver_was !== $ver_now;

			if (isset($base_map[$rel])) {
				if ($base_map[$rel] !== $sig && !$version_changed) {
					$modified_by_component[$component][] = $rel;
				}
			} elseif (!$version_changed && $ver_was !== '') {
				// A file that did not exist at baseline, in a component whose
				// version did not move — i.e. something added a file without a
				// legitimate update.
				$new_by_component[$component][] = $rel;
			}
		}

		update_option(self::EXTCODE_BASELINE_OPTION, $save, false);

		foreach ($modified_by_component as $component => $rels) {
			$this->emit_extcode_finding($state, 'modified', $component, $rels);
		}

		foreach ($new_by_component as $component => $rels) {
			$this->emit_extcode_finding($state, 'new', $component, $rels);
		}
	}

	private function emit_extcode_finding(array &$state, string $kind, string $component, array $rels): void
	{
		$rels = array_values(array_unique($rels));
		$php = array_values(array_filter($rels, static fn (string $r): bool => (bool) preg_match('~\.(php|phtml|php\d|inc)$~i', $r)));
		$count = count($rels);
		$label = str_replace(['plugin:', 'theme:', 'mu:'], ['plugin ', 'theme ', 'mu-plugin '], $component);

		$modified = $kind === 'modified';
		$severe = $php !== [] || $count > 8;

		$this->add_finding($state, [
			'finding_key' => 'deep_extcode_' . $kind . '_' . md5($component),
			'category' => 'plugin_integrity',
			'severity' => $severe ? 'high' : 'medium',
			'title' => $modified
				? sprintf('%s: %d file(s) changed with no version update', ucfirst($label), $count)
				: sprintf('%s: %d file(s) appeared with no version update', ucfirst($label), $count),
			'description' => sprintf(
				'%s in %s %s since the last scan, but the component\'s version did not change. A legitimate update bumps the version; a change without one points at a manual edit, a failed deploy, or injected code. WordPress.org cannot verify this component, so this is the only integrity signal for it.',
				$modified ? sprintf('%d file(s) had their contents change', $count) : sprintf('%d new file(s) appeared', $count),
				$label,
				$php !== [] ? '(including PHP)' : ''
			),
			'recommendation' => 'Compare the listed files against a clean copy of this exact plugin/theme version. If you did not edit them, treat them as injected: restore the component from a trusted source and review access logs.',
			'evidence' => [
				'path' => $this->extcode_component_path($component),
				'component' => $component,
				'change_type' => $modified ? 'modified' : 'new',
				'changed_count' => $count,
				'modified_files' => array_slice($rels, 0, 20),
			],
			'score' => $severe ? 44 : 60,
		]);
	}

	/**
	 * plugin:<slug> / theme:<slug> / mu:<file> for a wp-content-relative path.
	 */
	private function extcode_component_for(string $rel): string
	{
		$rel = ltrim($rel, '/');
		$plugins = trim($this->relative_path(WP_PLUGIN_DIR), '/');
		$themes = trim($this->relative_path((string) get_theme_root()), '/');
		$mu = defined('WPMU_PLUGIN_DIR') ? trim($this->relative_path(WPMU_PLUGIN_DIR), '/') : '';

		if ($plugins !== '' && str_starts_with($rel, $plugins . '/')) {
			$after = substr($rel, strlen($plugins) + 1);

			return 'plugin:' . (strtok($after, '/') ?: $after);
		}

		if ($themes !== '' && str_starts_with($rel, $themes . '/')) {
			$after = substr($rel, strlen($themes) + 1);

			return 'theme:' . (strtok($after, '/') ?: $after);
		}

		if ($mu !== '' && str_starts_with($rel, $mu . '/')) {
			return 'mu:' . basename($rel);
		}

		return 'other:' . dirname($rel);
	}

	private function extcode_component_path(string $component): string
	{
		[$type, $name] = array_pad(explode(':', $component, 2), 2, '');

		if ($type === 'plugin') {
			return 'wp-content/plugins/' . $name;
		}

		if ($type === 'theme') {
			return 'wp-content/themes/' . $name;
		}

		if ($type === 'mu') {
			return 'wp-content/mu-plugins/' . $name;
		}

		return (string) $name;
	}

	/**
	 * Current version string for every plugin / theme, keyed the same way as
	 * extcode_component_for(). mu-plugins have no version and are omitted (any
	 * change to one is always worth surfacing).
	 *
	 * @return array<string,string>
	 */
	private function extcode_component_versions(): array
	{
		$versions = [];

		if (!function_exists('get_plugins') && is_readable(ABSPATH . 'wp-admin/includes/plugin.php')) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		if (function_exists('get_plugins')) {
			foreach (get_plugins() as $file => $data) {
				$slug = strtok((string) $file, '/');

				if (is_string($slug) && $slug !== '') {
					$versions['plugin:' . $slug] = (string) ($data['Version'] ?? '');
				}
			}
		}

		if (function_exists('wp_get_themes')) {
			foreach (wp_get_themes() as $slug => $theme) {
				$versions['theme:' . $slug] = (string) $theme->get('Version');
			}
		}

		return $versions;
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

	private function add_finding(array &$state, array $finding): bool
	{
		$finding = $this->reframe_self_finding($finding);

		$key = (string) ($finding['finding_key'] ?? '');

		if ($key === '') {
			$key = 'deep_' . md5(wp_json_encode($finding));
			$finding['finding_key'] = $key;
		}

		if (isset($state['findings'][$key])) {
			return false;
		}

		$cap = empty($state['full']) ? self::MAX_FINDINGS : self::MAX_FINDINGS_FULL;

		if (count($state['findings']) >= $cap) {
			$state['partial'] = true;
			$state['partial_reason'] = $state['partial_reason'] ?: 'finding_cap';

			return false;
		}

		$finding['severity'] = freesiem_sentinel_normalize_severity((string) ($finding['severity'] ?? 'info'));
		$finding['detected_at'] = freesiem_sentinel_get_iso8601_time();
		$finding['evidence'] = is_array($finding['evidence'] ?? null) ? $finding['evidence'] : [];
		$state['findings'][$key] = $finding;

		return true;
	}

	/**
	 * If we are mid-scan on a file inside freeSIEM Sentinel's own directory that
	 * is not in our release manifest, rewrite whatever finding was raised against
	 * it into a single, honestly-worded "unrecognized file inside freeSIEM
	 * Sentinel" finding. Collapsing to one stable finding_key per path also means
	 * three signature matches on the same fixture produce one finding, not three.
	 */
	private function reframe_self_finding(array $finding): array
	{
		$ctx = $this->self_file_context;

		if ($ctx === null) {
			return $finding;
		}

		$rel = (string) ($finding['evidence']['path'] ?? '');

		if ($rel === '' || $rel !== $ctx['rel']) {
			return $finding;
		}

		$version = defined('FREESIEM_SENTINEL_VERSION') ? (string) FREESIEM_SENTINEL_VERSION : '';
		$self_rel = $ctx['self_rel'];
		$looks_dev = (bool) preg_match('~(^|/)(tests?|dist|node_modules|\.github)(/|$)~', $self_rel)
			|| str_ends_with($self_rel, '.md');

		$evidence = is_array($finding['evidence'] ?? null) ? $finding['evidence'] : [];
		$evidence['self_unrecognized'] = true;
		$evidence['self_relative_path'] = $self_rel;
		$evidence['release_version'] = $version;
		$evidence['looks_like_dev_copy'] = $looks_dev;

		if (!empty($finding['title'])) {
			$evidence['original_title'] = (string) $finding['title'];
		}

		if (!empty($finding['evidence']['signature_id'])) {
			$evidence['matched_signature'] = (string) $finding['evidence']['signature_id'];
		}

		$description = sprintf(
			'%s sits inside the freeSIEM Sentinel plugin directory but is not part of the official freeSIEM Sentinel%s release. %s',
			$rel,
			$version !== '' ? ' ' . $version : '',
			$looks_dev
				? 'The path (tests/, dist/, a .md file, ...) is one the release build strips out, so this install was almost certainly copied from a development tree rather than installed from the release zip. freeSIEM Sentinel\'s own test fixtures deliberately contain malware-shaped strings to exercise the scanner.'
				: 'It is not a file the release ships and not one our detection code recognises.'
		);

		$recommendation = $looks_dev
			? sprintf(
				'If you deployed a development copy, reinstall freeSIEM Sentinel from the release zip (or delete the development-only files: %s and any tests/, dist/ or *.md paths under wp-content/plugins/%s/). If you did NOT put this file here, treat it as planted: quarantine it and review access logs.',
				$rel,
				defined('FREESIEM_SENTINEL_SLUG') ? (string) FREESIEM_SENTINEL_SLUG : 'freesiem-sentinel'
			)
			: sprintf(
				'A file that is neither shipped by freeSIEM Sentinel nor recognised by it is sitting in our plugin directory. If you did not add it deliberately, quarantine it, reinstall freeSIEM Sentinel from a clean copy, and review access logs for how it arrived.'
			);

		return [
			'finding_key' => 'deep_self_unrecognized_' . md5($rel),
			'category' => 'plugin_integrity',
			'severity' => $looks_dev ? 'medium' : (string) ($finding['severity'] ?? 'high'),
			'title' => __('Unrecognized file in freeSIEM Sentinel\'s directory', 'freesiem-sentinel'),
			'description' => $description,
			'recommendation' => $recommendation,
			'evidence' => $evidence,
			'score' => $looks_dev ? 60 : (int) ($finding['score'] ?? 40),
		];
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
		$is_backup_dir = str_contains($normalized, 'synchy-backups')
			|| str_contains($normalized, '/backups/')
			|| str_ends_with($normalized, '/backups');

		// A backup folder is only safe to walk past if it is actually sealed off
		// (deny-all .htaccess). An unsealed "backups" directory in a web-reachable
		// spot is a fine place to hide a shell — descend and scan it.
		if ($is_backup_dir) {
			return $this->directory_denies_web_access($path);
		}

		return false;
	}

	/**
	 * A subfolder that is a self-contained WordPress install of its own (staging/,
	 * old/, backup copies). Its files belong to a different application — scanning
	 * them as part of THIS site just produces dozens of duplicate signature hits on
	 * their unpatched core and vendor code. Flag the folder once and don't descend.
	 */
	private function is_secondary_wp_root(string $path): bool
	{
		$path = untrailingslashit(wp_normalize_path($path));

		if ($path === untrailingslashit(wp_normalize_path(ABSPATH))) {
			return false;
		}

		foreach ([WP_CONTENT_DIR, WP_PLUGIN_DIR, function_exists('get_theme_root') ? get_theme_root() : ''] as $known) {
			$known = untrailingslashit(wp_normalize_path((string) $known));

			if ($known !== '' && ($path === $known || str_starts_with($path . '/', $known . '/'))) {
				return false;
			}
		}

		return is_file($path . '/wp-load.php')
			&& is_file($path . '/wp-settings.php')
			&& (is_file($path . '/wp-includes/version.php') || is_dir($path . '/wp-admin'));
	}

	private function flag_secondary_wp_root(string $path, array &$state): void
	{
		$count = (int) ($state['counters']['secondary_wp_roots'] ?? 0);
		$state['counters']['secondary_wp_roots'] = $count + 1;

		if ($count >= 15) {
			return;
		}

		$rel = $this->relative_path($path);
		$rel = $rel !== '' ? $rel : basename($path);
		$version = '';
		$vfile = untrailingslashit(wp_normalize_path($path)) . '/wp-includes/version.php';

		if (is_readable($vfile)) {
			$src = (string) @file_get_contents($vfile, false, null, 0, 4096);

			if (preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', $src, $m)) {
				$version = $m[1];
			}
		}

		$this->add_finding($state, [
			'finding_key' => 'deep_secondary_wp_root_' . md5($rel),
			'category' => 'filesystem',
			'severity' => 'medium',
			'title' => 'A separate WordPress install sits in a subfolder',
			'description' => sprintf(
				'%s%s is a second, self-contained WordPress installation. Old / staging / backup copies in a web-reachable folder run unpatched code and expose their own wp-config.php — a common way in. Its files were not scanned as part of this site.',
				$rel,
				$version !== '' ? sprintf(' (WordPress %s)', $version) : ''
			),
			'recommendation' => sprintf(
				'If %s is not something you deliberately serve, delete it. If it is a staging site, move it outside the public web root or put it behind authentication and keep it updated.',
				$rel
			),
			'evidence' => [
				'path' => $rel,
				'full_path' => wp_normalize_path($path),
				'wp_version' => $version,
			],
			'score' => 60,
		]);
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
