<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Results
{
	public function get_cache(): array
	{
		$settings = freesiem_sentinel_get_settings();
		$cache = is_array($settings['summary_cache']) ? $settings['summary_cache'] : [];

		return wp_parse_args(
			$cache,
			[
				'fetched_at' => '',
				'summary' => [],
				'local_findings' => [],
				'local_inventory' => [],
				'severity_counts' => [],
				'top_issues' => [],
				'recommendations' => [],
				'notices' => [],
			]
		);
	}

	public function store_local_scan(array $scan): array
	{
		$cache = $this->get_cache();
		$scan_summary = is_array($scan['summary'] ?? null) ? $scan['summary'] : [];
		$cache['fetched_at'] = freesiem_sentinel_get_iso8601_time();
		$cache['local_findings'] = $this->sort_findings(array_values($scan['findings'] ?? []));
		$cache['local_inventory'] = $scan['inventory'] ?? [];
		$cache['severity_counts'] = $this->count_severities($cache['local_findings']);
		$cache['summary'] = array_merge(
			is_array($cache['summary']) ? $cache['summary'] : [],
			[
				'local_score' => (int) ($scan['score'] ?? freesiem_sentinel_score_from_findings($cache['local_findings'])),
				'last_local_scan_at' => freesiem_sentinel_get_iso8601_time(),
				'files_discovered' => (int) ($scan_summary['files_discovered'] ?? 0),
				'files_analyzed' => (int) ($scan_summary['files_analyzed'] ?? 0),
				'files_flagged' => (int) ($scan_summary['files_flagged'] ?? 0),
				'duration_seconds' => isset($scan_summary['duration_seconds']) ? (float) $scan_summary['duration_seconds'] : 0,
				'scan_modules' => array_values(is_array($scan_summary['scan_modules'] ?? null) ? $scan_summary['scan_modules'] : []),
			]
		);
		$cache['top_issues'] = array_slice($cache['local_findings'], 0, 5);
		$cache['recommendations'] = array_values(array_unique(array_map(static function (array $finding): string {
			return (string) ($finding['recommendation'] ?? '');
		}, $cache['local_findings'])));

		freesiem_sentinel_update_settings([
			'last_local_scan_at' => freesiem_sentinel_get_iso8601_time(),
			'summary_cache' => $cache,
		]);

		return $cache;
	}

	/**
	 * Merge deep-scan findings into the stored quick-scan results.
	 *
	 * Previous deep findings (finding_key prefixed "deep_", or in a deep-only category)
	 * are dropped and replaced, so re-running the deep scan does not pile up stale hits.
	 * The settings option is written directly (full replace) rather than through
	 * array_replace_recursive so a shorter findings list cannot leave stale tail entries.
	 */
	public function merge_deep_scan(array $deep_findings, array $metrics): array
	{
		$now = freesiem_sentinel_get_iso8601_time();
		$deep_categories = ['malware', 'core_integrity', 'plugin_integrity', 'database'];

		$cache = $this->get_cache();
		$existing = array_values(freesiem_sentinel_safe_array($cache['local_findings'] ?? []));

		$deep_paths = [];

		foreach ($deep_findings as $finding) {
			$path = is_array($finding) ? (string) ($finding['evidence']['path'] ?? '') : '';

			if ($path !== '') {
				$deep_paths[$path] = true;
			}
		}

		$base = array_filter($existing, static function ($finding) use ($deep_categories, $deep_paths): bool {
			if (!is_array($finding)) {
				return false;
			}

			if (str_starts_with((string) ($finding['finding_key'] ?? ''), 'deep_')) {
				return false;
			}

			if (in_array((string) ($finding['category'] ?? ''), $deep_categories, true)) {
				return false;
			}

			// Drop a quick-scan filesystem heuristic if the deep scan already
			// reported the same file, so the file is not listed twice.
			if ((string) ($finding['category'] ?? '') === 'filesystem'
				&& isset($deep_paths[(string) ($finding['evidence']['path'] ?? '')])) {
				return false;
			}

			return true;
		});

		$by_key = [];

		foreach (array_merge(array_values($base), array_values($deep_findings)) as $finding) {
			if (!is_array($finding)) {
				continue;
			}

			$key = (string) ($finding['finding_key'] ?? '');

			if ($key === '') {
				$key = 'auto_' . md5((string) wp_json_encode($finding));
			}

			$by_key[$key] = $finding;
		}

		$merged = $this->sort_findings(array_values($by_key));
		// Keep the settings option a sane size — the most severe 2000 is plenty
		// for the on-screen list; the per-run history keeps its own copy.
		$total_findings = count($merged);
		$merged = array_slice($merged, 0, 2000);

		$cache['fetched_at'] = $now;
		$cache['local_findings'] = $merged;
		$cache['local_findings_truncated'] = $total_findings > count($merged) ? $total_findings : 0;
		$cache['severity_counts'] = $this->count_severities($merged);
		$cache['top_issues'] = array_slice($merged, 0, 5);
		$cache['recommendations'] = array_values(array_unique(array_map(static function (array $finding): string {
			return (string) ($finding['recommendation'] ?? '');
		}, $merged)));
		$cache['summary'] = array_merge(
			is_array($cache['summary'] ?? null) ? $cache['summary'] : [],
			[
				'local_score' => freesiem_sentinel_score_from_findings($merged),
				'last_local_scan_at' => $now,
				'last_deep_scan_at' => (string) ($metrics['finished_at'] ?? $now),
				'files_content_scanned' => (int) ($metrics['files_scanned'] ?? 0),
				'files_seen_deep' => (int) ($metrics['files_seen'] ?? 0),
				'bytes_scanned' => (int) ($metrics['bytes_scanned'] ?? 0),
				'malware_hits' => (int) ($metrics['malware_hits'] ?? 0),
				'core_files_modified' => (int) ($metrics['core_files_modified'] ?? 0),
				'plugin_files_modified' => (int) ($metrics['plugin_files_modified'] ?? 0),
				'database_issues' => (int) ($metrics['database_issues'] ?? 0),
				'deep_scan_partial' => !empty($metrics['partial']),
				'deep_scan_partial_reason' => (string) ($metrics['partial_reason'] ?? ''),
			]
		);

		$settings = freesiem_sentinel_get_settings();
		$settings['summary_cache'] = $cache;
		$settings['last_local_scan_at'] = $now;
		update_option(FREESIEM_SENTINEL_OPTION, freesiem_sentinel_sanitize_settings($settings), false);

		return $cache;
	}

	public function clear_scan_results(): array
	{
		$defaults = freesiem_sentinel_get_default_settings();
		$empty_cache = is_array($defaults['summary_cache'] ?? null) ? $defaults['summary_cache'] : [];

		$settings = freesiem_sentinel_get_settings();
		$settings['last_local_scan_at'] = '';
		$settings['last_remote_scan_at'] = '';
		$settings['last_sync_at'] = '';
		$settings['fim_last_diff_at'] = '';
		$settings['fim_diff_cache'] = [];
		$settings['summary_cache'] = $empty_cache;

		update_option(FREESIEM_SENTINEL_OPTION, freesiem_sentinel_sanitize_settings($settings), false);

		$this->clear_scan_history();

		return $this->get_cache();
	}

	// -----------------------------------------------------------------
	// Per-run scan history
	// -----------------------------------------------------------------

	private const HISTORY_OPTION = 'freesiem_sentinel_scan_history';
	private const HISTORY_INDEX_MAX = 20;
	private const HISTORY_DETAIL_MAX = 5;

	/**
	 * Append a completed scan run to the history.
	 *
	 * The index (kept for HISTORY_INDEX_MAX runs) holds one summary row per run.
	 * The full findings for the most recent HISTORY_DETAIL_MAX runs are stored in
	 * their own options; older detail options are pruned.
	 */
	public function record_scan_run(string $type, array $findings, array $metrics): void
	{
		$type = in_array($type, ['quick', 'deep', 'weekly', 'combined'], true) ? $type : 'deep';
		$findings = array_values(array_filter($findings, 'is_array'));
		$id = gmdate('Ymd-His') . '-' . substr(md5(uniqid('', true)), 0, 6);

		$row = [
			'id' => $id,
			'type' => $type,
			'started_at' => (string) ($metrics['started_at'] ?? ''),
			'finished_at' => (string) ($metrics['finished_at'] ?? freesiem_sentinel_get_iso8601_time()),
			'score' => freesiem_sentinel_score_from_findings($findings),
			'severity_counts' => $this->count_severities($findings),
			'findings_count' => count($findings),
			'files_scanned' => (int) ($metrics['files_scanned'] ?? 0),
			'malware_hits' => (int) ($metrics['malware_hits'] ?? 0),
			'core_files_modified' => (int) ($metrics['core_files_modified'] ?? 0),
			'database_issues' => (int) ($metrics['database_issues'] ?? 0),
			'partial' => !empty($metrics['partial']),
			'full' => !empty($metrics['full']),
			'has_detail' => true,
		];

		$index = $this->get_scan_history();
		array_unshift($index, $row);
		$index = array_slice($index, 0, self::HISTORY_INDEX_MAX);

		// Store findings for this run (most-severe first, bounded so a badly
		// infected site cannot bloat wp_options).
		update_option($this->run_option_key($id), [
			'meta' => $row,
			'findings' => array_slice($this->sort_findings($findings), 0, 750),
		], false);

		// Prune detail options beyond the newest HISTORY_DETAIL_MAX.
		foreach ($index as $pos => &$entry) {
			if ($pos < self::HISTORY_DETAIL_MAX) {
				continue;
			}

			if (!empty($entry['has_detail'])) {
				delete_option($this->run_option_key((string) $entry['id']));
				$entry['has_detail'] = false;
			}
		}
		unset($entry);

		update_option(self::HISTORY_OPTION, $index, false);
	}

	public function get_scan_history(): array
	{
		$index = get_option(self::HISTORY_OPTION, []);

		return is_array($index) ? array_values(array_filter($index, 'is_array')) : [];
	}

	/**
	 * @return array{meta:array,findings:array}|null
	 */
	public function get_scan_run(string $id): ?array
	{
		foreach ($this->get_scan_history() as $row) {
			if ((string) ($row['id'] ?? '') !== $id) {
				continue;
			}

			$detail = get_option($this->run_option_key($id), null);

			if (is_array($detail) && isset($detail['findings'])) {
				return [
					'meta' => is_array($detail['meta'] ?? null) ? $detail['meta'] : $row,
					'findings' => array_values(array_filter((array) $detail['findings'], 'is_array')),
				];
			}

			return ['meta' => $row, 'findings' => []];
		}

		return null;
	}

	public function clear_scan_history(): void
	{
		foreach ($this->get_scan_history() as $row) {
			delete_option($this->run_option_key((string) ($row['id'] ?? '')));
		}

		delete_option(self::HISTORY_OPTION);
	}

	private function run_option_key(string $id): string
	{
		return 'freesiem_sentinel_scan_run_' . preg_replace('/[^A-Za-z0-9\-]/', '', $id);
	}

	public function store_remote_summary(array $summary): array
	{
		$cache = $this->get_cache();
		$cache['fetched_at'] = freesiem_sentinel_get_iso8601_time();
		$cache['summary'] = $summary;
		$cache['severity_counts'] = is_array($summary['severity_counts'] ?? null) ? $summary['severity_counts'] : $cache['severity_counts'];
		$cache['top_issues'] = is_array($summary['top_issues'] ?? null) ? $summary['top_issues'] : $cache['top_issues'];
		$cache['recommendations'] = is_array($summary['recommendations'] ?? null) ? $summary['recommendations'] : $cache['recommendations'];

		freesiem_sentinel_update_settings([
			'summary_cache' => $cache,
			'last_remote_scan_at' => sanitize_text_field((string) ($summary['last_remote_scan_at'] ?? freesiem_sentinel_get_setting('last_remote_scan_at', ''))),
			'last_sync_at' => freesiem_sentinel_get_iso8601_time(),
		]);

		return $cache;
	}

	public function store_notices(array $notices): array
	{
		$cache = $this->get_cache();
		$cache['notices'] = array_values($notices);
		freesiem_sentinel_update_settings(['summary_cache' => $cache]);

		return $cache;
	}

	public function count_severities(array $findings): array
	{
		$counts = [
			'critical' => 0,
			'high' => 0,
			'medium' => 0,
			'low' => 0,
			'info' => 0,
		];

		foreach ($findings as $finding) {
			if (!is_array($finding)) {
				continue;
			}

			$severity = freesiem_sentinel_normalize_severity((string) ($finding['severity'] ?? 'info'));
			$counts[$severity]++;
		}

		return $counts;
	}

	private function sort_findings(array $findings): array
	{
		usort($findings, static function (array $left, array $right): int {
			$order = [
				'critical' => 0,
				'high' => 1,
				'medium' => 2,
				'low' => 3,
				'info' => 4,
			];
			$left_severity = freesiem_sentinel_normalize_severity((string) ($left['severity'] ?? 'info'));
			$right_severity = freesiem_sentinel_normalize_severity((string) ($right['severity'] ?? 'info'));
			$left_rank = $order[$left_severity] ?? 4;
			$right_rank = $order[$right_severity] ?? 4;

			if ($left_rank === $right_rank) {
				return strcmp((string) ($left['title'] ?? ''), (string) ($right['title'] ?? ''));
			}

			return $left_rank <=> $right_rank;
		});

		return $findings;
	}
}
