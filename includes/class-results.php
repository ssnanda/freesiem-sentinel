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

		return $this->get_cache();
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
