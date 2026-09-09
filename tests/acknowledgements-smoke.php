<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/acknowledgements-smoke.php');
}

/**
 * Smoke test for Freesiem_Acknowledgements ("Mark as safe").
 *
 * Plants a benign but flag-worthy file in uploads, stores a findings cache that
 * references it, marks the finding safe, and checks that:
 *
 *   - it drops out of the active list, the severity counts and the score;
 *   - it survives clear_scan_results();
 *   - it is restored to active when the mark is removed;
 *   - the mark auto-voids when the file's bytes change.
 *
 *   wp eval-file wp-content/plugins/freesiem-sentinel/tests/acknowledgements-smoke.php
 */

$assert = static function (bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException('FAIL: ' . $message);
	}

	echo 'ok - ' . $message . "\n";
};

$plugin = Freesiem_Plugin::instance();
$results = $plugin->get_results();

$uploads = wp_get_upload_dir();
$dir = trailingslashit($uploads['basedir']) . 'freesiem-ack-smoke';
wp_mkdir_p($dir);
$archive = $dir . '/harmless-kit.zip';
file_put_contents($archive, "PK\x03\x04 not really a zip, just a fixture\n");

$rel = ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($archive)), '/');

$saved_option = get_option(Freesiem_Acknowledgements::OPTION, null);
$saved_cache = $results->get_cache();

$finding = [
	'finding_key' => 'smoke_ack_' . md5($rel),
	'category' => 'filesystem',
	'severity' => 'high',
	'title' => 'Suspicious file on disk (ack smoke)',
	'description' => 'Fixture finding for the acknowledgements smoke test.',
	'recommendation' => 'Confirm whether this file is expected.',
	'evidence' => ['path' => $rel],
	'score' => 58,
];

$restore = static function () use ($saved_option, $saved_cache, $archive, $dir): void {
	if ($saved_option === null) {
		delete_option(Freesiem_Acknowledgements::OPTION);
	} else {
		update_option(Freesiem_Acknowledgements::OPTION, $saved_option, false);
	}

	$settings = freesiem_sentinel_get_settings();
	$settings['summary_cache'] = $saved_cache;
	update_option(FREESIEM_SENTINEL_OPTION, freesiem_sentinel_sanitize_settings($settings), false);

	@unlink($archive);
	@rmdir($dir);
};

try {
	Freesiem_Acknowledgements::clear_all();

	// Seed a results cache with the one fixture finding.
	$results->store_local_scan([
		'findings' => [$finding],
		'score' => 42,
		'summary' => [],
		'inventory' => [],
	]);

	$cache = $results->get_cache();
	$assert((int) ($cache['severity_counts']['high'] ?? 0) === 1, 'fixture finding counts as 1 high before marking safe');
	$assert((int) ($cache['acknowledged_count'] ?? 0) === 0, 'nothing acknowledged yet');
	$score_before = (int) ($cache['summary']['local_score'] ?? 100);

	// Mark it safe.
	$added = Freesiem_Acknowledgements::add($finding, 'Fixture archive I placed for the smoke test', 'smoke-runner', 0);
	$assert($added === true, 'add() accepted the finding with a note');

	$rejected = Freesiem_Acknowledgements::add($finding, '   ', 'smoke-runner', 0);
	$assert(is_wp_error($rejected), 'add() rejects an empty note');

	$results->reapply_acknowledgements();
	$cache = $results->get_cache();

	$assert((int) ($cache['severity_counts']['high'] ?? 0) === 0, 'finding no longer counts as high after marking safe');
	$assert((int) ($cache['acknowledged_count'] ?? 0) === 1, 'acknowledged_count is 1');
	$assert((int) ($cache['summary']['local_score'] ?? 0) >= $score_before, 'score recovered (or held) after excluding the finding');

	$partition = Freesiem_Acknowledgements::partition($cache['local_findings']);
	$assert(count($partition['active']) === 0, 'partition() puts the finding in the acknowledged bucket');
	$assert(count($partition['acknowledged']) === 1, 'partition() acknowledged bucket has the finding');

	// Survives Clear Results.
	$plugin->clear_scan_results();
	$assert(Freesiem_Acknowledgements::count() === 1, 'the safe mark survives clear_scan_results()');

	// Auto-voids when the file changes.
	file_put_contents($archive, "PK\x03\x04 different bytes now\n");
	$record = Freesiem_Acknowledgements::get($finding['finding_key']);
	$assert(is_array($record), 'record still present before revalidation');
	$assert(Freesiem_Acknowledgements::is_valid($record) === false, 'is_valid() is false once the file bytes change');

	$partition = Freesiem_Acknowledgements::partition([$finding]);
	$assert(count($partition['active']) === 1, 'a changed-file finding returns to the active bucket');
	$assert(!empty($partition['active'][0]['acknowledgement_voided']), 'the returned finding is tagged acknowledgement_voided');

	$removed = Freesiem_Acknowledgements::prune_stale();
	$assert($removed === 1, 'prune_stale() drops the now-invalid record');
	$assert(Freesiem_Acknowledgements::count() === 0, 'no records left after prune');

	// Remove-mark path.
	Freesiem_Acknowledgements::add($finding, 'second time', 'smoke-runner', 0);
	$assert(Freesiem_Acknowledgements::remove($finding['finding_key'], 'smoke-runner') === true, 'remove() deletes the mark');
	$assert(Freesiem_Acknowledgements::count() === 0, 'no records left after remove');

	echo "\nPASS - acknowledgements smoke test\n";
} finally {
	$restore();
}
