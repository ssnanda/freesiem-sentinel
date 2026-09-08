<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/deep-scanner-smoke.php');
}

// Drive every slice synchronously from this process — no WP-Cron loopback
// racing the loop below for the scan lock.
if (!defined('DISABLE_WP_CRON')) {
	define('DISABLE_WP_CRON', true);
}

/**
 * Smoke test for Freesiem_Deep_Scanner.
 *
 * Plants a handful of benign-but-signature-matching artifacts, runs the deep scan
 * to completion, asserts the expected findings appear in the results cache, then
 * removes the artifacts and clears the scan state.
 *
 *   wp eval-file wp-content/plugins/freesiem-sentinel/tests/deep-scanner-smoke.php
 */

$assert = static function (bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException('FAIL: ' . $message);
	}

	echo 'ok - ' . $message . "\n";
};

$plugin = Freesiem_Plugin::instance();
$deep = $plugin->get_deep_scanner();

$uploads = wp_get_upload_dir();
$dir = trailingslashit($uploads['basedir']) . 'freesiem-smoke';
wp_mkdir_p($dir);

$shell = $dir . '/smoke-shell.php';
$polyglot = $dir . '/smoke-image.jpg';
$htaccess = $dir . '/.htaccess';

// The planted files must contain real attack bytes for the scanner to match,
// but assembling those strings from fragments here keeps THIS fixture from
// tripping the deep scanner (and now the "unrecognized file in our own
// directory" check) when a developer runs a scan over their working copy.
$php_open = '<' . '?php';
$eval_expr = 'ev' . 'al(bas' . 'e64_' . 'decode($_POST[' . "'q'" . ']))';

file_put_contents($shell, $php_open . ' /* freesiem smoke */ @' . $eval_expr . '; ?' . '>');
file_put_contents($polyglot, "\xFF\xD8\xFF\xE0JFIF\x00 " . $php_open . ' /* freesiem smoke */ echo 1; ?' . '>');
file_put_contents($htaccess, "AddType application/x-httpd-php .jpg\n");

$cleanup = static function () use ($shell, $polyglot, $htaccess, $dir, $deep): void {
	@unlink($shell);
	@unlink($polyglot);
	@unlink($htaccess);
	@rmdir($dir);
	$deep->abort();
};

try {
	$deep->start([
		'scan_malware' => 1,
		'scan_core_integrity' => 1,
		'scan_plugin_integrity' => 0,
		'scan_database' => 1,
		'scan_uploads_deep' => 1,
		'scan_intensity' => 'thorough',
	]);

	$guard = 0;

	do {
		delete_transient('freesiem_sentinel_deep_scan_lock');
		$result = $deep->run_slice(['files' => 20000, 'seconds' => 45, 'throttle_us' => 0, 'batch' => 2000]);
		$guard++;
	} while (empty($result['done']) && $guard < 60);

	$assert(!empty($result['done']), 'deep scan reached completion in ' . $guard . ' slice(s)');

	$deep->finalize();

	$cache = $plugin->get_results()->get_cache();
	$findings = is_array($cache['local_findings'] ?? null) ? $cache['local_findings'] : [];

	$paths = [];
	$signatures = [];

	foreach ($findings as $finding) {
		if (!is_array($finding)) {
			continue;
		}

		$paths[] = (string) ($finding['evidence']['path'] ?? '');

		if (!empty($finding['evidence']['signature_id'])) {
			$signatures[] = (string) $finding['evidence']['signature_id'];
		}
	}

	$has_shell = false;

	foreach ($paths as $path) {
		if (str_contains($path, 'smoke-shell.php')) {
			$has_shell = true;
			break;
		}
	}

	$assert($has_shell, 'the planted web shell was flagged');
	$assert(in_array('php_eval_encoded_payload', $signatures, true), 'the eval(base64_decode(...)) signature matched');
	$assert(in_array('polyglot_php_tag', $signatures, true), 'PHP inside the image polyglot was detected');
	$assert(in_array('htaccess_addtype_php', $signatures, true), 'the .htaccess AddType abuse was detected');

	$summary = is_array($cache['summary'] ?? null) ? $cache['summary'] : [];
	$assert((int) ($summary['files_content_scanned'] ?? 0) > 0, 'files were content-scanned');
	$assert((int) ($summary['malware_hits'] ?? 0) >= 3, 'malware hit counter advanced');

	echo "\nPASS - deep scanner smoke test\n";
} finally {
	$cleanup();
}
