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
$orphan_security = WP_CONTENT_DIR . '/wflogs';
$orphan_forms = trailingslashit($uploads['basedir']) . 'wpforms';
$owned_data = trailingslashit($uploads['basedir']) . 'rank-math';
$owner_plugin = WP_PLUGIN_DIR . '/seo-by-rank-math';
$duplicate = ABSPATH . 'wp-header-test.php';
// Refuse collisions rather than overwrite real plugin data during a smoke test.
foreach ([$orphan_security, $orphan_forms, $owned_data, $owner_plugin, $duplicate] as $fixture) {
	if (file_exists($fixture) || is_link($fixture)) {
		throw new RuntimeException('Fixture path already exists: ' . $fixture);
	}
}
foreach (['wordfence', 'wpforms', 'wpforms-lite'] as $slug) {
	if (is_dir(WP_PLUGIN_DIR . '/' . $slug)) {
		throw new RuntimeException('Orphan fixture owner is installed: ' . $slug);
	}
}

wp_mkdir_p($dir);

$shell = $dir . '/smoke-shell.php';
$polyglot = $dir . '/smoke-image.jpg';
$htaccess = $dir . '/.htaccess';
$disguised = $dir . '/smoke-notes.old';
$selfmod = $dir . '/smoke-fm.php';

// The planted files must contain real attack bytes for the scanner to match,
// but assembling those strings from fragments here keeps THIS fixture from
// tripping the deep scanner (and now the "unrecognized file in our own
// directory" check) when a developer runs a scan over their working copy.
$php_open = '<' . '?php';
$eval_expr = 'ev' . 'al(bas' . 'e64_' . 'decode($_POST[' . "'q'" . ']))';

file_put_contents($shell, $php_open . ' /* freesiem smoke */ @' . $eval_expr . '; ?' . '>');
file_put_contents($polyglot, "\xFF\xD8\xFF\xE0JFIF\x00 " . $php_open . ' /* freesiem smoke */ echo 1; ?' . '>');
file_put_contents($htaccess, "AddType application/x-httpd-php .jpg\n");
// Executable PHP behind a ".old" name — must be pulled into the scan as PHP.
file_put_contents($disguised, $php_open . ' /* freesiem smoke */ ev' . 'al(trim($_' . 'POST[' . "'c'" . '])); ?' . '>');
// Self-rewriting / anti-forensic file-manager shape.
file_put_contents($selfmod, $php_open . " /* freesiem smoke */ file_put_" . "contents(__FILE__, \$x); tou" . "ch(__FILE__, \$mt); ?" . '>');

// Abandoned backup folders. These sit at the top level of uploads/ because that
// is where a backup plugin writes them, and the check only walks one level down
// from wp-content / uploads / ABSPATH. The "archive" only has to carry a backup
// extension — the check reports on names and sizes, it never opens the file.
$backup_dir = trailingslashit($uploads['basedir']) . 'ai1wm-backups';
$backup_file = $backup_dir . '/freesiem-smoke-20250602-000000-abcdef.wpress';
$empty_backup_dir = trailingslashit($uploads['basedir']) . 'backups-dup-lite';
wp_mkdir_p($backup_dir);
wp_mkdir_p($empty_backup_dir);
file_put_contents($backup_file, str_repeat("\0", 2097152));
file_put_contents($empty_backup_dir . '/smoke.log', "freesiem smoke\n");

$cleanup = static function () use ($orphan_security, $orphan_forms, $owned_data, $owner_plugin, $duplicate, $shell, $polyglot, $htaccess, $disguised, $selfmod, $dir, $backup_dir, $backup_file, $empty_backup_dir, $deep): void {
	@unlink($shell);
	@unlink($polyglot);
	@unlink($htaccess);
	@unlink($disguised);
	@unlink($selfmod);
	@rmdir($dir);
	@unlink($backup_file);
	@rmdir($backup_dir);
	@unlink($empty_backup_dir . '/smoke.log');
	@rmdir($empty_backup_dir);
	@unlink($orphan_security . '/config.php');
	@rmdir($orphan_security);
	@unlink($orphan_forms . '/cache/smoke.txt');
	@rmdir($orphan_forms . '/cache');
	@rmdir($orphan_forms);
	@unlink($owned_data . '/smoke.txt');
	@rmdir($owned_data);
	@unlink($owner_plugin . '/smoke-owner.php');
	@rmdir($owner_plugin);
	@unlink($duplicate);
	$deep->abort();
};

try {
	wp_mkdir_p($orphan_security);
	wp_mkdir_p($orphan_forms . '/cache');
	wp_mkdir_p($owned_data);
	wp_mkdir_p($owner_plugin);
	file_put_contents($orphan_security . '/config.php', $php_open . " // benign smoke configuration\n");
	file_put_contents($orphan_forms . '/cache/smoke.txt', 'smoke');
	file_put_contents($owned_data . '/smoke.txt', 'smoke');
	file_put_contents($owner_plugin . '/smoke-owner.php', $php_open . "\n/* Plugin Name: Smoke fixture owner */\n");
	$bootstrap = file_get_contents(ABSPATH . 'wp-blog-header.php');
	$assert(is_string($bootstrap) && $bootstrap !== '', 'live bootstrap fixture is readable');
	$stripped = '';
	foreach (token_get_all($bootstrap) as $token) {
		$stripped .= is_array($token) ? (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true) ? ' ' : $token[1]) : $token;
	}
	file_put_contents($duplicate, $stripped);
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

	$keys = [];
	foreach ($findings as $finding) {
		if (is_array($finding)) {
			$keys[] = (string) ($finding['finding_key'] ?? '');
		}
	}
	$has = static function (string $prefix) use ($keys): bool {
		foreach ($keys as $k) {
			if (str_starts_with($k, $prefix)) {
				return true;
			}
		}

		return false;
	};

	$assert($has('deep_disguised_php_'), 'executable PHP behind a .old extension was flagged as disguised');
	$assert(in_array('php_eval_request_console', $signatures, true), 'eval() fed from request input was detected in the disguised file');
	$assert(in_array('php_self_rewrite', $signatures, true), 'the self-rewriting-source shape was detected');
	$assert(in_array('php_mtime_reset', $signatures, true), 'the timestamp-reset anti-forensics shape was detected');

	$assert($has('deep_backup_dir_'), 'the abandoned backup folder holding a .wpress export was flagged');
	$assert($has('deep_backup_dir_empty_'), 'the empty leftover backup folder was reported separately');

	// The archive-bearing folder must outrank the empty one: an exposed export is
	// a disclosure risk, an empty leftover is only clutter.
	$backup_severity = '';
	$empty_severity = '';

	foreach ($findings as $finding) {
		if (!is_array($finding)) {
			continue;
		}

		$key = (string) ($finding['finding_key'] ?? '');

		if (str_starts_with($key, 'deep_backup_dir_empty_')) {
			$empty_severity = (string) ($finding['severity'] ?? '');
		} elseif (str_starts_with($key, 'deep_backup_dir_')) {
			$backup_severity = (string) ($finding['severity'] ?? '');
			$assert(!empty($finding['evidence']['contains_dump']), 'the .wpress export was recognised as a full site dump');
			$assert(empty($finding['evidence']['denies_web_access']), 'the folder was correctly reported as web-reachable');
		}
	}

	$assert($backup_severity === 'high', 'an exposed export folder is reported as high severity, got: ' . $backup_severity);
	$assert($empty_severity === 'low', 'an empty leftover folder is reported as low severity, got: ' . $empty_severity);

	$fixture_finding = static function (string $prefix, string $absolute) use ($findings): ?array {
		$relative = ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($absolute)), '/');
		foreach ($findings as $finding) {
			if (str_starts_with($finding['finding_key'] ?? '', $prefix) && ($finding['evidence']['path'] ?? '') === $relative) {
				return $finding;
			}
		}
		return null;
	};
	$assert(($fixture_finding('deep_orphan_data_', $orphan_security)['severity'] ?? '') === 'medium', 'orphaned security configuration is medium');
	$assert(($fixture_finding('deep_orphan_data_', $orphan_forms)['severity'] ?? '') === 'low', 'orphaned form cache is low');
	$assert(($fixture_finding('deep_duplicate_bootstrap_', $duplicate)['severity'] ?? '') === 'high', 'comment-stripped bootstrap copy is high');
	$assert($fixture_finding('deep_orphan_data_', $owned_data) === null, 'inactive installed plugin still owns its data');
	$assert($fixture_finding('deep_orphan_data_', $backup_dir) === null, 'backup directory is not also orphan data');

	$summary = is_array($cache['summary'] ?? null) ? $cache['summary'] : [];
	$assert((int) ($summary['files_content_scanned'] ?? 0) > 0, 'files were content-scanned');
	$assert((int) ($summary['malware_hits'] ?? 0) >= 3, 'malware hit counter advanced');

	echo "\nPASS - deep scanner smoke test\n";
} finally {
	$cleanup();
}
