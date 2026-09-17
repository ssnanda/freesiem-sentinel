<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/synchy-sync-delete-smoke.php');
}

$uploads = wp_upload_dir();
$detect_dir = wp_normalize_path(trailingslashit((string) $uploads['basedir']) . 'synchy-delete-detect');
$apply_dir = wp_normalize_path(trailingslashit((string) $uploads['basedir']) . 'synchy-delete-apply');
$detect_file = wp_normalize_path(trailingslashit($detect_dir) . 'keep.txt');
$apply_file = wp_normalize_path(trailingslashit($apply_dir) . 'remove.txt');

$content_dir = wp_normalize_path(WP_CONTENT_DIR);
$mu_dir = $content_dir . '/mu-plugins';
$mu_dir_created = !is_dir($mu_dir);
// .txt, not .php: WordPress autoloads every top-level mu-plugins/*.php file.
$mu_file = $mu_dir . '/synchy-delete-smoke-remove.txt';
$mu_nested_dir = $mu_dir . '/synchy-delete-smoke-nested';
$mu_nested_file = $mu_nested_dir . '/remove.txt';
$mu_disabled_dir = $mu_dir . '/synchy-delete-smoke-disabled';
$mu_disabled_file = $mu_disabled_dir . '/keep.txt';
$mu_hostinger_file = $mu_dir . '/synchy-delete-smoke-hostinger-keep.txt';
$hostinger_plugin_dir = $content_dir . '/plugins/hostinger';
$hostinger_plugin_dir_created = !is_dir($hostinger_plugin_dir);
$hostinger_plugin_file = $hostinger_plugin_dir . '/synchy-delete-smoke-keep.txt';

$assert = static function (bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException($message);
	}
};

$reset_fixtures = static function () use ($mu_dir, $mu_file, $mu_nested_dir, $mu_nested_file, $mu_disabled_dir, $mu_disabled_file, $mu_hostinger_file, $hostinger_plugin_dir, $hostinger_plugin_file): void {
	foreach ([$mu_dir, $mu_nested_dir, $mu_disabled_dir, $hostinger_plugin_dir] as $dir) {
		wp_mkdir_p($dir);
	}

	foreach ([$mu_file, $mu_nested_file, $mu_disabled_file, $mu_hostinger_file, $hostinger_plugin_file] as $file) {
		file_put_contents($file, "fixture\n");
	}
};

try {
	wp_mkdir_p($detect_dir);
	wp_mkdir_p($apply_dir);
	file_put_contents($detect_file, "keep\n");
	file_put_contents($apply_file, "remove\n");

	$state = [
		'scope_sync_times' => [
			'files_uploads' => time() - 300,
		],
		'file_paths' => [
			'files_uploads' => [
				'uploads/synchy-delete-detect/keep.txt',
				'uploads/synchy-delete-detect/missing.txt',
			],
		],
	];

	$delta = synchy_collect_sync_file_delta($state, ['files_uploads'], false);
	$deleted_paths = (array) (($delta['deleted_paths']['files_uploads'] ?? []));
	$assert(in_array('uploads/synchy-delete-detect/missing.txt', $deleted_paths, true), 'Expected deleted upload paths to be detected from prior sync state.');

	$result = synchy_apply_sync_deleted_paths([
		'files' => [
			'deletedPaths' => [
				'uploads/synchy-delete-apply/remove.txt',
			],
		],
	]);

	$assert(!is_wp_error($result), 'Expected deleted-path apply helper to succeed.');
	$assert(!file_exists($apply_file), 'Expected deleted upload file to be removed.');
	$assert(!is_dir($apply_dir), 'Expected empty upload directory to be pruned.');

	// Path rules shared by sender and receiver.
	$assert(synchy_is_allowed_sync_deleted_path('mu-plugins/upos-example.php'), 'Expected mu-plugins deletions to be allowed.');
	$assert(!synchy_is_allowed_sync_deleted_path('mu-plugins/hostinger-preview-domain.php'), 'Expected hostinger mu-plugins to be protected.');
	$assert(!synchy_is_allowed_sync_deleted_path('plugins/synchy/synchy.php'), 'Expected plugins/synchy to be protected.');
	$assert(!synchy_is_allowed_sync_deleted_path('plugins/ajcore/config/synced-settings.json'), 'Expected AJ Core runtime files to be protected.');
	$assert(!synchy_is_allowed_sync_deleted_path('uploads/synchy-sync/sync-state.json'), 'Expected Synchy bookkeeping uploads to be protected.');

	foreach (['', '../wp-config.php', 'plugins/../../wp-config.php', 'uploads/..', '/etc/passwd', 'C:/Windows/win.ini', 'wp-config.php', 'mu-plugins', 'languages/de_DE.mo'] as $bad_path) {
		$validated = synchy_validate_sync_deleted_path($bad_path);
		$assert(is_wp_error($validated) && $validated->get_error_code() === 'synchy_sync_deleted_path_invalid', 'Expected structurally unsafe deleted path to be rejected: ' . $bad_path);
		$assert(!synchy_is_allowed_sync_deleted_path($bad_path), 'Expected unsafe deleted path to be disallowed: ' . $bad_path);
	}

	// Sender: a protected path in the previous baseline never becomes a deletion.
	$reset_fixtures();
	@unlink($mu_hostinger_file);
	@unlink($mu_file);
	$mu_delta = synchy_collect_sync_file_delta([
		'scope_sync_times' => ['files_mu_plugins' => time() - 300],
		'file_paths' => [
			'files_mu_plugins' => [
				'mu-plugins/synchy-delete-smoke-remove.txt',
				'mu-plugins/synchy-delete-smoke-hostinger-keep.txt',
			],
		],
	], ['files_mu_plugins'], false);
	$mu_deleted = (array) ($mu_delta['deleted_paths']['files_mu_plugins'] ?? []);
	$assert(in_array('mu-plugins/synchy-delete-smoke-remove.txt', $mu_deleted, true), 'Expected a locally removed mu-plugin to be reported as deleted.');
	$assert(!in_array('mu-plugins/synchy-delete-smoke-hostinger-keep.txt', $mu_deleted, true), 'Expected a protected hostinger mu-plugin never to be sent as a deletion.');

	// Receiver: allowed mu-plugins deletion.
	$reset_fixtures();
	$result = synchy_apply_sync_deleted_paths([
		'files' => ['deletedPaths' => ['mu-plugins/synchy-delete-smoke-remove.txt']],
	]);
	$assert(!is_wp_error($result), 'Expected a mu-plugins deletion to be accepted.');
	$assert(!file_exists($mu_file), 'Expected the mu-plugins file to be deleted.');
	$assert((int) $result['skippedProtectedCount'] === 0, 'Expected no skipped deletions for an allowed mu-plugins path.');
	$assert(is_dir($mu_dir), 'Expected wp-content/mu-plugins itself never to be pruned.');

	// Receiver: protected hostinger mu-plugin is skipped and reported, not an error.
	$reset_fixtures();
	$result = synchy_apply_sync_deleted_paths([
		'files' => ['deletedPaths' => ['mu-plugins/synchy-delete-smoke-hostinger-keep.txt']],
	]);
	$assert(!is_wp_error($result), 'Expected a protected hostinger mu-plugin deletion to be skipped, not to abort the Sync.');
	$assert(is_file($mu_hostinger_file), 'Expected the protected hostinger mu-plugin to survive.');
	$assert((int) $result['skippedProtectedCount'] === 1 && in_array('mu-plugins/synchy-delete-smoke-hostinger-keep.txt', (array) $result['skippedProtectedPaths'], true), 'Expected the skipped hostinger mu-plugin to be reported.');

	// Receiver: protected plugin path is skipped and reported.
	$result = synchy_apply_sync_deleted_paths([
		'files' => ['deletedPaths' => ['plugins/hostinger/synchy-delete-smoke-keep.txt']],
	]);
	$assert(!is_wp_error($result), 'Expected a protected plugin deletion to be skipped, not to abort the Sync.');
	$assert(is_file($hostinger_plugin_file), 'Expected the protected plugin file to survive.');
	$assert((int) $result['skippedProtectedCount'] === 1, 'Expected the skipped plugin path to be counted.');

	// Receiver: a "../" path rejects the whole package before anything is deleted.
	$reset_fixtures();
	$result = synchy_apply_sync_deleted_paths([
		'files' => ['deletedPaths' => ['mu-plugins/synchy-delete-smoke-remove.txt', 'plugins/../../wp-config.php']],
	]);
	$assert(is_wp_error($result) && $result->get_error_code() === 'synchy_sync_deleted_path_invalid', 'Expected a traversal path to be rejected.');
	$assert(str_contains($result->get_error_message(), 'plugins/../../wp-config.php'), 'Expected the rejection message to name the offending path.');
	$assert(is_file($mu_file), 'Expected no deletions to be applied when the package contains an invalid path.');

	// Receiver: mixed package -- valid deletions apply, protected ones are skipped,
	// a directory-like entry is left alone, and emptied parent dirs are pruned.
	$reset_fixtures();
	$result = synchy_apply_sync_deleted_paths([
		'files' => [
			'deletedPaths' => [
				'mu-plugins/synchy-delete-smoke-remove.txt',
				'mu-plugins/synchy-delete-smoke-nested/remove.txt',
				'mu-plugins/synchy-delete-smoke-disabled',
				'mu-plugins/synchy-delete-smoke-hostinger-keep.txt',
				'plugins/hostinger/synchy-delete-smoke-keep.txt',
				'mu-plugins/synchy-delete-smoke-already-gone.txt',
			],
		],
	]);
	$assert(!is_wp_error($result), 'Expected a mixed deletion package to succeed.');
	$assert(!file_exists($mu_file) && !file_exists($mu_nested_file), 'Expected the valid mu-plugins deletions to apply.');
	$assert(!is_dir($mu_nested_dir), 'Expected the emptied nested mu-plugins directory to be pruned.');
	$assert(is_file($mu_disabled_file) && is_dir($mu_disabled_dir), 'Expected a non-empty directory entry never to be removed recursively.');
	$assert((int) $result['skippedNonFileCount'] === 1 && in_array('mu-plugins/synchy-delete-smoke-disabled', (array) $result['skippedNonFilePaths'], true), 'Expected the directory entry to be reported as skipped.');
	$assert(is_file($mu_hostinger_file) && is_file($hostinger_plugin_file), 'Expected protected files in a mixed package to survive.');
	$assert((int) $result['skippedProtectedCount'] === 2, 'Expected both protected paths in the mixed package to be reported.');
	$assert((int) $result['deletedFiles'] === 2, 'Expected exactly the two valid files to be deleted.');
	$assert(is_dir($mu_dir), 'Expected wp-content/mu-plugins to survive the mixed package.');

	echo "synchy-sync-delete-smoke: ok\n";
} finally {
	if (is_file($detect_file)) {
		@unlink($detect_file);
	}

	if (is_dir($detect_dir)) {
		@rmdir($detect_dir);
	}

	if (is_file($apply_file)) {
		@unlink($apply_file);
	}

	if (is_dir($apply_dir)) {
		@rmdir($apply_dir);
	}

	foreach ([$mu_file, $mu_nested_file, $mu_disabled_file, $mu_hostinger_file, $hostinger_plugin_file] as $fixture_file) {
		if (is_file($fixture_file)) {
			@unlink($fixture_file);
		}
	}

	foreach ([$mu_nested_dir, $mu_disabled_dir] as $fixture_dir) {
		if (is_dir($fixture_dir)) {
			@rmdir($fixture_dir);
		}
	}

	if ($hostinger_plugin_dir_created && is_dir($hostinger_plugin_dir)) {
		@rmdir($hostinger_plugin_dir);
	}

	if ($mu_dir_created && is_dir($mu_dir)) {
		@rmdir($mu_dir);
	}
}
