<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/synchy-sync-delete-smoke.php');
}

$uploads = wp_upload_dir();
$detect_dir = wp_normalize_path(trailingslashit((string) $uploads['basedir']) . 'synchy-delete-detect');
$apply_dir = wp_normalize_path(trailingslashit((string) $uploads['basedir']) . 'synchy-delete-apply');
$detect_file = wp_normalize_path(trailingslashit($detect_dir) . 'keep.txt');
$apply_file = wp_normalize_path(trailingslashit($apply_dir) . 'remove.txt');

$assert = static function (bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException($message);
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
}
