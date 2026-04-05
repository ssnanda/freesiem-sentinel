<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/synchy-integration-smoke.php');
}

$old_get = $_GET;

$assert = static function (bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException($message);
	}
};

try {
	$plugin = Freesiem_Plugin::instance();
	$admin = new Freesiem_Admin($plugin);

	wp_set_current_user(1);

	$tabs = [
		'export' => 'Export',
		'import' => 'Import',
		'schedule' => 'Schedule',
		'upload-live' => 'Upload to Live',
		'sync' => 'Sync',
		'about' => 'About',
	];

	$assert(function_exists('synchy_render_page'), 'Expected Synchy runtime functions to be available.');

	foreach ($tabs as $tab => $label) {
		$_GET['page'] = FREESIEM_SENTINEL_SYNCHY_PAGE;
		$_GET['tab'] = $tab;
		ob_start();
		$admin->render_synchy_page();
		$html = ob_get_clean();
		$assert(str_contains($html, 'nav-tab-wrapper'), 'Expected Synchy tab navigation to render.');
		$assert(str_contains($html, $label), 'Expected Synchy tab content for ' . $tab . '.');
	}

	echo "synchy-integration-smoke: ok\n";
} finally {
	$_GET = $old_get;
}
