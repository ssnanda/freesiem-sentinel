<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/synchy-customer-files-smoke.php');
}

// Customer-file and live-ownership rules for Sync. Every case below is a failure that actually
// happened (or a hole found in the audit). Almost everything is pure: no fixtures, nothing written
// to live-owned tables. Two blocks touch the site read-only/with a temp folder and say so.

$assert = static function (bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException($message);
	}
};
$post = static fn(string $type = 'post', string $mime = '', string $guid = ''): array => ['post_type' => $type, 'post_mime_type' => $mime, 'guid_key' => $guid];
$live = static fn(string $mime, string $guid = ''): array => ['mime' => $mime, 'guid_key' => $guid];
$rules = static fn(array $posts = [], array $children = [], array $customers = [], array $attachments = [], array $tables = [], array $options = [], array $in_terms = [], array $live_terms = []): array => synchy_evaluate_customer_file_rules($posts, $children, $customers, $attachments, $tables, $options, $in_terms, $live_terms);

// 1. Failure: a local post at an ID that is a live customer attachment (E1).
$v = $rules([1000000001 => $post('post')], [], [1000000001]);
$assert(count($v) === 1 && str_contains($v[0], 'E1'), 'E1: a post at a live customer file ID must be flagged.');
$v = $rules([], [1000000002], [1000000002]);
$assert(count($v) === 1 && str_contains($v[0], 'E1'), 'E1: meta or term links aimed at a customer file must be flagged.');
$assert($rules([1500000005 => $post('attachment', 'image/jpeg', '/a.jpg'), 4082 => $post('post')], [4082], [1000000001]) === [], 'A normal push, including blog images at 1.5e9+, must pass.');

// 2. Failure: a local attachment of a different type at a live attachment's ID (E4).
$v = $rules([4162 => $post('attachment', 'image/jpeg', '/2026/11/illustration.jpg')], [], [], [4162 => $live('application/pdf', '/2026/11/aoo.pdf')]);
$assert(count($v) === 1 && str_contains($v[0], 'E4'), 'E4: a different record of another type at the same ID must be flagged.');
// E4 root-cause rule: the SAME record (same guid) changing type is a legitimate replacement, not a collision.
$assert($rules([300 => $post('attachment', 'image/jpeg', '/2026/11/logo.png')], [], [], [300 => $live('image/png', '/2026/11/logo.png')]) === [], 'E4: the same record changing type (file replaced) must pass.');
$assert($rules([301 => $post('attachment', 'image/png', '/x.png')], [], [], [301 => $live('IMAGE/PNG', '/y.png')]) === [], 'E4: a different record of the same type is ordinary mirrored media and must pass.');

// 3. Failure: a push that carries the storage option (E3), and the protected tables.
$v = $rules([], [], [], [], [], ['ajcore_storage_settings']);
$assert(count($v) === 1 && str_contains($v[0], 'E3'), 'E3: the storage option must be flagged.');
foreach (['wp_aj_portal_files', 'wp_aj_portal_file_users', 'wp_aj_portal_file_tags', 'wp_aj_storage_objects'] as $table) {
	$assert(count($rules([], [], [], [], [$table => 3])) === 1, "E3: rows for $table must be flagged.");
	$assert($rules([], [], [], [], [$table => 0]) === [], "E3: an empty $table entry must pass.");
}
// Default-deny for AJ Core-owned options: the audit found 17 unprotected secrets/state options.
foreach (['ajcore_storage_settings', 'ajcore_jwt_secret', 'ajcore_ajphone_client_secret', 'ajcore_settings_encryption_key', 'ajcore_ra_esign_drafts', 'ajcore_ra_gmail_intake', 'ajcore_ra_zoho_mail', 'ajforms_settings'] as $option) {
	$assert(synchy_should_sync_option_name($option) === false, "$option must never sync.");
}
$assert(synchy_should_sync_option_name('blogname') === true && synchy_should_sync_option_name('theme_mods_ajnanda') === true, 'Ordinary site and theme options must still sync.');
add_filter('synchy_ajcore_syncable_option_names', $allow = static fn(): array => ['ajcore_ra_filing_task_status']);
$assert(synchy_should_sync_option_name('ajcore_ra_filing_task_status') === true, 'AJ Core can declare an option syncable.');
remove_filter('synchy_ajcore_syncable_option_names', $allow);
$assert(synchy_should_sync_option_name('ajcore_ra_filing_task_status') === false, 'Back to deny once the declaration is removed.');
$assert(in_array('aj_portal_file_tags', synchy_get_ajcore_protected_table_suffixes(), true) && in_array('aj_storage_objects', synchy_get_ajcore_protected_table_suffixes(), true), 'The AJ Core file tables must be protected.');

// 4. Failure: a locally deleted ID that is a live customer file.
$assert(synchy_filter_deletable_post_ids([4096, 1000000001, 4097], [1000000001]) === [4096, 4097], 'A deleted-locally ID that is a customer file here must not be deleted.');

// 5. Failure: a push that would replace wp_posts wholesale. Only merge statements may execute.
$tables = ['wp_posts', 'wp_postmeta'];
$ok = static fn(string $sql): bool => synchy_sync_statement_allowed($sql, $tables, 'wp_postmeta');
$assert($ok("INSERT INTO `wp_posts` (`ID`, `post_title`) VALUES (1, 'a') ON DUPLICATE KEY UPDATE `post_title` = VALUES(`post_title`);"), 'A normal upsert must be allowed.');
$assert($ok("DELETE FROM `wp_postmeta` WHERE (`post_id` = 5 AND `meta_key` = '_x') OR (`post_id` = 6 AND `meta_key` = '_y');"), 'An exact (post, key) pair delete must be allowed.');
foreach ([
	'TRUNCATE TABLE `wp_posts`;',
	'DROP TABLE `wp_posts`;',
	"REPLACE INTO `wp_posts` (`ID`) VALUES (1);",
	'DELETE FROM `wp_posts`;',
	'DELETE FROM `wp_posts` WHERE `ID` > 0;',
	'DELETE FROM `wp_postmeta`;',
	'DELETE FROM `wp_postmeta` WHERE `post_id` = 5;',
	'UPDATE `wp_posts` SET `post_title` = \'x\';',
	'INSERT INTO `wp_posts` (`ID`) SELECT `ID` FROM `wp_users`;',
	"INSERT INTO `wp_users` (`ID`) VALUES (1);",
] as $statement) {
	$assert(!$ok($statement), 'Must be refused: ' . $statement);
}

// 6. Audit finding: terms are keyed by ID too (E5).
$v = $rules([], [], [], [], [], [], [20 => ['name' => 'IRS', 'slug' => 'irs']], [20 => ['name' => 'Customer Tag', 'slug' => 'customer-tag']]);
$assert(count($v) === 1 && str_contains($v[0], 'E5'), 'E5: a different term at the same ID must be flagged.');
$assert($rules([], [], [], [], [], [], [20 => ['name' => 'IRS Filing', 'slug' => 'irs']], [20 => ['name' => 'IRS', 'slug' => 'irs']]) === [], 'E5: renaming the same term must pass.');

// 7. Audit finding: post authors are site-specific user IDs.
$authors = [3 => ['login' => 'ssnanda', 'email' => 's@example.com'], 1 => ['login' => 'ht2025', 'email' => 'h@example.com']];
$resolve = static fn(string $login, string $email): int => $login === 'ssnanda' ? 42 : 0;
$rows = synchy_remap_post_authors([['ID' => 10, 'post_author' => 3], ['ID' => 11, 'post_author' => 1], ['ID' => 12, 'post_author' => 1]], $authors, [11 => 7], $resolve);
$assert($rows[0]['post_author'] === 42, 'An author with a login match must map to the destination user.');
$assert($rows[1]['post_author'] === 7, 'With no match, an existing post keeps the author it already has.');
$assert($rows[2]['post_author'] === 0, 'With no match and no existing post, the author is 0, never a stranger\'s ID.');

// 8. Audit finding: order of operations. Files must not be written before the database rules run.
// (Writes only inside a temp folder it creates and removes; the uploads path below must stay absent.)
$zip_path = wp_tempnam('synchy-order-test') . '.zip';
$zip = new ZipArchive();
$zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE);
$zip->addFromString('.synchy-sync/db/manifest.json', '{}');
$zip->addFromString('.synchy-sync/db/delta.sql', '');
$zip->addFromString('uploads/synchy-order-test.txt', 'must not exist after phase 1');
$zip->close();
$phase1 = synchy_extract_sync_package_meta($zip_path);
$assert(!is_wp_error($phase1), 'Phase 1 (manifest and SQL only) must succeed.');
$assert(is_readable($phase1['manifest_path']), 'Phase 1 must unpack the manifest.');
$assert(!file_exists(WP_CONTENT_DIR . '/uploads/synchy-order-test.txt'), 'Phase 1 must not write any content file.');
$assert($phase1['content_entries'] === ['uploads/synchy-order-test.txt'], 'The content files must be held back for phase 2.');
synchy_rrmdir($phase1['meta_root']);
@unlink($zip_path);

// 8a. AJ Core update (2026-11-12): the customer-file marker, transients, and health baselines.
$assert(in_array('_ajcore_customer_file', synchy_get_protected_postmeta_keys(), true), 'The _ajcore_customer_file marker must be a protected post meta key.');
$v = synchy_evaluate_customer_file_rules([], [], [], [], [], [], [], [], ['_thumbnail_id', '_ajcore_customer_file'], synchy_get_protected_postmeta_keys());
$assert(count($v) === 1 && str_contains($v[0], 'E3'), 'E3: a package carrying the marker meta key must be flagged.');
$assert(synchy_evaluate_customer_file_rules([], [], [], [], [], [], [], [], ['_thumbnail_id'], synchy_get_protected_postmeta_keys()) === [], 'Ordinary meta keys must pass.');
$statements = synchy_build_sync_postmeta_statements('wp_postmeta', [
	['meta_id' => 1, 'post_id' => 5, 'meta_key' => '_ajcore_customer_file', 'meta_value' => '1'],
	['meta_id' => 2, 'post_id' => 5, 'meta_key' => '_thumbnail_id', 'meta_value' => '9'],
]);
$assert($statements !== [] && !str_contains(implode("\n", $statements), '_ajcore_customer_file'), 'The SQL generator must never delete or insert the marker meta key.');
foreach (['_transient_ajcore_media_refs', '_transient_ajcore_media_tile_counts', '_transient_timeout_ajcore_media_refs', '_site_transient_x', 'ajcore_customer_flag_backfilled'] as $option) {
	$assert(synchy_should_sync_option_name($option) === false, "$option must never sync.");
}
// Health: judged against the reading taken just before the push, never against a fixed number.
$assert(synchy_customer_file_health_increases(['orphanMappings' => 0, 'mappingMismatch' => 0], ['orphanMappings' => 0, 'mappingMismatch' => 0]) === [], 'No change must not alert.');
$assert(synchy_customer_file_health_increases(['orphanMappings' => 29], ['orphanMappings' => 25]) === [], 'A decrease must not alert, whatever the old baseline was.');
$inc = synchy_customer_file_health_increases(['orphanMappings' => 0, 'orphanPortalRows' => 0], ['orphanMappings' => 0, 'orphanPortalRows' => 2]);
$assert(array_keys($inc) === ['orphanPortalRows'] && $inc['orphanPortalRows'] === ['before' => 0, 'after' => 2], 'Any increase must alert, with before and after.');

// 8b. Audit finding: upload folders the destination owns (AJ Core declares them; Synchy only consumes the declaration).
$owned = ['ajcore-backups', 'ajphone-rules'];
$assert(synchy_is_live_owned_upload_path('uploads/ajcore-backups/db.sql.gz', $owned), 'A file inside a declared live-owned folder must be treated as owned.');
$assert(!synchy_is_live_owned_upload_path('uploads/ajcore-backups-old/x', $owned) && !synchy_is_live_owned_upload_path('uploads/2026/11/a.jpg', $owned), 'Similar names and ordinary uploads must not be treated as owned.');

// 9. Dry run (read-only): this site's customer files are flagged, and none are in the send list.
$customer = synchy_get_customer_file_ids();
$sent = synchy_get_changed_post_ids_for_sync(0);
$assert(array_intersect($customer, $sent) === [], 'No customer file ID may appear in the list of posts Sync sends.');
global $wpdb;
$leaked = synchy_find_customer_files_in_payload([$wpdb->posts => ['rows' => array_map(static fn(int $id): array => ['ID' => $id], array_slice($customer, 0, 3))]]);
$assert($customer === [] || $leaked !== [], 'The source tripwire must catch a customer file placed in a payload.');
foreach (synchy_describe_live_owned_upload_dirs() as $entry) {
	echo 'upload folder skipped (live-owned): ' . $entry['dir'] . ($entry['exists'] ? ' - ' . $entry['files'] . ' file(s) not sent' : ' (not present here)') . "\n";
}
echo 'customer files flagged and skipped on this site: ' . count($customer) . ($customer !== [] ? ' (IDs ' . implode(', ', array_slice($customer, 0, 10)) . (count($customer) > 10 ? ', ...' : '') . ')' : '') . "\n";
echo "synchy-customer-files-smoke: OK\n";
