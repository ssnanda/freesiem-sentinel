<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/synchy-url-replacement-smoke.php');
}

$assert = static function (bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException($message);
	}
};

$changed = false;
$serialized = serialize([
	'image' => 'http://wp-local.ddev.site/wp-content/uploads/2025/07/JNPease_Drone-1.jpeg',
	'json' => '{"url":"http:\/\/wp-local.ddev.site\/wp-content\/uploads\/2025\/07\/JNPease_Drone-1.jpeg"}',
]);

$updated = synchy_sync_apply_replacements($serialized, [], $changed, 'https://universityofficesuites.com');
$decoded = maybe_unserialize($updated);

$assert($changed, 'Expected local URL replacement to mark content as changed.');
$assert(is_array($decoded), 'Expected serialized payload to remain serialized safely.');
$assert(
	$decoded['image'] === 'https://universityofficesuites.com/wp-content/uploads/2025/07/JNPease_Drone-1.jpeg',
	'Expected DDEV image URL to be rewritten to the live origin.'
);
$assert(
	$decoded['json'] === '{"url":"https:\/\/universityofficesuites.com\/wp-content\/uploads\/2025\/07\/JNPease_Drone-1.jpeg"}',
	'Expected escaped JSON DDEV image URL to be rewritten to the live origin.'
);

echo "synchy-url-replacement-smoke: ok\n";
