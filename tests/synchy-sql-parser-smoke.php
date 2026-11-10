<?php

if (!defined('ABSPATH')) {
	exit('Run this with wp eval-file tests/synchy-sql-parser-smoke.php');
}

// Regression: a multi-table delta.sql must parse to one statement per INSERT. The
// "-- Table:" header of every table after the first used to be glued onto its INSERT
// and the statement discarded as a comment, silently dropping postmeta/terms/etc.
$path = wp_tempnam('synchy-sql-parser');
file_put_contents($path, "-- hdr\n\n-- Table: wp_a\nINSERT INTO `wp_a` (`x`) VALUES ('1; -- not a comment');\n\n-- Table: wp_b\nINSERT INTO `wp_b` (`x`) VALUES ('it\\'s');\n\n-- Table: wp_c\nINSERT INTO `wp_c` (`x`) VALUES ('3');\n\n");

$seen = [];
$count = synchy_iterate_sync_sql_statements($path, static function (string $statement) use (&$seen): void {
	$seen[] = $statement;
});
@unlink($path);

if ($count !== 3 || count($seen) !== 3 || !str_starts_with($seen[1], 'INSERT INTO `wp_b`') || !str_starts_with($seen[2], 'INSERT INTO `wp_c`')) {
	throw new RuntimeException('Expected 3 statements, got ' . $count . ': ' . wp_json_encode($seen));
}

echo "synchy-sql-parser-smoke: OK\n";
