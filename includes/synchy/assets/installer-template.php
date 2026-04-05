<?php
@set_time_limit(0);

if (function_exists('ignore_user_abort')) {
	ignore_user_abort(true);
}

const SYNCHY_INSTALLER_ACCESS_TOKEN = '__SYNCHY_ACCESS_TOKEN__';
const SYNCHY_PACKAGE_ID = '__SYNCHY_PACKAGE_ID__';
const SYNCHY_PACKAGE_NAME = '__SYNCHY_PACKAGE_NAME__';
const SYNCHY_ARCHIVE_FILENAME = '__SYNCHY_ARCHIVE_FILENAME__';
const SYNCHY_ARCHIVE_SIZE_BYTES = '__SYNCHY_ARCHIVE_SIZE_BYTES__';
const SYNCHY_ARCHIVE_SHA256 = '__SYNCHY_ARCHIVE_SHA256__';
const SYNCHY_SOURCE_HOME_URL = '__SYNCHY_SOURCE_HOME_URL__';
const SYNCHY_SOURCE_SITE_URL = '__SYNCHY_SOURCE_SITE_URL__';
const SYNCHY_SOURCE_DB_PREFIX = '__SYNCHY_SOURCE_DB_PREFIX__';

function synchyInstallerEscape(string $value): string
{
	return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function synchyInstallerPath(string $base, string $path = ''): string
{
	$base = rtrim(str_replace('\\', '/', $base), '/');
	$path = ltrim(str_replace('\\', '/', $path), '/');

	if ($path === '') {
		return $base;
	}

	return $base . '/' . $path;
}

function synchyInstallerConfiguredValue(string $value): string
{
	if (preg_match('/^__SYNCHY_[A-Z0-9_]+__$/', $value)) {
		return '';
	}

	return $value;
}

function synchyInstallerPostedString(string $key, string $default = ''): string
{
	if (!isset($_POST[$key])) {
		return $default;
	}

	return trim((string) $_POST[$key]);
}

function synchyInstallerReadableSize(int $bytes): string
{
	$units = ['B', 'KB', 'MB', 'GB', 'TB'];
	$size = max(0, $bytes);
	$power = $size > 0 ? (int) floor(log($size, 1024)) : 0;
	$power = min($power, count($units) - 1);
	$value = $size / (1024 ** $power);

	return number_format($value, $power === 0 ? 0 : 2) . ' ' . $units[$power];
}

function synchyInstallerPhpStringLiteral(string $value): string
{
	return "'" . str_replace(["\\", "'"], ["\\\\", "\\'"], $value) . "'";
}

function synchyInstallerQuoteIdentifier(string $identifier): string
{
	return '`' . str_replace('`', '``', $identifier) . '`';
}

function synchyInstallerFindArchivePath(string $directory): string
{
	$expected = synchyInstallerConfiguredValue(SYNCHY_ARCHIVE_FILENAME);

	if ($expected !== '') {
		$path = synchyInstallerPath($directory, $expected);

		if (is_readable($path)) {
			return $path;
		}
	}

	$items = @scandir($directory);

	if (!is_array($items)) {
		return '';
	}

	foreach ($items as $item) {
		if ($item === '.' || $item === '..') {
			continue;
		}

		if (strtolower((string) pathinfo($item, PATHINFO_EXTENSION)) !== 'zip') {
			continue;
		}

		$path = synchyInstallerPath($directory, $item);

		if (is_readable($path)) {
			return $path;
		}
	}

	return '';
}

function synchyInstallerFindWordPressRoot(string $startDirectory): string
{
	$current = rtrim(str_replace('\\', '/', $startDirectory), '/');

	for ($depth = 0; $depth < 8; $depth++) {
		$wp_config = synchyInstallerPath($current, 'wp-config.php');
		$wp_admin = synchyInstallerPath($current, 'wp-admin');

		if (is_readable($wp_config) && is_dir($wp_admin)) {
			return $current;
		}

		$parent = dirname($current);

		if ($parent === $current) {
			break;
		}

		$current = rtrim(str_replace('\\', '/', $parent), '/');
	}

	return '';
}

function synchyInstallerReadWordPressConfigDefaults(string $root, string $packagePrefix): array
{
	$defaults = [
		'host' => 'localhost',
		'name' => '',
		'user' => '',
		'prefix' => $packagePrefix !== '' ? $packagePrefix : 'wp_',
	];

	$config_path = synchyInstallerPath($root, 'wp-config.php');

	if (!is_readable($config_path)) {
		return $defaults;
	}

	$contents = (string) file_get_contents($config_path);

	if ($contents === '') {
		return $defaults;
	}

	$constant_patterns = [
		'name' => 'DB_NAME',
		'user' => 'DB_USER',
		'host' => 'DB_HOST',
	];

	foreach ($constant_patterns as $key => $constant) {
		if (
			preg_match(
				"/define\\(\\s*['\\\"]" . preg_quote($constant, '/') . "['\\\"]\\s*,\\s*['\\\"]([^'\\\"]*)['\\\"]\\s*\\)\\s*;/",
				$contents,
				$matches
			)
		) {
			$defaults[$key] = (string) $matches[1];
		}
	}

	if (preg_match("/\\$table_prefix\\s*=\\s*['\\\"]([^'\\\"]+)['\\\"]\\s*;/", $contents, $matches)) {
		$defaults['prefix'] = (string) $matches[1];
	}

	return $defaults;
}

function synchyInstallerIsWordPressRoot(string $root): bool
{
	if ($root === '' || !is_dir($root)) {
		return false;
	}

	$config_path = synchyInstallerPath($root, 'wp-config.php');
	$wp_admin = synchyInstallerPath($root, 'wp-admin');

	return is_readable($config_path) && is_dir($wp_admin);
}

function synchyInstallerGenerateSecret(): string
{
	try {
		return bin2hex(random_bytes(32));
	} catch (Throwable $throwable) {
		return sha1(uniqid('synchy', true) . microtime(true));
	}
}

function synchyInstallerCurrentSiteUrl(): string
{
	$host = $_SERVER['HTTP_X_ORIGINAL_HOST'] ?? $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
	$is_https = false;

	if (
		isset($_SERVER['HTTPS'])
		&& $_SERVER['HTTPS'] !== ''
		&& strtolower((string) $_SERVER['HTTPS']) !== 'off'
	) {
		$is_https = true;
	}

	if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string) $_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') {
		$is_https = true;
	}

	if (isset($_SERVER['HTTP_X_FORWARDED_SSL']) && in_array(strtolower((string) $_SERVER['HTTP_X_FORWARDED_SSL']), ['on', 'https'], true)) {
		$is_https = true;
	}

	if (isset($_SERVER['HTTP_CF_VISITOR'])) {
		$visitor = json_decode((string) $_SERVER['HTTP_CF_VISITOR'], true);

		if (is_array($visitor) && ($visitor['scheme'] ?? '') === 'https') {
			$is_https = true;
		}
	}

	$script_name = str_replace('\\', '/', (string) ($_SERVER['SCRIPT_NAME'] ?? '/installer.php'));
	$directory = dirname($script_name);
	$directory = $directory === '.' || $directory === '/' ? '' : rtrim($directory, '/');

	return ($is_https ? 'https' : 'http') . '://' . $host . $directory;
}

function synchyInstallerRemoveTree(string $path): void
{
	if (!file_exists($path)) {
		return;
	}

	if (is_file($path) || is_link($path)) {
		@unlink($path);
		return;
	}

	$items = @scandir($path);

	if (!is_array($items)) {
		return;
	}

	foreach ($items as $item) {
		if ($item === '.' || $item === '..') {
			continue;
		}

		synchyInstallerRemoveTree(synchyInstallerPath($path, $item));
	}

	@rmdir($path);
}

function synchyInstallerExists(string $path): bool
{
	return $path !== '' && (is_file($path) || is_dir($path) || is_link($path));
}

function synchyInstallerDiscoverMatchingStageDirectories(string $wordpressRoot, string $archivePath): array
{
	$archiveFilename = $archivePath !== '' ? basename($archivePath) : '';
	$roots = [
		synchyInstallerPath($wordpressRoot, 'wp-content/uploads/synchy-import'),
		synchyInstallerPath($wordpressRoot, 'wp-content/uploads/synchy-site-sync'),
	];
	$matches = [];

	foreach ($roots as $root) {
		if (!is_dir($root) || !is_readable($root)) {
			continue;
		}

		$items = @scandir($root);

		if (!is_array($items)) {
			continue;
		}

		foreach ($items as $item) {
			if ($item === '.' || $item === '..') {
				continue;
			}

			$directory = synchyInstallerPath($root, $item);

			if (!is_dir($directory)) {
				continue;
			}

			$archiveMatch = $archiveFilename !== '' && is_file(synchyInstallerPath($directory, $archiveFilename));

			if ($archiveMatch) {
				$matches[] = $directory;
			}
		}
	}

	return array_values(array_unique($matches));
}

function synchyInstallerBuildCleanupTargets(string $wordpressRoot, string $packageDirectory, string $archivePath, string $workspaceRoot): array
{
	$targets = [];
	$installerPath = str_replace('\\', '/', __FILE__);

	if (synchyInstallerExists($archivePath)) {
		$targets[] = [
			'label' => 'Package zip',
			'path' => $archivePath,
			'type' => 'file',
		];
	}

	if (synchyInstallerExists($workspaceRoot)) {
		$targets[] = [
			'label' => 'Restore workspace',
			'path' => $workspaceRoot,
			'type' => 'dir',
		];
	}

	foreach (synchyInstallerDiscoverMatchingStageDirectories($wordpressRoot, $archivePath) as $directory) {
		$targets[] = [
			'label' => 'Matched staging session',
			'path' => $directory,
			'type' => 'dir',
		];
	}

	if (synchyInstallerExists($installerPath)) {
		$targets[] = [
			'label' => 'installer.php',
			'path' => $installerPath,
			'type' => 'self',
		];
	}

	return $targets;
}

function synchyInstallerDeleteCleanupTargets(array $targets, array &$messages): void
{
	usort(
		$targets,
		static function (array $a, array $b): int {
			return (($a['type'] ?? '') === 'self') <=> (($b['type'] ?? '') === 'self');
		}
	);

	foreach ($targets as $target) {
		$path = isset($target['path']) ? (string) $target['path'] : '';
		$type = isset($target['type']) ? (string) $target['type'] : 'file';
		$label = isset($target['label']) ? (string) $target['label'] : 'Cleanup item';

		if ($path === '' || !synchyInstallerExists($path)) {
			continue;
		}

		if ($type === 'dir') {
			synchyInstallerRemoveTree($path);

			if (synchyInstallerExists($path)) {
				throw new RuntimeException('Could not remove ' . $label . ' at ' . $path . '.');
			}

			$messages[] = 'Deleted ' . $label . ' at ' . $path . '.';
			continue;
		}

		if (!@unlink($path)) {
			throw new RuntimeException('Could not remove ' . $label . ' at ' . $path . '.');
		}

		$messages[] = 'Deleted ' . $label . ' at ' . $path . '.';
	}
}

function synchyInstallerEnsureDirectory(string $path): void
{
	if (is_dir($path)) {
		return;
	}

	if (!@mkdir($path, 0755, true) && !is_dir($path)) {
		throw new RuntimeException('Could not create directory: ' . $path);
	}
}

function synchyInstallerWriteMaintenanceFile(string $root): void
{
	$maintenance_file = synchyInstallerPath($root, '.maintenance');
	$contents = '<?php $upgrading = ' . time() . ';';
	@file_put_contents($maintenance_file, $contents);
}

function synchyInstallerRemoveMaintenanceFile(string $root): void
{
	$maintenance_file = synchyInstallerPath($root, '.maintenance');

	if (file_exists($maintenance_file)) {
		@unlink($maintenance_file);
	}
}

function synchyInstallerExpectedArchiveSize(): int
{
	$expected = synchyInstallerConfiguredValue(SYNCHY_ARCHIVE_SIZE_BYTES);

	return ctype_digit($expected) ? (int) $expected : 0;
}

function synchyInstallerValidateArchive(string $archivePath): void
{
	if (!is_readable($archivePath)) {
		throw new RuntimeException('Could not read the Synchy archive next to this installer.');
	}

	$expected_size = synchyInstallerExpectedArchiveSize();

	if ($expected_size > 0) {
		$actual_size = (int) filesize($archivePath);

		if ($actual_size !== $expected_size) {
			throw new RuntimeException(
				'Archive size mismatch detected. Expected ' . synchyInstallerReadableSize($expected_size) . ' but found ' . synchyInstallerReadableSize($actual_size) . '.'
			);
		}
	}

	$expected_hash = strtolower(synchyInstallerConfiguredValue(SYNCHY_ARCHIVE_SHA256));

	if ($expected_hash !== '') {
		$actual_hash = strtolower((string) hash_file('sha256', $archivePath));

		if (!hash_equals($expected_hash, $actual_hash)) {
			throw new RuntimeException('Archive hash mismatch detected. Make sure installer.php and the zip belong to the same Synchy package.');
		}
	}
}

function synchyInstallerExtractArchive(string $archivePath, string $extractDirectory, array &$messages): void
{
	if (!class_exists('ZipArchive')) {
		throw new RuntimeException('ZipArchive is not available on this server.');
	}

	synchyInstallerRemoveTree($extractDirectory);
	synchyInstallerEnsureDirectory($extractDirectory);

	$zip = new ZipArchive();
	$result = $zip->open($archivePath);

	if ($result !== true) {
		throw new RuntimeException('Could not open the Synchy archive for extraction.');
	}

	if (!$zip->extractTo($extractDirectory)) {
		$zip->close();
		throw new RuntimeException('Could not extract the Synchy archive into the restore workspace.');
	}

	$zip->close();
	$messages[] = 'Archive extracted to ' . $extractDirectory . '.';
}

function synchyInstallerValidateDatabaseConfig(array $config, bool $requireDatabase = true): void
{
	if ($config['host'] === '') {
		throw new RuntimeException('Enter a database host before continuing.');
	}

	if ($config['user'] === '') {
		throw new RuntimeException('Enter a database username before continuing.');
	}

	if ($requireDatabase && $config['name'] === '') {
		throw new RuntimeException('Select or enter a destination database before continuing.');
	}
}

function synchyInstallerConnectDatabase(array $config, bool $selectDatabase): mysqli
{
	if (!function_exists('mysqli_init')) {
		throw new RuntimeException('MySQLi is not available on this server.');
	}

	$connection = mysqli_init();

	if ($connection === false) {
		throw new RuntimeException('Could not initialize a MySQL connection.');
	}

	mysqli_report(MYSQLI_REPORT_OFF);
	@mysqli_options($connection, MYSQLI_OPT_CONNECT_TIMEOUT, 10);

	$database = $selectDatabase && $config['name'] !== '' ? $config['name'] : null;
	$connected = @$connection->real_connect($config['host'], $config['user'], $config['password'], $database);

	if (!$connected) {
		$message = $connection->connect_error !== '' ? $connection->connect_error : 'Unknown connection error.';
		throw new RuntimeException('Database connection failed: ' . $message);
	}

	@$connection->set_charset('utf8mb4');

	if ($selectDatabase && !@$connection->select_db($config['name'])) {
		$message = $connection->error !== '' ? $connection->error : 'Unknown database selection error.';
		throw new RuntimeException('Could not select database ' . $config['name'] . ': ' . $message);
	}

	return $connection;
}

function synchyInstallerLoadDatabases(array $config): array
{
	$connection = synchyInstallerConnectDatabase($config, false);
	$result = @$connection->query('SHOW DATABASES');

	if (!$result instanceof mysqli_result) {
		$message = $connection->error !== '' ? $connection->error : 'Unknown database listing error.';
		$connection->close();
		throw new RuntimeException('Could not list databases for this connection: ' . $message);
	}

	$databases = [];
	$system_databases = ['information_schema', 'mysql', 'performance_schema', 'sys'];

	while ($row = $result->fetch_row()) {
		$name = isset($row[0]) ? (string) $row[0] : '';

		if ($name === '' || in_array($name, $system_databases, true)) {
			continue;
		}

		$databases[] = $name;
	}

	$result->free();
	$connection->close();

	sort($databases, SORT_NATURAL | SORT_FLAG_CASE);

	return $databases;
}

function synchyInstallerDropDatabaseObjects(mysqli $connection, array &$messages): void
{
	$objects = [];
	$result = @$connection->query('SHOW FULL TABLES');

	if (!$result instanceof mysqli_result) {
		$message = $connection->error !== '' ? $connection->error : 'Unknown database inspection error.';
		throw new RuntimeException('Could not inspect existing database objects: ' . $message);
	}

	while ($row = $result->fetch_row()) {
		if (!isset($row[0])) {
			continue;
		}

		$objects[] = [
			'name' => (string) $row[0],
			'type' => strtoupper((string) ($row[1] ?? 'BASE TABLE')),
		];
	}

	$result->free();
	@$connection->query('SET FOREIGN_KEY_CHECKS=0');

	foreach ($objects as $object) {
		$sql = ($object['type'] === 'VIEW' ? 'DROP VIEW IF EXISTS ' : 'DROP TABLE IF EXISTS ') . synchyInstallerQuoteIdentifier($object['name']);

		if (!$connection->query($sql)) {
			@$connection->query('SET FOREIGN_KEY_CHECKS=1');
			throw new RuntimeException('Could not drop existing database object ' . $object['name'] . ': ' . $connection->error);
		}
	}

	@$connection->query('SET FOREIGN_KEY_CHECKS=1');
	$messages[] = 'Dropped ' . number_format(count($objects)) . ' existing database objects from the selected destination database.';
}

function synchyInstallerIterateSqlStatements(string $sqlPath, callable $callback): int
{
	$handle = @fopen($sqlPath, 'rb');

	if ($handle === false) {
		throw new RuntimeException('Could not open the database.sql file from the extracted package.');
	}

	$buffer = '';
	$in_single_quote = false;
	$in_double_quote = false;
	$escaped = false;
	$statement_count = 0;

	while (($line = fgets($handle)) !== false) {
		if (!$in_single_quote && !$in_double_quote && $buffer === '') {
			$trimmed = ltrim($line);

			if ($trimmed === '' || strncmp($trimmed, '-- ', 3) === 0) {
				continue;
			}
		}

		$length = strlen($line);

		for ($index = 0; $index < $length; $index++) {
			$character = $line[$index];
			$buffer .= $character;

			if ($escaped) {
				$escaped = false;
				continue;
			}

			if ($character === '\\') {
				$escaped = true;
				continue;
			}

			if ($character === "'" && !$in_double_quote) {
				$in_single_quote = !$in_single_quote;
				continue;
			}

			if ($character === '"' && !$in_single_quote) {
				$in_double_quote = !$in_double_quote;
				continue;
			}

			if ($character === ';' && !$in_single_quote && !$in_double_quote) {
				$statement = trim($buffer);
				$buffer = '';

				if ($statement === '' || strncmp(ltrim($statement), '-- ', 3) === 0) {
					continue;
				}

				$callback($statement);
				$statement_count++;
			}
		}
	}

	fclose($handle);

	$statement = trim($buffer);

	if ($statement !== '' && strncmp(ltrim($statement), '-- ', 3) !== 0) {
		$callback($statement);
		$statement_count++;
	}

	return $statement_count;
}

function synchyInstallerImportDatabase(string $sqlPath, mysqli $connection, array &$messages): void
{
	@$connection->query('SET FOREIGN_KEY_CHECKS=0');

	$count = synchyInstallerIterateSqlStatements(
		$sqlPath,
		static function (string $statement) use ($connection): void {
			if ($statement === '') {
				return;
			}

			if (!$connection->query($statement)) {
				throw new RuntimeException('Database import failed while executing SQL: ' . $connection->error);
			}
		}
	);

	@$connection->query('SET FOREIGN_KEY_CHECKS=1');
	$messages[] = 'Database import completed (' . number_format($count) . ' SQL statements).';
}

function synchyInstallerReplaceValue($value, string $search, string $replace, bool &$changed)
{
	if (is_string($value)) {
		$updated = str_replace($search, $replace, $value);

		if ($updated !== $value) {
			$changed = true;
		}

		return $updated;
	}

	if (is_array($value)) {
		foreach ($value as $key => $item) {
			$value[$key] = synchyInstallerReplaceValue($item, $search, $replace, $changed);
		}

		return $value;
	}

	if (is_object($value)) {
		foreach (get_object_vars($value) as $key => $item) {
			$value->$key = synchyInstallerReplaceValue($item, $search, $replace, $changed);
		}

		return $value;
	}

	return $value;
}

function synchyInstallerIsSerialized(string $value): bool
{
	$value = trim($value);

	if ($value === 'N;') {
		return true;
	}

	if ($value === '') {
		return false;
	}

	if (!preg_match('/^[aOsibdC]:/', $value)) {
		return false;
	}

	return @unserialize($value) !== false || $value === 'b:0;';
}

function synchyInstallerMaybeUnserialize(string $value, bool &$wasSerialized)
{
	$wasSerialized = false;
	$trimmed = trim($value);

	if (!synchyInstallerIsSerialized($trimmed)) {
		return $value;
	}

	$decoded = @unserialize($trimmed);

	if ($decoded === false && $trimmed !== 'b:0;') {
		return $value;
	}

	$wasSerialized = true;

	return $decoded;
}

function synchyInstallerPrepareDatabaseValue(string $value, string $search, string $replace, bool &$changed): string
{
	$wasSerialized = false;
	$decoded = synchyInstallerMaybeUnserialize($value, $wasSerialized);
	$updated = synchyInstallerReplaceValue($decoded, $search, $replace, $changed);

	if ($wasSerialized) {
		return serialize($updated);
	}

	return (string) $updated;
}

function synchyInstallerBindParams(mysqli_stmt $statement, array $values): void
{
	$types = str_repeat('s', count($values));
	$references = [$types];

	foreach ($values as $index => $value) {
		$values[$index] = $value === null ? null : (string) $value;
		$references[] = &$values[$index];
	}

	call_user_func_array([$statement, 'bind_param'], $references);
}

function synchyInstallerBuildWhereClause(array $where, array &$values): string
{
	$parts = [];

	foreach ($where as $column => $value) {
		if ($value === null) {
			$parts[] = synchyInstallerQuoteIdentifier($column) . ' IS NULL';
			continue;
		}

		$parts[] = synchyInstallerQuoteIdentifier($column) . ' = ?';
		$values[] = $value;
	}

	return implode(' AND ', $parts);
}

function synchyInstallerUpdateRow(mysqli $connection, string $tableName, array $updates, array $where): void
{
	$set_parts = [];
	$values = [];

	foreach ($updates as $column => $value) {
		$set_parts[] = synchyInstallerQuoteIdentifier($column) . ' = ?';
		$values[] = $value;
	}

	$where_clause = synchyInstallerBuildWhereClause($where, $values);

	if ($where_clause === '') {
		throw new RuntimeException('Search-replace could not build a row-matching clause for table ' . $tableName . '.');
	}

	$sql = 'UPDATE ' . synchyInstallerQuoteIdentifier($tableName)
		. ' SET ' . implode(', ', $set_parts)
		. ' WHERE ' . $where_clause;

	$statement = $connection->prepare($sql);

	if (!$statement instanceof mysqli_stmt) {
		throw new RuntimeException('Could not prepare search-replace update for table ' . $tableName . ': ' . $connection->error);
	}

	synchyInstallerBindParams($statement, $values);

	if (!$statement->execute()) {
		$error = $statement->error !== '' ? $statement->error : $connection->error;
		$statement->close();
		throw new RuntimeException('Search-replace failed for table ' . $tableName . ': ' . $error);
	}

	$statement->close();
}

function synchyInstallerSearchReplace(string $search, string $replace, mysqli $connection, array &$messages, array &$warnings): void
{
	if ($search === '' || $replace === '' || $search === $replace) {
		return;
	}

	$result = @$connection->query('SHOW TABLES');

	if (!$result instanceof mysqli_result) {
		throw new RuntimeException('Could not enumerate database tables for URL replacement: ' . $connection->error);
	}

	$tables = [];

	while ($row = $result->fetch_row()) {
		if (!isset($row[0])) {
			continue;
		}

		$tables[] = (string) $row[0];
	}

	$result->free();
	$total_updates = 0;

	foreach ($tables as $tableName) {
		$columns_result = @$connection->query('SHOW FULL COLUMNS FROM ' . synchyInstallerQuoteIdentifier($tableName));

		if (!$columns_result instanceof mysqli_result) {
			continue;
		}

		$text_columns = [];
		$primary_columns = [];

		while ($column = $columns_result->fetch_assoc()) {
			$field = isset($column['Field']) ? (string) $column['Field'] : '';
			$type = strtolower((string) ($column['Type'] ?? ''));
			$key = strtoupper((string) ($column['Key'] ?? ''));

			if ($field === '') {
				continue;
			}

			if ($key === 'PRI') {
				$primary_columns[] = $field;
			}

			if (
				str_contains($type, 'char')
				|| str_contains($type, 'text')
				|| str_contains($type, 'json')
			) {
				$text_columns[] = $field;
			}
		}

		$columns_result->free();

		if ($text_columns === []) {
			continue;
		}

		$match_columns = $primary_columns !== [] ? $primary_columns : $text_columns;

		$select_columns = array_values(array_unique(array_merge($match_columns, $text_columns)));
		$select_sql = 'SELECT ' . implode(
			', ',
			array_map(
				static fn(string $column): string => synchyInstallerQuoteIdentifier($column),
				$select_columns
			)
		) . ' FROM ' . synchyInstallerQuoteIdentifier($tableName);

		$rows_result = @$connection->query($select_sql);

		if (!$rows_result instanceof mysqli_result) {
			continue;
		}

		while ($row = $rows_result->fetch_assoc()) {
			$updates = [];

			foreach ($text_columns as $column) {
				$current = isset($row[$column]) ? (string) $row[$column] : '';

				if ($current === '' || strpos($current, $search) === false) {
					continue;
				}

				$changed = false;
				$updated = synchyInstallerPrepareDatabaseValue($current, $search, $replace, $changed);

				if ($changed && $updated !== $current) {
					$updates[$column] = $updated;
				}
			}

			if ($updates === []) {
				continue;
			}

			$where = [];

			foreach ($match_columns as $column) {
				$where[$column] = $row[$column] ?? null;
			}

			synchyInstallerUpdateRow($connection, $tableName, $updates, $where);
			$total_updates++;
		}

		$rows_result->free();
	}

	$messages[] = 'URL replacement completed for ' . number_format($total_updates) . ' rows.';
}

function synchyInstallerForceCoreUrls(mysqli $connection, string $prefix, string $destinationUrl, array &$messages): void
{
	$table = synchyInstallerQuoteIdentifier($prefix . 'options');
	$destinationUrl = synchyInstallerNormalizeUrl($destinationUrl);

	if ($destinationUrl === '') {
		return;
	}

	$sql = 'UPDATE ' . $table . ' SET option_value = ? WHERE option_name IN (?, ?)';
	$statement = $connection->prepare($sql);

	if (!$statement instanceof mysqli_stmt) {
		throw new RuntimeException('Could not prepare the destination URL update for the options table: ' . $connection->error);
	}

	$home = 'home';
	$siteurl = 'siteurl';
	$statement->bind_param('sss', $destinationUrl, $home, $siteurl);

	if (!$statement->execute()) {
		$error = $statement->error !== '' ? $statement->error : $connection->error;
		$statement->close();
		throw new RuntimeException('Could not update the home/siteurl options to the destination URL: ' . $error);
	}

	$statement->close();
	$messages[] = 'Forced home and siteurl to ' . $destinationUrl . '.';
}

function synchyInstallerBuildWpConfigContents(string $templatePath, array $config): string
{
	$contents = (string) file_get_contents($templatePath);

	if ($contents === '') {
		throw new RuntimeException('Could not read the wp-config template before updating the destination database credentials.');
	}

	$replacements = [
		'DB_NAME' => $config['name'],
		'DB_USER' => $config['user'],
		'DB_PASSWORD' => $config['password'],
		'DB_HOST' => $config['host'],
	];

	foreach ($replacements as $constant => $value) {
		$pattern = "/define\\(\\s*(['\\\"])" . preg_quote($constant, '/') . "\\1\\s*,\\s*[^\\r\\n]+\\);/";
		$replacement = "define('" . $constant . "', " . synchyInstallerPhpStringLiteral($value) . ");";
		$count = 0;
		$contents = (string) preg_replace($pattern, $replacement, $contents, 1, $count);

		if ($count !== 1) {
			throw new RuntimeException('Could not update ' . $constant . ' in the wp-config template. Synchy expects standard WordPress constant definitions.');
		}
	}

	$prefix_pattern = '/\\$table_prefix\\s*=\\s*[^;]+;/';
	$prefix_replacement = '$table_prefix = ' . synchyInstallerPhpStringLiteral($config['prefix']) . ';';
	$prefix_count = 0;
	$contents = (string) preg_replace($prefix_pattern, $prefix_replacement, $contents, 1, $prefix_count);

	if ($prefix_count !== 1) {
		throw new RuntimeException('Could not update $table_prefix in the wp-config template.');
	}

	foreach (['WP_HOME', 'WP_SITEURL'] as $constant) {
		$contents = (string) preg_replace(
			"/^\\s*define\\(\\s*['\\\"]" . preg_quote($constant, '/') . "['\\\"]\\s*,\\s*[^\\r\\n]+\\);\\s*$/m",
			'',
			$contents
		);
	}

	foreach (['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'] as $constant) {
		$pattern = "/define\\(\\s*['\\\"]" . preg_quote($constant, '/') . "['\\\"]\\s*,\\s*['\\\"]put your unique phrase here['\\\"]\\s*\\);/";
		$contents = (string) preg_replace(
			$pattern,
			"define('" . $constant . "', " . synchyInstallerPhpStringLiteral(synchyInstallerGenerateSecret()) . ');',
			$contents
		);
	}

	return $contents;
}

function synchyInstallerResolveWpConfigTemplate(string $wordpressRoot, string $extractDirectory): array
{
	$destination_config = synchyInstallerPath($wordpressRoot, 'wp-config.php');
	$sample_template = synchyInstallerPath($extractDirectory, 'wp-config-sample.php');
	$package_template = synchyInstallerPath($extractDirectory, 'wp-config.php');

	if (is_readable($destination_config)) {
		return [
			'path' => $destination_config,
			'mode' => 'update',
		];
	}

	if (is_readable($sample_template)) {
		return [
			'path' => $sample_template,
			'mode' => 'create',
		];
	}

	if (is_readable($package_template)) {
		return [
			'path' => $package_template,
			'mode' => 'create',
		];
	}

	throw new RuntimeException('Synchy could not find a wp-config template in the package. The archive must include wp-config.php or wp-config-sample.php.');
}

function synchyInstallerUpdateWpConfig(string $wordpressRoot, string $extractDirectory, array $config, array &$messages): void
{
	$config_path = synchyInstallerPath($wordpressRoot, 'wp-config.php');
	$template = synchyInstallerResolveWpConfigTemplate($wordpressRoot, $extractDirectory);
	$contents = synchyInstallerBuildWpConfigContents((string) $template['path'], $config);

	if (($template['mode'] ?? '') === 'update') {
		if (!is_writable($config_path)) {
			throw new RuntimeException('wp-config.php is not writable, so Synchy cannot update the destination database credentials.');
		}

		$backup_path = $config_path . '.synchy-' . date('Ymd-His') . '.bak';

		if (!@copy($config_path, $backup_path)) {
			throw new RuntimeException('Could not create a backup of wp-config.php before updating it.');
		}

		if (@file_put_contents($config_path, $contents, LOCK_EX) === false) {
			throw new RuntimeException('Could not write the updated database credentials into wp-config.php.');
		}

		$messages[] = 'Updated wp-config.php to use database ' . $config['name'] . ' at ' . $config['host'] . ' (prefix ' . $config['prefix'] . ').';
		$messages[] = 'Created a wp-config.php backup at ' . $backup_path . '.';
		return;
	}

	if (!is_writable($wordpressRoot)) {
		throw new RuntimeException('The destination folder is not writable, so Synchy cannot create wp-config.php there.');
	}

	if (@file_put_contents($config_path, $contents, LOCK_EX) === false) {
		throw new RuntimeException('Could not create wp-config.php in the destination folder.');
	}

	$messages[] = 'Created wp-config.php in the destination folder using database ' . $config['name'] . ' at ' . $config['host'] . ' (prefix ' . $config['prefix'] . ').';
}

function synchyInstallerCopyFiles(string $extractDirectory, string $wordpressRoot, array &$messages, array &$warnings): void
{
	$directory = new RecursiveDirectoryIterator($extractDirectory, FilesystemIterator::SKIP_DOTS);
	$iterator = new RecursiveIteratorIterator($directory, RecursiveIteratorIterator::SELF_FIRST);

	foreach ($iterator as $item) {
		$source_path = str_replace('\\', '/', $item->getPathname());
		$relative_path = ltrim(substr($source_path, strlen(rtrim(str_replace('\\', '/', $extractDirectory), '/'))), '/');

		if ($relative_path === '') {
			continue;
		}

		if ($relative_path === 'synchy' || str_starts_with($relative_path . '/', 'synchy/')) {
			continue;
		}

		if ($relative_path === 'wp-config.php') {
			continue;
		}

		$destination_path = synchyInstallerPath($wordpressRoot, $relative_path);

		if ($item->isDir()) {
			synchyInstallerEnsureDirectory($destination_path);
			continue;
		}

		synchyInstallerEnsureDirectory(dirname($destination_path));

		if (!@copy($source_path, $destination_path)) {
			throw new RuntimeException('Could not copy ' . $relative_path . ' into the destination site.');
		}
	}

	$messages[] = 'Package files copied into the destination WordPress root.';
}

function synchyInstallerNormalizeUrl(string $url): string
{
	return rtrim($url, '/');
}

function synchyInstallerDestinationPathFromUrl(string $url): string
{
	$path = (string) parse_url($url, PHP_URL_PATH);
	$path = trim(str_replace('\\', '/', $path));

	if ($path === '' || $path === '/') {
		return '/';
	}

	return '/' . trim($path, '/') . '/';
}

function synchyInstallerEnsureHtaccess(string $wordpressRoot, string $destinationUrl, array &$messages): void
{
	$htaccess_path = synchyInstallerPath($wordpressRoot, '.htaccess');

	if (file_exists($htaccess_path)) {
		return;
	}

	if (!is_writable($wordpressRoot)) {
		$messages[] = 'Skipped .htaccess creation because the destination folder is not writable.';
		return;
	}

	$rewrite_base = synchyInstallerDestinationPathFromUrl($destinationUrl);
	$contents = <<<HTACCESS
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase {$rewrite_base}
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . {$rewrite_base}index.php [L]
</IfModule>
# END WordPress

HTACCESS;

	if (@file_put_contents($htaccess_path, $contents, LOCK_EX) === false) {
		throw new RuntimeException('Could not create .htaccess in the destination folder.');
	}

	$messages[] = 'Created .htaccess with WordPress rewrite rules for ' . $rewrite_base . '.';
}

$messages = [];
$cleanup_messages = [];
$warnings = [];
$errors = [];
$restore_complete = false;
$cleanup_complete = false;
$database_list_message = '';
$package_directory = str_replace('\\', '/', __DIR__);
$archive_path = synchyInstallerFindArchivePath($package_directory);
$wordpress_root = $package_directory;
$package_id = synchyInstallerConfiguredValue(SYNCHY_PACKAGE_ID);
$package_name = synchyInstallerConfiguredValue(SYNCHY_PACKAGE_NAME);
$source_home = synchyInstallerNormalizeUrl(synchyInstallerConfiguredValue(SYNCHY_SOURCE_HOME_URL));
$source_site = synchyInstallerNormalizeUrl(synchyInstallerConfiguredValue(SYNCHY_SOURCE_SITE_URL));
$source_db_prefix = synchyInstallerConfiguredValue(SYNCHY_SOURCE_DB_PREFIX);
$workspace_root = synchyInstallerPath($package_directory, '.synchy-restore-' . preg_replace('/[^a-z0-9-]/i', '', $package_id !== '' ? $package_id : 'package'));
$extract_directory = synchyInstallerPath($workspace_root, 'extracted');
$database_path = synchyInstallerPath($extract_directory, 'synchy/database.sql');
$expected_archive_size = synchyInstallerExpectedArchiveSize();
$actual_archive_size = $archive_path !== '' && is_readable($archive_path) ? (int) filesize($archive_path) : 0;
$token_required = SYNCHY_INSTALLER_ACCESS_TOKEN !== '' && SYNCHY_INSTALLER_ACCESS_TOKEN !== '__SYNCHY_ACCESS_TOKEN__';
$provided_token = isset($_REQUEST['token']) ? trim((string) $_REQUEST['token']) : '';
$authorized = !$token_required || ($provided_token !== '' && hash_equals(SYNCHY_INSTALLER_ACCESS_TOKEN, $provided_token));
$detected_destination_url = synchyInstallerNormalizeUrl(synchyInstallerCurrentSiteUrl());
$destination_url = synchyInstallerNormalizeUrl(synchyInstallerPostedString('destination_url', $detected_destination_url));
$config_defaults = synchyInstallerReadWordPressConfigDefaults($wordpress_root, $source_db_prefix);
$database_config = [
	'host' => synchyInstallerPostedString('db_host', (string) ($config_defaults['host'] ?? 'localhost')),
	'user' => synchyInstallerPostedString('db_user', (string) ($config_defaults['user'] ?? '')),
	'password' => isset($_POST['db_password']) ? (string) $_POST['db_password'] : '',
	'name' => synchyInstallerPostedString('db_name', (string) ($config_defaults['name'] ?? '')),
	'prefix' => synchyInstallerPostedString('db_prefix', (string) ($source_db_prefix !== '' ? $source_db_prefix : ($config_defaults['prefix'] ?? 'wp_'))),
];
$available_databases = [];
$request_method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$action = $request_method === 'POST' ? synchyInstallerPostedString('action') : '';

if ($archive_path === '') {
	$errors[] = 'Could not find the Synchy archive next to this installer.';
} elseif ($expected_archive_size > 0 && $actual_archive_size !== $expected_archive_size) {
	$errors[] = 'Archive size mismatch detected. Expected ' . synchyInstallerReadableSize($expected_archive_size) . ' but found ' . synchyInstallerReadableSize($actual_archive_size) . '.';
}

if (!function_exists('mysqli_init')) {
	$errors[] = 'MySQLi is not available on this server, so the installer cannot connect to the destination database directly.';
}

if ($database_config['prefix'] === '') {
	$database_config['prefix'] = $source_db_prefix !== '' ? $source_db_prefix : 'wp_';
}

if ($request_method === 'POST') {
	if (!$authorized) {
		$errors[] = 'This installer URL is locked. Open it with the full tokenized URL from Synchy Site Sync.';
	} elseif ($action === 'load_databases') {
		try {
			synchyInstallerValidateDatabaseConfig($database_config, false);
			$available_databases = synchyInstallerLoadDatabases($database_config);

			if ($available_databases === []) {
				$warnings[] = 'The connection worked, but no non-system databases were returned for this user.';
			} else {
				$database_list_message = 'Loaded ' . number_format(count($available_databases)) . ' databases from ' . $database_config['host'] . '.';

				if ($database_config['name'] === '' || !in_array($database_config['name'], $available_databases, true)) {
					$database_config['name'] = $available_databases[0];
				}
			}
		} catch (Throwable $throwable) {
			$errors[] = $throwable->getMessage();
		}
	} elseif ($action === 'run_restore') {
		$connection = null;

		if (!isset($_POST['confirm_backup']) || $_POST['confirm_backup'] !== '1') {
			$errors[] = 'Confirm that you created a backup of the destination site before running the restore.';
		}

			try {
				synchyInstallerValidateDatabaseConfig($database_config);

				if ($destination_url === '') {
					throw new RuntimeException('Enter the final destination URL before running the restore.');
				}

				if ($database_config['host'] !== '' && $database_config['user'] !== '') {
					try {
						$available_databases = synchyInstallerLoadDatabases($database_config);
				} catch (Throwable $throwable) {
					$warnings[] = 'Could not refresh the database list before restore: ' . $throwable->getMessage();
				}
			}

			if ($errors !== []) {
				throw new RuntimeException('Resolve the installer preflight errors before attempting the restore.');
			}

			synchyInstallerValidateArchive($archive_path);
			synchyInstallerWriteMaintenanceFile($wordpress_root);
			synchyInstallerExtractArchive($archive_path, $extract_directory, $messages);

			if (!is_readable($database_path)) {
				throw new RuntimeException('Could not find synchy/database.sql after extracting the package.');
			}

			$connection = synchyInstallerConnectDatabase($database_config, true);
			synchyInstallerDropDatabaseObjects($connection, $messages);
			synchyInstallerImportDatabase($database_path, $connection, $messages);

				$pairs = [];

				foreach ([$source_home, $source_site] as $source_url) {
					$source_url = synchyInstallerNormalizeUrl($source_url);

					if ($source_url === '' || $source_url === $destination_url || isset($pairs[$source_url])) {
						continue;
					}

					$pairs[$source_url] = [$source_url, $destination_url];
				}

			foreach ($pairs as $pair) {
				if ($pair[0] !== '' && $pair[1] !== '' && $pair[0] !== $pair[1]) {
					synchyInstallerSearchReplace($pair[0], $pair[1], $connection, $messages, $warnings);
				}
			}

			synchyInstallerForceCoreUrls($connection, $database_config['prefix'], $destination_url, $messages);
			synchyInstallerUpdateWpConfig($wordpress_root, $extract_directory, $database_config, $messages);
			$connection->close();
			$connection = null;
			synchyInstallerCopyFiles($extract_directory, $wordpress_root, $messages, $warnings);
			synchyInstallerEnsureHtaccess($wordpress_root, $destination_url, $messages);
			$restore_complete = true;
			$messages[] = 'Restore complete. Review the destination site, then delete installer.php, the archive zip, and the hidden restore workspace.';
		} catch (Throwable $throwable) {
			$errors[] = $throwable->getMessage();
		}

		if ($connection instanceof mysqli) {
			$connection->close();
		}

		synchyInstallerRemoveMaintenanceFile($wordpress_root);
	} elseif ($action === 'cleanup_after_restore') {
		try {
			$cleanup_targets = synchyInstallerBuildCleanupTargets($wordpress_root, $package_directory, $archive_path, $workspace_root);

			if ($cleanup_targets === []) {
				$warnings[] = 'No Synchy cleanup files were found at this location.';
			} else {
				synchyInstallerDeleteCleanupTargets($cleanup_targets, $cleanup_messages);
				$cleanup_complete = true;
			}
		} catch (Throwable $throwable) {
			$errors[] = $throwable->getMessage();
		}
	}
}

$warnings = array_values(array_unique($warnings));
$cleanup_targets = synchyInstallerBuildCleanupTargets($wordpress_root, $package_directory, $archive_path, $workspace_root);
?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Synchy Installer</title>
<style>
body{margin:0;padding:32px;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#eef4ef;color:#12323b}
.shell{max-width:1040px;margin:0 auto;padding:28px;border:1px solid #d7e1da;border-radius:24px;background:#fff;box-shadow:0 18px 36px rgba(18,35,28,.08)}
.eyebrow{margin:0 0 8px;color:#16824f;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
h1{margin:0 0 12px;font-size:44px;line-height:1}
h2{margin:0 0 12px;font-size:22px}
p{margin:0 0 12px;color:#4a676c}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;margin:24px 0}
.card{padding:18px;border:1px solid #d7e1da;border-radius:18px;background:#f6fbf7}
.label{display:block;margin-bottom:6px;color:#426067;font-size:13px;text-transform:uppercase;letter-spacing:.04em}
.notice{margin:18px 0;padding:14px 16px;border-radius:16px}
.notice.error{background:#fff4f4;color:#8a1f1f}
.notice.success{background:#eefaf3;color:#19653f}
.notice.warn{background:#fff7e8;color:#845a0f}
.notice.info{background:#eef5fb;color:#184f7b}
.stack{display:grid;gap:14px}
code{padding:4px 8px;border-radius:10px;background:#f4f6f5}
ul{margin:0;padding-left:18px}
form{margin-top:24px;padding:18px;border:1px solid #d7e1da;border-radius:18px;background:#f8fbf8}
input,select{width:100%;box-sizing:border-box;padding:12px 14px;border:1px solid #bfd0c3;border-radius:12px;background:#fff;color:#12323b;font:inherit}
input:focus,select:focus{outline:none;border-color:#1e7bc8;box-shadow:0 0 0 3px rgba(30,123,200,.12)}
button{appearance:none;border:0;border-radius:12px;background:#1e7bc8;color:#fff;padding:12px 18px;font:inherit;font-weight:600;cursor:pointer}
button.secondary{background:#eef5fb;color:#1e7bc8;border:1px solid #1e7bc8}
button:disabled{opacity:.55;cursor:not-allowed}
label.checkbox{display:flex;gap:10px;align-items:flex-start;margin:14px 0;color:#304e55}
label.checkbox input{width:auto;margin-top:4px}
.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.meta > div{min-width:0}
.meta strong,.notice,.hint,p,li,code,a{overflow-wrap:anywhere;word-break:break-word}
.meta strong{display:block}
.field-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.field{display:grid;gap:6px}
.field.full{grid-column:1 / -1}
.hint{margin:0;color:#4a676c;font-size:14px}
.actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:18px}
a{color:#1e7bc8}
.cleanup-list{display:grid;gap:10px;margin:0;padding:0;list-style:none}
.cleanup-list li{display:grid;gap:4px;padding:12px 14px;border:1px solid #d7e1da;border-radius:14px;background:#fff}
.cleanup-list strong{display:block}
@media (max-width: 760px){body{padding:18px}.shell{padding:22px}.grid,.meta,.field-grid{grid-template-columns:1fr}h1{font-size:34px}}
</style>
</head>
<body>
<div class="shell">
	<p class="eyebrow">Synchy Installer</p>
	<h1>Manual Restore</h1>
		<p>This installer restores the Synchy archive staged next to it. It overwrites the destination files and replaces the selected MySQL database with the package database dump.</p>

	<?php if ($token_required && !$authorized) : ?>
		<div class="notice error">
			<strong>Installer locked.</strong>
			<p>Open this installer with the full tokenized URL provided by Synchy Site Sync.</p>
		</div>
	<?php endif; ?>

	<?php foreach ($errors as $error) : ?>
		<div class="notice error"><?php echo synchyInstallerEscape($error); ?></div>
	<?php endforeach; ?>

	<?php if ($restore_complete) : ?>
		<div class="notice success">
			<strong>Restore complete.</strong>
			<p>The selected database was replaced and the destination files were overwritten from the package.</p>
		</div>
	<?php endif; ?>

	<?php if ($cleanup_complete) : ?>
		<div class="notice success">
			<strong>Cleanup complete.</strong>
			<p>Synchy removed the installer, package zip, restore workspace, and any matching staged session folders it found for this restore.</p>
		</div>
	<?php endif; ?>

	<?php if ($warnings !== []) : ?>
		<div class="notice warn">
			<strong>Warnings</strong>
			<ul>
				<?php foreach ($warnings as $warning) : ?>
					<li><?php echo synchyInstallerEscape($warning); ?></li>
				<?php endforeach; ?>
			</ul>
		</div>
	<?php endif; ?>

	<?php if ($restore_complete && !$cleanup_complete) : ?>
		<div class="card stack">
			<h2>Cleanup Files</h2>
			<p>Use the button below to remove the temporary Synchy restore files from this destination. Synchy keeps any <code>wp-config.php.synchy-*.bak</code> backup file in place so you can recover it manually if needed.</p>
			<?php if ($cleanup_targets === []) : ?>
				<div class="notice info">No Synchy cleanup files were found at this location.</div>
			<?php else : ?>
				<ul class="cleanup-list">
					<?php foreach ($cleanup_targets as $target) : ?>
						<li>
							<strong><?php echo synchyInstallerEscape((string) ($target['label'] ?? 'Cleanup item')); ?></strong>
							<span><?php echo synchyInstallerEscape((string) ($target['path'] ?? '')); ?></span>
						</li>
					<?php endforeach; ?>
				</ul>
				<form method="post">
					<?php if ($provided_token !== '') : ?>
						<input type="hidden" name="token" value="<?php echo synchyInstallerEscape($provided_token); ?>">
					<?php endif; ?>
					<div class="actions">
						<button type="submit" name="action" value="cleanup_after_restore">Delete Cleanup Files</button>
						<a href="<?php echo synchyInstallerEscape($destination_url !== '' ? $destination_url . '/' : './'); ?>">Open site</a>
						<a href="<?php echo synchyInstallerEscape($destination_url !== '' ? $destination_url . '/wp-admin/' : './wp-admin/'); ?>">Open WordPress admin</a>
					</div>
				</form>
			<?php endif; ?>
		</div>
	<?php endif; ?>

	<?php if ($cleanup_messages !== []) : ?>
		<div class="card stack">
			<h2>Cleanup Log</h2>
			<ul>
				<?php foreach ($cleanup_messages as $message) : ?>
					<li><?php echo synchyInstallerEscape($message); ?></li>
				<?php endforeach; ?>
			</ul>
		</div>
	<?php endif; ?>

	<?php if ($messages !== []) : ?>
		<div class="card stack">
			<h2>Restore Log</h2>
			<ul>
				<?php foreach ($messages as $message) : ?>
					<li><?php echo synchyInstallerEscape($message); ?></li>
				<?php endforeach; ?>
			</ul>
		</div>
	<?php endif; ?>

	<div class="grid">
		<div class="card">
			<h2>Package</h2>
			<div class="meta">
				<div>
					<span class="label">Package Name</span>
					<strong><?php echo synchyInstallerEscape($package_name !== '' ? $package_name : 'Unavailable'); ?></strong>
				</div>
				<div>
					<span class="label">Package ID</span>
					<strong><?php echo synchyInstallerEscape($package_id !== '' ? $package_id : 'Unavailable'); ?></strong>
				</div>
					<div>
						<span class="label">Source Package URL</span>
						<strong><?php echo synchyInstallerEscape($source_home !== '' ? $source_home : 'Unavailable'); ?></strong>
					</div>
				<div>
					<span class="label">Archive</span>
					<strong><?php echo synchyInstallerEscape($archive_path !== '' ? basename($archive_path) : 'Unavailable'); ?></strong>
				</div>
				<div>
					<span class="label">Archive Size</span>
					<strong><?php echo synchyInstallerEscape($actual_archive_size > 0 ? synchyInstallerReadableSize($actual_archive_size) : 'Unavailable'); ?></strong>
				</div>
				<div>
					<span class="label">Source DB Prefix</span>
					<strong><?php echo synchyInstallerEscape($source_db_prefix !== '' ? $source_db_prefix : 'Unavailable'); ?></strong>
				</div>
			</div>
		</div>

		<div class="card">
			<h2>Destination</h2>
			<div class="meta">
				<div>
					<span class="label">WordPress Root</span>
					<strong><?php echo synchyInstallerEscape($wordpress_root !== '' ? $wordpress_root : 'Unavailable'); ?></strong>
				</div>
					<div>
						<span class="label">Detected Destination URL</span>
						<strong><?php echo synchyInstallerEscape($detected_destination_url !== '' ? $detected_destination_url : 'Unavailable'); ?></strong>
					</div>
					<div>
						<span class="label">Restore Target URL</span>
						<strong><?php echo synchyInstallerEscape($destination_url !== '' ? $destination_url : 'Unavailable'); ?></strong>
					</div>
					<div>
						<span class="label">Extract Workspace</span>
						<strong><?php echo synchyInstallerEscape($extract_directory); ?></strong>
					</div>
				<div>
					<span class="label">Database Dump</span>
					<strong><?php echo synchyInstallerEscape($database_path); ?></strong>
				</div>
			</div>
		</div>
	</div>

	<div class="card stack">
		<h2>What Restore Does</h2>
			<ul>
				<li>Validates that the zip next to this installer matches the expected Synchy package.</li>
				<li>Extracts the uploaded Synchy archive into a temporary workspace next to this installer.</li>
				<li>Connects to the destination MySQL server using the credentials you provide here.</li>
				<li>Drops all existing tables and views in the selected destination database, then imports the package dump.</li>
				<li>Runs URL replacement from the source package URLs to the destination URL you confirm below.</li>
				<li>Updates <code>wp-config.php</code> to use the selected database connection and package table prefix.</li>
				<li>Copies the extracted files into the WordPress root while preserving the destination <code>wp-config.php</code>.</li>
			</ul>
		<p><strong>Backup first.</strong> This restore overwrites the selected database and the destination site files.</p>
	</div>

	<?php if (!$restore_complete && !$cleanup_complete) : ?>
		<form method="post">
			<?php if ($provided_token !== '') : ?>
				<input type="hidden" name="token" value="<?php echo synchyInstallerEscape($provided_token); ?>">
			<?php endif; ?>

				<div class="field-grid">
					<div class="field full">
						<label for="destination_url"><span class="label">Destination URL</span></label>
						<input id="destination_url" type="url" name="destination_url" value="<?php echo synchyInstallerEscape($destination_url); ?>" placeholder="https://staging.example.com">
						<p class="hint">Synchy will replace the source package URLs with this value during restore. It defaults to the URL you opened this installer from, but you can correct it here before running the restore.</p>
					</div>
					<div class="field">
						<label for="db_host"><span class="label">Database Host</span></label>
						<input id="db_host" type="text" name="db_host" value="<?php echo synchyInstallerEscape($database_config['host']); ?>" placeholder="localhost">
					</div>
				<div class="field">
					<label for="db_user"><span class="label">Database Username</span></label>
					<input id="db_user" type="text" name="db_user" value="<?php echo synchyInstallerEscape($database_config['user']); ?>" placeholder="db_user">
				</div>
				<div class="field">
					<label for="db_password"><span class="label">Database Password</span></label>
					<input id="db_password" type="password" name="db_password" value="<?php echo synchyInstallerEscape($database_config['password']); ?>" placeholder="Database password">
				</div>
				<div class="field">
					<label for="db_prefix"><span class="label">Table Prefix</span></label>
					<input id="db_prefix" type="text" name="db_prefix" value="<?php echo synchyInstallerEscape($database_config['prefix']); ?>" placeholder="wp_">
					<p class="hint">Defaults to the package prefix and will be written into <code>wp-config.php</code>.</p>
				</div>
				<div class="field full">
					<label for="db_name"><span class="label">Destination Database</span></label>
					<?php if ($available_databases !== []) : ?>
						<select id="db_name" name="db_name">
							<?php foreach ($available_databases as $database_name) : ?>
								<option value="<?php echo synchyInstallerEscape($database_name); ?>" <?php echo $database_name === $database_config['name'] ? 'selected' : ''; ?>>
									<?php echo synchyInstallerEscape($database_name); ?>
								</option>
							<?php endforeach; ?>
							<?php if ($database_config['name'] !== '' && !in_array($database_config['name'], $available_databases, true)) : ?>
								<option value="<?php echo synchyInstallerEscape($database_config['name']); ?>" selected>
									<?php echo synchyInstallerEscape($database_config['name']); ?>
								</option>
							<?php endif; ?>
						</select>
					<?php else : ?>
						<input id="db_name" type="text" name="db_name" value="<?php echo synchyInstallerEscape($database_config['name']); ?>" placeholder="Select via Load Databases or type the database name">
					<?php endif; ?>
						<p class="hint">
							<strong>Load Databases</strong> is optional. It uses the host, username, and password above to ask MySQL which databases this user can access and fills the dropdown for you.
							If you already know the destination database name, type it directly and skip that step.
							<?php if ($database_list_message !== '') : ?>
								<br><?php echo synchyInstallerEscape($database_list_message); ?>
							<?php endif; ?>
					</p>
				</div>
			</div>

			<label class="checkbox">
				<input type="checkbox" name="confirm_backup" value="1" <?php echo isset($_POST['confirm_backup']) && $_POST['confirm_backup'] === '1' ? 'checked' : ''; ?>>
				<span>I created a database and file backup of this destination site and I understand this restore will overwrite it.</span>
			</label>

			<div class="actions">
				<button type="submit" name="action" value="load_databases" class="secondary" <?php echo !$authorized ? 'disabled' : ''; ?>>Load Databases</button>
				<button type="submit" name="action" value="run_restore" <?php echo (!$authorized || $errors !== []) ? 'disabled' : ''; ?>>Run Restore</button>
			</div>
		</form>
		<?php elseif ($restore_complete || $cleanup_complete) : ?>
			<p>
				<a href="<?php echo synchyInstallerEscape($destination_url . '/wp-admin/'); ?>">Open WordPress admin</a>
			</p>
		<?php endif; ?>
</div>
</body>
</html>
