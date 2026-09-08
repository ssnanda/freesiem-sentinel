<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * View, quarantine, restore and delete files that a scan flagged.
 *
 * Everything here is reached only from the Scan → finding-detail screen, is
 * gated on `manage_options` + the plugin nonce by the admin handlers, and
 * refuses to touch WordPress core, wp-config.php, directories or symlinks.
 *
 * "Quarantine" is the safe default: the file is moved into a private folder
 * under uploads (`freesiem-quarantine/`, denied to the web), its executable bit
 * stripped, and a record kept so it can be restored. "Delete" is a hard unlink
 * and always needs its own confirmation in the UI.
 */
class Freesiem_File_Actions
{
	public const QUARANTINE_OPTION = 'freesiem_sentinel_quarantine';
	public const MAX_VIEW_BYTES = 262144; // 256 KB rendered in the browser
	public const MAX_BINARY_VIEW_BYTES = 4096;
	private const QUARANTINE_DIRNAME = 'freesiem-quarantine';

	/**
	 * Are file actions available to the current user? A site can turn the whole
	 * feature off with the `freesiem_sentinel_allow_file_actions` filter.
	 */
	public static function can_act(): bool
	{
		return current_user_can('manage_options')
			&& (bool) apply_filters('freesiem_sentinel_allow_file_actions', true);
	}

	// -----------------------------------------------------------------
	// Path safety
	// -----------------------------------------------------------------

	/**
	 * Resolve a finding's stored relative path to an absolute path we are
	 * allowed to act on, or a WP_Error explaining why not.
	 *
	 * @return string|WP_Error
	 */
	public static function resolve(string $relative)
	{
		$relative = str_replace('\\', '/', trim($relative));
		$relative = ltrim(preg_replace('~^/+~', '', $relative) ?? '', '/');

		if ($relative === '' || str_contains($relative, '../') || str_contains($relative, "\0")) {
			return new WP_Error('freesiem_bad_path', __('That file path is not one this tool can act on.', 'freesiem-sentinel'));
		}

		$candidate = realpath(ABSPATH . $relative);

		if ($candidate === false) {
			$candidate = realpath(trailingslashit(WP_CONTENT_DIR) . preg_replace('~^wp-content/~', '', $relative));
		}

		if ($candidate === false) {
			return new WP_Error('freesiem_missing', __('That file no longer exists on disk.', 'freesiem-sentinel'));
		}

		$candidate = wp_normalize_path($candidate);
		$roots = array_values(array_filter([
			wp_normalize_path(realpath(ABSPATH) ?: ABSPATH),
			defined('WP_CONTENT_DIR') ? wp_normalize_path(realpath(WP_CONTENT_DIR) ?: WP_CONTENT_DIR) : '',
		]));

		$within = false;

		foreach ($roots as $root) {
			$root = untrailingslashit($root);

			if ($candidate === $root || str_starts_with($candidate, $root . '/')) {
				$within = true;
				break;
			}
		}

		if (!$within) {
			return new WP_Error('freesiem_outside_root', __('That file is outside the WordPress installation.', 'freesiem-sentinel'));
		}

		if (is_link($candidate)) {
			return new WP_Error('freesiem_symlink', __('That path is a symlink; refusing to act on it.', 'freesiem-sentinel'));
		}

		if (!is_file($candidate)) {
			return new WP_Error('freesiem_not_file', __('That path is not a regular file.', 'freesiem-sentinel'));
		}

		$protected = self::protected_reason($relative);

		if ($protected !== '') {
			return new WP_Error('freesiem_protected', $protected);
		}

		return $candidate;
	}

	/**
	 * Why a path must not be moved or deleted from here — empty string if it is
	 * fair game.
	 */
	public static function protected_reason(string $relative): string
	{
		$relative = ltrim(str_replace('\\', '/', $relative), '/');
		$lower = strtolower($relative);
		$basename = strtolower(basename($relative));

		if (str_starts_with($lower, 'wp-admin/') || str_starts_with($lower, 'wp-includes/')) {
			return __('That file belongs to WordPress core. Reinstall WordPress instead of removing core files by hand.', 'freesiem-sentinel');
		}

		$core_root_files = [
			'wp-config.php', 'wp-config-sample.php', 'wp-load.php', 'wp-settings.php',
			'wp-blog-header.php', 'wp-cron.php', 'index.php', 'xmlrpc.php',
			'wp-login.php', 'wp-mail.php', 'wp-links-opml.php', 'wp-activate.php',
			'wp-signup.php', 'wp-trackback.php', 'wp-comments-post.php',
		];

		if (!str_contains($relative, '/') && in_array($basename, $core_root_files, true)) {
			return __('That is a core WordPress file in the site root. Removing it would break the site.', 'freesiem-sentinel');
		}

		return '';
	}

	// -----------------------------------------------------------------
	// Viewing
	// -----------------------------------------------------------------

	/**
	 * Read a flagged file for display: never executed, capped, control bytes
	 * neutralised, and obvious secrets in wp-config-shaped files masked.
	 *
	 * @return array{type:string,content:string,bytes:int,truncated:bool,masked:bool}|WP_Error
	 */
	public static function read_for_display(string $relative)
	{
		$resolved = self::resolve_for_view($relative);

		if (is_wp_error($resolved)) {
			return $resolved;
		}

		$size = (int) @filesize($resolved);
		$raw = (string) @file_get_contents($resolved, false, null, 0, self::MAX_VIEW_BYTES);
		$truncated = $size > strlen($raw);

		$sample = substr($raw, 0, 4096);
		$non_text = strlen($sample) > 0
			? strlen(preg_replace('~[\x09\x0A\x0D\x20-\x7E]|[\xC2-\xF4][\x80-\xBF]+~', '', $sample))
			: 0;
		$is_binary = $raw !== '' && (
			str_contains(substr($raw, 0, 8192), "\0")
			|| ($sample !== '' && $non_text / strlen($sample) > 0.3)
		);

		if ($is_binary) {
			return [
				'type' => 'binary',
				'content' => self::hexdump(substr($raw, 0, self::MAX_BINARY_VIEW_BYTES)),
				'bytes' => $size,
				'truncated' => $size > self::MAX_BINARY_VIEW_BYTES,
				'masked' => false,
			];
		}

		$masked = false;
		$basename = strtolower(basename($relative));

		if (str_contains($basename, 'wp-config') || preg_match('~DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_SALT|NONCE_SALT~', $raw)) {
			$before = $raw;
			$raw = preg_replace(
				"~(define\\(\\s*['\"](?:DB_PASSWORD|DB_USER|DB_NAME|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['\"]\\s*,\\s*)(['\"]).*?\\2(\\s*\\)\\s*;)~i",
				'$1$2*** masked by freeSIEM Sentinel ***$2$3',
				$raw
			) ?? $raw;
			$masked = $raw !== $before;
		}

		// Neutralise control characters (keep tab / newline) for safe rendering.
		$raw = preg_replace('~[\x00-\x08\x0B\x0C\x0E-\x1F]~', '', $raw) ?? $raw;

		return [
			'type' => 'text',
			'content' => $raw,
			'bytes' => $size,
			'truncated' => $truncated,
			'masked' => $masked,
		];
	}

	/**
	 * Viewing tolerates a couple of things acting does not: a file already
	 * quarantined, and the core-file guard (reading core is harmless).
	 *
	 * @return string|WP_Error
	 */
	private static function resolve_for_view(string $relative)
	{
		$resolved = self::resolve($relative);

		if (!is_wp_error($resolved)) {
			return $resolved;
		}

		if ($resolved->get_error_code() === 'freesiem_protected') {
			$abs = realpath(ABSPATH . ltrim(str_replace('\\', '/', $relative), '/'));

			if ($abs !== false && is_file($abs) && !is_link($abs)) {
				return str_replace('\\', '/', $abs);
			}
		}

		return $resolved;
	}

	private static function hexdump(string $bytes): string
	{
		$out = '';
		$len = strlen($bytes);

		for ($i = 0; $i < $len; $i += 16) {
			$chunk = substr($bytes, $i, 16);
			$hex = '';
			$ascii = '';

			for ($j = 0; $j < strlen($chunk); $j++) {
				$ord = ord($chunk[$j]);
				$hex .= sprintf('%02x ', $ord);
				$ascii .= ($ord >= 32 && $ord <= 126) ? $chunk[$j] : '.';
			}

			$out .= sprintf("%08x  %-48s |%s|\n", $i, $hex, $ascii);
		}

		return $out;
	}

	// -----------------------------------------------------------------
	// Quarantine / delete / restore
	// -----------------------------------------------------------------

	/**
	 * Move a flagged file into the private quarantine folder.
	 *
	 * @return array{id:string}|WP_Error
	 */
	public static function quarantine(string $relative)
	{
		$resolved = self::resolve($relative);

		if (is_wp_error($resolved)) {
			return $resolved;
		}

		$store = self::quarantine_dir();

		if (is_wp_error($store)) {
			return $store;
		}

		$rel_clean = ltrim(str_replace('\\', '/', $relative), '/');
		$id = gmdate('Ymd-His') . '-' . substr(md5($rel_clean . '|' . microtime(true)), 0, 8);
		$dest_dir = trailingslashit($store) . $id;

		if (!wp_mkdir_p($dest_dir)) {
			return new WP_Error('freesiem_quarantine_mkdir', __('Could not create the quarantine folder.', 'freesiem-sentinel'));
		}

		$size = (int) @filesize($resolved);
		$hash = (string) @md5_file($resolved);
		$payload = trailingslashit($dest_dir) . 'payload';

		if (!@rename($resolved, $payload)) {
			if (!@copy($resolved, $payload) || !@unlink($resolved)) {
				@unlink($payload);
				@rmdir($dest_dir);

				return new WP_Error('freesiem_quarantine_move', __('Could not move the file into quarantine (permissions?).', 'freesiem-sentinel'));
			}
		}

		@chmod($payload, 0600);

		$user = wp_get_current_user();
		$record = [
			'id' => $id,
			'relative_path' => $rel_clean,
			'absolute_path' => $resolved,
			'size' => $size,
			'md5' => $hash,
			'quarantined_at' => freesiem_sentinel_get_iso8601_time(),
			'user_id' => (int) ($user->ID ?? 0),
			'user_login' => (string) ($user->user_login ?? ''),
		];

		@file_put_contents(trailingslashit($dest_dir) . 'meta.json', wp_json_encode($record));

		$records = self::records();
		$records[$id] = $record;
		update_option(self::QUARANTINE_OPTION, $records, false);

		freesiem_sentinel_log_event(
			'file_quarantined',
			sprintf('Quarantined %s (%s).', $rel_clean, size_format(max($size, 0))),
			(string) ($user->user_login ?? ''),
			'',
			['relative_path' => $rel_clean, 'quarantine_id' => $id, 'md5' => $hash]
		);

		return ['id' => $id];
	}

	/**
	 * Put a quarantined file back where it came from.
	 *
	 * @return true|WP_Error
	 */
	public static function restore(string $id)
	{
		$records = self::records();
		$record = $records[$id] ?? null;

		if (!is_array($record)) {
			return new WP_Error('freesiem_unknown_quarantine', __('That quarantine record no longer exists.', 'freesiem-sentinel'));
		}

		$store = self::quarantine_dir();

		if (is_wp_error($store)) {
			return $store;
		}

		$payload = trailingslashit($store) . $id . '/payload';
		$target = (string) $record['absolute_path'];

		if (!is_file($payload)) {
			return new WP_Error('freesiem_quarantine_gone', __('The quarantined copy is missing.', 'freesiem-sentinel'));
		}

		if (file_exists($target)) {
			return new WP_Error('freesiem_restore_conflict', sprintf(__('A file already exists at %s. Remove it first, then restore.', 'freesiem-sentinel'), $record['relative_path']));
		}

		if (!wp_mkdir_p(dirname($target)) || (!@rename($payload, $target) && !(@copy($payload, $target) && @unlink($payload)))) {
			return new WP_Error('freesiem_restore_failed', __('Could not move the file back into place.', 'freesiem-sentinel'));
		}

		@chmod($target, 0644);
		self::forget($id);

		freesiem_sentinel_log_event(
			'file_restored',
			sprintf('Restored %s from quarantine.', $record['relative_path']),
			'',
			'',
			['relative_path' => $record['relative_path'], 'quarantine_id' => $id]
		);

		return true;
	}

	/**
	 * Permanently delete — either a quarantined item (pass its id) or a
	 * still-live flagged file (pass its relative path).
	 *
	 * @return true|WP_Error
	 */
	public static function delete(string $id_or_relative)
	{
		$records = self::records();

		if (isset($records[$id_or_relative])) {
			$id = $id_or_relative;
			$store = self::quarantine_dir();

			if (is_wp_error($store)) {
				return $store;
			}

			$dir = trailingslashit($store) . $id;
			@unlink(trailingslashit($dir) . 'payload');
			@unlink(trailingslashit($dir) . 'meta.json');
			@rmdir($dir);
			self::forget($id);

			freesiem_sentinel_log_event(
				'file_deleted',
				sprintf('Deleted quarantined file %s.', (string) ($records[$id]['relative_path'] ?? $id)),
				'',
				'',
				['quarantine_id' => $id]
			);

			return true;
		}

		$resolved = self::resolve($id_or_relative);

		if (is_wp_error($resolved)) {
			return $resolved;
		}

		$rel_clean = ltrim(str_replace('\\', '/', $id_or_relative), '/');
		$hash = (string) @md5_file($resolved);

		if (!@unlink($resolved)) {
			return new WP_Error('freesiem_delete_failed', __('Could not delete the file (permissions?).', 'freesiem-sentinel'));
		}

		freesiem_sentinel_log_event(
			'file_deleted',
			sprintf('Deleted %s.', $rel_clean),
			'',
			'',
			['relative_path' => $rel_clean, 'md5' => $hash]
		);

		return true;
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	public static function records(): array
	{
		$stored = get_option(self::QUARANTINE_OPTION, []);

		return is_array($stored) ? array_filter($stored, 'is_array') : [];
	}

	private static function forget(string $id): void
	{
		$records = self::records();
		unset($records[$id]);
		update_option(self::QUARANTINE_OPTION, $records, false);
	}

	/**
	 * @return string|WP_Error absolute quarantine directory, created and sealed.
	 */
	private static function quarantine_dir()
	{
		$uploads = wp_get_upload_dir();

		if (!empty($uploads['error']) || empty($uploads['basedir'])) {
			return new WP_Error('freesiem_uploads', __('The uploads directory is not writable.', 'freesiem-sentinel'));
		}

		$dir = trailingslashit($uploads['basedir']) . self::QUARANTINE_DIRNAME;

		if (!wp_mkdir_p($dir)) {
			return new WP_Error('freesiem_quarantine_dir', __('Could not create the quarantine directory.', 'freesiem-sentinel'));
		}

		if (!is_file(trailingslashit($dir) . '.htaccess')) {
			@file_put_contents(trailingslashit($dir) . '.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
		}

		if (!is_file(trailingslashit($dir) . 'index.php')) {
			@file_put_contents(trailingslashit($dir) . 'index.php', "<?php // Silence is golden.\n");
		}

		if (!is_file(trailingslashit($dir) . 'web.config')) {
			@file_put_contents(trailingslashit($dir) . 'web.config', "<configuration>\n<system.webServer>\n<authorization>\n<deny users=\"*\" />\n</authorization>\n</system.webServer>\n</configuration>\n");
		}

		return $dir;
	}
}
