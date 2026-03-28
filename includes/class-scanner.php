<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Scanner
{
	private const MAX_FILES = 1000;
	private const MAX_DEPTH = 5;
	private const MAX_HASHED_FILES = 500;
	private const MAX_STORED_DIFFS = 200;
	private int $max_files = self::MAX_FILES;
	private int $max_depth = self::MAX_DEPTH;
	private int $max_hashed_files = self::MAX_HASHED_FILES;
	private bool $include_uploads = false;
	private bool $scan_wordpress = true;
	private bool $scan_filesystem_enabled = true;
	private bool $scan_fim_enabled = false;
	private bool $filesystem_advanced_enabled = false;

	public function run(array $options = []): array
	{
		try {
			if (!function_exists('get_plugin_updates')) {
				require_once ABSPATH . 'wp-admin/includes/update.php';
			}

			$this->apply_scan_preferences($options);

			wp_version_check();
			wp_update_plugins();
			wp_update_themes();

			$metadata = $this->build_metadata();
			$inventory = $this->build_inventory();
			$filesystem = $this->scan_filesystem();
			$integrity = $this->scan_fim_enabled ? $this->run_file_integrity_monitor($filesystem['flagged_files']) : [
				'summary' => [
					'enabled' => false,
					'baseline_created' => false,
					'partial' => false,
					'hashed_files' => 0,
					'new_files_count' => 0,
					'modified_files_count' => 0,
					'deleted_files_count' => 0,
					'last_baseline_at' => '',
					'last_diff_at' => '',
				],
				'findings' => [],
			];

			$inventory['filesystem'] = $filesystem['summary'];
			$inventory['filesystem_flagged_files'] = $filesystem['flagged_files'];
			$inventory['file_integrity'] = $integrity['summary'];
			$inventory['scan_profile'] = [
				'scan_wordpress' => $this->scan_wordpress,
				'scan_filesystem' => $this->scan_filesystem_enabled,
				'scan_fim' => $this->scan_fim_enabled,
				'include_uploads' => $this->include_uploads,
				'max_files' => $this->max_files,
				'max_depth' => $this->max_depth,
			];

			$findings = array_merge(
				$this->collect_findings($metadata, $inventory),
				$filesystem['findings'],
				$integrity['findings']
			);

			return [
				'metadata' => $metadata,
				'inventory' => $inventory,
				'findings' => $findings,
				'scan_timestamps' => [
					'local' => freesiem_sentinel_get_iso8601_time(),
				],
				'score' => freesiem_sentinel_score_from_findings($findings),
			];
		} catch (Throwable $throwable) {
			return [
				'status' => 'error',
				'message' => __('Scan failed safely', 'freesiem-sentinel'),
				'metadata' => [],
				'inventory' => [
					'filesystem' => [
						'targets' => [],
						'max_files' => $this->max_files,
						'max_depth' => $this->max_depth,
						'inspected_files' => 0,
						'visited_directories' => 0,
						'flagged_files' => 0,
						'partial' => true,
						'unreadable_paths' => [],
						'skipped_directories' => [],
						'enabled' => false,
					],
					'file_integrity' => [
						'enabled' => false,
						'baseline_created' => false,
						'partial' => true,
						'hashed_files' => 0,
						'new_files_count' => 0,
						'modified_files_count' => 0,
						'deleted_files_count' => 0,
						'last_baseline_at' => '',
						'last_diff_at' => '',
					],
				],
				'findings' => [],
				'scan_timestamps' => [
					'local' => freesiem_sentinel_get_iso8601_time(),
				],
				'score' => 0,
			];
		}
	}

	private function apply_scan_preferences(array $options): void
	{
		$settings = freesiem_sentinel_get_settings();
		$saved = freesiem_sentinel_safe_array($settings['scan_preferences'] ?? []);
		$resolved = wp_parse_args($options, $saved);

		$this->scan_wordpress = !empty($resolved['scan_wordpress']);
		$this->scan_filesystem_enabled = !empty($resolved['scan_filesystem']) && Freesiem_Features::is_enabled('filesystem_basic');
		$this->filesystem_advanced_enabled = Freesiem_Features::is_enabled('filesystem_advanced');
		$this->scan_fim_enabled = !empty($resolved['scan_fim']) && Freesiem_Features::is_enabled('fim');
		$this->include_uploads = !empty($resolved['include_uploads']);
		$this->max_files = max(100, min(5000, (int) ($resolved['max_files'] ?? self::MAX_FILES)));
		$this->max_depth = max(1, min(10, (int) ($resolved['max_depth'] ?? self::MAX_DEPTH)));
		$this->max_hashed_files = max(100, min(self::MAX_HASHED_FILES, $this->max_files));
	}

	private function build_metadata(): array
	{
		$theme = wp_get_theme();

		return [
			'site_url' => site_url('/'),
			'home_url' => home_url('/'),
			'site_name' => get_bloginfo('name'),
			'timezone' => wp_timezone_string() ?: 'UTC',
			'plugin_version' => FREESIEM_SENTINEL_VERSION,
			'wp_version' => get_bloginfo('version'),
			'php_version' => PHP_VERSION,
			'active_theme' => [
				'name' => $theme->get('Name'),
				'stylesheet' => $theme->get_stylesheet(),
				'version' => $theme->get('Version'),
			],
		];
	}

	private function build_inventory(): array
	{
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';

		$all_plugins = get_plugins();
		$active_plugins = array_fill_keys((array) get_option('active_plugins', []), true);
		$mu_plugins = get_mu_plugins();
		$plugin_updates = get_plugin_updates();
		$theme_updates = get_theme_updates();
		$themes = wp_get_themes();
		$core_updates = get_core_updates();

		$plugins = [];

		foreach ($all_plugins as $file => $plugin) {
			$plugins[] = [
				'file' => $file,
				'name' => (string) ($plugin['Name'] ?? $file),
				'version' => (string) ($plugin['Version'] ?? ''),
				'active' => isset($active_plugins[$file]),
				'outdated' => isset($plugin_updates[$file]),
			];
		}

		$must_use = [];

		foreach ($mu_plugins as $file => $plugin) {
			$must_use[] = [
				'file' => $file,
				'name' => (string) ($plugin['Name'] ?? $file),
				'version' => (string) ($plugin['Version'] ?? ''),
			];
		}

		$theme_list = [];

		foreach ($themes as $stylesheet => $theme) {
			$theme_list[] = [
				'stylesheet' => $stylesheet,
				'name' => $theme->get('Name'),
				'version' => $theme->get('Version'),
				'active' => get_stylesheet() === $stylesheet,
				'outdated' => isset($theme_updates[$stylesheet]),
			];
		}

		$core_outdated = false;

		if (is_array($core_updates)) {
			foreach ($core_updates as $update) {
				if (!empty($update->response) && $update->response === 'upgrade') {
					$core_outdated = true;
					break;
				}
			}
		}

		return [
			'plugins' => $plugins,
			'mu_plugins' => $must_use,
			'themes' => $theme_list,
			'core_outdated' => $core_outdated,
			'core_updates' => is_array($core_updates) ? array_map(static function ($update): array {
				return [
					'version' => (string) ($update->current ?? ''),
					'response' => (string) ($update->response ?? ''),
				];
			}, $core_updates) : [],
			'plugin_counts' => [
				'all' => count($plugins),
				'active' => count(array_filter($plugins, static fn(array $plugin): bool => !empty($plugin['active']))),
				'inactive' => count(array_filter($plugins, static fn(array $plugin): bool => empty($plugin['active']))),
				'mu' => count($must_use),
			],
		];
	}

	private function collect_findings(array $metadata, array $inventory): array
	{
		if (!$this->scan_wordpress) {
			return [];
		}

		global $wpdb;

		$findings = [];
		$theme = wp_get_theme();
		$site_url = site_url('/');
		$home_url = home_url('/');
		$active_plugins = array_filter($inventory['plugins'], static fn(array $plugin): bool => !empty($plugin['active']));
		$outdated_plugins = array_filter($inventory['plugins'], static fn(array $plugin): bool => !empty($plugin['outdated']));
		$outdated_themes = array_filter($inventory['themes'], static fn(array $theme_data): bool => !empty($theme_data['outdated']));

		$admin_user = get_user_by('login', 'admin');
		$xmlrpc_enabled = apply_filters('xmlrpc_enabled', true);
		$rest_enabled = rest_url() !== '';
		$wp_debug = defined('WP_DEBUG') && WP_DEBUG;
		$wp_debug_log = defined('WP_DEBUG_LOG') && WP_DEBUG_LOG;
		$file_edit_disabled = defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT;
		$file_mods_disabled = defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS;
		$cron_disabled = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;
		$config_path = ABSPATH . 'wp-config.php';
		$wp_config_writable = file_exists($config_path) ? is_writable($config_path) : false;
		$content_writable = is_writable(WP_CONTENT_DIR);
		$ssl_mismatch = str_starts_with($site_url, 'https://') !== str_starts_with($home_url, 'https://');
		$using_default_db_prefix = strtolower((string) $wpdb->prefix) === 'wp_';

		if (version_compare(PHP_VERSION, '8.1', '<')) {
			$findings[] = $this->finding('php_version_old', 'platform', 'high', 'PHP version is outdated', 'The server is running an older PHP version.', 'Upgrade PHP to a currently supported release.', ['php_version' => PHP_VERSION], 82);
		}

		if (!empty($inventory['core_outdated'])) {
			$findings[] = $this->finding('wp_core_outdated', 'updates', 'high', 'WordPress core update available', 'WordPress core is not on the latest available release.', 'Apply the latest stable WordPress update after testing.', ['wp_version' => $metadata['wp_version'], 'updates' => $inventory['core_updates']], 80);
		}

		if ($outdated_plugins !== []) {
			$findings[] = $this->finding('plugins_outdated', 'updates', 'high', 'Outdated plugins detected', 'One or more installed plugins have updates available.', 'Update plugins promptly and remove unused plugins.', ['plugins' => array_values($outdated_plugins)], 78);
		}

		if ($outdated_themes !== []) {
			$findings[] = $this->finding('themes_outdated', 'updates', 'medium', 'Outdated themes detected', 'One or more installed themes have updates available.', 'Update themes and remove any unused themes that are no longer required.', ['themes' => array_values($outdated_themes)], 86);
		}

		if ($admin_user instanceof WP_User) {
			$findings[] = $this->finding('admin_username_present', 'identity', 'medium', 'Default admin username exists', 'A user account named "admin" is present.', 'Rename or remove the default admin-style username and enforce MFA where possible.', ['user_id' => $admin_user->ID], 88);
		}

		if ($xmlrpc_enabled) {
			$findings[] = $this->finding('xmlrpc_enabled', 'surface', 'medium', 'XML-RPC is enabled', 'XML-RPC expands the remote attack surface if it is not required.', 'Disable XML-RPC if no legitimate integrations depend on it.', ['xmlrpc_enabled' => true], 90);
		}

		if ($rest_enabled) {
			$findings[] = $this->finding('rest_api_exposed', 'surface', 'low', 'REST API is reachable', 'The WordPress REST API is publicly reachable, which is common but still worth reviewing.', 'Limit unnecessary user enumeration and review exposed endpoints.', ['rest_url' => rest_url()], 94);
		}

		if ($wp_debug) {
			$findings[] = $this->finding('wp_debug_enabled', 'configuration', 'high', 'WP_DEBUG is enabled', 'Debug mode can expose sensitive errors or paths in production.', 'Disable WP_DEBUG in production.', ['wp_debug' => true], 75);
		}

		if ($wp_debug_log) {
			$findings[] = $this->finding('wp_debug_log_enabled', 'configuration', 'medium', 'WP_DEBUG_LOG is enabled', 'Debug logging is enabled, which can leave verbose application logs on disk.', 'Disable WP_DEBUG_LOG outside controlled debugging windows and protect any generated logs.', ['wp_debug_log' => true], 84);
		}

		if (!$file_edit_disabled) {
			$findings[] = $this->finding('file_editor_enabled', 'configuration', 'medium', 'Plugin/theme file editor is enabled', 'The built-in file editor allows dashboard-based code edits.', 'Set DISALLOW_FILE_EDIT to true in wp-config.php.', ['disallow_file_edit' => false], 89);
		}

		if (!$file_mods_disabled) {
			$findings[] = $this->finding('file_mods_enabled', 'configuration', 'low', 'Automatic file modifications are allowed', 'WordPress can install or modify code directly from the dashboard.', 'Consider setting DISALLOW_FILE_MODS to true on hardened production systems.', ['disallow_file_mods' => false], 92);
		}

		if ($using_default_db_prefix) {
			$findings[] = $this->finding('default_db_prefix', 'database', 'low', 'Default database table prefix in use', 'The database prefix is still set to wp_.', 'Use a non-default table prefix on new deployments or during a planned migration.', ['db_prefix' => $wpdb->prefix], 95);
		}

		if ($ssl_mismatch || !str_starts_with($site_url, 'https://') || !str_starts_with($home_url, 'https://')) {
			$findings[] = $this->finding('ssl_consistency', 'transport', 'high', 'SSL configuration is inconsistent', 'Site URL and home URL are not consistently using HTTPS.', 'Force HTTPS for both site URL values and ensure valid TLS is configured.', ['site_url' => $site_url, 'home_url' => $home_url], 76);
		}

		if ($cron_disabled) {
			$findings[] = $this->finding('wp_cron_disabled', 'operations', 'medium', 'WP-Cron is disabled', 'The internal WordPress scheduler is disabled.', 'Ensure a real system cron is invoking wp-cron.php if WP-Cron is disabled.', ['disable_wp_cron' => true], 87);
		}

		if ($wp_config_writable) {
			$findings[] = $this->finding('wp_config_writable', 'permissions', 'medium', 'wp-config.php is writable', 'The main WordPress configuration file is writable by the web process.', 'Reduce file permissions on wp-config.php to read-only for the web user.', ['path' => $config_path], 88);
		}

		if ($content_writable) {
			$findings[] = $this->finding('wp_content_writable', 'permissions', 'low', 'wp-content is writable', 'The content directory is writable, which is common but should be tightly controlled.', 'Review ownership and permissions on wp-content and restrict unexpected write access.', ['path' => WP_CONTENT_DIR], 93);
		}

		if (count($active_plugins) > 30) {
			$findings[] = $this->finding('high_plugin_count', 'posture', 'low', 'High active plugin count', 'A high number of active plugins can increase attack surface and maintenance burden.', 'Remove unused plugins and consolidate overlapping functionality.', ['active_plugin_count' => count($active_plugins)], 94);
		}

		if (!is_ssl()) {
			$findings[] = $this->finding('frontend_not_ssl', 'transport', 'high', 'Current request is not using SSL', 'The site does not appear to be enforcing SSL for frontend traffic.', 'Enable HTTPS and configure redirects from HTTP to HTTPS.', ['is_ssl' => false], 74);
		}

		if ($theme->parent()) {
			$findings[] = $this->finding('child_theme_active', 'inventory', 'info', 'Child theme active', 'A child theme is active on this site.', 'Ensure the parent theme is maintained and updated together with the child theme.', ['theme' => $theme->get_stylesheet(), 'parent' => $theme->parent()->get_stylesheet()], 98);
		}

		return array_values($findings);
	}

	private function scan_filesystem(): array
	{
		if (!$this->scan_filesystem_enabled) {
			return [
				'summary' => [
					'targets' => [],
					'max_files' => $this->max_files,
					'max_depth' => $this->max_depth,
					'inspected_files' => 0,
					'visited_directories' => 0,
					'flagged_files' => 0,
					'partial' => false,
					'unreadable_paths' => [],
					'skipped_directories' => [],
					'enabled' => false,
				],
				'findings' => [],
				'flagged_files' => [],
			];
		}

		$targets = $this->get_scan_targets();
		$summary = [
			'targets' => array_values(array_map(static fn(array $target): array => [
				'label' => $target['label'],
				'path' => $target['path'],
			], $targets)),
			'max_files' => $this->max_files,
			'max_depth' => $this->max_depth,
			'inspected_files' => 0,
			'visited_directories' => 0,
			'flagged_files' => 0,
			'partial' => false,
			'unreadable_paths' => [],
			'skipped_directories' => [],
			'enabled' => true,
		];
		$findings = [];
		$flagged_files = [];

		foreach ($targets as $target) {
			if ($summary['inspected_files'] >= $this->max_files) {
				$summary['partial'] = true;
				break;
			}

			$this->scan_path($target['path'], $target['label'], 0, $summary, $findings, $flagged_files);
		}

		$summary['flagged_files'] = count($flagged_files);

		return [
			'summary' => $summary,
			'findings' => array_values($findings),
			'flagged_files' => array_values($flagged_files),
		];
	}

	private function run_file_integrity_monitor(array $flagged_files): array
	{
		$settings = freesiem_sentinel_get_settings();
		$enabled = !empty($settings['fim_enabled']);
		$now = freesiem_sentinel_get_iso8601_time();
		$baseline = freesiem_sentinel_safe_array($settings['fim_baseline'] ?? []);

		if (!$enabled) {
			return [
				'summary' => [
					'enabled' => false,
					'baseline_created' => false,
					'partial' => false,
					'hashed_files' => 0,
					'new_files_count' => 0,
					'modified_files_count' => 0,
					'deleted_files_count' => 0,
					'last_baseline_at' => freesiem_sentinel_safe_string($settings['fim_last_baseline_at'] ?? ''),
					'last_diff_at' => freesiem_sentinel_safe_string($settings['fim_last_diff_at'] ?? ''),
				],
				'findings' => [],
			];
		}

		$snapshot_result = $this->build_integrity_snapshot($flagged_files);
		$current_snapshot = $snapshot_result['snapshot'];

		if ($baseline === []) {
			$diff_cache = [
				'generated_at' => $now,
				'baseline_created' => true,
				'partial' => !empty($snapshot_result['summary']['partial']),
				'new_files_count' => 0,
				'modified_files_count' => 0,
				'deleted_files_count' => 0,
				'changes' => [],
			];

			freesiem_sentinel_update_settings([
				'fim_baseline' => $current_snapshot,
				'fim_last_baseline_at' => $now,
				'fim_last_diff_at' => '',
				'fim_diff_cache' => $diff_cache,
			]);

			freesiem_sentinel_set_notice('success', __('freeSIEM Sentinel established the initial file integrity baseline.', 'freesiem-sentinel'));

			return [
				'summary' => [
					'enabled' => true,
					'baseline_created' => true,
					'partial' => !empty($snapshot_result['summary']['partial']),
					'hashed_files' => (int) ($snapshot_result['summary']['hashed_files'] ?? 0),
					'new_files_count' => 0,
					'modified_files_count' => 0,
					'deleted_files_count' => 0,
					'last_baseline_at' => $now,
					'last_diff_at' => '',
				],
				'findings' => [],
			];
		}

		$diff = $this->compare_integrity_snapshots($baseline, $current_snapshot);
		$diff_cache = [
			'generated_at' => $now,
			'baseline_created' => false,
			'partial' => !empty($snapshot_result['summary']['partial']) || !empty($diff['partial']),
			'new_files_count' => (int) $diff['new_files_count'],
			'modified_files_count' => (int) $diff['modified_files_count'],
			'deleted_files_count' => (int) $diff['deleted_files_count'],
			'changes' => array_slice($diff['changes'], 0, self::MAX_STORED_DIFFS),
		];

		freesiem_sentinel_update_settings([
			'fim_baseline' => $current_snapshot,
			'fim_last_baseline_at' => $now,
			'fim_last_diff_at' => $now,
			'fim_diff_cache' => $diff_cache,
		]);

		return [
			'summary' => [
				'enabled' => true,
				'baseline_created' => false,
				'partial' => !empty($diff_cache['partial']),
				'hashed_files' => (int) ($snapshot_result['summary']['hashed_files'] ?? 0),
				'new_files_count' => (int) $diff['new_files_count'],
				'modified_files_count' => (int) $diff['modified_files_count'],
				'deleted_files_count' => (int) $diff['deleted_files_count'],
				'last_baseline_at' => $now,
				'last_diff_at' => $now,
			],
			'findings' => $diff['findings'],
		];
	}

	private function build_integrity_snapshot(array $flagged_files): array
	{
		$summary = [
			'hashed_files' => 0,
			'visited_directories' => 0,
			'partial' => false,
			'unreadable_paths' => [],
			'skipped_directories' => [],
			'included_flagged_uploads' => 0,
		];
		$snapshot = [];

		$this->hash_root_files($summary, $snapshot);

		foreach ($this->get_integrity_targets() as $target) {
			if ($summary['hashed_files'] >= $this->max_hashed_files) {
				$summary['partial'] = true;
				break;
			}

			$this->hash_path($target['path'], 0, $summary, $snapshot);
		}

		foreach ($flagged_files as $flagged_file) {
			$path = freesiem_sentinel_safe_string($flagged_file['path'] ?? '');

			if ($path === '' || !str_starts_with($path, 'wp-content/uploads/')) {
				continue;
			}

			if (isset($snapshot[$path])) {
				continue;
			}

			if ($summary['hashed_files'] >= $this->max_hashed_files) {
				$summary['partial'] = true;
				break;
			}

			$absolute = wp_normalize_path(untrailingslashit(ABSPATH) . '/' . ltrim($path, '/'));

			if (!is_file($absolute) || !is_readable($absolute)) {
				continue;
			}

			$entry = $this->snapshot_entry($absolute);

			if ($entry === null) {
				continue;
			}

			$snapshot[$path] = $entry;
			$summary['hashed_files']++;
			$summary['included_flagged_uploads']++;
		}

		ksort($snapshot);

		return [
			'snapshot' => $snapshot,
			'summary' => $summary,
		];
	}

	private function compare_integrity_snapshots(array $baseline, array $current): array
	{
		$findings = [];
		$changes = [];
		$new_files_count = 0;
		$modified_files_count = 0;
		$deleted_files_count = 0;

		foreach ($current as $path => $entry) {
			if (!isset($baseline[$path])) {
				$new_files_count++;
				$this->append_integrity_change('new', null, $entry, $changes, $findings);
				continue;
			}

			$previous = is_array($baseline[$path]) ? $baseline[$path] : [];

			if (($previous['hash'] ?? '') !== ($entry['hash'] ?? '') || (int) ($previous['size'] ?? 0) !== (int) ($entry['size'] ?? 0) || (string) ($previous['modified_time'] ?? '') !== (string) ($entry['modified_time'] ?? '')) {
				$modified_files_count++;
				$this->append_integrity_change('modified', $previous, $entry, $changes, $findings);
			}
		}

		foreach ($baseline as $path => $entry) {
			if (isset($current[$path])) {
				continue;
			}

			$deleted_files_count++;
			$this->append_integrity_change('deleted', is_array($entry) ? $entry : [], null, $changes, $findings);
		}

		return [
			'findings' => $findings,
			'changes' => $changes,
			'new_files_count' => $new_files_count,
			'modified_files_count' => $modified_files_count,
			'deleted_files_count' => $deleted_files_count,
			'partial' => count($changes) >= self::MAX_STORED_DIFFS,
		];
	}

	private function append_integrity_change(string $change_type, ?array $previous, ?array $current, array &$changes, array &$findings): void
	{
		$change = $this->build_integrity_change($change_type, $previous, $current);

		if ($change === null) {
			return;
		}

		if (count($changes) < self::MAX_STORED_DIFFS) {
			$changes[] = $change['evidence'];
			$findings[] = $change['finding'];
		}
	}

	private function build_integrity_change(string $change_type, ?array $previous, ?array $current): ?array
	{
		$previous = is_array($previous) ? $previous : [];
		$current = is_array($current) ? $current : [];
		$path = freesiem_sentinel_safe_string($current['path'] ?? $previous['path'] ?? '');

		if ($path === '') {
			return null;
		}

		$extension = strtolower(freesiem_sentinel_safe_string($current['extension'] ?? $previous['extension'] ?? ''));
		$is_php = in_array($extension, ['php', 'phtml', 'phar', 'php5', 'php7', 'php8'], true);
		$is_code_asset = in_array($extension, ['css', 'js'], true);
		$is_archive = in_array($extension, ['zip', 'tar', 'gz', 'tgz', 'sql', 'bak', 'old'], true);
		$is_uploads = str_starts_with($path, 'wp-content/uploads/');
		$is_core_or_code_path = $path === 'wp-config.php' || str_starts_with($path, 'wp-admin/') || str_starts_with($path, 'wp-includes/') || str_starts_with($path, 'wp-content/plugins/') || str_starts_with($path, 'wp-content/themes/') || str_starts_with($path, 'wp-content/mu-plugins/');

		$severity = 'low';
		$score = 93;

		if ($change_type === 'new' && $is_uploads && $is_php) {
			$severity = 'critical';
			$score = 35;
		} elseif ($change_type === 'new' && $is_archive && !str_contains(trim($path, '/'), '/')) {
			$severity = 'high';
			$score = 52;
		} elseif ($change_type === 'modified' && $is_php && $is_core_or_code_path) {
			$severity = 'high';
			$score = 55;
		} elseif ($change_type === 'deleted' && $is_php && $is_core_or_code_path) {
			$severity = 'high';
			$score = 58;
		} elseif ($change_type === 'modified' && $is_code_asset) {
			$severity = 'medium';
			$score = 75;
		} elseif ($change_type === 'new' && $is_php) {
			$severity = 'high';
			$score = 57;
		}

		$title = match ($change_type) {
			'new' => 'New monitored file detected',
			'deleted' => 'Previously monitored file disappeared',
			default => 'Monitored file changed',
		};

		$description = match ($change_type) {
			'new' => 'freeSIEM Sentinel detected a new file within the integrity monitoring scope.',
			'deleted' => 'freeSIEM Sentinel detected that a previously monitored file is no longer present.',
			default => 'freeSIEM Sentinel detected a change in a monitored file hash or metadata.',
		};

		$evidence = [
			'change_type' => $change_type,
			'path' => $path,
			'extension' => $extension,
			'previous_hash' => freesiem_sentinel_safe_string($previous['hash'] ?? ''),
			'current_hash' => freesiem_sentinel_safe_string($current['hash'] ?? ''),
			'previous_size' => (int) ($previous['size'] ?? 0),
			'current_size' => (int) ($current['size'] ?? 0),
			'previous_modified_time' => freesiem_sentinel_safe_string($previous['modified_time'] ?? ''),
			'current_modified_time' => freesiem_sentinel_safe_string($current['modified_time'] ?? ''),
		];

		return [
			'evidence' => $evidence,
			'finding' => $this->finding(
				'file_integrity_' . $change_type . '_' . md5($path),
				'file_integrity',
				$severity,
				$title,
				$description,
				'Review the change, confirm it was expected, and compare deployment or maintenance activity against the detected file event.',
				$evidence,
				$score
			),
		];
	}

	private function hash_root_files(array &$summary, array &$snapshot): void
	{
		$root = untrailingslashit(wp_normalize_path(ABSPATH));

		if (!is_dir($root) || !is_readable($root)) {
			return;
		}

		$items = scandir($root);

		if (!is_array($items)) {
			$summary['unreadable_paths'][] = '';
			return;
		}

		foreach ($items as $item) {
			if ($item === '.' || $item === '..') {
				continue;
			}

			$current = $root . '/' . $item;

			if (!is_file($current)) {
				continue;
			}

			if ($summary['hashed_files'] >= $this->max_hashed_files) {
				$summary['partial'] = true;
				return;
			}

			$entry = $this->snapshot_entry($current);

			if ($entry === null) {
				continue;
			}

			$snapshot[$entry['path']] = $entry;
			$summary['hashed_files']++;
		}
	}

	private function hash_path(string $path, int $depth, array &$summary, array &$snapshot): void
	{
		if ($summary['hashed_files'] >= $this->max_hashed_files) {
			$summary['partial'] = true;
			return;
		}

		if (!file_exists($path)) {
			return;
		}

		if (is_file($path)) {
			$entry = $this->snapshot_entry($path);

			if ($entry !== null) {
				$snapshot[$entry['path']] = $entry;
				$summary['hashed_files']++;
			}

			return;
		}

		if (!is_readable($path)) {
			$summary['unreadable_paths'][] = $this->relative_path($path);
			return;
		}

		$items = scandir($path);

		if (!is_array($items)) {
			$summary['unreadable_paths'][] = $this->relative_path($path);
			return;
		}

		$summary['visited_directories']++;

		foreach ($items as $item) {
			if ($item === '.' || $item === '..') {
				continue;
			}

			$current = $path . DIRECTORY_SEPARATOR . $item;

			if (is_dir($current)) {
				if ($depth >= $this->max_depth) {
					$summary['partial'] = true;
					continue;
				}

				if ($this->should_skip_directory($item, $current)) {
					$summary['skipped_directories'][] = $this->relative_path($current);
					continue;
				}

				$this->hash_path($current, $depth + 1, $summary, $snapshot);
				continue;
			}

			if ($summary['hashed_files'] >= $this->max_hashed_files) {
				$summary['partial'] = true;
				return;
			}

			$entry = $this->snapshot_entry($current);

			if ($entry === null) {
				continue;
			}

			$snapshot[$entry['path']] = $entry;
			$summary['hashed_files']++;
		}
	}

	private function snapshot_entry(string $path): ?array
	{
		if (!is_file($path) || !is_readable($path)) {
			return null;
		}

		$hash = @hash_file('sha256', $path);

		if (!is_string($hash) || $hash === '') {
			return null;
		}

		$modified = @filemtime($path);

		return [
			'path' => $this->relative_path($path),
			'hash' => $hash,
			'size' => (int) @filesize($path),
			'modified_time' => $modified ? gmdate('c', $modified) : '',
			'extension' => strtolower((string) pathinfo($path, PATHINFO_EXTENSION)),
		];
	}

	private function scan_path(string $path, string $target_label, int $depth, array &$summary, array &$findings, array &$flagged_files): void
	{
		if ($summary['inspected_files'] >= $this->max_files) {
			$summary['partial'] = true;
			return;
		}

		if (!file_exists($path)) {
			return;
		}

		if (is_file($path)) {
			if ($summary['inspected_files'] >= $this->max_files) {
				$summary['partial'] = true;
				return;
			}

			$summary['inspected_files']++;
			$this->flag_file($path, $target_label, $findings, $flagged_files);
			return;
		}

		if (!is_readable($path)) {
			$summary['unreadable_paths'][] = $this->relative_path($path);
			return;
		}

		$items = scandir($path);

		if (!is_array($items)) {
			$summary['unreadable_paths'][] = $this->relative_path($path);
			return;
		}

		$summary['visited_directories']++;

		foreach ($items as $item) {
			if ($item === '.' || $item === '..') {
				continue;
			}

			$current = $path . DIRECTORY_SEPARATOR . $item;

			if (is_dir($current)) {
				if ($depth >= $this->max_depth) {
					$summary['partial'] = true;
					continue;
				}

				if ($this->should_skip_directory($item, $current)) {
					$summary['skipped_directories'][] = $this->relative_path($current);
					continue;
				}

				$this->scan_path($current, $target_label, $depth + 1, $summary, $findings, $flagged_files);
				continue;
			}

			if ($summary['inspected_files'] >= $this->max_files) {
				$summary['partial'] = true;
				return;
			}

			$summary['inspected_files']++;
			$this->flag_file($current, $target_label, $findings, $flagged_files);
		}
	}

	private function flag_file(string $path, string $target_label, array &$findings, array &$flagged_files): void
	{
		$relative = $this->relative_path($path);
		$basename = strtolower((string) basename($path));
		$extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
		$size = is_file($path) ? (int) @filesize($path) : 0;
		$modified = is_file($path) ? (int) @filemtime($path) : 0;
		$is_writable = is_writable($path);
		$reasons = [];
		$severity = 'low';
		$score = 95;
		$uploads_relative = $this->relative_path(WP_CONTENT_DIR . '/uploads');
		$in_uploads = $uploads_relative !== '' && str_starts_with($relative, $uploads_relative);
		$in_public_root = !str_contains(trim($relative, '/'), '/');

		if ($in_uploads && in_array($extension, ['php', 'phtml', 'phar', 'php5', 'php7', 'php8'], true)) {
			$reasons[] = 'Executable PHP-like file in uploads directory';
			$severity = 'critical';
			$score = 45;
		}

		if (in_array($basename, ['shell.php', 'cmd.php', 'eval.php', 'up.php', 'wshell.php', 'mini.php', 'phpinfo.php'], true)) {
			$reasons[] = 'Matches a common web shell or reconnaissance filename';
			$severity = 'critical';
			$score = min($score, 42);
		}

		if ($basename === 'install.php' && !str_starts_with($relative, 'wp-admin/')) {
			$reasons[] = 'Standalone install.php found outside the standard admin area';
			$severity = 'high';
			$score = min($score, 58);
		}

		if (in_array($extension, ['zip', 'tar', 'gz', 'tgz', 'sql', 'bak', 'old'], true) && ($in_public_root || $in_uploads || str_starts_with($relative, 'wp-content/'))) {
			$reasons[] = 'Publicly reachable backup or archive file';
			$severity = $severity === 'critical' ? 'critical' : 'high';
			$score = min($score, 60);
		}

		if (in_array($basename, ['.env', 'debug.log', 'error_log'], true)) {
			$reasons[] = 'Sensitive environment or log file present in a readable location';
			$severity = $severity === 'critical' ? 'critical' : 'medium';
			$score = min($score, 70);
		}

		if ($in_uploads && $extension === 'php' && $size > 512000) {
			if ($this->filesystem_advanced_enabled) {
				$reasons[] = 'Large PHP file in uploads directory';
				$severity = 'high';
				$score = min($score, 57);
			}
		}

		if ($in_uploads && preg_match('/\.(jpg|jpeg|png|gif|svg|ico)\.(php|phtml)$/i', $basename)) {
			if ($this->filesystem_advanced_enabled) {
				$reasons[] = 'Suspicious extension mismatch in uploads';
				$severity = 'critical';
				$score = min($score, 40);
			}
		}

		if ($extension === 'php' && (strlen($basename) > 35 || preg_match('/^[a-f0-9]{16,}\.php$/i', $basename))) {
			if ($this->filesystem_advanced_enabled) {
				$reasons[] = 'Oddly named or random-looking PHP filename';
				$severity = $severity === 'critical' ? 'critical' : 'high';
				$score = min($score, 62);
			}
		}

		if ($is_writable && in_array($basename, ['wp-config.php', '.env', 'debug.log', 'error_log'], true)) {
			if ($this->filesystem_advanced_enabled) {
				$reasons[] = 'Sensitive file is writable by the current process';
				$severity = $severity === 'critical' ? 'critical' : 'medium';
				$score = min($score, 73);
			}
		}

		if ($reasons === []) {
			return;
		}

		$flagged_file = [
			'path' => $relative,
			'target' => $target_label,
			'extension' => $extension,
			'size' => $size,
			'modified_time' => $modified ? gmdate('c', $modified) : '',
			'writable' => $is_writable,
			'reasons' => $reasons,
		];

		$flagged_files[$relative] = $flagged_file;
		$findings[] = $this->finding(
			'filesystem_' . md5($relative . implode('|', $reasons)),
			'filesystem',
			$severity,
			'Suspicious filesystem artifact detected',
			'freeSIEM Sentinel found a file that matches one or more filesystem risk heuristics.',
			'Review the file, confirm whether it is expected, and remove or restrict access if it is not required.',
			$flagged_file,
			$score
		);
	}

	private function get_scan_targets(): array
	{
		$targets = [
			['label' => 'WordPress Root', 'path' => untrailingslashit(ABSPATH)],
			['label' => 'wp-admin', 'path' => untrailingslashit(ABSPATH) . '/wp-admin'],
			['label' => 'wp-includes', 'path' => untrailingslashit(ABSPATH) . '/wp-includes'],
			['label' => 'wp-content', 'path' => WP_CONTENT_DIR],
			['label' => 'plugins', 'path' => WP_PLUGIN_DIR],
			['label' => 'themes', 'path' => get_theme_root()],
		];

		if ($this->include_uploads) {
			$targets[] = ['label' => 'uploads', 'path' => WP_CONTENT_DIR . '/uploads'];
		}

		if (defined('WPMU_PLUGIN_DIR')) {
			$targets[] = ['label' => 'mu-plugins', 'path' => WPMU_PLUGIN_DIR];
		}

		return $this->unique_targets($targets);
	}

	private function get_integrity_targets(): array
	{
		$targets = [
			['label' => 'wp-admin', 'path' => untrailingslashit(ABSPATH) . '/wp-admin'],
			['label' => 'wp-includes', 'path' => untrailingslashit(ABSPATH) . '/wp-includes'],
			['label' => 'plugins', 'path' => WP_PLUGIN_DIR],
			['label' => 'themes', 'path' => get_theme_root()],
		];

		if (defined('WPMU_PLUGIN_DIR')) {
			$targets[] = ['label' => 'mu-plugins', 'path' => WPMU_PLUGIN_DIR];
		}

		return $this->unique_targets($targets);
	}

	private function unique_targets(array $targets): array
	{
		$unique = [];

		foreach ($targets as $target) {
			$path = wp_normalize_path((string) $target['path']);

			if ($path === '' || isset($unique[$path])) {
				continue;
			}

			$unique[$path] = [
				'label' => freesiem_sentinel_safe_string($target['label'] ?? ''),
				'path' => $path,
			];
		}

		return array_values($unique);
	}

	private function should_skip_directory(string $basename, string $path): bool
	{
		$basename = strtolower($basename);
		$skip = [
			'.git',
			'.svn',
			'node_modules',
			'vendor',
			'cache',
			'caches',
			'upgrade',
			'backups',
			'backup',
			'logs',
			'tmp',
			'temp',
		];

		if (in_array($basename, $skip, true)) {
			return true;
		}

		$normalized = $this->relative_path($path);

		return str_contains($normalized, 'synchy-backups') || str_contains($normalized, 'cache');
	}

	private function relative_path(string $path): string
	{
		$path = wp_normalize_path($path);
		$root = untrailingslashit(wp_normalize_path(ABSPATH));

		if (str_starts_with($path, $root . '/')) {
			return ltrim(substr($path, strlen($root)), '/');
		}

		if ($path === $root) {
			return '';
		}

		return ltrim($path, '/');
	}

	private function finding(string $key, string $category, string $severity, string $title, string $description, string $recommendation, array $evidence, int $score): array
	{
		return [
			'finding_key' => $key,
			'category' => $category,
			'severity' => freesiem_sentinel_normalize_severity($severity),
			'title' => $title,
			'description' => $description,
			'recommendation' => $recommendation,
			'evidence' => $evidence,
			'score' => $score,
			'detected_at' => freesiem_sentinel_get_iso8601_time(),
		];
	}
}
