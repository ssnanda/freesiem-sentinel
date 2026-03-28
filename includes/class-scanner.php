<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Scanner
{
	public function run(): array
	{
		if (!function_exists('get_plugin_updates')) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		wp_version_check();
		wp_update_plugins();
		wp_update_themes();

		$metadata = $this->build_metadata();
		$inventory = $this->build_inventory();
		$findings = $this->collect_findings($metadata, $inventory);

		return [
			'metadata' => $metadata,
			'inventory' => $inventory,
			'findings' => $findings,
			'scan_timestamps' => [
				'local' => freesiem_sentinel_get_iso8601_time(),
			],
			'score' => freesiem_sentinel_score_from_findings($findings),
		];
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
		];
	}

	private function collect_findings(array $metadata, array $inventory): array
	{
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
