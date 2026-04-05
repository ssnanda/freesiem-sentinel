<?php
/**
 * Plugin Name: Synchy
 * Plugin URI: https://github.com/ssnanda/synchy
 * Description: Starter admin shell for Synchy backup, restore, schedule, and sync tooling.
 * Version: 0.7.57
 * Update URI: https://github.com/ssnanda/synchy
 * Author: sandman
 */

if (!defined('ABSPATH')) {
	exit;
}

const SYNCHY_VERSION = '0.7.57';
const SYNCHY_SLUG = 'synchy';
const SYNCHY_EXPORT_OPTIONS = 'synchy_export_options';
const SYNCHY_LAST_EXPORT_OPTION = 'synchy_last_export';
const SYNCHY_EXPORT_HISTORY_OPTION = 'synchy_export_history';
const SYNCHY_EXPORT_JOB_OPTION = 'synchy_export_job';
const SYNCHY_SITE_SYNC_OPTIONS = 'synchy_site_sync_options';
const SYNCHY_SITE_SYNC_JOB_OPTION = 'synchy_site_sync_job';
const SYNCHY_SYNC_LAST_TIME_OPTION = 'syncy_last_sync_time';
const SYNCHY_SYNC_STATUS_OPTION = 'synchy_sync_status';
const SYNCHY_SYNC_JOB_OPTION = 'synchy_sync_job';
const SYNCHY_SYNC_CONNECTION_STATE_OPTION = 'synchy_sync_connection_state';
const SYNCHY_IMPORT_OPTIONS = 'synchy_import_options';
const SYNCHY_IMPORT_RESULT_OPTION = 'synchy_import_result';
const SYNCHY_NOTICE_PREFIX = 'synchy_admin_notice_';

if (!defined('SYNCHY_GITHUB_REPOSITORY')) {
	define('SYNCHY_GITHUB_REPOSITORY', 'https://github.com/ssnanda/synchy');
}

if (!defined('SYNCHY_GITHUB_BRANCH')) {
	define('SYNCHY_GITHUB_BRANCH', 'main');
}

if (!defined('SYNCHY_GITHUB_RELEASE_ASSET')) {
	define('SYNCHY_GITHUB_RELEASE_ASSET', 'synchy.zip');
}

function synchy_get_plugin_basename(): string
{
	return plugin_basename(__FILE__);
}

function synchy_get_plugin_slug(): string
{
	return dirname(synchy_get_plugin_basename());
}

function synchy_parse_github_repository(string $value): string
{
	$value = trim(preg_replace('#\.git$#i', '', $value) ?? '');

	if ($value === '') {
		return '';
	}

	if (preg_match('#^https?://github\.com/([^/]+)/([^/]+?)(?:/.*)?$#i', $value, $matches)) {
		return strtolower($matches[1] . '/' . $matches[2]);
	}

	if (preg_match('#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $value)) {
		return strtolower($value);
	}

	return '';
}

function synchy_get_github_update_config(): array
{
	$repository = synchy_parse_github_repository((string) apply_filters('synchy_github_repository', SYNCHY_GITHUB_REPOSITORY));
	$branch = sanitize_text_field((string) apply_filters('synchy_github_branch', SYNCHY_GITHUB_BRANCH));
	$asset_name = sanitize_file_name((string) apply_filters('synchy_github_release_asset', SYNCHY_GITHUB_RELEASE_ASSET));

	if ($branch === '') {
		$branch = 'main';
	}

	return [
		'enabled' => $repository !== '',
		'repository' => $repository,
		'branch' => $branch,
		'asset_name' => $asset_name,
		'html_url' => $repository !== '' ? 'https://github.com/' . $repository : '',
		'api_url' => $repository !== '' ? 'https://api.github.com/repos/' . $repository . '/releases/latest' : '',
	];
}

function synchy_get_github_release_cache_key(array $config): string
{
	return 'synchy_github_release_' . md5($config['repository'] . '|' . $config['asset_name']);
}

function synchy_find_github_release_asset_url(array $release, string $asset_name): string
{
	$assets = isset($release['assets']) && is_array($release['assets']) ? $release['assets'] : [];

	if ($asset_name !== '') {
		foreach ($assets as $asset) {
			if (!is_array($asset)) {
				continue;
			}

			if ((string) ($asset['name'] ?? '') === $asset_name && !empty($asset['browser_download_url'])) {
				return (string) $asset['browser_download_url'];
			}
		}
	}

	foreach ($assets as $asset) {
		if (!is_array($asset)) {
			continue;
		}

		$name = (string) ($asset['name'] ?? '');

		if (strtolower((string) pathinfo($name, PATHINFO_EXTENSION)) === 'zip' && !empty($asset['browser_download_url'])) {
			return (string) $asset['browser_download_url'];
		}
	}

	return '';
}

function synchy_get_github_release_data(bool $force = false)
{
	$config = synchy_get_github_update_config();

	if (empty($config['enabled'])) {
		return new WP_Error('synchy_github_updates_disabled', __('GitHub updates are not configured for Synchy.', 'synchy'));
	}

	$cache_key = synchy_get_github_release_cache_key($config);

	if (!$force) {
		$cached = get_site_transient($cache_key);

		if (is_array($cached) && !empty($cached['version']) && !empty($cached['package_url'])) {
			return $cached;
		}
	}

	$response = wp_remote_get(
		$config['api_url'],
		[
			'timeout' => 20,
			'headers' => [
				'Accept' => 'application/vnd.github+json',
				'User-Agent' => 'Synchy/' . SYNCHY_VERSION . '; ' . wp_parse_url(home_url('/'), PHP_URL_HOST),
			],
		]
	);

	if (is_wp_error($response)) {
		return $response;
	}

	$code = (int) wp_remote_retrieve_response_code($response);
	$body = (string) wp_remote_retrieve_body($response);
	$release = json_decode($body, true);

	if ($code < 200 || $code >= 300 || !is_array($release)) {
		return new WP_Error('synchy_github_release_request_failed', __('Synchy could not read the latest GitHub release metadata.', 'synchy'));
	}

	$version = ltrim((string) ($release['tag_name'] ?? ''), 'vV');
	$package_url = synchy_find_github_release_asset_url($release, (string) $config['asset_name']);

	if ($version === '' || $package_url === '') {
		return new WP_Error('synchy_github_release_invalid', __('Synchy could not find a valid version tag and zip asset in the latest GitHub release.', 'synchy'));
	}

	$data = [
		'version' => $version,
		'package_url' => $package_url,
		'html_url' => (string) ($release['html_url'] ?? $config['html_url']),
		'name' => (string) ($release['name'] ?? 'Synchy'),
		'body' => (string) ($release['body'] ?? ''),
		'published_at' => (string) ($release['published_at'] ?? ''),
		'repository_url' => (string) $config['html_url'],
	];

	set_site_transient($cache_key, $data, 6 * HOUR_IN_SECONDS);

	return $data;
}

function synchy_get_github_release_sections(array $release): array
{
	$repository_url = !empty($release['repository_url']) ? esc_url($release['repository_url']) : '';
	$description = $repository_url === ''
		? '<p>' . esc_html__('Synchy updates are served from a public GitHub release feed.', 'synchy') . '</p>'
		: '<p>' . sprintf(
			/* translators: %s: GitHub repository URL */
			esc_html__('Synchy updates are served from %s.', 'synchy'),
			'<a href="' . $repository_url . '" target="_blank" rel="noopener noreferrer">' . esc_html($repository_url) . '</a>'
		) . '</p>';
	$changelog_body = trim((string) ($release['body'] ?? ''));
	$changelog = $changelog_body === ''
		? '<p>' . esc_html__('No changelog was provided in the latest GitHub release.', 'synchy') . '</p>'
		: wpautop(esc_html($changelog_body));

	return [
		'description' => $description,
		'changelog' => $changelog,
	];
}

function synchy_build_github_update_payload(array $release): object
{
	$plugin_file = synchy_get_plugin_basename();
	$slug = synchy_get_plugin_slug();

	return (object) [
		'id' => $release['html_url'] ?? '',
		'slug' => $slug,
		'plugin' => $plugin_file,
		'new_version' => (string) ($release['version'] ?? SYNCHY_VERSION),
		'url' => (string) ($release['html_url'] ?? ''),
		'package' => (string) ($release['package_url'] ?? ''),
		'icons' => [],
		'banners' => [],
		'banners_rtl' => [],
		'tested' => '',
		'requires' => '',
		'requires_php' => '',
	];
}

function synchy_clear_github_update_cache(): void
{
	$config = synchy_get_github_update_config();

	if (!empty($config['enabled'])) {
		delete_site_transient(synchy_get_github_release_cache_key($config));
	}

	delete_site_transient('update_plugins');

	if (function_exists('wp_clean_plugins_cache')) {
		wp_clean_plugins_cache(true);
	}
}

function synchy_refresh_plugin_update_state()
{
	$config = synchy_get_github_update_config();

	if (empty($config['enabled'])) {
		return new WP_Error('synchy_github_updates_disabled', __('GitHub updates are not configured for Synchy.', 'synchy'));
	}

	synchy_clear_github_update_cache();
	$release = synchy_get_github_release_data(true);

	if (is_wp_error($release)) {
		return $release;
	}

	if (function_exists('wp_update_plugins')) {
		wp_update_plugins();
	}

	return [
		'release' => $release,
		'update_available' => version_compare((string) ($release['version'] ?? SYNCHY_VERSION), SYNCHY_VERSION, '>'),
	];
}

function synchy_get_plugin_upgrade_url(): string
{
	return wp_nonce_url(
		self_admin_url('update.php?action=upgrade-plugin&plugin=' . rawurlencode(synchy_get_plugin_basename())),
		'upgrade-plugin_' . synchy_get_plugin_basename()
	);
}

function synchy_get_check_updates_url(string $redirect_to = ''): string
{
	$url = add_query_arg(
		[
			'action' => 'synchy_check_updates',
		],
		admin_url('admin-post.php')
	);

	if ($redirect_to !== '') {
		$url = add_query_arg('redirect_to', $redirect_to, $url);
	}

	return wp_nonce_url(
		$url,
		'synchy_check_updates'
	);
}

add_filter('pre_set_site_transient_update_plugins', function ($transient) {
	if (!is_object($transient)) {
		$transient = new stdClass();
	}

	$config = synchy_get_github_update_config();

	if (empty($config['enabled'])) {
		return $transient;
	}

	$release = synchy_get_github_release_data();

	if (is_wp_error($release)) {
		return $transient;
	}

	$plugin_file = synchy_get_plugin_basename();
	$payload = synchy_build_github_update_payload($release);

	if (version_compare((string) $release['version'], SYNCHY_VERSION, '>')) {
		if (!isset($transient->response) || !is_array($transient->response)) {
			$transient->response = [];
		}

		$transient->response[$plugin_file] = $payload;
		return $transient;
	}

	if (!isset($transient->no_update) || !is_array($transient->no_update)) {
		$transient->no_update = [];
	}

	$transient->no_update[$plugin_file] = $payload;

	return $transient;
});

add_filter('plugins_api', function ($result, string $action, $args) {
	if ($action !== 'plugin_information' || !is_object($args) || (($args->slug ?? '') !== synchy_get_plugin_slug())) {
		return $result;
	}

	$config = synchy_get_github_update_config();

	if (empty($config['enabled'])) {
		return $result;
	}

	$release = synchy_get_github_release_data();

	if (is_wp_error($release)) {
		return $result;
	}

	$sections = synchy_get_github_release_sections($release);

	return (object) [
		'name' => 'Synchy',
		'slug' => synchy_get_plugin_slug(),
		'version' => (string) ($release['version'] ?? SYNCHY_VERSION),
		'author' => '<a href="https://github.com/' . esc_attr(str_replace('https://github.com/', '', (string) ($release['repository_url'] ?? ''))) . '">Synchy</a>',
		'author_profile' => (string) ($release['repository_url'] ?? ''),
		'homepage' => (string) ($release['html_url'] ?? $release['repository_url'] ?? ''),
		'download_link' => (string) ($release['package_url'] ?? ''),
		'last_updated' => (string) ($release['published_at'] ?? ''),
		'sections' => $sections,
		'banners' => [],
	];
}, 20, 3);

add_action('upgrader_process_complete', function ($upgrader, array $hook_extra): void {
	if (($hook_extra['type'] ?? '') !== 'plugin' || empty($hook_extra['plugins']) || !is_array($hook_extra['plugins'])) {
		return;
	}

	if (!in_array(synchy_get_plugin_basename(), $hook_extra['plugins'], true)) {
		return;
	}

	$config = synchy_get_github_update_config();

	if (empty($config['enabled'])) {
		return;
	}

	delete_site_transient(synchy_get_github_release_cache_key($config));
	delete_site_transient('update_plugins');
}, 10, 2);

add_filter('plugin_action_links_' . plugin_basename(__FILE__), function (array $actions): array {
	$links = [
		'check_updates' => '<a href="' . esc_url(synchy_get_check_updates_url(self_admin_url('plugins.php'))) . '">' . esc_html__('Check for Updates', 'synchy') . '</a>',
		'about' => '<a href="' . esc_url(admin_url('admin.php?page=synchy-settings')) . '">' . esc_html__('About', 'synchy') . '</a>',
	];

	return array_merge($links, $actions);
});

add_action('admin_post_synchy_check_updates', function (): void {
	if (!current_user_can('manage_options')) {
		wp_die(esc_html__('You are not allowed to check Synchy updates.', 'synchy'));
	}

	check_admin_referer('synchy_check_updates');

	$redirect_to = isset($_GET['redirect_to']) ? wp_unslash((string) $_GET['redirect_to']) : '';
	$redirect_to = wp_validate_redirect($redirect_to, admin_url('admin.php?page=synchy-settings'));

	$result = synchy_refresh_plugin_update_state();

	if (is_wp_error($result)) {
		synchy_set_notice('error', $result->get_error_message());
		wp_safe_redirect($redirect_to);
		exit;
	}

	$release = is_array($result['release'] ?? null) ? $result['release'] : [];
	$latest_version = (string) ($release['version'] ?? '');

	if (!empty($result['update_available']) && $latest_version !== '') {
		synchy_set_notice(
			'success',
			sprintf(
				/* translators: %s: latest release version */
				__('Synchy found a newer GitHub release: v%s. You can update from Plugins or the About page.', 'synchy'),
				$latest_version
			)
		);
	} elseif ($latest_version !== '') {
		synchy_set_notice(
			'success',
			sprintf(
				/* translators: %s: current plugin version */
				__('Synchy is already on the latest GitHub release (v%s).', 'synchy'),
				SYNCHY_VERSION
			)
		);
	} else {
		synchy_set_notice('success', __('Synchy checked GitHub successfully, but the latest release version could not be determined.', 'synchy'));
	}

	wp_safe_redirect($redirect_to);
	exit;
});

function synchy_get_pages(): array
{
	return [
		[
			'slug' => SYNCHY_SLUG,
			'title' => __('Overview', 'synchy'),
			'menu_title' => __('Overview', 'synchy'),
			'headline' => __('Synchy', 'synchy'),
			'description' => __('WordPress backup and site sync tools, starting with a clean admin foundation.', 'synchy'),
		],
		[
			'slug' => 'synchy-export',
			'title' => __('Export', 'synchy'),
			'menu_title' => __('Export', 'synchy'),
			'headline' => __('Export', 'synchy'),
			'description' => __('Create on-demand site packages with an archive and installer workflow.', 'synchy'),
		],
		[
			'slug' => 'synchy-import',
			'title' => __('Import', 'synchy'),
			'menu_title' => __('Import', 'synchy'),
			'headline' => __('Import', 'synchy'),
			'description' => __('Restore a site from a Synchy package and safely replace the current install.', 'synchy'),
		],
		[
			'slug' => 'synchy-scheduled-backups',
			'title' => __('Schedule', 'synchy'),
			'menu_title' => __('Schedule', 'synchy'),
			'headline' => __('Schedule', 'synchy'),
			'description' => __('Automate recurring backups with retention and destination controls.', 'synchy'),
		],
		[
			'slug' => 'synchy-push-live-site',
			'title' => __('Upload to Live', 'synchy'),
			'menu_title' => __('Upload to Live', 'synchy'),
			'headline' => __('Upload to Live', 'synchy'),
			'description' => __('Upload a full Synchy backup package to another WordPress site and launch the manual restore there.', 'synchy'),
		],
			[
				'slug' => 'synchy-site-sync',
				'title' => __('Sync', 'synchy'),
				'menu_title' => __('Sync', 'synchy'),
				'headline' => __('Sync', 'synchy'),
				'description' => __('Sync only changed files and selected database deltas after the first baseline.', 'synchy'),
			],
		[
			'slug' => 'synchy-settings',
			'title' => __('About', 'synchy'),
			'menu_title' => __('About', 'synchy'),
			'headline' => __('About', 'synchy'),
			'description' => __('See Synchy configuration details, release/update wiring, and what each workflow area is responsible for.', 'synchy'),
		],
	];
}

function synchy_get_default_output_directory(): string
{
	return 'wp-content/uploads/synchy-backups/';
}

function synchy_get_default_package_name(): string
{
	$host = (string) wp_parse_url(home_url('/'), PHP_URL_HOST);

	if ($host === '') {
		$host = 'site';
	}

	$host = strtolower(preg_replace('/[^a-z0-9]+/i', '-', $host) ?: 'site');
	$host = trim($host, '-');

	if ($host === '') {
		$host = 'site';
	}

	return 'synchy-' . $host . '-' . gmdate('Ymd-His');
}

function synchy_get_export_defaults(): array
{
	return [
		'package_mode' => 'full_export',
		'output_directory' => synchy_get_default_output_directory(),
		'package_name' => '',
		'exclude_vcs' => 1,
		'exclude_local_dev' => 1,
		'exclude_os_junk' => 1,
		'exclude_cache_temp' => 1,
		'exclude_existing_backups' => 1,
		'exclude_dev_artifacts' => 1,
		'custom_excludes' => '',
	];
}

function synchy_normalize_relative_path(string $path): string
{
	$path = wp_normalize_path($path);
	$path = trim($path);
	$path = preg_replace('#/+#', '/', $path);

	return trim((string) $path, '/');
}

function synchy_sanitize_package_name(string $value): string
{
	$value = sanitize_text_field($value);
	$value = preg_replace('/\.(zip|php|json)$/i', '', $value);
	$value = preg_replace('/[^A-Za-z0-9._ -]+/', '-', $value);
	$value = trim((string) $value);
	$value = preg_replace('/\s+/', '-', $value);
	$value = preg_replace('/-+/', '-', (string) $value);
	$value = trim((string) $value, '-_.');

	if ($value === '') {
		$value = synchy_get_default_package_name();
	}

	return strtolower($value);
}

function synchy_sanitize_output_directory(string $value): string
{
	$value = sanitize_text_field($value);
	$value = str_replace('\\', '/', $value);
	$value = trim($value);

	if ($value === '') {
		$value = synchy_get_default_output_directory();
	}

	$is_absolute = (bool) preg_match('#^([A-Za-z]:)?/#', $value);
	$value = preg_replace('#/+#', '/', $value);

	if ($is_absolute) {
		return untrailingslashit($value) . '/';
	}

	$value = ltrim($value, '/');

	return trailingslashit(synchy_normalize_relative_path($value));
}

function synchy_sanitize_export_options($value): array
{
	$value = is_array($value) ? $value : [];
	$defaults = synchy_get_export_defaults();
	$sanitized = [];

	foreach ($defaults as $key => $default) {
		if ($key === 'package_mode') {
			$sanitized[$key] = 'full_export';
			continue;
		}

		if ($key === 'output_directory') {
			$raw = isset($value[$key]) ? (string) $value[$key] : '';
			$sanitized[$key] = synchy_sanitize_output_directory($raw);
			continue;
		}

		if ($key === 'package_name') {
			$raw = isset($value[$key]) ? (string) $value[$key] : '';
			$raw = sanitize_text_field($raw);
			$sanitized[$key] = trim($raw);
			continue;
		}

		if ($key === 'custom_excludes') {
			$raw = isset($value[$key]) ? (string) $value[$key] : '';
			$lines = preg_split('/\r\n|\r|\n/', $raw) ?: [];
			$lines = array_map('trim', $lines);
			$lines = array_filter($lines, static fn(string $line): bool => $line !== '');
			$sanitized[$key] = implode("\n", $lines);
			continue;
		}

		$sanitized[$key] = empty($value[$key]) ? 0 : 1;
	}

	return $sanitized;
}

function synchy_get_export_options(): array
{
	$saved = get_option(SYNCHY_EXPORT_OPTIONS, []);

	if (!is_array($saved)) {
		$saved = [];
	}

	$options = wp_parse_args($saved, synchy_get_export_defaults());
	$options = synchy_sanitize_export_options($options);

	if ($options['package_name'] === '') {
		$options['package_name'] = synchy_get_default_package_name();
	}

	return $options;
}

function synchy_get_site_sync_defaults(): array
{
	$defaults = [
		'destination_url' => '',
		'destination_username' => '',
		'destination_application_password' => '',
		'verify_ssl' => 1,
	];

	foreach (synchy_get_sync_scope_definitions() as $scope) {
		$defaults[(string) $scope['option_key']] = 1;
	}

	return $defaults;
}

function synchy_get_sync_scope_definitions(): array
{
	return [
		'files_plugins' => [
			'option_key' => 'sync_scope_files_plugins',
			'type' => 'file',
			'group' => 'files',
			'label' => __('Plugins', 'synchy'),
			'description' => __('Everything inside wp-content/plugins.', 'synchy'),
		],
		'files_themes' => [
			'option_key' => 'sync_scope_files_themes',
			'type' => 'file',
			'group' => 'files',
			'label' => __('Active Theme', 'synchy'),
			'description' => __('The active theme plus its parent theme when one is active.', 'synchy'),
		],
		'files_uploads' => [
			'option_key' => 'sync_scope_files_uploads',
			'type' => 'file',
			'group' => 'files',
			'label' => __('Uploads', 'synchy'),
			'description' => __('Everything inside wp-content/uploads.', 'synchy'),
		],
		'db_content' => [
			'option_key' => 'sync_scope_db_content',
			'type' => 'db',
			'group' => 'database',
			'label' => __('Posts & Post Meta', 'synchy'),
			'description' => __('Posts, pages, CPTs, and related postmeta rows.', 'synchy'),
		],
		'db_options' => [
			'option_key' => 'sync_scope_db_options',
			'type' => 'db',
			'group' => 'database',
			'label' => __('Options', 'synchy'),
			'description' => __('Selected WordPress options, excluding Synchy and transient data.', 'synchy'),
		],
		'db_taxonomies' => [
			'option_key' => 'sync_scope_db_taxonomies',
			'type' => 'db',
			'group' => 'database',
			'label' => __('Terms & Taxonomies', 'synchy'),
			'description' => __('Terms, taxonomies, and term relationships.', 'synchy'),
		],
		'db_wp_formy' => [
			'option_key' => 'sync_scope_db_wp_formy',
			'type' => 'db',
			'group' => 'database',
			'label' => __('WP Formy', 'synchy'),
			'description' => __('WP Formy forms, entries, and entry notes stored in custom database tables.', 'synchy'),
		],
	];
}

function synchy_get_sync_scope_groups(): array
{
	$definitions = synchy_get_sync_scope_definitions();

	return [
		'files' => [
			'label' => __('Files', 'synchy'),
			'scopes' => array_filter(
				$definitions,
				static fn(array $scope): bool => (string) ($scope['group'] ?? '') === 'files'
			),
		],
		'database' => [
			'label' => __('Database', 'synchy'),
			'scopes' => array_filter(
				$definitions,
				static fn(array $scope): bool => (string) ($scope['group'] ?? '') === 'database'
			),
		],
	];
}

function synchy_get_sync_top_level_entries(string $path, array $excluded = []): array
{
	if ($path === '' || !is_dir($path)) {
		return [];
	}

	$items = scandir($path);

	if (!is_array($items)) {
		return [];
	}

	$excluded_lookup = array_fill_keys($excluded, true);
	$entries = [];

	foreach ($items as $item) {
		if ($item === '.' || $item === '..') {
			continue;
		}

		if (isset($excluded_lookup[$item])) {
			continue;
		}

		$entries[] = (string) $item;
	}

	natcasesort($entries);

	return array_values($entries);
}

function synchy_get_sync_scope_tracked_items(string $scope_id): array
{
	global $wpdb;

	return match ($scope_id) {
		'files_plugins' => array_map(
			static fn(string $entry): string => 'wp-content/plugins/' . $entry,
			synchy_get_sync_top_level_entries(WP_PLUGIN_DIR)
		),
		'files_themes' => array_map(
			static fn(string $slug): string => 'wp-content/themes/' . $slug,
			synchy_get_sync_active_theme_slugs()
		) ?: [__('No active theme directories detected.', 'synchy')],
		'files_uploads' => array_merge(
			['wp-content/uploads/**'],
			array_map(
				static fn(string $entry): string => 'wp-content/uploads/' . $entry,
				synchy_get_sync_top_level_entries(
					wp_get_upload_dir()['basedir'] ?? '',
					['synchy-backups', 'synchy-site-sync', 'synchy-sync', 'synchy-import']
				)
			)
		),
		'db_content' => [
			$wpdb->posts,
			$wpdb->postmeta,
		],
		'db_options' => [
			$wpdb->options . ' (' . __('excluding transients and Synchy state', 'synchy') . ')',
		],
		'db_taxonomies' => [
			$wpdb->terms,
			$wpdb->term_taxonomy,
			$wpdb->term_relationships,
		],
		'db_wp_formy' => array_map(
			static fn(string $table): string => $table,
			synchy_get_wp_formy_sync_tables()
		),
		default => [],
	};
}

function synchy_get_selected_sync_scope_ids(array $options, string $group = ''): array
{
	$selected = [];

	foreach (synchy_get_sync_scope_definitions() as $scope_id => $scope) {
		if ($group !== '' && (string) ($scope['group'] ?? '') !== $group) {
			continue;
		}

		if (!empty($options[(string) $scope['option_key']])) {
			$selected[] = (string) $scope_id;
		}
	}

	return $selected;
}

function synchy_get_sync_scope_labels(array $scope_ids): array
{
	$definitions = synchy_get_sync_scope_definitions();
	$labels = [];

	foreach ($scope_ids as $scope_id) {
		if (!isset($definitions[$scope_id])) {
			continue;
		}

		$labels[] = (string) $definitions[$scope_id]['label'];
	}

	return $labels;
}

function synchy_get_sync_scope_status(array $options, ?array $state = null): array
{
	$state = is_array($state) ? $state : synchy_get_sync_state();
	$scope_sync_times = isset($state['scope_sync_times']) && is_array($state['scope_sync_times']) ? $state['scope_sync_times'] : [];
	$selected_scope_ids = synchy_get_selected_sync_scope_ids($options);
	$pending_baseline_scope_ids = [];

	foreach ($selected_scope_ids as $scope_id) {
		if (max(0, (int) ($scope_sync_times[$scope_id] ?? 0)) <= 0) {
			$pending_baseline_scope_ids[] = $scope_id;
		}
	}

	return [
		'selectedScopeIds' => $selected_scope_ids,
		'selectedScopeLabels' => synchy_get_sync_scope_labels($selected_scope_ids),
		'pendingBaselineScopeIds' => $pending_baseline_scope_ids,
		'pendingBaselineLabels' => synchy_get_sync_scope_labels($pending_baseline_scope_ids),
		'hasPendingBaseline' => $pending_baseline_scope_ids !== [],
		'hasSelection' => $selected_scope_ids !== [],
	];
}

function synchy_sanitize_site_sync_url(string $value): string
{
	$value = trim($value);

	if ($value === '') {
		return '';
	}

	$value = esc_url_raw($value, ['http', 'https']);

	return $value === '' ? '' : untrailingslashit($value);
}

function synchy_normalize_application_password(string $value): string
{
	$value = sanitize_text_field($value);

	return (string) preg_replace('/\s+/', '', $value);
}

function synchy_sanitize_site_sync_options($value): array
{
	$value = is_array($value) ? $value : [];
	$existing = get_option(SYNCHY_SITE_SYNC_OPTIONS, []);

	if (!is_array($existing)) {
		$existing = [];
	}

	$sanitized = synchy_get_site_sync_defaults();
	$sanitized['destination_url'] = synchy_sanitize_site_sync_url((string) ($value['destination_url'] ?? ''));
	$sanitized['destination_username'] = trim(sanitize_text_field((string) ($value['destination_username'] ?? '')));

	$raw_password = isset($value['destination_application_password']) ? (string) $value['destination_application_password'] : '';
	$normalized_password = synchy_normalize_application_password($raw_password);

	if ($normalized_password === '' && !empty($existing['destination_application_password'])) {
		$normalized_password = (string) $existing['destination_application_password'];
	}

	$sanitized['destination_application_password'] = $normalized_password;
	$sanitized['verify_ssl'] = empty($value['verify_ssl']) ? 0 : 1;

	$scope_definitions = synchy_get_sync_scope_definitions();
	$scope_input_present = !empty($value['sync_scope_selection_present']);
	$existing_has_selected_scope = false;

	foreach ($scope_definitions as $scope) {
		$option_key = (string) $scope['option_key'];

		if (array_key_exists($option_key, $value)) {
			$scope_input_present = true;
		}

		if (!empty($existing[$option_key])) {
			$existing_has_selected_scope = true;
		}
	}

	foreach ($scope_definitions as $scope) {
		$option_key = (string) $scope['option_key'];

		if ($scope_input_present) {
			$sanitized[$option_key] = empty($value[$option_key]) ? 0 : 1;
			continue;
		}

		if ($existing_has_selected_scope && array_key_exists($option_key, $existing)) {
			$sanitized[$option_key] = empty($existing[$option_key]) ? 0 : 1;
			continue;
		}

		$sanitized[$option_key] = 1;
	}

	return $sanitized;
}

function synchy_get_site_sync_options(): array
{
	$saved = get_option(SYNCHY_SITE_SYNC_OPTIONS, []);

	if (!is_array($saved)) {
		$saved = [];
	}

	$options = wp_parse_args($saved, synchy_get_site_sync_defaults());
	$options['destination_url'] = synchy_sanitize_site_sync_url((string) ($options['destination_url'] ?? ''));
	$options['destination_username'] = trim(sanitize_text_field((string) ($options['destination_username'] ?? '')));
	$options['destination_application_password'] = synchy_normalize_application_password((string) ($options['destination_application_password'] ?? ''));
	$options['verify_ssl'] = empty($options['verify_ssl']) ? 0 : 1;

	$scope_selected = false;

	foreach (synchy_get_sync_scope_definitions() as $scope) {
		$option_key = (string) $scope['option_key'];
		$options[$option_key] = empty($options[$option_key]) ? 0 : 1;

		if (!empty($options[$option_key])) {
			$scope_selected = true;
		}
	}

	if (!$scope_selected) {
		foreach (synchy_get_sync_scope_definitions() as $scope) {
			$options[(string) $scope['option_key']] = 1;
		}
	}

	return $options;
}

function synchy_get_site_sync_password_hint(array $options): string
{
	$password = (string) ($options['destination_application_password'] ?? '');

	if ($password === '') {
		return __('No application password is saved yet.', 'synchy');
	}

	return sprintf(
		/* translators: %s: final 4 characters of the saved application password */
		__('Application password saved. Ending in %s.', 'synchy'),
		substr($password, -4)
	);
}

function synchy_get_sync_last_time(): int
{
	return max(0, (int) get_option(SYNCHY_SYNC_LAST_TIME_OPTION, 0));
}

function synchy_build_sync_connection_fingerprint(array $options): string
{
	$options = synchy_sanitize_site_sync_options($options);

	return hash(
		'sha256',
		implode(
			'|',
			[
				(string) ($options['destination_url'] ?? ''),
				(string) ($options['destination_username'] ?? ''),
				(string) ($options['destination_application_password'] ?? ''),
				empty($options['verify_ssl']) ? '0' : '1',
			]
		)
	);
}

function synchy_get_sync_connection_state(): array
{
	$value = get_option(SYNCHY_SYNC_CONNECTION_STATE_OPTION, []);

	return is_array($value) ? $value : [];
}

function synchy_set_sync_connection_state(array $state): void
{
	update_option(SYNCHY_SYNC_CONNECTION_STATE_OPTION, $state, false);
}

function synchy_get_current_sync_connection_state(array $options): array
{
	$state = synchy_get_sync_connection_state();

	if ($state === []) {
		return [];
	}

	if ((string) ($state['fingerprint'] ?? '') !== synchy_build_sync_connection_fingerprint($options)) {
		return [];
	}

	return $state;
}

function synchy_store_sync_connection_success(array $options, array $remote_site): array
{
	$state = [
		'status' => 'connected',
		'fingerprint' => synchy_build_sync_connection_fingerprint($options),
		'checked_at' => gmdate('c'),
		'message' => __('Destination site is ready for Sync.', 'synchy'),
		'remoteSite' => $remote_site,
	];

	synchy_set_sync_connection_state($state);

	return $state;
}

function synchy_store_sync_connection_error(array $options, string $message): array
{
	$state = [
		'status' => 'error',
		'fingerprint' => synchy_build_sync_connection_fingerprint($options),
		'checked_at' => gmdate('c'),
		'message' => $message,
		'remoteSite' => [],
	];

	synchy_set_sync_connection_state($state);

	return $state;
}

function synchy_set_sync_last_time(int $timestamp): void
{
	update_option(SYNCHY_SYNC_LAST_TIME_OPTION, max(0, $timestamp), false);
}

function synchy_get_sync_status(): array
{
	$value = get_option(SYNCHY_SYNC_STATUS_OPTION, []);

	return is_array($value) ? $value : [];
}

function synchy_set_sync_status(array $status): void
{
	update_option(SYNCHY_SYNC_STATUS_OPTION, $status, false);
}

function synchy_sync_phase_label(string $phase): string
{
	return match ($phase) {
		'building_package' => __('Building Sync Package', 'synchy'),
		'sending_package' => __('Sending Package', 'synchy'),
		'applying_destination' => __('Applying on Destination', 'synchy'),
		'finalizing' => __('Finalizing Sync', 'synchy'),
		'complete' => __('Complete', 'synchy'),
		'error' => __('Error', 'synchy'),
		default => __('Preparing Sync', 'synchy'),
	};
}

function synchy_get_sync_stage_definitions(): array
{
	return [
		'building_package' => [
			'label' => __('Build Delta Package', 'synchy'),
			'description' => __('Calculate the selected file and database changes and package them for delivery.', 'synchy'),
		],
		'sending_package' => [
			'label' => __('Send Package', 'synchy'),
			'description' => __('Upload the selected delta package to the configured destination site.', 'synchy'),
		],
		'applying_destination' => [
			'label' => __('Apply on Destination', 'synchy'),
			'description' => __('Wait for the destination site to apply the incoming files and database rows.', 'synchy'),
		],
		'finalizing' => [
			'label' => __('Finalize State', 'synchy'),
			'description' => __('Store the new Sync baseline and update the final run summary.', 'synchy'),
		],
		'complete' => [
			'label' => __('Done', 'synchy'),
			'description' => __('The selected Sync changes have finished processing.', 'synchy'),
		],
	];
}

function synchy_get_sync_stage_order(): array
{
	return array_keys(synchy_get_sync_stage_definitions());
}

function synchy_get_sync_stage_index(string $phase): int
{
	$order = synchy_get_sync_stage_order();
	$index = array_search($phase, $order, true);

	return $index === false ? -1 : (int) $index;
}

function synchy_get_sync_stage_items(array $job): array
{
	$definitions = synchy_get_sync_stage_definitions();
	$status = (string) ($job['status'] ?? '');
	$phase = (string) ($job['phase'] ?? '');
	$active_phase = $status === 'error' ? (string) ($job['last_phase'] ?? '') : $phase;
	$active_index = synchy_get_sync_stage_index($active_phase);
	$items = [];

	foreach ($definitions as $stage_key => $definition) {
		$index = synchy_get_sync_stage_index($stage_key);
		$state = 'pending';

		if ($status === 'complete') {
			$state = 'complete';
		} elseif ($status === 'error') {
			if ($active_index >= 0 && $index < $active_index) {
				$state = 'complete';
			} elseif ($active_index >= 0 && $index === $active_index) {
				$state = 'error';
			}
		} elseif ($status === 'running') {
			if ($active_index >= 0 && $index < $active_index) {
				$state = 'complete';
			} elseif ($active_index >= 0 && $index === $active_index) {
				$state = 'active';
			}
		}

		$items[] = [
			'key' => $stage_key,
			'label' => (string) $definition['label'],
			'description' => (string) $definition['description'],
			'state' => $state,
		];
	}

	return $items;
}

function synchy_update_sync_job(array $job): array
{
	if (!isset($job['created_at']) || !is_string($job['created_at']) || $job['created_at'] === '') {
		$job['created_at'] = gmdate('c');
	}

	$job['updated_at'] = gmdate('c');
	update_option(SYNCHY_SYNC_JOB_OPTION, $job, false);

	return $job;
}

function synchy_get_sync_job(): array
{
	$value = get_option(SYNCHY_SYNC_JOB_OPTION, []);

	return is_array($value) ? $value : [];
}

function synchy_get_running_sync_job(): array
{
	$job = synchy_get_visible_sync_job();

	return (($job['status'] ?? '') === 'running') ? $job : [];
}

function synchy_build_sync_job_response(array $job): array
{
	if ($job === []) {
		return [
			'stages' => synchy_get_sync_stage_items([]),
		];
	}

	return [
		'id' => (string) ($job['job_id'] ?? ''),
		'syncId' => (string) ($job['sync_id'] ?? ''),
		'status' => (string) ($job['status'] ?? ''),
		'runMode' => (string) ($job['run_mode'] ?? 'delta'),
		'resumable' => !empty($job['resumable']),
		'pauseRequested' => !empty($job['pause_requested']),
		'phase' => (string) ($job['phase'] ?? ''),
		'phaseLabel' => synchy_sync_phase_label((string) ($job['phase'] ?? '')),
		'message' => (string) ($job['message'] ?? ''),
		'progress' => (int) round((float) ($job['progress'] ?? 0)),
		'createdAt' => (string) ($job['created_at'] ?? ''),
		'updatedAt' => (string) ($job['updated_at'] ?? ''),
		'destinationUrl' => (string) ($job['destination_url'] ?? ''),
		'filesCount' => (int) ($job['files_count'] ?? 0),
		'dbRows' => (int) ($job['db_rows'] ?? 0),
		'totalBatches' => (int) ($job['total_batches'] ?? 0),
		'completedBatches' => (int) ($job['completed_batches'] ?? 0),
		'currentBatchIndex' => (int) ($job['current_batch_index'] ?? 0),
		'currentBatchLabel' => (string) ($job['current_batch_label'] ?? ''),
		'completedWorkUnits' => (int) ($job['completed_work_units'] ?? 0),
		'totalWorkUnits' => (int) ($job['total_work_units'] ?? 0),
		'selectedScopeLabels' => array_values(array_filter((array) ($job['selected_scope_labels'] ?? []), 'is_string')),
		'batches' => array_values(array_map(
			static function (array $batch): array {
				return [
					'batchId' => (string) ($batch['batch_id'] ?? ''),
					'type' => (string) ($batch['type'] ?? ''),
					'scopeId' => (string) ($batch['scope_id'] ?? ''),
					'label' => (string) ($batch['label'] ?? ''),
					'sequence' => (int) ($batch['sequence'] ?? 0),
					'status' => (string) ($batch['status'] ?? 'pending'),
					'fileCount' => (int) ($batch['file_count'] ?? 0),
					'dbRows' => (int) ($batch['db_rows'] ?? 0),
					'workUnits' => (int) ($batch['work_units'] ?? 0),
					'error' => (string) ($batch['error_message'] ?? ''),
				];
			},
			array_values(array_filter((array) ($job['batches'] ?? []), 'is_array'))
		)),
		'stages' => synchy_get_sync_stage_items($job),
	];
}

function synchy_start_sync_job(array $options): array
{
	return synchy_update_sync_job([
		'job_id' => wp_generate_uuid4(),
		'run_mode' => 'delta',
		'status' => 'running',
		'phase' => 'building_package',
		'progress' => 10,
		'message' => __('Reviewing the selected scopes and building the Sync package.', 'synchy'),
		'created_at' => gmdate('c'),
		'destination_url' => (string) ($options['destination_url'] ?? ''),
		'selected_scope_labels' => synchy_get_sync_scope_labels(synchy_get_selected_sync_scope_ids($options)),
		'files_count' => 0,
		'db_rows' => 0,
	]);
}

function synchy_mark_sync_job_error(array $job, string $message): array
{
	if (($job['phase'] ?? '') !== 'error') {
		$job['last_phase'] = (string) ($job['phase'] ?? '');
	}

	$job['status'] = 'error';
	$job['phase'] = 'error';
	$job['message'] = $message;
	$job['progress'] = 100;

	return synchy_update_sync_job($job);
}

function synchy_write_full_sync_batch_payload(string $job_dir, array $batch): array|WP_Error
{
	$sequence = (int) ($batch['sequence'] ?? 0);
	$payload_path = wp_normalize_path(trailingslashit($job_dir) . 'batch-' . str_pad((string) $sequence, 3, '0', STR_PAD_LEFT) . '.json');
	$json = wp_json_encode(
		[
			'files' => array_values((array) ($batch['files'] ?? [])),
			'tables' => (array) ($batch['tables'] ?? []),
		],
		JSON_UNESCAPED_SLASHES
	);

	if ($json === false || file_put_contents($payload_path, $json) === false) {
		return new WP_Error('synchy_full_sync_batch_payload_failed', __('Synchy could not save the full Sync batch payload.', 'synchy'));
	}

	return [
		'payload_path' => $payload_path,
	];
}

function synchy_read_full_sync_batch_payload(array $batch): array
{
	$path = (string) ($batch['payload_path'] ?? '');

	if ($path === '' || !is_readable($path)) {
		return [
			'files' => [],
			'tables' => [],
		];
	}

	$decoded = json_decode((string) file_get_contents($path), true);

	return is_array($decoded) ? $decoded : ['files' => [], 'tables' => []];
}

function synchy_build_full_sync_job(array $options, array $payload)
{
	$job_id = wp_generate_uuid4();
	$job_dir = synchy_prepare_sync_job_dir($job_id);

	if (is_wp_error($job_dir)) {
		return $job_dir;
	}

	$batches = synchy_build_full_sync_batches(
		(array) ($payload['file_delta'] ?? []),
		(array) ($payload['db_delta'] ?? [])
	);
	$total_work_units = 0;
	$files_count = 0;
	$db_rows = 0;

	foreach ($batches as &$batch) {
		$payload_written = synchy_write_full_sync_batch_payload($job_dir, $batch);

		if (is_wp_error($payload_written)) {
			synchy_rrmdir($job_dir);
			return $payload_written;
		}

		$batch['payload_path'] = (string) ($payload_written['payload_path'] ?? '');
		unset($batch['files'], $batch['tables']);
		$total_work_units += (int) ($batch['work_units'] ?? 0);
		$files_count += (int) ($batch['file_count'] ?? 0);
		$db_rows += (int) ($batch['db_rows'] ?? 0);
	}
	unset($batch);

	return synchy_update_sync_job([
		'job_id' => $job_id,
		'sync_id' => (string) (($payload['summary']['syncId'] ?? '') ?: ('full-' . gmdate('YmdHis') . '-' . strtolower(wp_generate_password(6, false, false)))),
		'worker_token' => wp_generate_password(32, false, false),
		'run_mode' => 'full',
		'status' => 'running',
		'resumable' => true,
		'pause_requested' => false,
		'phase' => 'building_package',
		'progress' => 1,
		'message' => __('Preparing the full Sync batch plan.', 'synchy'),
		'created_at' => gmdate('c'),
		'started_at_unix' => microtime(true),
		'destination_url' => (string) ($options['destination_url'] ?? ''),
		'selected_scope_labels' => (array) (($payload['summary']['selectedScopeLabels'] ?? [])),
		'selected_scope_ids' => (array) (($payload['summary']['selectedScopes'] ?? [])),
		'options_signature' => synchy_build_sync_options_signature($options),
		'files_count' => $files_count,
		'db_rows' => $db_rows,
		'total_batches' => count($batches),
		'completed_batches' => 0,
		'current_batch_index' => 0,
		'current_batch_label' => '',
		'completed_work_units' => 0,
		'total_work_units' => $total_work_units,
		'batches' => $batches,
		'next_state' => (array) ($payload['next_state'] ?? []),
		'summary' => (array) ($payload['summary'] ?? []),
		'temp_dir' => $job_dir,
	]);
}

function synchy_build_sync_manual_baseline_fingerprints(array $selected_scope_ids): array
{
	global $wpdb;

	$specs = synchy_get_sync_table_specs();
	$fingerprints = [];

	if (in_array('db_options', $selected_scope_ids, true)) {
		$fingerprints[$wpdb->options] = synchy_build_sync_table_fingerprints(
			synchy_get_sync_option_rows(),
			(array) ($specs[$wpdb->options]['key_columns'] ?? [])
		);
	}

	if (in_array('db_taxonomies', $selected_scope_ids, true)) {
		foreach ([$wpdb->terms, $wpdb->term_taxonomy, $wpdb->term_relationships] as $table) {
			$fingerprints[$table] = synchy_build_sync_table_fingerprints(
				synchy_fetch_all_rows_from_table($table),
				(array) ($specs[$table]['key_columns'] ?? [])
			);
		}
	}

	if (in_array('db_wp_formy', $selected_scope_ids, true)) {
		foreach (synchy_get_wp_formy_sync_tables() as $table) {
			$fingerprints[$table] = synchy_build_sync_table_fingerprints(
				synchy_fetch_all_rows_from_table($table),
				(array) ($specs[$table]['key_columns'] ?? [])
			);
		}
	}

	return $fingerprints;
}

function synchy_mark_sync_baseline_complete(array $raw_options)
{
	$options = synchy_sanitize_site_sync_options($raw_options);
	$validation = synchy_validate_site_sync_options($options);

	if (is_wp_error($validation)) {
		return $validation;
	}

	$selected_scope_ids = synchy_get_selected_sync_scope_ids($options);

	if ($selected_scope_ids === []) {
		return new WP_Error('synchy_sync_no_scope_selected', __('Select at least one file or database scope before marking the baseline.', 'synchy'));
	}

	$sync_time = time();
	$state = synchy_get_sync_state();
	$scope_sync_times = isset($state['scope_sync_times']) && is_array($state['scope_sync_times']) ? $state['scope_sync_times'] : [];

	foreach ($selected_scope_ids as $scope_id) {
		$scope_sync_times[$scope_id] = $sync_time;
	}

	$state['last_sync_time'] = $sync_time;
	$state['scope_sync_times'] = $scope_sync_times;
	$state['db_fingerprints'] = array_replace(
		isset($state['db_fingerprints']) && is_array($state['db_fingerprints']) ? $state['db_fingerprints'] : [],
		synchy_build_sync_manual_baseline_fingerprints($selected_scope_ids)
	);

	$write = synchy_write_sync_state($state);

	if (is_wp_error($write)) {
		return $write;
	}

	synchy_set_sync_last_time($sync_time);
	synchy_set_sync_status([
		'status' => 'success',
		'mode' => 'baseline',
		'at' => gmdate('c', $sync_time),
		'lastSyncTime' => $sync_time,
		'destinationUrl' => (string) ($options['destination_url'] ?? ''),
		'filesSynced' => 0,
		'dbRowsSynced' => 0,
		'durationSeconds' => 0,
		'selectedScopes' => $selected_scope_ids,
		'selectedScopeLabels' => synchy_get_sync_scope_labels($selected_scope_ids),
		'message' => sprintf(
			/* translators: %s: comma-separated scope labels */
			__('Manual baseline marked for %s. The next Sync preview will calculate deltas from this baseline.', 'synchy'),
			implode(', ', synchy_get_sync_scope_labels($selected_scope_ids))
		),
	]);

	return [
		'status' => synchy_get_sync_status(),
		'selectedScopes' => $selected_scope_ids,
	];
}

function synchy_get_import_result(): array
{
	$value = get_option(SYNCHY_IMPORT_RESULT_OPTION, []);

	return is_array($value) ? $value : [];
}

function synchy_set_import_result(array $result): void
{
	update_option(SYNCHY_IMPORT_RESULT_OPTION, $result, false);
}

function synchy_get_sync_storage_root(): string
{
	$uploads = wp_upload_dir();

	if (!empty($uploads['error']) || empty($uploads['basedir'])) {
		return '';
	}

	return wp_normalize_path(trailingslashit((string) $uploads['basedir']) . 'synchy-sync');
}

function synchy_get_sync_state_path(): string
{
	$root = synchy_get_sync_storage_root();

	return $root === '' ? '' : wp_normalize_path(trailingslashit($root) . 'sync-state.json');
}

function synchy_get_sync_temp_root(): string
{
	$root = synchy_get_sync_storage_root();

	return $root === '' ? '' : wp_normalize_path(trailingslashit($root) . 'tmp');
}

function synchy_get_sync_state(): array
{
	$path = synchy_get_sync_state_path();

	if ($path === '' || !is_readable($path)) {
		return [
			'last_sync_time' => synchy_get_sync_last_time(),
			'db_fingerprints' => [],
			'scope_sync_times' => [],
		];
	}

	$decoded = json_decode((string) file_get_contents($path), true);

	if (!is_array($decoded)) {
		return [
			'last_sync_time' => synchy_get_sync_last_time(),
			'db_fingerprints' => [],
			'scope_sync_times' => [],
		];
	}

	$decoded['last_sync_time'] = max(0, (int) ($decoded['last_sync_time'] ?? synchy_get_sync_last_time()));
	$decoded['db_fingerprints'] = isset($decoded['db_fingerprints']) && is_array($decoded['db_fingerprints'])
		? $decoded['db_fingerprints']
		: [];
	$decoded['scope_sync_times'] = isset($decoded['scope_sync_times']) && is_array($decoded['scope_sync_times'])
		? array_map(static fn($value): int => max(0, (int) $value), $decoded['scope_sync_times'])
		: [];

	return $decoded;
}

function synchy_write_sync_state(array $state)
{
	$root = synchy_get_sync_storage_root();
	$path = synchy_get_sync_state_path();

	if ($root === '' || $path === '') {
		return new WP_Error('synchy_sync_state_root_missing', __('Synchy could not resolve the sync state storage folder.', 'synchy'));
	}

	if (!wp_mkdir_p($root)) {
		return new WP_Error('synchy_sync_state_root_failed', __('Synchy could not create the sync state storage folder.', 'synchy'));
	}

	$json = wp_json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

	if ($json === false || file_put_contents($path, $json) === false) {
		return new WP_Error('synchy_sync_state_write_failed', __('Synchy could not write the sync state file.', 'synchy'));
	}

	return true;
}

function synchy_prepare_sync_temp_dir(string $suffix = '') 
{
	$root = synchy_get_sync_temp_root();

	if ($root === '') {
		return new WP_Error('synchy_sync_temp_root_missing', __('Synchy could not resolve the temporary sync workspace.', 'synchy'));
	}

	if (!wp_mkdir_p($root)) {
		return new WP_Error('synchy_sync_temp_root_failed', __('Synchy could not create the temporary sync workspace.', 'synchy'));
	}

	$dir = wp_normalize_path(
		trailingslashit($root)
		. gmdate('Ymd-His')
		. '-'
		. strtolower(wp_generate_password(6, false, false))
		. ($suffix !== '' ? '-' . sanitize_title($suffix) : '')
	);

	if (!wp_mkdir_p($dir)) {
		return new WP_Error('synchy_sync_temp_dir_failed', __('Synchy could not create the working sync folder.', 'synchy'));
	}

	return $dir;
}

function synchy_get_full_sync_batch_max_bytes(): int
{
	return 50 * 1024 * 1024;
}

function synchy_get_full_sync_batch_max_files(): int
{
	return 500;
}

function synchy_get_full_sync_batch_max_rows(): int
{
	return 1000;
}

function synchy_prepare_sync_job_dir(string $job_id)
{
	$root = synchy_get_sync_temp_root();
	$job_id = sanitize_key($job_id);

	if ($root === '' || $job_id === '') {
		return new WP_Error('synchy_sync_job_dir_missing', __('Synchy could not resolve the full Sync job workspace.', 'synchy'));
	}

	if (!wp_mkdir_p($root)) {
		return new WP_Error('synchy_sync_job_dir_root_failed', __('Synchy could not create the full Sync job workspace.', 'synchy'));
	}

	$dir = wp_normalize_path(trailingslashit($root) . $job_id . '-full-sync');

	if (is_dir($dir)) {
		synchy_rrmdir($dir);
	}

	if (!wp_mkdir_p($dir)) {
		return new WP_Error('synchy_sync_job_dir_failed', __('Synchy could not create the working folder for this full Sync job.', 'synchy'));
	}

	return $dir;
}

function synchy_build_sync_options_signature(array $options): string
{
	$selected_scope_ids = synchy_get_selected_sync_scope_ids($options);

	return md5((string) wp_json_encode([
		'destination_url' => (string) ($options['destination_url'] ?? ''),
		'destination_username' => (string) ($options['destination_username'] ?? ''),
		'verify_ssl' => !empty($options['verify_ssl']) ? '1' : '0',
		'selected_scopes' => array_values($selected_scope_ids),
	], JSON_UNESCAPED_SLASHES));
}

function synchy_get_full_sync_worker_lock_timeout(): int
{
	return 120;
}

function synchy_is_full_sync_job_lock_stale(array $job): bool
{
	$acquired_at = (float) ($job['worker_lock_acquired_at'] ?? 0);

	return $acquired_at > 0 && ((microtime(true) - $acquired_at) > synchy_get_full_sync_worker_lock_timeout());
}

function synchy_is_full_sync_job_locked(array $job): bool
{
	$lock_token = (string) ($job['worker_lock_token'] ?? '');

	if ($lock_token === '') {
		return false;
	}

	return !synchy_is_full_sync_job_lock_stale($job);
}

function synchy_acquire_full_sync_job_lock(array $job, string $lock_token)
{
	if (($job['run_mode'] ?? '') !== 'full') {
		return new WP_Error('synchy_full_sync_not_found', __('There is no full Sync job available to lock.', 'synchy'));
	}

	if (synchy_is_full_sync_job_locked($job) && (string) ($job['worker_lock_token'] ?? '') !== $lock_token) {
		return new WP_Error('synchy_full_sync_locked', __('Another Synchy worker is already processing this full Sync.', 'synchy'));
	}

	$job['worker_lock_token'] = $lock_token;
	$job['worker_lock_acquired_at'] = microtime(true);
	$job['worker_last_heartbeat'] = gmdate('c');

	return synchy_update_sync_job($job);
}

function synchy_release_full_sync_job_lock(array $job, string $lock_token = ''): array
{
	if ($lock_token !== '' && (string) ($job['worker_lock_token'] ?? '') !== '' && (string) ($job['worker_lock_token'] ?? '') !== $lock_token) {
		return $job;
	}

	unset($job['worker_lock_token'], $job['worker_lock_acquired_at']);
	$job['worker_last_heartbeat'] = gmdate('c');

	return synchy_update_sync_job($job);
}

function synchy_schedule_full_sync_worker(array $job, int $delay_seconds = 0): array
{
	$worker_token = (string) ($job['worker_token'] ?? '');

	if (($job['run_mode'] ?? '') !== 'full' || $worker_token === '') {
		return $job;
	}

	$timestamp = time() + max(0, $delay_seconds);
	$job['next_run_at'] = gmdate('c', $timestamp);
	$job = synchy_update_sync_job($job);

	if (!wp_next_scheduled('synchy_run_full_sync_worker_event', [$worker_token])) {
		wp_schedule_single_event($timestamp, 'synchy_run_full_sync_worker_event', [$worker_token]);
	}

	return $job;
}

function synchy_trigger_full_sync_worker_async(string $worker_token): void
{
	if ($worker_token === '') {
		return;
	}

	$ajax_url = admin_url('admin-ajax.php');

	wp_remote_post(
		$ajax_url,
		[
			'timeout' => 1,
			'blocking' => false,
			'sslverify' => false,
			'body' => [
				'action' => 'synchy_run_full_sync_worker',
				'token' => $worker_token,
			],
		]
	);
}

function synchy_is_resumable_sync_job_status(string $status): bool
{
	return in_array($status, ['paused', 'failed_partial'], true);
}

function synchy_get_visible_sync_job(): array
{
	$job = synchy_get_sync_job();

	if ($job === []) {
		return [];
	}

	$status = (string) ($job['status'] ?? '');

	if ($status === 'running') {
		$updated_at = strtotime((string) ($job['updated_at'] ?? $job['created_at'] ?? ''));

		if ($updated_at > 0 && (time() - $updated_at) > 1800) {
			$job['status'] = !empty($job['sync_id']) ? 'failed_partial' : 'error';
			$job['phase'] = 'error';
			$job['progress'] = (int) ($job['progress'] ?? 0);
			$job['message'] = __('This earlier Sync run appears to have been interrupted. Resume it or start a new preview when you are ready.', 'synchy');
			$job['resumable'] = !empty($job['sync_id']);
			synchy_update_sync_job($job);
			return $job;
		}
	}

	if ($status === 'running' || synchy_is_resumable_sync_job_status($status)) {
		return $job;
	}

	return [];
}

function synchy_get_sync_active_theme_slugs(): array
{
	$slugs = [];
	$stylesheet = get_stylesheet();
	$template = get_template();

	if ($stylesheet !== '') {
		$slugs[] = $stylesheet;
	}

	if ($template !== '' && !in_array($template, $slugs, true)) {
		$slugs[] = $template;
	}

	return array_values(array_filter($slugs));
}

function synchy_get_sync_file_targets(array $selected_scope_ids = []): array
{
	$targets = [];
	$selected_scope_ids = $selected_scope_ids === [] ? array_keys(synchy_get_sync_scope_definitions()) : $selected_scope_ids;
	$plugins_dir = wp_normalize_path(WP_CONTENT_DIR . '/plugins');

	if (in_array('files_plugins', $selected_scope_ids, true) && is_dir($plugins_dir)) {
		$targets[] = [
			'scope_id' => 'files_plugins',
			'path' => $plugins_dir,
			'archive_prefix' => 'plugins',
		];
	}

	if (in_array('files_themes', $selected_scope_ids, true)) {
		foreach (synchy_get_sync_active_theme_slugs() as $slug) {
		$theme_dir = wp_normalize_path(WP_CONTENT_DIR . '/themes/' . $slug);

			if (!is_dir($theme_dir)) {
				continue;
			}

			$targets[] = [
				'scope_id' => 'files_themes',
				'path' => $theme_dir,
				'archive_prefix' => 'themes/' . $slug,
			];
		}
	}

	$uploads = wp_upload_dir();

	if (
		in_array('files_uploads', $selected_scope_ids, true)
		&& empty($uploads['error'])
		&& !empty($uploads['basedir'])
		&& is_dir((string) $uploads['basedir'])
	) {
		$targets[] = [
			'scope_id' => 'files_uploads',
			'path' => wp_normalize_path((string) $uploads['basedir']),
			'archive_prefix' => 'uploads',
		];
	}

	return $targets;
}

function synchy_is_sync_file_excluded(string $archive_path): bool
{
	$archive_path = ltrim(wp_normalize_path($archive_path), '/');

	if ($archive_path === '') {
		return true;
	}

	$excluded_exact = [
		'.DS_Store',
		'Thumbs.db',
		'desktop.ini',
		'uploads/ast-block-templates-json/index.html',
	];

	foreach ($excluded_exact as $exact) {
		if ($archive_path === $exact || basename($archive_path) === $exact) {
			return true;
		}
	}

	$excluded_contains = [
		'/.git/',
		'/.github/',
		'/.svn/',
		'/.hg/',
		'/node_modules/',
		'/coverage/',
		'/__MACOSX/',
		'/uploads/synchy-backups/',
		'/uploads/synchy-site-sync/',
		'/uploads/synchy-sync/',
	];

	foreach ($excluded_contains as $needle) {
		if (str_contains('/' . $archive_path, $needle)) {
			return true;
		}
	}

	return false;
}

function synchy_collect_sync_file_delta(array $state, array $selected_scope_ids, bool $force_full = false): array
{
	$files = [];
	$total_bytes = 0;
	$baseline_scopes = [];
	$scope_sync_times = isset($state['scope_sync_times']) && is_array($state['scope_sync_times']) ? $state['scope_sync_times'] : [];

	foreach (synchy_get_sync_file_targets($selected_scope_ids) as $target) {
		$scope_id = (string) ($target['scope_id'] ?? '');
		$scope_last_sync_time = max(0, (int) ($scope_sync_times[$scope_id] ?? 0));

		if (($force_full || $scope_last_sync_time <= 0) && $scope_id !== '') {
			$baseline_scopes[$scope_id] = true;
		}

		$base_path = wp_normalize_path((string) $target['path']);
		$archive_prefix = trim((string) $target['archive_prefix'], '/');
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($base_path, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ($iterator as $item) {
			if (!$item->isFile()) {
				continue;
			}

			$absolute_path = wp_normalize_path($item->getPathname());
			$relative_path = ltrim(substr($absolute_path, strlen($base_path)), '/');
			$archive_path = $archive_prefix . '/' . $relative_path;

			if (synchy_is_sync_file_excluded($archive_path)) {
				continue;
			}

			$mtime = (int) $item->getMTime();

			if (!$force_full && $scope_last_sync_time > 0 && $mtime <= $scope_last_sync_time) {
				continue;
			}

			$size = (int) $item->getSize();

			$files[] = [
				'scope_id' => $scope_id,
				'absolute_path' => $absolute_path,
				'archive_path' => $archive_path,
				'size' => $size,
				'mtime' => $mtime,
			];

			$total_bytes += $size;
		}
	}

	usort(
		$files,
		static fn(array $left, array $right): int => strcmp((string) $left['archive_path'], (string) $right['archive_path'])
	);

	return [
		'mode' => $baseline_scopes !== [] ? 'baseline' : 'delta',
		'files' => $files,
		'count' => count($files),
		'bytes' => $total_bytes,
		'baseline_scopes' => array_keys($baseline_scopes),
		'selected_scopes' => array_values($selected_scope_ids),
	];
}

function synchy_should_sync_option_name(string $option_name): bool
{
	if ($option_name === '') {
		return false;
	}

	if (preg_match('/^(_site)?_transient(_timeout)?_/', $option_name)) {
		return false;
	}

	$excluded = [
		'home',
		'siteurl',
		'cron',
		'recently_edited',
		'uagb_asset_version',
		'__uagb_asset_version',
		'fs_active_plugins',
		'wcstripe_cache_live_account_data',
		SYNCHY_EXPORT_OPTIONS,
		SYNCHY_LAST_EXPORT_OPTION,
		SYNCHY_EXPORT_JOB_OPTION,
		SYNCHY_IMPORT_OPTIONS,
		SYNCHY_IMPORT_RESULT_OPTION,
		SYNCHY_SITE_SYNC_OPTIONS,
		SYNCHY_SITE_SYNC_JOB_OPTION,
		SYNCHY_SYNC_STATUS_OPTION,
		SYNCHY_SYNC_JOB_OPTION,
		SYNCHY_SYNC_LAST_TIME_OPTION,
	];

	if (in_array($option_name, $excluded, true)) {
		return false;
	}

	$excluded_prefixes = [
		'action_scheduler_lock_',
		'wcstripe_cache_',
		'fs_',
	];

	foreach ($excluded_prefixes as $prefix) {
		if (str_starts_with($option_name, $prefix)) {
			return false;
		}
	}

	if (str_starts_with($option_name, 'synchy_') || str_starts_with($option_name, 'syncy_')) {
		return false;
	}

	return true;
}

function synchy_get_sync_row_key(array $row, array $key_columns): string
{
	$parts = [];

	foreach ($key_columns as $column) {
		$parts[] = isset($row[$column]) ? (string) $row[$column] : '';
	}

	return implode(':', $parts);
}

function synchy_hash_sync_row(array $row): string
{
	ksort($row);

	return md5((string) wp_json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

function synchy_build_sync_table_fingerprints(array $rows, array $key_columns): array
{
	$fingerprints = [];

	foreach ($rows as $row) {
		$key = synchy_get_sync_row_key($row, $key_columns);

		if ($key === '') {
			continue;
		}

		$fingerprints[$key] = synchy_hash_sync_row($row);
	}

	return $fingerprints;
}

function synchy_get_sync_table_specs(): array
{
	global $wpdb;

	return [
		$wpdb->posts => [
			'key_columns' => ['ID'],
		],
		$wpdb->postmeta => [
			'key_columns' => ['meta_id'],
		],
		$wpdb->options => [
			'key_columns' => ['option_name'],
			'select_columns' => ['option_name', 'option_value', 'autoload'],
			'update_columns' => ['option_value', 'autoload'],
		],
		$wpdb->terms => [
			'key_columns' => ['term_id'],
		],
		$wpdb->term_taxonomy => [
			'key_columns' => ['term_taxonomy_id'],
		],
		$wpdb->term_relationships => [
			'key_columns' => ['object_id', 'term_taxonomy_id'],
			'update_columns' => ['term_order'],
		],
		$wpdb->prefix . 'formy_forms' => [
			'key_columns' => ['id'],
		],
		$wpdb->prefix . 'formy_leads' => [
			'key_columns' => ['id'],
		],
		$wpdb->prefix . 'formy_lead_notes' => [
			'key_columns' => ['id'],
		],
	];
}

function synchy_fetch_all_rows_from_table(string $table, array $columns = []): array
{
	global $wpdb;

	$select = $columns === []
		? '*'
		: implode(', ', array_map(static fn(string $column): string => '`' . str_replace('`', '``', $column) . '`', $columns));

	$rows = $wpdb->get_results('SELECT ' . $select . ' FROM `' . str_replace('`', '``', $table) . '`', ARRAY_A);

	return is_array($rows) ? array_values($rows) : [];
}

function synchy_fetch_rows_by_ids(string $table, string $column, array $ids, array $columns = []): array
{
	global $wpdb;

	if ($ids === []) {
		return [];
	}

	$rows = [];
	$select = $columns === []
		? '*'
		: implode(', ', array_map(static fn(string $name): string => '`' . str_replace('`', '``', $name) . '`', $columns));

	foreach (array_chunk(array_values(array_unique($ids)), 250) as $chunk) {
		$placeholders = implode(', ', array_fill(0, count($chunk), '%s'));
		$sql = $wpdb->prepare(
			'SELECT ' . $select . ' FROM `' . str_replace('`', '``', $table) . '` WHERE `' . str_replace('`', '``', $column) . '` IN (' . $placeholders . ')',
			$chunk
		);

		$chunk_rows = $wpdb->get_results($sql, ARRAY_A);

		if (is_array($chunk_rows)) {
			$rows = array_merge($rows, array_values($chunk_rows));
		}
	}

	return $rows;
}

function synchy_get_changed_post_ids_for_sync(int $last_sync_time): array
{
	global $wpdb;

	if ($last_sync_time <= 0) {
		$rows = $wpdb->get_col('SELECT `ID` FROM `' . str_replace('`', '``', $wpdb->posts) . '`');

		return is_array($rows) ? array_values(array_map('intval', $rows)) : [];
	}

	$since = gmdate('Y-m-d H:i:s', $last_sync_time);
	$sql = $wpdb->prepare(
		'SELECT `ID` FROM `' . str_replace('`', '``', $wpdb->posts) . '` WHERE `post_modified_gmt` > %s OR `post_date_gmt` > %s',
		$since,
		$since
	);
	$rows = $wpdb->get_col($sql);

	return is_array($rows) ? array_values(array_map('intval', $rows)) : [];
}

function synchy_get_wp_formy_sync_tables(): array
{
	global $wpdb;

	$candidates = [
		$wpdb->prefix . 'formy_forms',
		$wpdb->prefix . 'formy_leads',
		$wpdb->prefix . 'formy_lead_notes',
	];

	$tables = [];

	foreach ($candidates as $table) {
		$table_exists = $wpdb->get_var(
			$wpdb->prepare('SHOW TABLES LIKE %s', $table)
		);

		if ($table_exists === $table) {
			$tables[] = $table;
		}
	}

	return $tables;
}

function synchy_build_sync_snapshot_delta(array $rows, array $previous_fingerprints, array $key_columns, bool $baseline): array
{
	$current = synchy_build_sync_table_fingerprints($rows, $key_columns);
	$changed = [];

	foreach ($rows as $row) {
		$key = synchy_get_sync_row_key($row, $key_columns);

		if ($key === '') {
			continue;
		}

		if ($baseline || !isset($previous_fingerprints[$key]) || $previous_fingerprints[$key] !== ($current[$key] ?? '')) {
			$changed[] = $row;
		}
	}

	return [
		'rows' => $changed,
		'fingerprints' => $current,
		'row_ids' => array_map(static fn(array $row): string => synchy_get_sync_row_key($row, $key_columns), $changed),
	];
}

function synchy_get_sync_option_rows(): array
{
	global $wpdb;

	$rows = $wpdb->get_results(
		'SELECT `option_name`, `option_value`, `autoload` FROM `' . str_replace('`', '``', $wpdb->options) . '`',
		ARRAY_A
	);

	if (!is_array($rows)) {
		return [];
	}

	return array_values(
		array_filter(
			$rows,
			static fn(array $row): bool => synchy_should_sync_option_name((string) ($row['option_name'] ?? ''))
		)
	);
}

function synchy_build_sync_database_delta(array $state, array $selected_scope_ids, bool $force_full = false): array
{
	global $wpdb;

	$specs = synchy_get_sync_table_specs();
	$previous_fingerprints = isset($state['db_fingerprints']) && is_array($state['db_fingerprints']) ? $state['db_fingerprints'] : [];
	$scope_sync_times = isset($state['scope_sync_times']) && is_array($state['scope_sync_times']) ? $state['scope_sync_times'] : [];
	$tables = [];
	$current_fingerprints = [];
	$total_rows = 0;
	$baseline_scopes = [];

	if (in_array('db_content', $selected_scope_ids, true)) {
		$content_last_sync = max(0, (int) ($scope_sync_times['db_content'] ?? 0));
		$content_baseline = $force_full || $content_last_sync <= 0;

		if ($content_baseline) {
			$baseline_scopes[] = 'db_content';
		}

		$post_ids = $content_baseline
			? synchy_get_changed_post_ids_for_sync(0)
			: synchy_get_changed_post_ids_for_sync($content_last_sync);
		$posts_rows = synchy_fetch_rows_by_ids($wpdb->posts, 'ID', $post_ids);

		if ($posts_rows !== []) {
			$tables[$wpdb->posts] = [
				'scope_id' => 'db_content',
				'key_columns' => $specs[$wpdb->posts]['key_columns'],
				'rows' => $posts_rows,
				'row_ids' => array_values(array_map(static fn(array $row): string => (string) ($row['ID'] ?? ''), $posts_rows)),
				'update_columns' => [],
			];
			$total_rows += count($posts_rows);
		}

		$postmeta_rows = $post_ids === [] ? [] : synchy_fetch_rows_by_ids($wpdb->postmeta, 'post_id', $post_ids);

		if ($postmeta_rows !== []) {
			$tables[$wpdb->postmeta] = [
				'scope_id' => 'db_content',
				'key_columns' => $specs[$wpdb->postmeta]['key_columns'],
				'rows' => $postmeta_rows,
				'row_ids' => array_values(array_map(static fn(array $row): string => (string) ($row['meta_id'] ?? ''), $postmeta_rows)),
				'update_columns' => [],
			];
			$total_rows += count($postmeta_rows);
		}
	}

	if (in_array('db_options', $selected_scope_ids, true)) {
		$options_baseline = $force_full || max(0, (int) ($scope_sync_times['db_options'] ?? 0)) <= 0;

		if ($options_baseline) {
			$baseline_scopes[] = 'db_options';
		}

		$options_delta = synchy_build_sync_snapshot_delta(
			synchy_get_sync_option_rows(),
			isset($previous_fingerprints[$wpdb->options]) && is_array($previous_fingerprints[$wpdb->options]) ? $previous_fingerprints[$wpdb->options] : [],
			$specs[$wpdb->options]['key_columns'],
			$options_baseline
		);
		$current_fingerprints[$wpdb->options] = $options_delta['fingerprints'];

		if ($options_delta['rows'] !== []) {
			$tables[$wpdb->options] = [
				'scope_id' => 'db_options',
				'key_columns' => $specs[$wpdb->options]['key_columns'],
				'rows' => $options_delta['rows'],
				'row_ids' => $options_delta['row_ids'],
				'update_columns' => $specs[$wpdb->options]['update_columns'],
			];
			$total_rows += count($options_delta['rows']);
		}
	}

	if (in_array('db_taxonomies', $selected_scope_ids, true)) {
		$taxonomy_baseline = $force_full || max(0, (int) ($scope_sync_times['db_taxonomies'] ?? 0)) <= 0;

		if ($taxonomy_baseline) {
			$baseline_scopes[] = 'db_taxonomies';
		}

		foreach ([$wpdb->terms, $wpdb->term_taxonomy, $wpdb->term_relationships] as $table) {
			$delta = synchy_build_sync_snapshot_delta(
				synchy_fetch_all_rows_from_table($table),
				isset($previous_fingerprints[$table]) && is_array($previous_fingerprints[$table]) ? $previous_fingerprints[$table] : [],
				$specs[$table]['key_columns'],
				$taxonomy_baseline
			);

			$current_fingerprints[$table] = $delta['fingerprints'];

			if ($delta['rows'] === []) {
				continue;
			}

			$tables[$table] = [
				'scope_id' => 'db_taxonomies',
				'key_columns' => $specs[$table]['key_columns'],
				'rows' => $delta['rows'],
				'row_ids' => $delta['row_ids'],
				'update_columns' => $specs[$table]['update_columns'] ?? [],
			];
			$total_rows += count($delta['rows']);
		}
	}

	if (in_array('db_wp_formy', $selected_scope_ids, true)) {
		$wp_formy_baseline = $force_full || max(0, (int) ($scope_sync_times['db_wp_formy'] ?? 0)) <= 0;

		if ($wp_formy_baseline) {
			$baseline_scopes[] = 'db_wp_formy';
		}

		foreach (synchy_get_wp_formy_sync_tables() as $table) {
			if (!isset($specs[$table])) {
				continue;
			}

			$delta = synchy_build_sync_snapshot_delta(
				synchy_fetch_all_rows_from_table($table),
				isset($previous_fingerprints[$table]) && is_array($previous_fingerprints[$table]) ? $previous_fingerprints[$table] : [],
				$specs[$table]['key_columns'],
				$wp_formy_baseline
			);

			$current_fingerprints[$table] = $delta['fingerprints'];

			if ($delta['rows'] === []) {
				continue;
			}

			$tables[$table] = [
				'scope_id' => 'db_wp_formy',
				'key_columns' => $specs[$table]['key_columns'],
				'rows' => $delta['rows'],
				'row_ids' => $delta['row_ids'],
				'update_columns' => $specs[$table]['update_columns'] ?? [],
			];
			$total_rows += count($delta['rows']);
		}
	}

	$table_counts = [];

	foreach ($tables as $table => $data) {
		$table_counts[$table] = count((array) ($data['rows'] ?? []));
	}

	return [
		'mode' => $baseline_scopes !== [] ? 'baseline' : 'delta',
		'tables' => $tables,
		'table_counts' => $table_counts,
		'total_rows' => $total_rows,
		'current_fingerprints' => $current_fingerprints,
		'baseline_scopes' => array_values(array_unique($baseline_scopes)),
		'selected_scopes' => array_values($selected_scope_ids),
	];
}

function synchy_sync_sql_value($value): string
{
	if ($value === null) {
		return 'NULL';
	}

	if (is_bool($value)) {
		return $value ? '1' : '0';
	}

	if (is_int($value) || is_float($value)) {
		return (string) $value;
	}

	return "'" . esc_sql((string) $value) . "'";
}

function synchy_build_sync_upsert_statements(string $table, array $rows, array $key_columns, array $update_columns = []): array
{
	if ($rows === []) {
		return [];
	}

	$columns = array_keys(reset($rows));
	$update_columns = $update_columns === [] ? array_values(array_diff($columns, $key_columns)) : $update_columns;
	$statements = [];

	foreach (array_chunk($rows, 100) as $chunk) {
		$values_sql = [];

		foreach ($chunk as $row) {
			$ordered_values = [];

			foreach ($columns as $column) {
				$ordered_values[] = synchy_sync_sql_value($row[$column] ?? null);
			}

			$values_sql[] = '(' . implode(', ', $ordered_values) . ')';
		}

		$update_sql = [];

		foreach ($update_columns as $column) {
			$escaped = '`' . str_replace('`', '``', $column) . '`';
			$update_sql[] = $escaped . ' = VALUES(' . $escaped . ')';
		}

		$statements[] = 'INSERT INTO `' . str_replace('`', '``', $table) . '` ('
			. implode(', ', array_map(static fn(string $column): string => '`' . str_replace('`', '``', $column) . '`', $columns))
			. ') VALUES ' . implode(",\n", $values_sql)
			. ($update_sql !== [] ? ' ON DUPLICATE KEY UPDATE ' . implode(', ', $update_sql) : '')
			. ';';
	}

	return $statements;
}

function synchy_write_sync_sql_file(array $tables, string $path)
{
	$sql = "-- Synchy Sync Delta\n";
	$sql .= '-- Generated at ' . gmdate('c') . "\n\n";

	foreach ($tables as $table => $data) {
		$sql .= '-- Table: ' . $table . "\n";

		foreach (
			synchy_build_sync_upsert_statements(
				$table,
				(array) ($data['rows'] ?? []),
				(array) ($data['key_columns'] ?? []),
				(array) ($data['update_columns'] ?? [])
			) as $statement
		) {
			$sql .= $statement . "\n\n";
		}
	}

	if (file_put_contents($path, $sql) === false) {
		return new WP_Error('synchy_sync_sql_write_failed', __('Synchy could not write the sync SQL file.', 'synchy'));
	}

	return true;
}

function synchy_build_sync_manifest(array $file_delta, array $db_delta, int $sync_time, array $options): array
{
	global $wpdb;

	$tables = [];

	foreach ($db_delta['tables'] as $table => $data) {
		$tables[$table] = [
			'keyColumns' => array_values((array) ($data['key_columns'] ?? [])),
			'updateColumns' => array_values((array) ($data['update_columns'] ?? [])),
			'rowIds' => array_values((array) ($data['row_ids'] ?? [])),
			'rowCount' => (int) count((array) ($data['rows'] ?? [])),
			'rows' => array_values((array) ($data['rows'] ?? [])),
		];
	}

	return [
		'plugin' => 'Synchy',
		'pluginVersion' => SYNCHY_VERSION,
		'mode' => (string) ($db_delta['mode'] ?? $file_delta['mode'] ?? 'delta'),
		'syncedAt' => $sync_time,
		'source' => [
			'homeUrl' => home_url('/'),
			'siteUrl' => site_url('/'),
			'homeUrlAliases' => synchy_get_sync_source_url_aliases('home'),
			'siteUrlAliases' => synchy_get_sync_source_url_aliases('siteurl'),
			'absPath' => wp_normalize_path(ABSPATH),
			'contentPath' => wp_normalize_path(WP_CONTENT_DIR),
			'dbPrefix' => $wpdb->prefix,
		],
		'destination' => [
			'url' => (string) ($options['destination_url'] ?? ''),
		],
		'scopes' => [
			'selected' => array_values(array_unique(array_merge(
				(array) ($file_delta['selected_scopes'] ?? []),
				(array) ($db_delta['selected_scopes'] ?? [])
			))),
			'selectedLabels' => synchy_get_sync_scope_labels(array_values(array_unique(array_merge(
				(array) ($file_delta['selected_scopes'] ?? []),
				(array) ($db_delta['selected_scopes'] ?? [])
			)))),
			'baseline' => array_values(array_unique(array_merge(
				(array) ($file_delta['baseline_scopes'] ?? []),
				(array) ($db_delta['baseline_scopes'] ?? [])
			))),
		],
		'files' => [
			'count' => (int) ($file_delta['count'] ?? 0),
			'bytes' => (int) ($file_delta['bytes'] ?? 0),
			'paths' => array_values(array_map(static fn(array $file): string => (string) $file['archive_path'], (array) ($file_delta['files'] ?? []))),
		],
		'database' => [
			'totalRows' => (int) ($db_delta['total_rows'] ?? 0),
			'tableCounts' => (array) ($db_delta['table_counts'] ?? []),
			'tables' => $tables,
		],
	];
}

function synchy_get_sync_source_url_aliases(string $type): array
{
	$type = $type === 'siteurl' ? 'siteurl' : 'home';
	$current = $type === 'siteurl' ? site_url('/') : home_url('/');
	$stored = (string) get_option($type);
	$aliases = [$current, $stored];

	$normalized = [];

	foreach ($aliases as $alias) {
		$alias = trim((string) $alias);

		if ($alias === '') {
			continue;
		}

		$normalized[] = $alias;
		$normalized[] = untrailingslashit($alias);
	}

	$normalized = array_values(array_unique(array_filter($normalized, static fn($value): bool => is_string($value) && $value !== '')));

	return $normalized;
}

function synchy_get_sync_preview_selection(array $source): array
{
	$selection_present = !empty($source['synchy_sync_preview_selection_present']);
	$scope_definitions = synchy_get_sync_scope_definitions();
	$file_scope_ids = [];

	foreach ((array) ($source['synchy_sync_selected_file_scopes'] ?? []) as $scope_id) {
		$scope_id = sanitize_key((string) $scope_id);

		if (
			$scope_id !== ''
			&& isset($scope_definitions[$scope_id])
			&& (string) ($scope_definitions[$scope_id]['group'] ?? '') === 'files'
		) {
			$file_scope_ids[] = $scope_id;
		}
	}

	$db_tables = [];

	foreach ((array) ($source['synchy_sync_selected_db_tables'] ?? []) as $table) {
		$table = wp_normalize_path(sanitize_text_field((string) $table));

		if ($table !== '') {
			$db_tables[] = $table;
		}
	}

	return [
		'selection_present' => $selection_present,
		'file_scope_ids' => array_values(array_unique($file_scope_ids)),
		'db_tables' => array_values(array_unique($db_tables)),
	];
}

function synchy_should_force_full_sync(array $source): bool
{
	$mode = sanitize_key((string) ($source['synchy_sync_run_mode'] ?? ''));

	return $mode === 'full';
}

function synchy_filter_sync_file_delta_by_selection(array $file_delta, array $selection): array
{
	if (empty($selection['selection_present'])) {
		return $file_delta;
	}

	$allowed_scope_ids = array_values(array_unique(array_map('strval', (array) ($selection['file_scope_ids'] ?? []))));
	$files = [];
	$total_bytes = 0;

	foreach ((array) ($file_delta['files'] ?? []) as $file) {
		$scope_id = (string) ($file['scope_id'] ?? '');

		if (!in_array($scope_id, $allowed_scope_ids, true)) {
			continue;
		}

		$files[] = $file;
		$total_bytes += (int) ($file['size'] ?? 0);
	}

	return array_replace(
		$file_delta,
		[
			'files' => $files,
			'count' => count($files),
			'bytes' => $total_bytes,
			'selected_scopes' => $allowed_scope_ids,
			'baseline_scopes' => array_values(array_intersect((array) ($file_delta['baseline_scopes'] ?? []), $allowed_scope_ids)),
		]
	);
}

function synchy_filter_sync_database_delta_by_selection(array $db_delta, array $selection): array
{
	if (empty($selection['selection_present'])) {
		return $db_delta;
	}

	$selected_tables = array_values(array_unique(array_map('strval', (array) ($selection['db_tables'] ?? []))));
	$selected_lookup = array_fill_keys($selected_tables, true);
	$tables = [];
	$table_counts = [];
	$current_fingerprints = [];
	$total_rows = 0;
	$selected_scopes = [];
	$baseline_scopes = [];

	foreach ((array) ($db_delta['tables'] ?? []) as $table => $data) {
		if (!isset($selected_lookup[$table])) {
			continue;
		}

		$tables[$table] = $data;
		$table_counts[$table] = count((array) ($data['rows'] ?? []));
		$total_rows += $table_counts[$table];

		if (isset($db_delta['current_fingerprints'][$table])) {
			$current_fingerprints[$table] = $db_delta['current_fingerprints'][$table];
		}

		$scope_id = (string) ($data['scope_id'] ?? '');

		if ($scope_id !== '') {
			$selected_scopes[$scope_id] = true;

			if (in_array($scope_id, (array) ($db_delta['baseline_scopes'] ?? []), true)) {
				$baseline_scopes[$scope_id] = true;
			}
		}
	}

	return array_replace(
		$db_delta,
		[
			'tables' => $tables,
			'table_counts' => $table_counts,
			'total_rows' => $total_rows,
			'current_fingerprints' => $current_fingerprints,
			'selected_scopes' => array_keys($selected_scopes),
			'baseline_scopes' => array_keys($baseline_scopes),
		]
	);
}

function synchy_build_sync_preview_tree(array $file_delta, array $db_delta): array
{
	$scope_definitions = synchy_get_sync_scope_definitions();
	$file_groups = [];

	foreach ((array) ($file_delta['files'] ?? []) as $file) {
		$scope_id = (string) ($file['scope_id'] ?? '');

		if ($scope_id === '') {
			continue;
		}

		if (!isset($file_groups[$scope_id])) {
			$file_groups[$scope_id] = [
				'id' => $scope_id,
				'label' => (string) ($scope_definitions[$scope_id]['label'] ?? $scope_id),
				'count' => 0,
				'bytes' => 0,
				'files' => [],
				'paths' => [],
			];
		}

		$file_groups[$scope_id]['count']++;
		$file_groups[$scope_id]['bytes'] += (int) ($file['size'] ?? 0);
		$file_groups[$scope_id]['files'][] = [
			'path' => (string) ($file['archive_path'] ?? ''),
			'size' => (int) ($file['size'] ?? 0),
		];
		$file_groups[$scope_id]['paths'][] = (string) ($file['archive_path'] ?? '');
	}

	foreach ($file_groups as &$group) {
		sort($group['paths']);
		usort(
			$group['files'],
			static fn(array $left, array $right): int => strcmp((string) ($left['path'] ?? ''), (string) ($right['path'] ?? ''))
		);
	}
	unset($group);

	$db_tables = [];

	foreach ((array) ($db_delta['tables'] ?? []) as $table => $data) {
		$scope_id = (string) ($data['scope_id'] ?? '');
		$db_tables[] = [
			'id' => $table,
			'table' => $table,
			'label' => $table,
			'scopeId' => $scope_id,
			'scopeLabel' => (string) ($scope_definitions[$scope_id]['label'] ?? ''),
			'rowCount' => count((array) ($data['rows'] ?? [])),
			'rowIds' => array_slice(array_values((array) ($data['row_ids'] ?? [])), 0, 25),
		];
	}

	return [
		'fileGroups' => array_values($file_groups),
		'databaseTables' => $db_tables,
	];
}

function synchy_prepare_sync_payload(array $options, array $selection = [], bool $force_full = false): array|WP_Error
{
	$state = synchy_get_sync_state();
	$selected_scope_ids = synchy_get_selected_sync_scope_ids($options);

	if ($selected_scope_ids === []) {
		return new WP_Error('synchy_sync_no_scope_selected', __('Select at least one file or database scope before previewing or syncing.', 'synchy'));
	}

	$state['last_sync_time'] = synchy_get_sync_last_time();
	$file_delta = synchy_collect_sync_file_delta($state, synchy_get_selected_sync_scope_ids($options, 'files'), $force_full);
	$db_delta = synchy_build_sync_database_delta($state, synchy_get_selected_sync_scope_ids($options, 'database'), $force_full);

	if (!$force_full && !empty($selection['selection_present'])) {
		$file_delta = synchy_filter_sync_file_delta_by_selection($file_delta, $selection);
		$db_delta = synchy_filter_sync_database_delta_by_selection($db_delta, $selection);
	}

	$sync_time = time();
	$manifest = synchy_build_sync_manifest($file_delta, $db_delta, $sync_time, $options);
	$baseline_scope_ids = array_values(array_unique(array_merge(
		(array) ($file_delta['baseline_scopes'] ?? []),
		(array) ($db_delta['baseline_scopes'] ?? [])
	)));
	$effective_selected_scope_ids = array_values(array_unique(array_merge(
		(array) ($file_delta['selected_scopes'] ?? []),
		(array) ($db_delta['selected_scopes'] ?? [])
	)));
	$scope_sync_times = isset($state['scope_sync_times']) && is_array($state['scope_sync_times']) ? $state['scope_sync_times'] : [];

	foreach ($effective_selected_scope_ids as $scope_id) {
		$scope_sync_times[$scope_id] = $sync_time;
	}

	$next_state = [
		'last_sync_time' => $sync_time,
		'db_fingerprints' => array_replace(
			isset($state['db_fingerprints']) && is_array($state['db_fingerprints']) ? $state['db_fingerprints'] : [],
			(array) ($db_delta['current_fingerprints'] ?? [])
		),
		'scope_sync_times' => $scope_sync_times,
	];

	$summary = [
		'mode' => $baseline_scope_ids !== [] ? 'baseline' : 'delta',
		'filesCount' => (int) ($manifest['files']['count'] ?? 0),
		'filesBytes' => (int) ($manifest['files']['bytes'] ?? 0),
		'filePaths' => array_slice((array) ($manifest['files']['paths'] ?? []), 0, 40),
		'dbRows' => (int) ($manifest['database']['totalRows'] ?? 0),
		'tableCounts' => (array) ($manifest['database']['tableCounts'] ?? []),
		'lastSyncTime' => synchy_get_sync_last_time(),
		'syncedAt' => $sync_time,
		'selectedScopes' => $effective_selected_scope_ids,
		'selectedScopeLabels' => synchy_get_sync_scope_labels($effective_selected_scope_ids),
		'pendingBaselineScopes' => $baseline_scope_ids,
		'pendingBaselineLabels' => synchy_get_sync_scope_labels($baseline_scope_ids),
		'previewTree' => synchy_build_sync_preview_tree($file_delta, $db_delta),
		'forceFull' => $force_full,
	];

	return [
		'file_delta' => $file_delta,
		'db_delta' => $db_delta,
		'manifest' => $manifest,
		'next_state' => $next_state,
		'summary' => $summary,
	];
}

function synchy_write_sync_package_from_parts(array $file_delta, array $db_delta, int $sync_time, array $options, string $temp_dir)
{
	$manifest = synchy_build_sync_manifest($file_delta, $db_delta, $sync_time, $options);
	$manifest_path = wp_normalize_path(trailingslashit($temp_dir) . 'manifest.json');
	$sql_path = wp_normalize_path(trailingslashit($temp_dir) . 'delta.sql');
	$zip_path = wp_normalize_path(trailingslashit($temp_dir) . 'sync-package.zip');
	$manifest_json = wp_json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

	if ($manifest_json === false || file_put_contents($manifest_path, $manifest_json) === false) {
		return new WP_Error('synchy_sync_manifest_write_failed', __('Synchy could not write the sync manifest file.', 'synchy'));
	}

	$sql_written = synchy_write_sync_sql_file((array) ($db_delta['tables'] ?? []), $sql_path);

	if (is_wp_error($sql_written)) {
		return $sql_written;
	}

	$zip = new ZipArchive();
	$result = $zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE);

	if ($result !== true) {
		return new WP_Error('synchy_sync_zip_open_failed', __('Synchy could not open the sync package for writing.', 'synchy'));
	}

	foreach ((array) ($file_delta['files'] ?? []) as $file) {
		if (!$zip->addFile((string) $file['absolute_path'], (string) $file['archive_path'])) {
			$zip->close();
			return new WP_Error(
				'synchy_sync_zip_add_file_failed',
				sprintf(
					/* translators: %s: file path inside the archive */
					__('Synchy could not add %s to the sync package.', 'synchy'),
					(string) $file['archive_path']
				)
			);
		}
	}

	$zip->addFile($sql_path, '.synchy-sync/db/delta.sql');
	$zip->addFile($manifest_path, '.synchy-sync/db/manifest.json');
	$zip->close();

	return [
		'manifest' => $manifest,
		'zip_path' => $zip_path,
		'manifest_path' => $manifest_path,
		'sql_path' => $sql_path,
	];
}

function synchy_get_full_sync_file_batch_group(string $scope_id, string $archive_path): array
{
	$segments = array_values(array_filter(explode('/', ltrim(wp_normalize_path($archive_path), '/')), 'strlen'));
	$root = $segments[0] ?? '';

	if ($scope_id === 'files_plugins') {
		$slug = $segments[1] ?? basename($archive_path);
		return [
			'key' => 'plugin:' . $slug,
			'label' => 'Plugin / ' . $slug,
			'path' => $root . '/' . $slug,
		];
	}

	if ($scope_id === 'files_themes') {
		$slug = $segments[1] ?? basename($archive_path);
		return [
			'key' => 'theme:' . $slug,
			'label' => 'Theme / ' . $slug,
			'path' => $root . '/' . $slug,
		];
	}

	if ($scope_id === 'files_uploads') {
		$year = $segments[1] ?? '';
		$month = $segments[2] ?? '';

		if (preg_match('/^\d{4}$/', $year) && preg_match('/^\d{2}$/', $month)) {
			return [
				'key' => 'uploads:' . $year . '/' . $month,
				'label' => 'Uploads / ' . $year . ' / ' . $month,
				'path' => $root . '/' . $year . '/' . $month,
			];
		}

		if ($year !== '') {
			return [
				'key' => 'uploads:' . $year,
				'label' => 'Uploads / ' . $year,
				'path' => $root . '/' . $year,
			];
		}

		return [
			'key' => 'uploads:root',
			'label' => 'Uploads / Root',
			'path' => $root,
		];
	}

	return [
		'key' => $scope_id . ':' . ($segments[1] ?? ($segments[0] ?? 'root')),
		'label' => $archive_path,
		'path' => $archive_path,
	];
}

function synchy_finalize_full_sync_file_batch(array $base_batch, array $files, int $part_number = 0): array
{
	$total_bytes = 0;

	foreach ($files as $file) {
		$total_bytes += (int) ($file['size'] ?? 0);
	}

	$part_suffix = $part_number > 0 ? '-part-' . str_pad((string) $part_number, 2, '0', STR_PAD_LEFT) : '';
	$label = (string) ($base_batch['label'] ?? '') . ($part_number > 0 ? ' / Part ' . $part_number : '');

	return [
		'batch_id' => sanitize_key((string) ($base_batch['batch_id'] ?? '') . $part_suffix),
		'type' => 'files',
		'scope_id' => (string) ($base_batch['scope_id'] ?? ''),
		'label' => $label,
		'object_path' => (string) ($base_batch['object_path'] ?? ''),
		'file_count' => count($files),
		'db_rows' => 0,
		'work_units' => $total_bytes,
		'files' => array_values($files),
		'tables' => [],
	];
}

function synchy_split_full_sync_file_batch(array $base_batch, array $files): array
{
	usort(
		$files,
		static fn(array $left, array $right): int => strcmp((string) ($left['archive_path'] ?? ''), (string) ($right['archive_path'] ?? ''))
	);

	$max_bytes = synchy_get_full_sync_batch_max_bytes();
	$max_files = synchy_get_full_sync_batch_max_files();
	$chunks = [];
	$current = [];
	$current_bytes = 0;
	$part = 1;

	foreach ($files as $file) {
		$size = (int) ($file['size'] ?? 0);
		$would_exceed = $current !== [] && (($current_bytes + $size) > $max_bytes || count($current) >= $max_files);

		if ($would_exceed) {
			$chunks[] = synchy_finalize_full_sync_file_batch($base_batch, $current, count($chunks) > 0 || count($files) > count($current) ? $part : 0);
			$current = [];
			$current_bytes = 0;
			$part++;
		}

		$current[] = $file;
		$current_bytes += $size;
	}

	if ($current !== []) {
		$chunks[] = synchy_finalize_full_sync_file_batch($base_batch, $current, count($chunks) > 0 ? $part : 0);
	}

	return $chunks;
}

function synchy_split_full_sync_database_batch(array $base_batch, array $tables): array
{
	$max_rows = synchy_get_full_sync_batch_max_rows();
	$batches = [];
	$current_tables = [];
	$current_rows = 0;
	$part = 1;

	foreach ($tables as $table_name => $table_data) {
		$rows = array_values((array) ($table_data['rows'] ?? []));
		$row_ids = array_values((array) ($table_data['row_ids'] ?? []));
		$key_columns = array_values((array) ($table_data['key_columns'] ?? []));
		$update_columns = array_values((array) ($table_data['update_columns'] ?? []));

		foreach (array_chunk($rows, $max_rows) as $row_index => $row_chunk) {
			$id_chunk = array_slice($row_ids, $row_index * $max_rows, count($row_chunk));

			if ($current_rows > 0 && ($current_rows + count($row_chunk)) > $max_rows) {
				$batches[] = [
					'batch_id' => sanitize_key((string) ($base_batch['batch_id'] ?? '') . '-part-' . str_pad((string) $part, 2, '0', STR_PAD_LEFT)),
					'type' => 'database',
					'scope_id' => (string) ($base_batch['scope_id'] ?? ''),
					'label' => (string) ($base_batch['label'] ?? '') . ' / Part ' . $part,
					'object_path' => (string) ($base_batch['object_path'] ?? ''),
					'file_count' => 0,
					'db_rows' => $current_rows,
					'work_units' => $current_rows,
					'files' => [],
					'tables' => $current_tables,
				];
				$current_tables = [];
				$current_rows = 0;
				$part++;
			}

			$current_tables[$table_name] = [
				'scope_id' => (string) ($table_data['scope_id'] ?? ''),
				'key_columns' => $key_columns,
				'update_columns' => $update_columns,
				'rows' => $row_chunk,
				'row_ids' => $id_chunk,
			];
			$current_rows += count($row_chunk);
		}
	}

	if ($current_rows > 0) {
		$batches[] = [
			'batch_id' => sanitize_key((string) ($base_batch['batch_id'] ?? '') . (count($batches) > 0 ? '-part-' . str_pad((string) $part, 2, '0', STR_PAD_LEFT) : '')),
			'type' => 'database',
			'scope_id' => (string) ($base_batch['scope_id'] ?? ''),
			'label' => (string) ($base_batch['label'] ?? '') . (count($batches) > 0 ? ' / Part ' . $part : ''),
			'object_path' => (string) ($base_batch['object_path'] ?? ''),
			'file_count' => 0,
			'db_rows' => $current_rows,
			'work_units' => $current_rows,
			'files' => [],
			'tables' => $current_tables,
		];
	}

	return $batches;
}

function synchy_build_full_sync_batches(array $file_delta, array $db_delta): array
{
	$batches = [];
	$file_groups = [];

	foreach ((array) ($file_delta['files'] ?? []) as $file) {
		$scope_id = (string) ($file['scope_id'] ?? '');

		if ($scope_id === '') {
			continue;
		}

		$group = synchy_get_full_sync_file_batch_group($scope_id, (string) ($file['archive_path'] ?? ''));
		$key = $scope_id . '|' . (string) ($group['key'] ?? '');

		if (!isset($file_groups[$key])) {
			$file_groups[$key] = [
				'batch_id' => sanitize_key('batch-file-' . $scope_id . '-' . md5((string) ($group['path'] ?? $group['key'] ?? ''))),
				'scope_id' => $scope_id,
				'label' => (string) ($group['label'] ?? $scope_id),
				'object_path' => (string) ($group['path'] ?? ''),
				'files' => [],
			];
		}

		$file_groups[$key]['files'][] = $file;
	}

	foreach ($file_groups as $group) {
		$chunks = synchy_split_full_sync_file_batch(
			[
				'batch_id' => (string) $group['batch_id'],
				'scope_id' => (string) $group['scope_id'],
				'label' => (string) $group['label'],
				'object_path' => (string) $group['object_path'],
			],
			(array) ($group['files'] ?? [])
		);
		$batches = array_merge($batches, $chunks);
	}

	$scope_labels = [
		'db_content' => 'Database / Posts & Post Meta',
		'db_options' => 'Database / Options',
		'db_taxonomies' => 'Database / Terms & Taxonomies',
		'db_wp_formy' => 'Database / WP Formy',
	];
	$db_scope_tables = [];

	foreach ((array) ($db_delta['tables'] ?? []) as $table_name => $table_data) {
		$scope_id = (string) ($table_data['scope_id'] ?? '');

		if ($scope_id === '') {
			continue;
		}

		if (!isset($db_scope_tables[$scope_id])) {
			$db_scope_tables[$scope_id] = [];
		}

		$db_scope_tables[$scope_id][$table_name] = $table_data;
	}

	foreach ($db_scope_tables as $scope_id => $tables) {
		$batches = array_merge(
			$batches,
			synchy_split_full_sync_database_batch(
				[
					'batch_id' => sanitize_key('batch-db-' . $scope_id),
					'scope_id' => (string) $scope_id,
					'label' => $scope_labels[$scope_id] ?? ('Database / ' . $scope_id),
					'object_path' => (string) $scope_id,
				],
				$tables
			)
		);
	}

	foreach ($batches as $index => &$batch) {
		$batch['sequence'] = $index + 1;
		$batch['status'] = 'pending';
	}
	unset($batch);

	return $batches;
}

function synchy_build_full_sync_preview_batches(array $batches): array
{
	return array_values(
		array_map(
			static function (array $batch): array {
				return [
					'batchId' => (string) ($batch['batch_id'] ?? ''),
					'type' => (string) ($batch['type'] ?? ''),
					'scopeId' => (string) ($batch['scope_id'] ?? ''),
					'label' => (string) ($batch['label'] ?? ''),
					'sequence' => (int) ($batch['sequence'] ?? 0),
					'status' => (string) ($batch['status'] ?? 'pending'),
					'fileCount' => (int) ($batch['file_count'] ?? 0),
					'dbRows' => (int) ($batch['db_rows'] ?? 0),
					'workUnits' => (int) ($batch['work_units'] ?? 0),
				];
			},
			$batches
		)
	);
}

function synchy_build_sync_package(array $options, bool $preview_only = false, array $selection = [], bool $force_full = false)
{
	$payload = synchy_prepare_sync_payload($options, $selection, $force_full);

	if (is_wp_error($payload)) {
		return $payload;
	}

	$file_delta = (array) ($payload['file_delta'] ?? []);
	$db_delta = (array) ($payload['db_delta'] ?? []);
	$manifest = (array) ($payload['manifest'] ?? []);
	$next_state = (array) ($payload['next_state'] ?? []);
	$summary = (array) ($payload['summary'] ?? []);

	if ($force_full) {
		$batches = synchy_build_full_sync_batches($file_delta, $db_delta);
		$summary['syncId'] = 'full-' . gmdate('YmdHis') . '-' . strtolower(wp_generate_password(6, false, false));
		$summary['batches'] = synchy_build_full_sync_preview_batches($batches);
		$summary['totalBatches'] = count($batches);
		$summary['totalWorkUnits'] = array_sum(array_map(static fn(array $batch): int => (int) ($batch['work_units'] ?? 0), $batches));
	}

	if ($preview_only) {
		return [
			'preview' => $summary,
			'manifest' => $manifest,
			'next_state' => $next_state,
		];
	}

	if ($summary['filesCount'] === 0 && $summary['dbRows'] === 0 && $summary['mode'] === 'delta') {
		return [
			'no_changes' => true,
			'preview' => $summary,
			'manifest' => $manifest,
			'next_state' => $next_state,
		];
	}

	$temp_dir = synchy_prepare_sync_temp_dir($summary['mode']);

	if (is_wp_error($temp_dir)) {
		return $temp_dir;
	}

	$package_written = synchy_write_sync_package_from_parts($file_delta, $db_delta, (int) ($summary['syncedAt'] ?? time()), $options, $temp_dir);

	if (is_wp_error($package_written)) {
		synchy_rrmdir($temp_dir);

		return $package_written;
	}

	return [
		'preview' => $summary,
		'manifest' => (array) ($package_written['manifest'] ?? $manifest),
		'next_state' => $next_state,
		'temp_dir' => $temp_dir,
		'zip_path' => (string) ($package_written['zip_path'] ?? ''),
	];
}

function synchy_get_export_included_items(): array
{
	return [
		[
			'label' => __('WordPress database', 'synchy'),
			'description' => __('Full SQL export of the current WordPress database.', 'synchy'),
		],
		[
			'label' => __('WordPress core files', 'synchy'),
			'description' => __('Root files plus wp-admin and wp-includes for a portable full-site package.', 'synchy'),
		],
		[
			'label' => __('Plugins', 'synchy'),
			'description' => __('Everything in wp-content/plugins needed by the live site.', 'synchy'),
		],
		[
			'label' => __('Themes', 'synchy'),
			'description' => __('All themes in wp-content/themes so the package is migration-ready.', 'synchy'),
		],
		[
			'label' => __('MU plugins', 'synchy'),
			'description' => __('Any must-use plugins in wp-content/mu-plugins.', 'synchy'),
		],
		[
			'label' => __('Uploads and media', 'synchy'),
			'description' => __('The full uploads library from wp-content/uploads.', 'synchy'),
		],
		[
			'label' => __('Package metadata', 'synchy'),
			'description' => __('Manifest details like site URL, timestamps, versions, checksums.', 'synchy'),
		],
	];
}

function synchy_get_export_filter_groups(): array
{
	return [
		'exclude_vcs' => [
			'label' => __('Version control artifacts', 'synchy'),
			'description' => __('Skip repository metadata and automation files that do not belong in a restore package.', 'synchy'),
			'patterns' => ['.git/', '.github/', '.gitignore', '.gitattributes', '.gitlab/', '.svn/', '.hg/'],
		],
		'exclude_local_dev' => [
			'label' => __('Local development files', 'synchy'),
			'description' => __('Skip machine-specific folders and environment files used for local tooling and editors.', 'synchy'),
			'patterns' => ['.ddev/', '.idea/', '.vscode/', '*.code-workspace', '.env', '.env.*'],
		],
		'exclude_os_junk' => [
			'label' => __('Operating system junk', 'synchy'),
			'description' => __('Exclude Mac and Windows metadata that should never be migrated.', 'synchy'),
			'patterns' => ['.DS_Store', '__MACOSX/', 'Thumbs.db', 'desktop.ini'],
		],
		'exclude_cache_temp' => [
			'label' => __('Cache and temporary files', 'synchy'),
			'description' => __('Exclude runtime caches, upgrade leftovers, and transient logs.', 'synchy'),
			'patterns' => ['wp-content/cache/', 'wp-content/upgrade/', 'wp-content/uploads/cache/', 'error_log', 'debug.log'],
		],
		'exclude_existing_backups' => [
			'label' => __('Existing backup archives', 'synchy'),
			'description' => __('Prevent recursive backup-of-backup packages and stale restore artifacts.', 'synchy'),
			'patterns' => ['wp-content/ai1wm-backups/', 'wp-content/updraft/', 'wp-content/backups/', 'wp-content/duplicator/', 'wp-content/uploads/synchy-backups/', 'wp-snapshots/'],
		],
		'exclude_dev_artifacts' => [
			'label' => __('Development build artifacts', 'synchy'),
			'description' => __('Exclude folders that are usually safe to omit from a production restore package.', 'synchy'),
			'patterns' => ['node_modules/', 'coverage/', '.sass-cache/'],
		],
	];
}

function synchy_get_notice_key(): string
{
	$user_id = get_current_user_id();

	return SYNCHY_NOTICE_PREFIX . ($user_id > 0 ? (string) $user_id : 'guest');
}

function synchy_set_notice(string $type, string $message): void
{
	set_transient(
		synchy_get_notice_key(),
		[
			'type' => $type,
			'message' => $message,
		],
		120
	);
}

function synchy_get_notice(): ?array
{
	$notice = get_transient(synchy_get_notice_key());

	if (!is_array($notice) || empty($notice['message'])) {
		return null;
	}

	delete_transient(synchy_get_notice_key());

	return $notice;
}

function synchy_render_notice(): void
{
	$notice = synchy_get_notice();

		if ($notice === null) {
			$page = isset($_GET['page']) ? sanitize_key(wp_unslash((string) $_GET['page'])) : '';
			$settings_updated = isset($_GET['settings-updated']) ? sanitize_text_field(wp_unslash((string) $_GET['settings-updated'])) : '';

			if (in_array($page, ['synchy-push-live-site', 'synchy-site-sync'], true) && $settings_updated === 'true') {
				$notice = [
					'type' => 'success',
					'message' => __('Destination connection settings saved.', 'synchy'),
				];
			} else {
				return;
			}
		}

	$class = $notice['type'] === 'error' ? 'notice notice-error' : 'notice notice-success';
	?>
	<div class="<?php echo esc_attr($class); ?>">
		<p><?php echo esc_html((string) $notice['message']); ?></p>
	</div>
	<?php
}

add_action('admin_notices', function (): void {
	$page = isset($_GET['page']) ? sanitize_key(wp_unslash((string) $_GET['page'])) : '';

	if ($page !== '' && str_starts_with($page, 'synchy')) {
		return;
	}

	synchy_render_notice();
});

function synchy_get_last_export(): array
{
	$value = get_option(SYNCHY_LAST_EXPORT_OPTION, []);

	return is_array($value) ? $value : [];
}

function synchy_export_history_contains_package(array $history, string $package_id): bool
{
	foreach ($history as $entry) {
		if (($entry['package_id'] ?? '') === $package_id) {
			return true;
		}
	}

	return false;
}

function synchy_is_export_artifact_readable($artifact): bool
{
	return is_array($artifact) && !empty($artifact['path']) && is_readable((string) $artifact['path']);
}

function synchy_is_export_record_available(array $record): bool
{
	$archive = $record['artifacts']['archive'] ?? null;

	return synchy_is_export_artifact_readable($archive);
}

function synchy_build_export_history_entry_from_manifest_path(string $manifest_path): array
{
	$manifest_path = wp_normalize_path($manifest_path);

	if (!is_readable($manifest_path)) {
		return [];
	}

	$contents = file_get_contents($manifest_path);

	if ($contents === false) {
		return [];
	}

	$manifest = json_decode($contents, true);

	if (!is_array($manifest) || empty($manifest['package_id'])) {
		return [];
	}

	$directory = wp_normalize_path(dirname($manifest_path));
	$archive_filename = sanitize_file_name((string) ($manifest['artifacts']['archive']['filename'] ?? ''));
	$installer_filename = sanitize_file_name((string) ($manifest['artifacts']['installer']['filename'] ?? ''));
	$manifest_filename = sanitize_file_name((string) ($manifest['artifacts']['manifest']['filename'] ?? basename($manifest_path)));
	$archive_path = $archive_filename !== '' ? wp_normalize_path(trailingslashit($directory) . $archive_filename) : '';
	$installer_path = $installer_filename !== '' ? wp_normalize_path(trailingslashit($directory) . $installer_filename) : '';
	$resolved_manifest_path = $manifest_filename !== '' ? wp_normalize_path(trailingslashit($directory) . $manifest_filename) : $manifest_path;

	return [
		'package_id' => (string) $manifest['package_id'],
		'package_name' => (string) ($manifest['package_name'] ?? $manifest['package_id']),
		'created_at' => (string) ($manifest['created_at_gmt'] ?? ''),
		'output_directory' => (string) ($manifest['output_directory'] ?? synchy_display_output_directory($directory)),
		'archive_size' => is_readable($archive_path)
			? (int) filesize($archive_path)
			: (int) ($manifest['artifacts']['archive']['size_bytes'] ?? 0),
		'file_count' => (int) ($manifest['files']['included_count'] ?? 0),
		'file_bytes' => (int) ($manifest['files']['included_bytes'] ?? 0),
		'table_count' => (int) ($manifest['database']['tables'] ?? 0),
		'artifacts' => [
			'archive' => [
				'label' => __('Download archive', 'synchy'),
				'filename' => $archive_filename,
				'path' => $archive_path,
			],
			'installer' => [
				'label' => __('Download installer', 'synchy'),
				'filename' => $installer_filename,
				'path' => $installer_path,
			],
			'manifest' => [
				'label' => __('Download manifest', 'synchy'),
				'filename' => $manifest_filename,
				'path' => $resolved_manifest_path,
			],
		],
	];
}

function synchy_discover_export_history_from_directory(string $directory): array
{
	$directory = wp_normalize_path(untrailingslashit($directory));

	if ($directory === '' || !is_dir($directory) || !is_readable($directory)) {
		return [];
	}

	$matches = glob($directory . '/*-manifest.json') ?: [];
	$history = [];

	foreach ($matches as $manifest_path) {
		$entry = synchy_build_export_history_entry_from_manifest_path((string) $manifest_path);

		if ($entry !== []) {
			$history[] = $entry;
		}
	}

	usort(
		$history,
		static function (array $a, array $b): int {
			return strcmp((string) ($b['created_at'] ?? ''), (string) ($a['created_at'] ?? ''));
		}
	);

	return $history;
}

function synchy_discover_export_history(): array
{
	$options = synchy_get_export_options();
	$directories = [];
	$current_output = synchy_resolve_output_directory_path((string) ($options['output_directory'] ?? ''));

	if ($current_output !== '') {
		$directories[] = $current_output;
	}

	$last_export = synchy_get_last_export();
	$last_output = trim((string) ($last_export['output_directory'] ?? ''));

	if ($last_output !== '') {
		$directories[] = synchy_resolve_output_directory_path($last_output);
	}

	$history = [];

	foreach (array_values(array_unique(array_filter($directories))) as $directory) {
		$history = array_merge($history, synchy_discover_export_history_from_directory((string) $directory));
	}

	return $history;
}

function synchy_update_export_history(array $history): array
{
	$history = array_values($history);
	update_option(SYNCHY_EXPORT_HISTORY_OPTION, $history, false);

	$latest = $history[0] ?? [];

	if ($latest === []) {
		delete_option(SYNCHY_LAST_EXPORT_OPTION);
	} else {
		update_option(SYNCHY_LAST_EXPORT_OPTION, $latest, false);
	}

	return $history;
}

function synchy_get_export_history(): array
{
	$stored = get_option(SYNCHY_EXPORT_HISTORY_OPTION, []);
	$history = is_array($stored) ? $stored : [];
	$changed = !is_array($stored);
	$last_export = synchy_get_last_export();

	if ($last_export !== [] && !synchy_export_history_contains_package($history, (string) ($last_export['package_id'] ?? ''))) {
		array_unshift($history, $last_export);
		$changed = true;
	}

	foreach (synchy_discover_export_history() as $entry) {
		if (!synchy_export_history_contains_package($history, (string) ($entry['package_id'] ?? ''))) {
			$history[] = $entry;
			$changed = true;
		}
	}

	$normalized = [];
	$seen = [];

	foreach ($history as $entry) {
		if (!is_array($entry)) {
			$changed = true;
			continue;
		}

		$package_id = trim((string) ($entry['package_id'] ?? ''));

		if ($package_id === '' || isset($seen[$package_id])) {
			$changed = true;
			continue;
		}

		if (!synchy_is_export_record_available($entry)) {
			$changed = true;
			continue;
		}

		$seen[$package_id] = true;
		$normalized[] = $entry;
	}

	$latest_package_id = (string) ($last_export['package_id'] ?? '');
	$current_latest_package_id = (string) (($normalized[0] ?? [])['package_id'] ?? '');

	if ($changed || $latest_package_id !== $current_latest_package_id) {
		return synchy_update_export_history($normalized);
	}

	return $normalized;
}

function synchy_record_export_history(array $record): array
{
	$package_id = (string) ($record['package_id'] ?? '');

	if ($package_id === '') {
		return synchy_get_export_history();
	}

	$history = array_values(
		array_filter(
			synchy_get_export_history(),
			static fn(array $entry): bool => (string) ($entry['package_id'] ?? '') !== $package_id
		)
	);

	array_unshift($history, $record);

	return synchy_update_export_history($history);
}

function synchy_find_export_history_item(string $package_id): array
{
	foreach (synchy_get_export_history() as $entry) {
		if (($entry['package_id'] ?? '') === $package_id) {
			return $entry;
		}
	}

	return [];
}

function synchy_delete_export_history_item(string $package_id)
{
	$history = synchy_get_export_history();
	$entry = [];
	$remaining = [];

	foreach ($history as $item) {
		if ($entry === [] && ($item['package_id'] ?? '') === $package_id) {
			$entry = $item;
			continue;
		}

		$remaining[] = $item;
	}

	if ($entry === []) {
		return new WP_Error('synchy_export_missing', __('That Synchy export is no longer available.', 'synchy'));
	}

	$deleted_files = 0;
	$artifacts = isset($entry['artifacts']) && is_array($entry['artifacts']) ? $entry['artifacts'] : [];

	foreach ($artifacts as $artifact) {
		$path = wp_normalize_path((string) ($artifact['path'] ?? ''));

		if ($path === '' || !file_exists($path)) {
			continue;
		}

		if (!is_file($path)) {
			continue;
		}

		if (@unlink($path) === false) {
			return new WP_Error(
				'synchy_export_delete_failed',
				sprintf(
					/* translators: %s: file path */
					__('Synchy could not delete %s from the export history.', 'synchy'),
					$path
				)
			);
		}

		$deleted_files++;
	}

	synchy_update_export_history($remaining);

	return [
		'package_id' => $package_id,
		'package_name' => (string) ($entry['package_name'] ?? $package_id),
		'deleted_files' => $deleted_files,
	];
}

function synchy_update_export_job(array $job): array
{
	update_option(SYNCHY_EXPORT_JOB_OPTION, $job, false);

	return $job;
}

function synchy_get_export_job(): array
{
	$value = get_option(SYNCHY_EXPORT_JOB_OPTION, []);

	return is_array($value) ? $value : [];
}

function synchy_get_running_export_job(): array
{
	$job = synchy_get_export_job();

	if (($job['status'] ?? '') !== 'running') {
		return [];
	}

	return $job;
}

function synchy_update_site_sync_job(array $job): array
{
	update_option(SYNCHY_SITE_SYNC_JOB_OPTION, $job, false);

	return $job;
}

function synchy_get_site_sync_job(): array
{
	$value = get_option(SYNCHY_SITE_SYNC_JOB_OPTION, []);

	return is_array($value) ? $value : [];
}

function synchy_get_running_site_sync_job(): array
{
	$job = synchy_get_site_sync_job();

	if (($job['status'] ?? '') !== 'running') {
		return [];
	}

	return $job;
}

function synchy_absolute_to_relative(string $absolute_path, ?string $root = null): string
{
	$root = $root === null ? wp_normalize_path(untrailingslashit(ABSPATH)) : wp_normalize_path(untrailingslashit($root));
	$absolute_path = wp_normalize_path($absolute_path);

	if ($absolute_path === $root) {
		return '';
	}

	$prefix = $root . '/';

	if (!str_starts_with($absolute_path, $prefix)) {
		return synchy_normalize_relative_path($absolute_path);
	}

	return synchy_normalize_relative_path(substr($absolute_path, strlen($prefix)));
}

function synchy_is_absolute_path(string $path): bool
{
	return (bool) preg_match('#^([A-Za-z]:)?/#', wp_normalize_path($path));
}

function synchy_is_path_within(string $path, string $root): bool
{
	$path = wp_normalize_path(untrailingslashit($path));
	$root = wp_normalize_path(untrailingslashit($root));

	return $path === $root || str_starts_with($path . '/', $root . '/');
}

function synchy_resolve_output_directory_path(string $path)
{
	$path = synchy_sanitize_output_directory($path);

	if ($path === '') {
		$path = synchy_get_default_output_directory();
	}

	if (synchy_is_absolute_path($path)) {
		return wp_normalize_path(untrailingslashit($path));
	}

	return wp_normalize_path(untrailingslashit(trailingslashit(ABSPATH) . ltrim($path, '/')));
}

function synchy_display_output_directory(string $absolute_path): string
{
	$root = wp_normalize_path(untrailingslashit(ABSPATH));
	$absolute_path = wp_normalize_path(untrailingslashit($absolute_path));

	if (synchy_is_path_within($absolute_path, $root)) {
		$relative = synchy_absolute_to_relative($absolute_path, $root);

		return $relative === '' ? './' : trailingslashit($relative);
	}

	return trailingslashit($absolute_path);
}

function synchy_get_effective_exclude_patterns(array $options, string $output_directory_abs = ''): array
{
	$groups = synchy_get_export_filter_groups();
	$patterns = [];

	foreach ($groups as $key => $group) {
		if (empty($options[$key])) {
			continue;
		}

		foreach ($group['patterns'] as $pattern) {
			$patterns[] = synchy_normalize_relative_path($pattern);
		}
	}

	$custom = preg_split('/\r\n|\r|\n/', (string) ($options['custom_excludes'] ?? '')) ?: [];

	foreach ($custom as $pattern) {
		$pattern = synchy_normalize_relative_path($pattern);

		if ($pattern !== '') {
			$patterns[] = $pattern;
		}
	}

	if ($output_directory_abs !== '') {
		$root = wp_normalize_path(untrailingslashit(ABSPATH));
		$output_directory_abs = wp_normalize_path(untrailingslashit($output_directory_abs));

		if (synchy_is_path_within($output_directory_abs, $root)) {
			$patterns[] = trailingslashit(synchy_absolute_to_relative($output_directory_abs, $root));
		}
	}

	$patterns[] = 'wp-content/uploads/synchy-temp/';

	return array_values(array_unique(array_filter($patterns)));
}

function synchy_path_matches_pattern(string $relative_path, string $pattern, bool $is_dir): bool
{
	$relative_path = synchy_normalize_relative_path($relative_path);
	$pattern = synchy_normalize_relative_path($pattern);

	if ($relative_path === '' || $pattern === '') {
		return false;
	}

	$basename = wp_basename($relative_path);
	$is_prefix_pattern = str_ends_with($pattern, '/');
	$has_glob = strpbrk($pattern, '*?[') !== false;

	if ($is_prefix_pattern) {
		$prefix = rtrim($pattern, '/');

		return $relative_path === $prefix || str_starts_with($relative_path . '/', $prefix . '/');
	}

	if ($has_glob) {
		return fnmatch($pattern, $relative_path, FNM_PATHNAME) || fnmatch($pattern, $basename);
	}

	if (strpos($pattern, '/') === false) {
		if ($basename === $pattern) {
			return true;
		}

		return $is_dir && $relative_path === $pattern;
	}

	return $relative_path === $pattern;
}

function synchy_should_exclude_relative_path(string $relative_path, array $patterns, bool $is_dir): bool
{
	foreach ($patterns as $pattern) {
		if (synchy_path_matches_pattern($relative_path, (string) $pattern, $is_dir)) {
			return true;
		}
	}

	return false;
}

function synchy_collect_export_files(array $exclude_patterns)
{
	$root = wp_normalize_path(untrailingslashit(ABSPATH));

	try {
		$directory = new RecursiveDirectoryIterator(
			$root,
			FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO
		);
		$filter = new RecursiveCallbackFilterIterator(
			$directory,
			static function (SplFileInfo $current) use ($exclude_patterns, $root): bool {
				$absolute = wp_normalize_path($current->getPathname());
				$relative = synchy_absolute_to_relative($absolute, $root);

				if ($relative === '') {
					return true;
				}

				if ($current->isLink()) {
					return false;
				}

				return !synchy_should_exclude_relative_path($relative, $exclude_patterns, $current->isDir());
			}
		);
		$iterator = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::LEAVES_ONLY);
	} catch (UnexpectedValueException $exception) {
		return new WP_Error('synchy_iterator_failed', $exception->getMessage());
	}

	$files = [];
	$total_bytes = 0;

	foreach ($iterator as $file) {
		if (!$file instanceof SplFileInfo || !$file->isFile()) {
			continue;
		}

		$absolute = wp_normalize_path($file->getPathname());

		if (!is_readable($absolute)) {
			return new WP_Error('synchy_unreadable_file', sprintf(__('Synchy could not read %s while building the export.', 'synchy'), $absolute));
		}

		$relative = synchy_absolute_to_relative($absolute, $root);
		$size = (int) $file->getSize();

		$files[] = [
			'absolute' => $absolute,
			'relative' => $relative,
			'size' => $size,
		];

		$total_bytes += $size;
	}

	return [
		'files' => $files,
		'count' => count($files),
		'bytes' => $total_bytes,
	];
}

function synchy_get_zip_batch_size(): int
{
	$batch_size = (int) apply_filters('synchy_export_zip_batch_size', 500);

	return max(100, $batch_size);
}

function synchy_get_zip_build_mode(): string
{
	$mode = (string) apply_filters('synchy_export_zip_build_mode', 'continuous');

	return $mode === 'batched' ? 'batched' : 'continuous';
}

function synchy_get_zip_progress_update_interval(): int
{
	$interval = (int) apply_filters('synchy_export_zip_progress_update_interval', 500);

	return max(100, $interval);
}

function synchy_should_store_without_compression(string $relative_path): bool
{
	$extension = strtolower((string) pathinfo($relative_path, PATHINFO_EXTENSION));

	if ($extension === '') {
		return false;
	}

	$stored_extensions = [
		'7z',
		'avif',
		'bz2',
		'gif',
		'gz',
		'heic',
		'heif',
		'ico',
		'jpeg',
		'jpg',
		'mov',
		'mp3',
		'mp4',
		'pdf',
		'png',
		'rar',
		'svgz',
		'webm',
		'webp',
		'woff',
		'woff2',
		'zip',
	];

	return in_array($extension, $stored_extensions, true);
}

function synchy_maybe_optimize_zip_entry(ZipArchive $zip, string $relative_path): void
{
	if (!method_exists($zip, 'setCompressionName')) {
		return;
	}

	if (!synchy_should_store_without_compression($relative_path)) {
		return;
	}

	@$zip->setCompressionName($relative_path, ZipArchive::CM_STORE);
}

function synchy_get_export_zip_progress(int $cursor, int $total): int
{
	if ($total <= 0) {
		return 95;
	}

	return (int) floor(35 + (60 * ($cursor / $total)));
}

function synchy_get_export_zip_message(int $cursor, int $total): string
{
	return sprintf(
		/* translators: 1: current file count, 2: total file count */
		__('Added %1$s of %2$s files to the archive.', 'synchy'),
		number_format_i18n($cursor),
		number_format_i18n($total)
	);
}

function synchy_finalize_export_job(array $job): array
{
	$manifest = synchy_build_manifest($job);
	$manifest_path = (string) $job['artifact_paths']['manifest'];
	$installer_path = (string) $job['artifact_paths']['installer'];
	$manifest_json = wp_json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

	if ($manifest_json === false || file_put_contents($manifest_path, $manifest_json) === false) {
		return synchy_mark_export_job_error($job, __('Synchy could not write the manifest file.', 'synchy'));
	}

	$installer_contents = synchy_generate_installer_contents($manifest);

	if ($installer_contents === '' || file_put_contents($installer_path, $installer_contents) === false) {
		return synchy_mark_export_job_error($job, __('Synchy could not write the installer file.', 'synchy'));
	}

	synchy_rrmdir((string) $job['temp_dir']);

	$last_export = [
		'package_id' => $job['package_id'],
		'package_name' => $job['package_name'],
		'created_at' => gmdate('c'),
		'output_directory' => $job['output_directory'],
		'archive_size' => (int) filesize((string) $job['artifact_paths']['archive']),
		'file_count' => (int) $job['file_count'],
		'file_bytes' => (int) $job['file_bytes'],
		'table_count' => (int) $job['table_count'],
		'artifacts' => [
			'archive' => [
				'label' => __('Download archive', 'synchy'),
				'filename' => $job['artifact_names']['archive'],
				'path' => $job['artifact_paths']['archive'],
			],
			'installer' => [
				'label' => __('Download installer', 'synchy'),
				'filename' => $job['artifact_names']['installer'],
				'path' => $job['artifact_paths']['installer'],
			],
			'manifest' => [
				'label' => __('Download manifest', 'synchy'),
				'filename' => $job['artifact_names']['manifest'],
				'path' => $job['artifact_paths']['manifest'],
			],
		],
	];

	synchy_record_export_history($last_export);
	synchy_set_notice(
		'success',
		sprintf(
			/* translators: %s: export package name */
			__('Full export complete. %s is ready to download.', 'synchy'),
			$job['package_name']
		)
	);

	$job['status'] = 'complete';
	$job['phase'] = 'complete';
	$job['message'] = __('Export complete. Refreshing the page with download links.', 'synchy');
	$job['progress'] = 100;

	return synchy_update_export_job($job);
}

function synchy_process_export_zip_in_batches(array $job, array $files): array
{
	$cursor = (int) $job['cursor'];
	$total = count($files);
	$batch_size = synchy_get_zip_batch_size();
	$batch_end = min($cursor + $batch_size, $total);
	$archive_path = (string) $job['artifact_paths']['archive'];
	$flags = $cursor === 0 ? ZipArchive::CREATE | ZipArchive::OVERWRITE : ZipArchive::CREATE;
	$zip = new ZipArchive();
	$open_result = $zip->open($archive_path, $flags);

	if ($open_result !== true) {
		return synchy_mark_export_job_error($job, __('Synchy could not open the export archive for writing.', 'synchy'));
	}

	if ($cursor === 0 && !$zip->addFile((string) $job['database_path'], 'synchy/database.sql')) {
		$zip->close();
		return synchy_mark_export_job_error($job, __('Synchy could not add the database dump to the export archive.', 'synchy'));
	}

	for ($index = $cursor; $index < $batch_end; $index++) {
		$file = $files[$index];
		$relative_path = (string) $file['relative'];

		if (!$zip->addFile((string) $file['absolute'], $relative_path)) {
			$zip->close();
			return synchy_mark_export_job_error($job, sprintf(__('Synchy could not add %s to the archive.', 'synchy'), $relative_path));
		}

		synchy_maybe_optimize_zip_entry($zip, $relative_path);
	}

	$zip->close();
	$cursor = $batch_end;
	$job['cursor'] = $cursor;
	$job['progress'] = synchy_get_export_zip_progress($cursor, $total);

	if ($cursor >= $total) {
		$job['phase'] = 'finalizing';
		$job['message'] = __('Writing the manifest and installer files.', 'synchy');
		$job['progress'] = 96;

		return synchy_finalize_export_job($job);
	}

	$job['message'] = synchy_get_export_zip_message($cursor, $total);

	return synchy_update_export_job($job);
}

function synchy_process_export_zip_continuously(array $job, array $files): array
{
	$cursor = (int) $job['cursor'];
	$total = count($files);
	$archive_path = (string) $job['artifact_paths']['archive'];
	$flags = $cursor === 0 ? ZipArchive::CREATE | ZipArchive::OVERWRITE : ZipArchive::CREATE;
	$zip = new ZipArchive();
	$open_result = $zip->open($archive_path, $flags);

	if ($open_result !== true) {
		return synchy_mark_export_job_error($job, __('Synchy could not open the export archive for writing.', 'synchy'));
	}

	if ($cursor === 0 && !$zip->addFile((string) $job['database_path'], 'synchy/database.sql')) {
		$zip->close();
		return synchy_mark_export_job_error($job, __('Synchy could not add the database dump to the export archive.', 'synchy'));
	}

	$progress_interval = synchy_get_zip_progress_update_interval();

	for ($index = $cursor; $index < $total; $index++) {
		$file = $files[$index];
		$relative_path = (string) $file['relative'];

		if (!$zip->addFile((string) $file['absolute'], $relative_path)) {
			$zip->close();
			return synchy_mark_export_job_error($job, sprintf(__('Synchy could not add %s to the archive.', 'synchy'), $relative_path));
		}

		synchy_maybe_optimize_zip_entry($zip, $relative_path);

		$cursor = $index + 1;

		if ($cursor < $total && $cursor % $progress_interval === 0) {
			$job['cursor'] = $cursor;
			$job['progress'] = synchy_get_export_zip_progress($cursor, $total);
			$job['message'] = synchy_get_export_zip_message($cursor, $total);
			synchy_update_export_job($job);
		}
	}

	$close_result = $zip->close();

	if ($close_result !== true) {
		return synchy_mark_export_job_error($job, __('Synchy could not finish writing the export archive.', 'synchy'));
	}

	$job['cursor'] = $total;
	$job['progress'] = 96;
	$job['phase'] = 'finalizing';
	$job['message'] = __('Writing the manifest and installer files.', 'synchy');

	return synchy_finalize_export_job($job);
}

function synchy_process_export_zip_phase(array $job): array
{
	$files = synchy_get_export_file_manifest($job);

	if ($files === []) {
		return synchy_mark_export_job_error($job, __('Synchy could not load the file list for this export.', 'synchy'));
	}

	if (synchy_get_zip_build_mode() === 'batched') {
		return synchy_process_export_zip_in_batches($job, $files);
	}

	return synchy_process_export_zip_continuously($job, $files);
}

function synchy_sql_escape_string(string $value): string
{
	return strtr(
		$value,
		[
			'\\' => '\\\\',
			"\0" => '\\0',
			"\n" => '\\n',
			"\r" => '\\r',
			"'" => "\\'",
			"\x1a" => '\\Z',
		]
	);
}

function synchy_sql_value($value): string
{
	if ($value === null) {
		return 'NULL';
	}

	if (is_bool($value)) {
		return $value ? '1' : '0';
	}

	return "'" . synchy_sql_escape_string((string) $value) . "'";
}

function synchy_write_database_dump(string $file_path)
{
	global $wpdb;

	$handle = fopen($file_path, 'wb');

	if ($handle === false) {
		return new WP_Error('synchy_db_dump_open_failed', __('Synchy could not create the SQL dump file.', 'synchy'));
	}

	$write = static function ($content) use ($handle): void {
		fwrite($handle, (string) $content);
	};

	$write("-- Synchy SQL Dump\n");
	$write('-- Site: ' . home_url('/') . "\n");
	$write('-- Generated: ' . gmdate('c') . "\n\n");
	$write("SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';\n");
	$write("SET FOREIGN_KEY_CHECKS = 0;\n\n");

	$tables = $wpdb->get_results('SHOW FULL TABLES', ARRAY_N);

	if (!is_array($tables)) {
		fclose($handle);

		return new WP_Error('synchy_db_tables_failed', __('Synchy could not read the database table list.', 'synchy'));
	}

	$table_count = 0;

	foreach ($tables as $table_row) {
		$table = isset($table_row[0]) ? (string) $table_row[0] : '';
		$type = strtoupper((string) ($table_row[1] ?? 'BASE TABLE'));

		if ($table === '') {
			continue;
		}

		$table_name = str_replace('`', '``', $table);
		$table_count++;

		if ($type === 'VIEW') {
			$create_view = $wpdb->get_row("SHOW CREATE VIEW `{$table_name}`", ARRAY_N);

			if (!is_array($create_view) || empty($create_view[1])) {
				fclose($handle);

				return new WP_Error('synchy_db_view_failed', sprintf(__('Synchy could not export the database view %s.', 'synchy'), $table));
			}

			$write("-- View: {$table}\n");
			$write("DROP VIEW IF EXISTS `{$table_name}`;\n");
			$write($create_view[1] . ";\n\n");
			continue;
		}

		$create_table = $wpdb->get_row("SHOW CREATE TABLE `{$table_name}`", ARRAY_N);

		if (!is_array($create_table) || empty($create_table[1])) {
			fclose($handle);

			return new WP_Error('synchy_db_create_failed', sprintf(__('Synchy could not export the table definition for %s.', 'synchy'), $table));
		}

		$write("-- Table: {$table}\n");
		$write("DROP TABLE IF EXISTS `{$table_name}`;\n");
		$write($create_table[1] . ";\n\n");

		$total_rows = (int) $wpdb->get_var("SELECT COUNT(*) FROM `{$table_name}`");

		if ($total_rows < 1) {
			$write("\n");
			continue;
		}

		$limit = 250;

		for ($offset = 0; $offset < $total_rows; $offset += $limit) {
			$query = $wpdb->prepare("SELECT * FROM `{$table_name}` LIMIT %d OFFSET %d", $limit, $offset);
			$rows = $wpdb->get_results($query, ARRAY_A);

			if (!is_array($rows)) {
				fclose($handle);

				return new WP_Error('synchy_db_rows_failed', sprintf(__('Synchy could not read rows from %s.', 'synchy'), $table));
			}

			foreach ($rows as $row) {
				$columns = array_map(
					static fn(string $column): string => '`' . str_replace('`', '``', $column) . '`',
					array_keys($row)
				);
				$values = array_map('synchy_sql_value', array_values($row));

				$write(
					'INSERT INTO `' . $table_name . '` (' . implode(', ', $columns) . ') VALUES (' . implode(', ', $values) . ");\n"
				);
			}
		}

		$write("\n");
	}

	$write("SET FOREIGN_KEY_CHECKS = 1;\n");
	fclose($handle);

	return [
		'tables' => $table_count,
		'size' => (int) filesize($file_path),
	];
}

function synchy_rrmdir(string $path): void
{
	if (!file_exists($path)) {
		return;
	}

	if (is_file($path) || is_link($path)) {
		@unlink($path);
		return;
	}

	$items = scandir($path);

	if (!is_array($items)) {
		return;
	}

	foreach ($items as $item) {
		if ($item === '.' || $item === '..') {
			continue;
		}

		synchy_rrmdir($path . DIRECTORY_SEPARATOR . $item);
	}

	@rmdir($path);
}

function synchy_export_phase_label(string $phase): string
{
	return match ($phase) {
		'queued' => __('Queued', 'synchy'),
		'dumping_database' => __('Database', 'synchy'),
		'scanning_files' => __('Scanning Files', 'synchy'),
		'zipping_files' => __('Building Archive', 'synchy'),
		'finalizing' => __('Finalizing', 'synchy'),
		'complete' => __('Complete', 'synchy'),
		'error' => __('Error', 'synchy'),
		default => __('Preparing', 'synchy'),
	};
}

function synchy_get_export_stage_definitions(): array
{
	return [
		'queued' => [
			'label' => __('Prepare Job', 'synchy'),
			'description' => __('Set up the temporary workspace and package files.', 'synchy'),
		],
		'dumping_database' => [
			'label' => __('Export Database', 'synchy'),
			'description' => __('Write the SQL dump that goes inside the package.', 'synchy'),
		],
		'scanning_files' => [
			'label' => __('Scan Files', 'synchy'),
			'description' => __('Index the WordPress files that belong in the export.', 'synchy'),
		],
		'zipping_files' => [
			'label' => __('Build Archive', 'synchy'),
			'description' => __('Add the database dump and site files into the zip archive.', 'synchy'),
		],
		'finalizing' => [
			'label' => __('Write Installer', 'synchy'),
			'description' => __('Generate installer.php and the manifest for this package.', 'synchy'),
		],
		'complete' => [
			'label' => __('Export Ready', 'synchy'),
			'description' => __('The package is complete and ready to download.', 'synchy'),
		],
	];
}

function synchy_get_export_stage_order(): array
{
	return array_keys(synchy_get_export_stage_definitions());
}

function synchy_get_export_stage_index(string $phase): int
{
	$order = synchy_get_export_stage_order();
	$index = array_search($phase, $order, true);

	return $index === false ? -1 : (int) $index;
}

function synchy_get_export_stage_items(array $job): array
{
	$definitions = synchy_get_export_stage_definitions();
	$status = (string) ($job['status'] ?? '');
	$phase = (string) ($job['phase'] ?? '');
	$active_phase = $status === 'error' ? (string) ($job['last_phase'] ?? '') : $phase;
	$active_index = synchy_get_export_stage_index($active_phase);
	$items = [];

	foreach ($definitions as $stage_key => $definition) {
		$index = synchy_get_export_stage_index($stage_key);
		$state = 'pending';

		if ($status === 'complete') {
			$state = 'complete';
		} elseif ($status === 'error') {
			if ($active_index >= 0 && $index < $active_index) {
				$state = 'complete';
			} elseif ($active_index >= 0 && $index === $active_index) {
				$state = 'error';
			}
		} elseif ($status === 'running') {
			if ($active_index >= 0 && $index < $active_index) {
				$state = 'complete';
			} elseif ($active_index >= 0 && $index === $active_index) {
				$state = 'active';
			}
		}

		$items[] = [
			'key' => $stage_key,
			'label' => (string) $definition['label'],
			'description' => (string) $definition['description'],
			'state' => $state,
		];
	}

	return $items;
}

function synchy_build_job_response(array $job): array
{
	if ($job === []) {
		return [
			'stages' => synchy_get_export_stage_items([]),
		];
	}
	
	return [
		'id' => (string) ($job['job_id'] ?? ''),
		'packageId' => (string) ($job['package_id'] ?? ''),
		'packageName' => (string) ($job['package_name'] ?? ''),
		'status' => (string) ($job['status'] ?? ''),
		'phase' => (string) ($job['phase'] ?? ''),
		'phaseLabel' => synchy_export_phase_label((string) ($job['phase'] ?? 'queued')),
		'message' => (string) ($job['message'] ?? ''),
		'progress' => (int) round((float) ($job['progress'] ?? 0)),
		'fileCount' => (int) ($job['file_count'] ?? 0),
		'fileCursor' => (int) ($job['cursor'] ?? 0),
		'fileBytes' => (int) ($job['file_bytes'] ?? 0),
		'outputDirectory' => (string) ($job['output_directory'] ?? ''),
		'artifactNames' => $job['artifact_names'] ?? [],
		'stages' => synchy_get_export_stage_items($job),
	];
}

function synchy_site_sync_phase_label(string $phase): string
{
	return match ($phase) {
		'testing_connection' => __('Testing Connection', 'synchy'),
		'starting_export' => __('Preparing Export', 'synchy'),
		'exporting_package' => __('Building Package', 'synchy'),
		'starting_remote_session' => __('Starting Destination Session', 'synchy'),
		'uploading_archive' => __('Uploading Archive', 'synchy'),
		'uploading_installer' => __('Uploading Installer', 'synchy'),
		'uploading_manifest' => __('Uploading Manifest', 'synchy'),
		'finalizing_remote_package' => __('Finalizing Package', 'synchy'),
		'complete' => __('Complete', 'synchy'),
		'error' => __('Error', 'synchy'),
		default => __('Preparing', 'synchy'),
	};
}

function synchy_get_site_sync_stage_definitions(): array
{
	return [
		'testing_connection' => [
			'label' => __('Verify Connection', 'synchy'),
			'description' => __('Authenticate with the destination WordPress site before any package work starts.', 'synchy'),
		],
		'starting_export' => [
			'label' => __('Prepare Package', 'synchy'),
			'description' => __('Set up the full export job that Upload to Live depends on.', 'synchy'),
		],
		'exporting_package' => [
			'label' => __('Build Package', 'synchy'),
			'description' => __('Run the full Synchy export that produces the zip and installer.', 'synchy'),
		],
		'starting_remote_session' => [
			'label' => __('Open Destination Session', 'synchy'),
			'description' => __('Create the upload session and staging paths on the destination site.', 'synchy'),
		],
		'uploading_archive' => [
			'label' => __('Upload Archive', 'synchy'),
			'description' => __('Transfer the main Synchy zip archive to the destination.', 'synchy'),
		],
		'uploading_installer' => [
			'label' => __('Upload Installer', 'synchy'),
			'description' => __('Transfer installer.php so the destination can run the manual restore.', 'synchy'),
		],
		'finalizing_remote_package' => [
			'label' => __('Place Files in Root', 'synchy'),
			'description' => __('Finalize the upload and try to place the zip and installer in the destination WordPress root.', 'synchy'),
		],
		'complete' => [
			'label' => __('Ready to Restore', 'synchy'),
			'description' => __('The package is on the destination and ready for installer.php.', 'synchy'),
		],
	];
}

function synchy_get_site_sync_stage_order(): array
{
	return array_keys(synchy_get_site_sync_stage_definitions());
}

function synchy_get_site_sync_stage_index(string $phase): int
{
	$order = synchy_get_site_sync_stage_order();
	$index = array_search($phase, $order, true);

	return $index === false ? -1 : (int) $index;
}

function synchy_get_site_sync_stage_items(array $job): array
{
	$definitions = synchy_get_site_sync_stage_definitions();
	$status = (string) ($job['status'] ?? '');
	$phase = (string) ($job['phase'] ?? '');
	$active_phase = $status === 'error' ? (string) ($job['last_phase'] ?? '') : $phase;
	$active_index = synchy_get_site_sync_stage_index($active_phase);
	$items = [];

	foreach ($definitions as $stage_key => $definition) {
		$index = synchy_get_site_sync_stage_index($stage_key);
		$state = 'pending';

		if ($status === 'complete') {
			$state = 'complete';
		} elseif ($status === 'error') {
			if ($active_index >= 0 && $index < $active_index) {
				$state = 'complete';
			} elseif ($active_index >= 0 && $index === $active_index) {
				$state = 'error';
			}
		} elseif ($status === 'running') {
			if ($active_index >= 0 && $index < $active_index) {
				$state = 'complete';
			} elseif ($active_index >= 0 && $index === $active_index) {
				$state = 'active';
			}
		}

		$items[] = [
			'key' => $stage_key,
			'label' => (string) $definition['label'],
			'description' => (string) $definition['description'],
			'state' => $state,
		];
	}

	return $items;
}

function synchy_build_site_sync_job_response(array $job): array
{
	if ($job === []) {
		return [
			'stages' => synchy_get_site_sync_stage_items([]),
		];
	}

	$progress = (int) round((float) ($job['progress'] ?? 0));
	$current_artifact = (string) ($job['current_artifact'] ?? '');
	$artifact_uploads = isset($job['artifact_uploads']) && is_array($job['artifact_uploads']) ? $job['artifact_uploads'] : [];
	$current_artifact_state = isset($artifact_uploads[$current_artifact]) && is_array($artifact_uploads[$current_artifact]) ? $artifact_uploads[$current_artifact] : [];
	$artifact_bytes_uploaded = (int) ($current_artifact_state['offset'] ?? 0);
	$artifact_bytes_total = (int) ($current_artifact_state['size'] ?? 0);
	$artifact_progress = 0;

	if ($artifact_bytes_total > 0) {
		$artifact_progress = min(100, max(0, (int) floor(($artifact_bytes_uploaded / $artifact_bytes_total) * 100)));
	}

	return [
		'id' => (string) ($job['job_id'] ?? ''),
		'status' => (string) ($job['status'] ?? ''),
		'phase' => (string) ($job['phase'] ?? ''),
		'phaseLabel' => synchy_site_sync_phase_label((string) ($job['phase'] ?? '')),
		'message' => (string) ($job['message'] ?? ''),
		'progress' => $progress,
		'createdAt' => (string) ($job['created_at'] ?? ''),
		'progressLabel' => in_array((string) ($job['phase'] ?? ''), ['uploading_archive', 'uploading_installer'], true)
			? sprintf(
				/* translators: %d: overall progress percent */
				__('%d%% overall', 'synchy'),
				$progress
			)
			: sprintf(
				/* translators: %d: progress percent */
				__('%d%%', 'synchy'),
				$progress
			),
		'packageName' => (string) ($job['package_name'] ?? ''),
		'destinationUrl' => (string) ($job['destination_url'] ?? ''),
		'remoteSiteName' => (string) ($job['remote_site']['name'] ?? ''),
		'remoteSiteUrl' => (string) ($job['remote_site']['siteUrl'] ?? ''),
		'bytesUploaded' => (int) ($job['bytes_uploaded'] ?? 0),
		'bytesTotal' => (int) ($job['bytes_total'] ?? 0),
		'currentArtifact' => $current_artifact,
		'artifactBytesUploaded' => $artifact_bytes_uploaded,
		'artifactBytesTotal' => $artifact_bytes_total,
		'artifactProgress' => $artifact_progress,
		'remoteSessionId' => (string) ($job['remote_session_id'] ?? ''),
		'installerUrl' => (string) (($job['remote_package']['installerUrl'] ?? '')),
		'installerPath' => (string) (($job['remote_package']['installerPath'] ?? '')),
		'archivePath' => (string) (($job['remote_package']['archivePath'] ?? '')),
		'stagedPath' => (string) (($job['remote_package']['destinationPath'] ?? '')),
		'rootPath' => (string) (($job['remote_package']['rootPath'] ?? '')),
		'deployStatus' => (string) (($job['remote_package']['deployStatus'] ?? '')),
		'stages' => synchy_get_site_sync_stage_items($job),
	];
}

function synchy_mark_export_job_error(array $job, string $message): array
{
	if (($job['phase'] ?? '') !== 'error') {
		$job['last_phase'] = (string) ($job['phase'] ?? '');
	}

	$job['status'] = 'error';
	$job['phase'] = 'error';
	$job['message'] = $message;
	$job['progress'] = 100;

	if (!empty($job['temp_dir'])) {
		synchy_rrmdir((string) $job['temp_dir']);
	}

	synchy_set_notice('error', $message);

	return synchy_update_export_job($job);
}

function synchy_mark_site_sync_job_error(array $job, string $message): array
{
	if (($job['phase'] ?? '') !== 'error') {
		$job['last_phase'] = (string) ($job['phase'] ?? '');
	}

	$job['status'] = 'error';
	$job['phase'] = 'error';
	$job['message'] = $message;
	$job['progress'] = 100;

	synchy_set_notice('error', $message);

	return synchy_update_site_sync_job($job);
}

function synchy_get_export_file_manifest(array $job): array
{
	$path = (string) ($job['file_manifest_path'] ?? '');

	if ($path === '' || !is_readable($path)) {
		return [];
	}

	$decoded = json_decode((string) file_get_contents($path), true);

	return is_array($decoded) ? $decoded : [];
}

function synchy_build_manifest(array $job): array
{
	global $wpdb;

	$archive_path = (string) $job['artifact_paths']['archive'];

	return [
		'plugin' => 'Synchy',
		'plugin_version' => SYNCHY_VERSION,
		'package_id' => $job['package_id'],
		'package_name' => $job['package_name'],
		'package_mode' => 'full_export',
		'created_at_gmt' => gmdate('c'),
		'site' => [
			'home_url' => home_url('/'),
			'site_url' => site_url('/'),
			'wordpress_version' => get_bloginfo('version'),
			'php_version' => PHP_VERSION,
			'db_prefix' => $wpdb->prefix,
		],
		'output_directory' => $job['output_directory'],
		'filters' => [
			'active_groups' => array_values(
				array_keys(
					array_filter(
						$job['options'],
						static fn($value, $key): bool => str_starts_with((string) $key, 'exclude_') && !empty($value),
						ARRAY_FILTER_USE_BOTH
					)
				)
			),
			'custom_excludes' => preg_split('/\r\n|\r|\n/', (string) ($job['options']['custom_excludes'] ?? '')) ?: [],
		],
		'database' => [
			'path_in_archive' => 'synchy/database.sql',
			'tables' => (int) ($job['table_count'] ?? 0),
			'size_bytes' => (int) ($job['database_size'] ?? 0),
		],
		'files' => [
			'included_count' => (int) ($job['file_count'] ?? 0),
			'included_bytes' => (int) ($job['file_bytes'] ?? 0),
		],
		'artifacts' => [
			'archive' => [
				'filename' => $job['artifact_names']['archive'],
				'size_bytes' => (int) filesize($archive_path),
				'sha256' => hash_file('sha256', $archive_path),
			],
			'installer' => [
				'filename' => $job['artifact_names']['installer'],
			],
			'manifest' => [
				'filename' => $job['artifact_names']['manifest'],
			],
		],
	];
}

function synchy_escape_php_single_quoted_string(string $value): string
{
	return str_replace(
		["\\", "'"],
		["\\\\", "\\'"],
		$value
	);
}

function synchy_get_installer_template_path(): string
{
	return wp_normalize_path(plugin_dir_path(__FILE__) . 'assets/installer-template.php');
}

function synchy_generate_installer_contents(array $manifest, string $access_token = ''): string
{
	$template_path = synchy_get_installer_template_path();

	if (!is_readable($template_path)) {
		return '';
	}

	$template = (string) file_get_contents($template_path);
	$archive = isset($manifest['artifacts']['archive']) && is_array($manifest['artifacts']['archive']) ? $manifest['artifacts']['archive'] : [];
	$site = isset($manifest['site']) && is_array($manifest['site']) ? $manifest['site'] : [];
	$token_value = $access_token === '' ? '__SYNCHY_ACCESS_TOKEN__' : synchy_escape_php_single_quoted_string($access_token);

	return strtr(
		$template,
		[
			'__SYNCHY_ACCESS_TOKEN__' => $token_value,
			'__SYNCHY_PACKAGE_ID__' => synchy_escape_php_single_quoted_string((string) ($manifest['package_id'] ?? '')),
			'__SYNCHY_PACKAGE_NAME__' => synchy_escape_php_single_quoted_string((string) ($manifest['package_name'] ?? '')),
			'__SYNCHY_ARCHIVE_FILENAME__' => synchy_escape_php_single_quoted_string((string) ($archive['filename'] ?? 'site.zip')),
			'__SYNCHY_ARCHIVE_SIZE_BYTES__' => synchy_escape_php_single_quoted_string((string) ($archive['size_bytes'] ?? '0')),
			'__SYNCHY_ARCHIVE_SHA256__' => synchy_escape_php_single_quoted_string((string) ($archive['sha256'] ?? '')),
			'__SYNCHY_SOURCE_HOME_URL__' => synchy_escape_php_single_quoted_string((string) ($site['home_url'] ?? '')),
			'__SYNCHY_SOURCE_SITE_URL__' => synchy_escape_php_single_quoted_string((string) ($site['site_url'] ?? '')),
			'__SYNCHY_SOURCE_DB_PREFIX__' => synchy_escape_php_single_quoted_string((string) ($site['db_prefix'] ?? '')),
		]
	);
}

function synchy_start_export_job(array $raw_options, bool $force = false)
{
	$existing_job = synchy_get_running_export_job();

	if (!$force && $existing_job !== []) {
		return new WP_Error('synchy_export_running', __('A Synchy export is already running. Wait for it to finish before starting another one.', 'synchy'));
	}

	if (!class_exists('ZipArchive')) {
		return new WP_Error('synchy_missing_zip', __('ZipArchive is not available on this server.', 'synchy'));
	}

	$options = synchy_sanitize_export_options($raw_options);

	if ($options['package_name'] === '') {
		$options['package_name'] = synchy_get_default_package_name();
	}

	$package_name = synchy_sanitize_package_name((string) $options['package_name']);
	$output_directory_abs = synchy_resolve_output_directory_path((string) $options['output_directory']);
	$output_directory_abs = wp_normalize_path(untrailingslashit($output_directory_abs));

	if (!wp_mkdir_p($output_directory_abs)) {
		return new WP_Error('synchy_output_dir_failed', __('Synchy could not create the export destination folder.', 'synchy'));
	}

	$package_id = 'synchy-' . gmdate('Ymd-His') . '-' . strtolower(wp_generate_password(6, false, false));
	$temp_dir = trailingslashit($output_directory_abs) . '.synchy-' . $package_id;
	$file_manifest_path = trailingslashit($temp_dir) . 'files.json';
	$database_path = trailingslashit($temp_dir) . 'database.sql';

	if (file_exists($temp_dir)) {
		synchy_rrmdir($temp_dir);
	}

	if (!wp_mkdir_p($temp_dir)) {
		return new WP_Error('synchy_temp_failed', __('Synchy could not create the temporary export workspace.', 'synchy'));
	}

	$artifact_paths = [
		'archive' => trailingslashit($output_directory_abs) . $package_name . '.zip',
		'installer' => trailingslashit($output_directory_abs) . $package_name . '-installer.php',
		'manifest' => trailingslashit($output_directory_abs) . $package_name . '-manifest.json',
	];
	$artifact_names = [
		'archive' => basename($artifact_paths['archive']),
		'installer' => basename($artifact_paths['installer']),
		'manifest' => basename($artifact_paths['manifest']),
	];

	foreach ($artifact_paths as $path) {
		if (file_exists($path)) {
			@unlink($path);
		}
	}

	$job = [
		'job_id' => wp_generate_uuid4(),
		'package_id' => $package_id,
		'package_name' => $package_name,
		'status' => 'running',
		'phase' => 'queued',
		'message' => __('Preparing export job.', 'synchy'),
		'progress' => 1,
		'created_at' => gmdate('c'),
		'output_directory' => synchy_display_output_directory($output_directory_abs),
		'output_directory_path' => $output_directory_abs,
		'options' => $options,
		'artifact_paths' => $artifact_paths,
		'artifact_names' => $artifact_names,
		'temp_dir' => $temp_dir,
		'file_manifest_path' => $file_manifest_path,
		'database_path' => $database_path,
		'file_count' => 0,
		'file_bytes' => 0,
		'cursor' => 0,
		'table_count' => 0,
		'database_size' => 0,
	];

	return synchy_update_export_job($job);
}

function synchy_process_export_job(array $job): array
{
	if (($job['status'] ?? '') !== 'running') {
		return $job;
	}

	if (function_exists('ignore_user_abort')) {
		ignore_user_abort(true);
	}

	if (function_exists('set_time_limit')) {
		@set_time_limit(0);
	}

	switch ($job['phase']) {
		case 'queued':
			$job['phase'] = 'dumping_database';
			$job['message'] = __('Exporting the database dump.', 'synchy');
			$job['progress'] = 8;
			return synchy_update_export_job($job);

		case 'dumping_database':
			$database_dump = synchy_write_database_dump((string) $job['database_path']);

			if (is_wp_error($database_dump)) {
				return synchy_mark_export_job_error($job, $database_dump->get_error_message());
			}

			$job['table_count'] = (int) $database_dump['tables'];
			$job['database_size'] = (int) $database_dump['size'];
			$job['phase'] = 'scanning_files';
			$job['message'] = __('Scanning files to include in the export.', 'synchy');
			$job['progress'] = 22;

			return synchy_update_export_job($job);

		case 'scanning_files':
			$exclude_patterns = synchy_get_effective_exclude_patterns(
				$job['options'],
				(string) $job['output_directory_path']
			);
			$file_collection = synchy_collect_export_files($exclude_patterns);

			if (is_wp_error($file_collection)) {
				return synchy_mark_export_job_error($job, $file_collection->get_error_message());
			}

			$json = wp_json_encode($file_collection['files'], JSON_UNESCAPED_SLASHES);

			if ($json === false || file_put_contents((string) $job['file_manifest_path'], $json) === false) {
				return synchy_mark_export_job_error($job, __('Synchy could not write the temporary file index for this export.', 'synchy'));
			}

			$job['file_count'] = (int) $file_collection['count'];
			$job['file_bytes'] = (int) $file_collection['bytes'];
			$job['cursor'] = 0;
			$job['phase'] = 'zipping_files';
			$job['message'] = __('Building the archive package.', 'synchy');
			$job['progress'] = 34;

			return synchy_update_export_job($job);

		case 'zipping_files':
			return synchy_process_export_zip_phase($job);

		case 'finalizing':
			return synchy_finalize_export_job($job);

		default:
			return synchy_mark_export_job_error($job, __('Synchy encountered an unknown export phase.', 'synchy'));
	}
}

function synchy_build_export_package(array $raw_options)
{
	$job = synchy_start_export_job($raw_options, true);

	if (is_wp_error($job)) {
		return $job;
	}

	do {
		$job = synchy_process_export_job($job);
	} while (($job['status'] ?? '') === 'running');

	if (($job['status'] ?? '') !== 'complete') {
		return new WP_Error('synchy_export_failed', (string) ($job['message'] ?? __('Synchy export failed.', 'synchy')));
	}

	return synchy_get_last_export();
}

function synchy_get_site_sync_package_directory(): string
{
	return trailingslashit(synchy_get_default_output_directory() . 'site-sync');
}

function synchy_get_site_sync_upload_chunk_bytes(): int
{
	$bytes = (int) apply_filters('synchy_site_sync_upload_chunk_bytes', 1 * MB_IN_BYTES);

	return max(512 * KB_IN_BYTES, $bytes);
}

function synchy_get_site_sync_export_options(array $site_sync_options): array
{
	$export_options = synchy_get_export_options();
	$destination_host = (string) wp_parse_url((string) ($site_sync_options['destination_url'] ?? ''), PHP_URL_HOST);
	$destination_slug = sanitize_title($destination_host !== '' ? $destination_host : 'destination');

	$export_options['output_directory'] = synchy_get_site_sync_package_directory();
	$export_options['package_name'] = 'synchy-site-sync-' . $destination_slug . '-' . gmdate('Ymd-His');

	return $export_options;
}

function synchy_validate_site_sync_options(array $options)
{
	if ((string) ($options['destination_url'] ?? '') === '') {
		return new WP_Error('synchy_site_sync_missing_url', __('Enter the destination WordPress URL before continuing.', 'synchy'));
	}

	if ((string) ($options['destination_username'] ?? '') === '') {
		return new WP_Error('synchy_site_sync_missing_username', __('Enter the destination username before continuing.', 'synchy'));
	}

	if ((string) ($options['destination_application_password'] ?? '') === '') {
		return new WP_Error('synchy_site_sync_missing_password', __('Enter the destination application password before continuing.', 'synchy'));
	}

	$current_home = untrailingslashit(home_url('/'));
	$destination_home = untrailingslashit((string) $options['destination_url']);

	if ($current_home !== '' && $destination_home !== '' && $current_home === $destination_home) {
		return new WP_Error('synchy_site_sync_same_site', __('The destination URL matches this site. Choose a different WordPress site.', 'synchy'));
	}

	return true;
}

function synchy_get_site_sync_route_url(array $options, string $route): string
{
	return trailingslashit((string) $options['destination_url']) . 'wp-json/synchy/v1/' . ltrim($route, '/');
}

function synchy_site_sync_remote_request(array $options, string $route, string $method = 'GET', array $request_args = [])
{
	$validation = synchy_validate_site_sync_options($options);

	if (is_wp_error($validation)) {
		return $validation;
	}

	$url = synchy_get_site_sync_route_url($options, $route);
	$headers = isset($request_args['headers']) && is_array($request_args['headers']) ? $request_args['headers'] : [];
	$headers['Authorization'] = 'Basic ' . base64_encode(
		(string) $options['destination_username'] . ':' . (string) $options['destination_application_password']
	);
	$headers['Accept'] = 'application/json';

	$args = [
		'method' => strtoupper($method),
		'timeout' => (int) ($request_args['timeout'] ?? 30),
		'sslverify' => !empty($options['verify_ssl']),
		'headers' => $headers,
	];

	if (array_key_exists('body', $request_args)) {
		$args['body'] = $request_args['body'];
	}

	if (isset($request_args['data_format'])) {
		$args['data_format'] = $request_args['data_format'];
	}

	$response = wp_remote_request($url, $args);

	if (is_wp_error($response)) {
		return new WP_Error(
			'synchy_site_sync_remote_request_failed',
			sprintf(
				/* translators: 1: remote URL, 2: error message */
				__('Synchy could not reach %1$s. %2$s', 'synchy'),
				$url,
				$response->get_error_message()
			)
		);
	}

	$code = (int) wp_remote_retrieve_response_code($response);
	$body = (string) wp_remote_retrieve_body($response);
	$decoded = json_decode($body, true);
	$data = is_array($decoded) && array_key_exists('data', $decoded) ? $decoded['data'] : $decoded;

	if ($code < 200 || $code >= 300) {
		$message = is_array($data) && !empty($data['message'])
			? (string) $data['message']
			: sprintf(
				/* translators: %d: HTTP status code */
				__('Destination site returned HTTP %d.', 'synchy'),
				$code
			);

		return new WP_Error('synchy_site_sync_remote_http_error', $message, ['status' => $code, 'body' => $data]);
	}

	if (is_array($decoded) && array_key_exists('success', $decoded) && !$decoded['success']) {
		$message = is_array($data) && !empty($data['message']) ? (string) $data['message'] : __('The destination site rejected the Synchy request.', 'synchy');

		return new WP_Error('synchy_site_sync_remote_error', $message, ['body' => $data]);
	}

	if (!is_array($data)) {
		return ['rawBody' => $body];
	}

	return $data;
}

function synchy_test_site_sync_connection(array $options)
{
	$response = synchy_site_sync_remote_request($options, 'push/ping', 'GET', ['timeout' => 20]);

	if (is_wp_error($response)) {
		return $response;
	}

	if (empty($response['siteUrl']) || empty($response['pluginVersion'])) {
		return new WP_Error('synchy_site_sync_invalid_ping', __('The destination site responded, but it did not look like a Synchy receiver.', 'synchy'));
	}

	return $response;
}

function synchy_build_self_update_package()
{
	if (!class_exists('ZipArchive')) {
		return new WP_Error('synchy_missing_zip', __('ZipArchive is not available on this server.', 'synchy'));
	}

	$temp_dir = synchy_prepare_sync_temp_dir('plugin-self-update');

	if (is_wp_error($temp_dir)) {
		return $temp_dir;
	}

	$plugin_dir = wp_normalize_path(plugin_dir_path(__FILE__));
	$zip_path = wp_normalize_path(trailingslashit($temp_dir) . 'synchy.zip');
	$zip = new ZipArchive();
	$result = $zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE);

	if ($result !== true) {
		synchy_rrmdir($temp_dir);
		return new WP_Error('synchy_self_update_zip_open_failed', __('Synchy could not create the remote plugin update package.', 'synchy'));
	}

	$iterator = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator($plugin_dir, FilesystemIterator::SKIP_DOTS),
		RecursiveIteratorIterator::SELF_FIRST
	);

	foreach ($iterator as $item) {
		if (!$item instanceof SplFileInfo || !$item->isFile()) {
			continue;
		}

		$absolute_path = wp_normalize_path($item->getPathname());
		$relative_path = ltrim(str_replace($plugin_dir, '', $absolute_path), '/');

		if ($relative_path === '' || str_starts_with($relative_path, '.git/')) {
			continue;
		}

		if (!$zip->addFile($absolute_path, 'synchy/' . $relative_path)) {
			$zip->close();
			synchy_rrmdir($temp_dir);
			return new WP_Error(
				'synchy_self_update_zip_add_failed',
				sprintf(
					/* translators: %s: plugin file path */
					__('Synchy could not add %s to the remote plugin update package.', 'synchy'),
					$relative_path
				)
			);
		}
	}

	$zip->close();

	return [
		'zip_path' => $zip_path,
		'temp_dir' => $temp_dir,
		'filename' => 'synchy.zip',
	];
}

function synchy_copy_directory_contents(string $source_dir, string $destination_dir)
{
	$source_dir = wp_normalize_path($source_dir);
	$destination_dir = wp_normalize_path($destination_dir);

	if (!is_dir($source_dir)) {
		return new WP_Error('synchy_copy_source_missing', __('Synchy could not find the extracted plugin files to install.', 'synchy'));
	}

	if (!wp_mkdir_p($destination_dir)) {
		return new WP_Error('synchy_copy_destination_missing', __('Synchy could not prepare the destination plugin folder.', 'synchy'));
	}

	$iterator = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator($source_dir, FilesystemIterator::SKIP_DOTS),
		RecursiveIteratorIterator::SELF_FIRST
	);

	foreach ($iterator as $item) {
		if (!$item instanceof SplFileInfo) {
			continue;
		}

		$source_path = wp_normalize_path($item->getPathname());
		$relative_path = ltrim(str_replace($source_dir, '', $source_path), '/');
		$destination_path = wp_normalize_path(trailingslashit($destination_dir) . $relative_path);

		if ($item->isDir()) {
			if (!wp_mkdir_p($destination_path)) {
				return new WP_Error(
					'synchy_copy_destination_dir_failed',
					sprintf(
						/* translators: %s: directory path */
						__('Synchy could not prepare the plugin folder %s on the destination site.', 'synchy'),
						$relative_path
					)
				);
			}

			continue;
		}

		if (!wp_mkdir_p(dirname($destination_path))) {
			return new WP_Error('synchy_copy_destination_parent_failed', __('Synchy could not prepare the destination plugin parent folder.', 'synchy'));
		}

		if (@copy($source_path, $destination_path) === false) {
			return new WP_Error(
				'synchy_copy_destination_file_failed',
				sprintf(
					/* translators: %s: file path */
					__('Synchy could not install the Synchy file %s on the destination site.', 'synchy'),
					$relative_path
				)
			);
		}
	}

	return true;
}

function synchy_apply_self_update_package(string $zip_path)
{
	if (!function_exists('unzip_file')) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
	}

	if (!function_exists('unzip_file')) {
		return new WP_Error('synchy_self_update_unzip_missing', __('WordPress unzip support is not available on the destination site.', 'synchy'));
	}

	$temp_dir = synchy_prepare_sync_temp_dir('plugin-self-update-receive');

	if (is_wp_error($temp_dir)) {
		return $temp_dir;
	}

	try {
		$unzipped = unzip_file($zip_path, $temp_dir);

		if (is_wp_error($unzipped)) {
			return $unzipped;
		}

		$source_dir = wp_normalize_path(trailingslashit($temp_dir) . 'synchy');
		$destination_dir = wp_normalize_path(plugin_dir_path(__FILE__));
		$copied = synchy_copy_directory_contents($source_dir, $destination_dir);

		if (is_wp_error($copied)) {
			return $copied;
		}

		return [
			'pluginVersion' => SYNCHY_VERSION,
			'pluginDirectory' => $destination_dir,
		];
	} finally {
		if (is_dir($temp_dir)) {
			synchy_rrmdir($temp_dir);
		}
	}
}

function synchy_update_remote_synchy(array $options)
{
	$package = synchy_build_self_update_package();

	if (is_wp_error($package)) {
		return $package;
	}

	try {
		$response = synchy_site_sync_remote_request(
			$options,
			'plugin/update-self',
			'POST',
			[
				'timeout' => 120,
				'headers' => [
					'Content-Type' => 'application/zip',
					'X-Synchy-Filename' => (string) ($package['filename'] ?? 'synchy.zip'),
				],
				'body' => file_get_contents((string) $package['zip_path']),
				'data_format' => 'body',
			]
		);

		if (is_wp_error($response)) {
			return $response;
		}

		return $response;
	} finally {
		if (!empty($package['temp_dir']) && is_dir((string) $package['temp_dir'])) {
			synchy_rrmdir((string) $package['temp_dir']);
		}
	}
}

function synchy_get_remote_sync_status(array $options)
{
	$response = synchy_site_sync_remote_request($options, 'push/status', 'GET', ['timeout' => 20]);

	if (is_wp_error($response)) {
		return $response;
	}

	if (!is_array($response)) {
		return new WP_Error('synchy_site_sync_invalid_status', __('The destination site returned an invalid Sync status payload.', 'synchy'));
	}

	return $response;
}

function synchy_get_sync_remote_route_url(array $options): string
{
	return trailingslashit((string) $options['destination_url']) . 'wp-json/syncy/v1/sync';
}

function synchy_sync_remote_request(array $options, int $expected_sync_time, string $zip_path, array $extra_headers = [])
{
	$validation = synchy_validate_site_sync_options($options);

	if (is_wp_error($validation)) {
		return $validation;
	}

	if (!is_readable($zip_path)) {
		return new WP_Error('synchy_sync_package_missing', __('Synchy could not read the generated sync package before upload.', 'synchy'));
	}

	$body = file_get_contents($zip_path);

	if ($body === false || $body === '') {
		return new WP_Error('synchy_sync_package_read_failed', __('Synchy could not read the sync package data before upload.', 'synchy'));
	}

	$response = wp_remote_post(
		synchy_get_sync_remote_route_url($options),
		[
			'timeout' => 600,
			'sslverify' => !empty($options['verify_ssl']),
			'headers' => array_merge([
				'Authorization' => 'Basic ' . base64_encode(
					(string) $options['destination_username'] . ':' . (string) $options['destination_application_password']
				),
				'Content-Type' => 'application/zip',
				'Accept' => 'application/json',
				'X-Syncy-Filename' => basename($zip_path),
			], $extra_headers),
			'body' => $body,
			'data_format' => 'body',
		]
	);

	if (is_wp_error($response)) {
		return new WP_Error(
			'synchy_sync_remote_request_failed',
			sprintf(
				/* translators: 1: remote URL, 2: error message */
				__('Synchy could not reach %1$s. %2$s', 'synchy'),
				synchy_get_sync_remote_route_url($options),
				$response->get_error_message()
			)
		);
	}

	$code = (int) wp_remote_retrieve_response_code($response);
	$body = (string) wp_remote_retrieve_body($response);
	$data = json_decode($body, true);

	if ($code < 200 || $code >= 300 || !is_array($data)) {
		if (in_array($code, [502, 503, 504], true) && $expected_sync_time > 0) {
			$recovered = synchy_wait_for_remote_sync_completion($options, $expected_sync_time, 150);

			if (!is_wp_error($recovered)) {
				return $recovered;
			}
		}

		$message = is_array($data) && !empty($data['message'])
			? (string) $data['message']
			: sprintf(__('Destination site returned HTTP %d during Sync.', 'synchy'), $code);

		return new WP_Error('synchy_sync_remote_http_error', $message);
	}

	if (!empty($data['success']) || !array_key_exists('success', $data)) {
		return isset($data['data']) && is_array($data['data']) ? $data['data'] : $data;
	}

	$message = isset($data['message']) ? (string) $data['message'] : __('The destination site rejected the Sync request.', 'synchy');

	return new WP_Error('synchy_sync_remote_rejected', $message);
}

function synchy_wait_for_remote_sync_completion(array $options, int $expected_sync_time, int $timeout_seconds = 150)
{
	$deadline = time() + max(15, $timeout_seconds);
	$last_error = null;

	while (time() <= $deadline) {
		$status = synchy_get_remote_sync_status($options);

		if (!is_wp_error($status)) {
			$remote_status = isset($status['status']) && is_array($status['status']) ? $status['status'] : [];
			$last_sync_time = max(0, (int) ($remote_status['lastSyncTime'] ?? 0));
			$state = (string) ($remote_status['status'] ?? '');

			if ($state === 'success' && $last_sync_time >= $expected_sync_time) {
				return [
					'success' => true,
					'mode' => (string) ($remote_status['mode'] ?? 'delta'),
					'filesSynced' => (int) ($remote_status['filesSynced'] ?? 0),
					'dbRowsSynced' => (int) ($remote_status['dbRowsSynced'] ?? 0),
					'lastSyncTime' => $last_sync_time,
					'message' => (string) ($remote_status['message'] ?? __('Destination site finished Sync after its HTTP response timed out.', 'synchy')),
					'recoveredAfterHttpError' => true,
				];
			}

			if ($state === 'error' && $last_sync_time >= $expected_sync_time) {
				return new WP_Error(
					'synchy_sync_remote_rejected',
					(string) ($remote_status['message'] ?? __('The destination site reported a Sync error after its HTTP response timed out.', 'synchy'))
				);
			}
		} else {
			$last_error = $status;
		}

		sleep(5);
	}

	return $last_error instanceof WP_Error
		? $last_error
		: new WP_Error('synchy_sync_remote_status_timeout', __('The destination site did not confirm whether the timed-out Sync finished successfully.', 'synchy'));
}

function synchy_build_sync_batch_request_headers(array $job, array $batch): array
{
	return [
		'X-Syncy-Sync-Id' => (string) ($job['sync_id'] ?? ''),
		'X-Syncy-Batch-Id' => (string) ($batch['batch_id'] ?? ''),
		'X-Syncy-Batch-Label' => rawurlencode((string) ($batch['label'] ?? '')),
		'X-Syncy-Batch-Type' => (string) ($batch['type'] ?? ''),
		'X-Syncy-Batch-Sequence' => (string) ((int) ($batch['sequence'] ?? 0)),
	];
}

function synchy_build_sync_batch_package(array $options, array $job, array $batch)
{
	$batch_payload = synchy_read_full_sync_batch_payload($batch);
	$temp_dir = synchy_prepare_sync_temp_dir('full-batch');

	if (is_wp_error($temp_dir)) {
		return $temp_dir;
	}

	$file_delta = [
		'mode' => 'baseline',
		'files' => array_values((array) ($batch_payload['files'] ?? [])),
		'count' => (int) ($batch['file_count'] ?? 0),
		'bytes' => array_sum(array_map(static fn(array $file): int => (int) ($file['size'] ?? 0), (array) ($batch_payload['files'] ?? []))),
		'baseline_scopes' => [(string) ($batch['scope_id'] ?? '')],
		'selected_scopes' => [(string) ($batch['scope_id'] ?? '')],
	];
	$db_tables = (array) ($batch_payload['tables'] ?? []);
	$db_total_rows = 0;

	foreach ($db_tables as $table_data) {
		$db_total_rows += count((array) ($table_data['rows'] ?? []));
	}

	$db_delta = [
		'mode' => 'baseline',
		'tables' => $db_tables,
		'table_counts' => array_map(static fn(array $table): int => count((array) ($table['rows'] ?? [])), $db_tables),
		'total_rows' => $db_total_rows,
		'current_fingerprints' => [],
		'baseline_scopes' => [(string) ($batch['scope_id'] ?? '')],
		'selected_scopes' => [(string) ($batch['scope_id'] ?? '')],
	];
	$sync_time = max(0, (int) ($job['sync_time_base'] ?? time())) + max(1, (int) ($batch['sequence'] ?? 1));
	$written = synchy_write_sync_package_from_parts($file_delta, $db_delta, $sync_time, $options, $temp_dir);

	if (is_wp_error($written)) {
		synchy_rrmdir($temp_dir);
		return $written;
	}

	return [
		'temp_dir' => $temp_dir,
		'zip_path' => (string) ($written['zip_path'] ?? ''),
		'sync_time' => $sync_time,
	];
}

function synchy_calculate_full_sync_job_progress(array $job): int
{
	$total = max(1, (int) ($job['total_work_units'] ?? 0));
	$completed = max(0, (int) ($job['completed_work_units'] ?? 0));

	return min(99, (int) floor(($completed / $total) * 100));
}

function synchy_mark_full_sync_batch_complete(array $job, int $index): array
{
	$batch = (array) ($job['batches'][$index] ?? []);
	$job['batches'][$index]['status'] = 'complete';
	$job['batches'][$index]['completed_at'] = gmdate('c');
	$job['batches'][$index]['error_message'] = '';
	$job['completed_batches'] = (int) ($job['completed_batches'] ?? 0) + 1;
	$job['completed_work_units'] = (int) ($job['completed_work_units'] ?? 0) + (int) ($batch['work_units'] ?? 0);
	$job['progress'] = synchy_calculate_full_sync_job_progress($job);

	return $job;
}

function synchy_mark_full_sync_batch_failed(array $job, int $index, string $message): array
{
	$job['batches'][$index]['status'] = 'failed';
	$job['batches'][$index]['error_message'] = $message;
	$job['batches'][$index]['failed_at'] = gmdate('c');
	$job['status'] = 'failed_partial';
	$job['phase'] = 'error';
	$job['resumable'] = true;
	$job['pause_requested'] = false;
	$job['message'] = $message;
	synchy_set_sync_status([
		'status' => 'error',
		'mode' => 'baseline',
		'filesSynced' => (int) ($job['files_count'] ?? 0),
		'dbRowsSynced' => (int) ($job['db_rows'] ?? 0),
		'durationSeconds' => 0,
		'destinationUrl' => (string) ($job['destination_url'] ?? ''),
		'selectedScopeLabels' => (array) ($job['selected_scope_labels'] ?? []),
		'at' => gmdate('c'),
		'message' => $message,
		'lastSyncTime' => synchy_get_sync_last_time(),
	]);

	return synchy_update_sync_job($job);
}

function synchy_finalize_full_sync_success(array $job, array $options, float $started_at): array
{
	$next_state = isset($job['next_state']) && is_array($job['next_state']) ? $job['next_state'] : [];
	$next_state['last_result'] = [
		'mode' => 'baseline',
		'filesSynced' => (int) ($job['files_count'] ?? 0),
		'dbRowsSynced' => (int) ($job['db_rows'] ?? 0),
		'at' => gmdate('c'),
	];

	$state_written = synchy_write_sync_state($next_state);
	$sync_time = max(0, (int) ($next_state['last_sync_time'] ?? time()));
	synchy_set_sync_last_time($sync_time);
	$duration = round(microtime(true) - $started_at, 2);
	$job['status'] = 'complete';
	$job['phase'] = 'complete';
	$job['progress'] = 100;
	$job['resumable'] = false;
	$job['pause_requested'] = false;
	$job['current_batch_label'] = '';
	$job['message'] = sprintf(
		__('Full Sync finished: %1$d files, %2$d DB rows, %3$d batches in %4$s.', 'synchy'),
		(int) ($job['files_count'] ?? 0),
		(int) ($job['db_rows'] ?? 0),
		(int) ($job['total_batches'] ?? 0),
		synchy_format_sync_duration($duration)
	);
	synchy_update_sync_job($job);

	$status = [
		'status' => 'success',
		'mode' => 'baseline',
		'filesSynced' => (int) ($job['files_count'] ?? 0),
		'dbRowsSynced' => (int) ($job['db_rows'] ?? 0),
		'durationSeconds' => $duration,
		'destinationUrl' => (string) ($options['destination_url'] ?? ''),
		'selectedScopeLabels' => (array) ($job['selected_scope_labels'] ?? []),
		'at' => gmdate('c'),
		'lastSyncTime' => $sync_time,
		'message' => $job['message'],
	];

	if (is_wp_error($state_written)) {
		$status['message'] .= ' ' . __('The live site finished, but Synchy could not update the local sync state file.', 'synchy');
	}

	synchy_set_sync_status($status);

	if (!empty($job['temp_dir']) && is_dir((string) $job['temp_dir'])) {
		synchy_rrmdir((string) $job['temp_dir']);
	}

	return $status;
}

function synchy_process_full_sync_job(array $job, array $options)
{
	$batches = array_values(array_filter((array) ($job['batches'] ?? []), 'is_array'));
	$started_at = (float) ($job['started_at_unix'] ?? microtime(true));

	if (($job['status'] ?? '') !== 'running') {
		return $job;
	}

	foreach ($batches as $index => $batch) {
		$state = (string) ($job['batches'][$index]['status'] ?? 'pending');

		if ($state === 'complete' || $state === 'running') {
			continue;
		}

		$job['status'] = 'running';
		$job['phase'] = 'sending_package';
		$job['current_batch_index'] = $index + 1;
		$job['current_batch_label'] = (string) ($batch['label'] ?? '');
		$job['message'] = sprintf(
			__('Syncing batch %1$d of %2$d: %3$s', 'synchy'),
			$index + 1,
			count($batches),
			(string) ($batch['label'] ?? '')
		);
		$job['batches'][$index]['status'] = 'running';
		synchy_update_sync_job($job);

		$package = synchy_build_sync_batch_package($options, $job, $batch);

		if (is_wp_error($package)) {
			return synchy_mark_full_sync_batch_failed($job, $index, $package->get_error_message());
		}

		$remote = synchy_sync_remote_request(
			$options,
			(int) ($package['sync_time'] ?? 0),
			(string) ($package['zip_path'] ?? ''),
			synchy_build_sync_batch_request_headers($job, $batch)
		);

		if (!empty($package['temp_dir']) && is_dir((string) $package['temp_dir'])) {
			synchy_rrmdir((string) $package['temp_dir']);
		}

		if (is_wp_error($remote)) {
			return synchy_mark_full_sync_batch_failed($job, $index, $remote->get_error_message());
		}

		$job = synchy_mark_full_sync_batch_complete($job, $index);
		synchy_update_sync_job($job);

		if (!empty($job['pause_requested']) && ($index + 1) < count($batches)) {
			$job['status'] = 'paused';
			$job['phase'] = 'complete';
			$job['message'] = __('Full Sync paused after the current batch. Resume to continue the remaining items.', 'synchy');
			$job['resumable'] = true;
			$job['current_batch_label'] = '';
			synchy_update_sync_job($job);
			synchy_set_sync_status([
				'status' => 'paused',
				'mode' => 'baseline',
				'filesSynced' => (int) ($job['files_count'] ?? 0),
				'dbRowsSynced' => (int) ($job['db_rows'] ?? 0),
				'durationSeconds' => round(microtime(true) - $started_at, 2),
				'destinationUrl' => (string) ($options['destination_url'] ?? ''),
				'selectedScopeLabels' => (array) ($job['selected_scope_labels'] ?? []),
				'at' => gmdate('c'),
				'message' => $job['message'],
				'lastSyncTime' => synchy_get_sync_last_time(),
			]);
			return $job;
		}

		return $job;
	}

	return synchy_finalize_full_sync_success($job, $options, $started_at);
}

function synchy_pause_full_sync_job(): array|WP_Error
{
	$job = synchy_get_sync_job();

	if (($job['run_mode'] ?? '') !== 'full' || ($job['status'] ?? '') !== 'running') {
		return new WP_Error('synchy_full_sync_not_running', __('There is no running full Sync to pause right now.', 'synchy'));
	}

	$job['pause_requested'] = true;
	$job['message'] = __('Pause requested. Synchy will stop after the current batch finishes.', 'synchy');

	return synchy_update_sync_job($job);
}

function synchy_resume_full_sync_job(array $options)
{
	$job = synchy_get_sync_job();

	if (($job['run_mode'] ?? '') !== 'full' || !synchy_is_resumable_sync_job_status((string) ($job['status'] ?? ''))) {
		return new WP_Error('synchy_full_sync_not_resumable', __('There is no paused or partial full Sync available to resume.', 'synchy'));
	}

	if ((string) ($job['options_signature'] ?? '') !== synchy_build_sync_options_signature($options)) {
		return new WP_Error('synchy_full_sync_resume_mismatch', __('The saved full Sync no longer matches the current destination or scope settings. Run a fresh Full Sync preview first.', 'synchy'));
	}

	if (empty($job['temp_dir']) || !is_dir((string) $job['temp_dir'])) {
		return new WP_Error('synchy_full_sync_resume_missing', __('Synchy could not find the saved full Sync plan on disk. Run a fresh Full Sync preview first.', 'synchy'));
	}

	$job['status'] = 'running';
	$job['phase'] = 'sending_package';
	$job['pause_requested'] = false;
	$job['message'] = __('Resuming the remaining full Sync batches.', 'synchy');
	$job = synchy_update_sync_job($job);
	$job = synchy_schedule_full_sync_worker($job, 0);
	synchy_trigger_full_sync_worker_async((string) ($job['worker_token'] ?? ''));

	return $job;
}

function synchy_continue_full_sync_job(array $options)
{
	$job = synchy_get_sync_job();

	if (($job['run_mode'] ?? '') !== 'full') {
		return new WP_Error('synchy_full_sync_not_found', __('There is no full Sync job available to continue.', 'synchy'));
	}

	if (($job['status'] ?? '') !== 'running') {
		return $job;
	}

	return synchy_process_full_sync_job($job, $options);
}

function synchy_run_full_sync_worker_by_token(string $worker_token)
{
	$worker_token = sanitize_text_field($worker_token);
	$job = synchy_get_sync_job();

	if ($worker_token === '' || ($job['run_mode'] ?? '') !== 'full' || (string) ($job['worker_token'] ?? '') !== $worker_token) {
		return new WP_Error('synchy_full_sync_worker_missing', __('Synchy could not find the requested full Sync worker.', 'synchy'));
	}

	if (($job['status'] ?? '') !== 'running') {
		return $job;
	}

	$lock_token = wp_generate_password(20, false, false);
	$locked_job = synchy_acquire_full_sync_job_lock($job, $lock_token);

	if (is_wp_error($locked_job)) {
		if ($locked_job->get_error_code() === 'synchy_full_sync_locked') {
			return $job;
		}

		return $locked_job;
	}

	$job = $locked_job;

	try {
		$options = synchy_get_site_sync_options();
		$result = synchy_process_full_sync_job($job, $options);

		if (is_wp_error($result)) {
			return $result;
		}

		$job = is_array($result) ? $result : synchy_get_sync_job();
		$job = synchy_release_full_sync_job_lock($job, $lock_token);

		if (($job['run_mode'] ?? '') === 'full' && ($job['status'] ?? '') === 'running') {
			$job = synchy_schedule_full_sync_worker($job, 1);
			synchy_trigger_full_sync_worker_async((string) ($job['worker_token'] ?? ''));
		}

		return $job;
	} finally {
		$latest_job = synchy_get_sync_job();

		if (($latest_job['run_mode'] ?? '') === 'full' && (string) ($latest_job['worker_lock_token'] ?? '') === $lock_token) {
			synchy_release_full_sync_job_lock($latest_job, $lock_token);
		}
	}
}

function synchy_sync_apply_replacements($value, array $replacements, bool &$changed)
{
	if (is_string($value)) {
		if (function_exists('is_serialized') && is_serialized($value)) {
			$decoded = maybe_unserialize($value);
			$updated = synchy_sync_apply_replacements($decoded, $replacements, $changed);

			return maybe_serialize($updated);
		}

		$updated = $value;

		foreach ($replacements as $search => $replace) {
			$updated = str_replace($search, $replace, $updated);
		}

		if ($updated !== $value) {
			$changed = true;
		}

		return $updated;
	}

	if (is_array($value)) {
		foreach ($value as $key => $item) {
			$value[$key] = synchy_sync_apply_replacements($item, $replacements, $changed);
		}

		return $value;
	}

	if (is_object($value)) {
		foreach (get_object_vars($value) as $key => $item) {
			$value->$key = synchy_sync_apply_replacements($item, $replacements, $changed);
		}

		return $value;
	}

	return $value;
}

function synchy_get_sync_replacements(array $manifest): array
{
	$source = isset($manifest['source']) && is_array($manifest['source']) ? $manifest['source'] : [];
	$target_home = untrailingslashit(home_url('/'));
	$target_home_trailing = trailingslashit($target_home);
	$target_site = untrailingslashit(site_url('/'));
	$target_site_trailing = trailingslashit($target_site);
	$target_abs = wp_normalize_path(ABSPATH);
	$target_content = wp_normalize_path(WP_CONTENT_DIR);
	$replacements = [];

	$append_pairs = static function (array &$pairs, string $search, string $replace, ?string $replace_trailing = null): void {
		$search = trim($search);
		$replace = trim($replace);

		if ($search === '' || $replace === '') {
			return;
		}

		$replace_trailing = $replace_trailing ?? trailingslashit($replace);
		$pairs[] = [$search, str_ends_with($search, '/') ? $replace_trailing : $replace];

		$trimmed_search = untrailingslashit($search);

		if ($trimmed_search !== '') {
			$pairs[] = [$trimmed_search, $replace];
			$pairs[] = [trailingslashit($trimmed_search), $replace_trailing];
		}
	};

	$pairs = [];
	$append_pairs($pairs, (string) ($source['siteUrl'] ?? ''), $target_site, $target_site_trailing);
	$append_pairs($pairs, (string) ($source['homeUrl'] ?? ''), $target_home, $target_home_trailing);
	$append_pairs($pairs, (string) ($source['contentPath'] ?? ''), $target_content, trailingslashit($target_content));
	$append_pairs($pairs, (string) ($source['absPath'] ?? ''), $target_abs, trailingslashit($target_abs));
	$append_pairs($pairs, $target_site . 'wp-content/', $target_site_trailing . 'wp-content/', $target_site_trailing . 'wp-content/');
	$append_pairs($pairs, $target_home . 'wp-content/', $target_home_trailing . 'wp-content/', $target_home_trailing . 'wp-content/');

	foreach ((array) ($source['siteUrlAliases'] ?? []) as $alias) {
		$alias = trim((string) $alias);

		if ($alias === '') {
			continue;
		}

		$append_pairs($pairs, $alias, $target_site, $target_site_trailing);
	}

	foreach ((array) ($source['homeUrlAliases'] ?? []) as $alias) {
		$alias = trim((string) $alias);

		if ($alias === '') {
			continue;
		}

		$append_pairs($pairs, $alias, $target_home, $target_home_trailing);
	}

	foreach ($pairs as $pair) {
		$search = (string) $pair[0];
		$replace = (string) $pair[1];

		if ($search === '' || $replace === '' || $search === $replace) {
			continue;
		}

		$replacements[$search] = $replace;
		$trimmed_search = untrailingslashit($search);
		$trimmed_replace = untrailingslashit($replace);

		if ($trimmed_search !== '' && $trimmed_search !== $search && !isset($replacements[$trimmed_search])) {
			$replacements[$trimmed_search] = $trimmed_replace;
		}
	}

	uksort(
		$replacements,
		static fn(string $left, string $right): int => strlen($right) <=> strlen($left)
	);

	return $replacements;
}

function synchy_build_sync_sql_from_manifest(array $manifest, string $sql_path)
{
	global $wpdb;

	$database = isset($manifest['database']) && is_array($manifest['database']) ? $manifest['database'] : [];
	$tables = isset($database['tables']) && is_array($database['tables']) ? $database['tables'] : [];
	$replacements = synchy_get_sync_replacements($manifest);
	$prepared_tables = [];
	$prepared_option_rows = [];

	foreach ($tables as $table => $data) {
		if (!is_array($data)) {
			continue;
		}

		$rows = isset($data['rows']) && is_array($data['rows']) ? $data['rows'] : [];
		$prepared_rows = [];

		foreach ($rows as $row) {
			if (!is_array($row)) {
				continue;
			}

			$changed = false;
			$prepared_rows[] = synchy_sync_apply_replacements($row, $replacements, $changed);
		}

		if ($table === $wpdb->options) {
			$prepared_option_rows = $prepared_rows;
			continue;
		}

		$prepared_tables[$table] = [
			'rows' => $prepared_rows,
			'key_columns' => array_values((array) ($data['keyColumns'] ?? [])),
			'update_columns' => array_values((array) ($data['updateColumns'] ?? [])),
		];
	}

	$result = synchy_write_sync_sql_file($prepared_tables, $sql_path);

	if (is_wp_error($result)) {
		return $result;
	}

	return [
		'tables' => $prepared_tables,
		'optionRows' => $prepared_option_rows,
		'totalRows' => array_sum(array_map(static fn(array $table): int => count((array) ($table['rows'] ?? [])), $prepared_tables)) + count($prepared_option_rows),
	];
}

function synchy_normalize_sync_option_autoload($autoload)
{
	if (is_bool($autoload)) {
		return $autoload ? 'yes' : 'no';
	}

	$autoload = strtolower(trim((string) $autoload));

	if ($autoload === '') {
		return null;
	}

	$truthy = ['yes', 'on', 'true', '1', 'auto', 'auto-on', 'auto-yes'];
	$falsy = ['no', 'off', 'false', '0', 'auto-off', 'auto-no'];

	if (in_array($autoload, $truthy, true)) {
		return 'yes';
	}

	if (in_array($autoload, $falsy, true)) {
		return 'no';
	}

	return null;
}

function synchy_apply_sync_option_rows(array $rows)
{
	global $wpdb;

	if ($rows === []) {
		return 0;
	}

	$applied = 0;

	foreach ($rows as $row) {
		if (!is_array($row)) {
			continue;
		}

		$option_name = isset($row['option_name']) ? (string) $row['option_name'] : '';

		if ($option_name === '') {
			continue;
		}

		$option_value = array_key_exists('option_value', $row) ? maybe_unserialize($row['option_value']) : null;
		$autoload = synchy_normalize_sync_option_autoload($row['autoload'] ?? null);
		$exists = get_option($option_name, null);

		if ($exists === null) {
			if ($autoload === null) {
				add_option($option_name, $option_value);
			} else {
				add_option($option_name, $option_value, '', $autoload === 'yes');
			}
		} elseif ($autoload === null) {
			update_option($option_name, $option_value);
		} else {
			update_option($option_name, $option_value, $autoload === 'yes');
		}

		if ($autoload !== null) {
			$wpdb->update(
				$wpdb->options,
				['autoload' => $autoload],
				['option_name' => $option_name],
				['%s'],
				['%s']
			);
		}

		wp_cache_delete($option_name, 'options');
		$applied++;
	}

	wp_cache_delete('alloptions', 'options');
	wp_load_alloptions(true);

	return $applied;
}

function synchy_iterate_sync_sql_statements(string $sql_path, callable $callback): int
{
	$handle = @fopen($sql_path, 'rb');

	if ($handle === false) {
		throw new RuntimeException('Could not open the Sync SQL file.');
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

function synchy_execute_sync_sql_file(string $sql_path)
{
	global $wpdb;

	$wpdb->query('START TRANSACTION');

	try {
		$count = synchy_iterate_sync_sql_statements(
			$sql_path,
			static function (string $statement) use ($wpdb): void {
				$result = $wpdb->query($statement);

				if ($result === false) {
					throw new RuntimeException((string) $wpdb->last_error);
				}
			}
		);

		$wpdb->query('COMMIT');

		return $count;
	} catch (Throwable $throwable) {
		$wpdb->query('ROLLBACK');

		return new WP_Error(
			'synchy_sync_sql_execute_failed',
			sprintf(
				/* translators: %s: SQL error */
				__('Synchy could not apply the Sync database delta. %s', 'synchy'),
				$throwable->getMessage()
			)
		);
	}
}

function synchy_validate_sync_zip_entries(ZipArchive $zip)
{
	$allowed = [];
	$has_manifest = false;
	$has_sql = false;

	for ($index = 0; $index < $zip->numFiles; $index++) {
		$name = wp_normalize_path((string) $zip->getNameIndex($index));

		if ($name === '' || str_contains($name, '../') || str_starts_with($name, '/')) {
			return new WP_Error('synchy_sync_zip_invalid_path', __('The Sync package contains an invalid file path.', 'synchy'));
		}

		if (
			!str_starts_with($name, 'plugins/')
			&& !str_starts_with($name, 'themes/')
			&& !str_starts_with($name, 'uploads/')
			&& !str_starts_with($name, '.synchy-sync/')
		) {
			return new WP_Error(
				'synchy_sync_zip_invalid_scope',
				sprintf(
					/* translators: %s: zip entry path */
					__('The Sync package contains a disallowed path: %s', 'synchy'),
					$name
				)
			);
		}

		if ($name === '.synchy-sync/db/manifest.json') {
			$has_manifest = true;
		}

		if ($name === '.synchy-sync/db/delta.sql') {
			$has_sql = true;
		}

		$allowed[] = $name;
	}

	if (!$has_manifest || !$has_sql) {
		return new WP_Error('synchy_sync_zip_missing_meta', __('The Sync package is missing its manifest or SQL metadata.', 'synchy'));
	}

	return $allowed;
}

function synchy_extract_sync_package_to_content(string $zip_path)
{
	$zip = new ZipArchive();
	$result = $zip->open($zip_path);

	if ($result !== true) {
		return new WP_Error('synchy_sync_zip_open_failed', __('Synchy could not open the uploaded Sync package.', 'synchy'));
	}

	$entries = synchy_validate_sync_zip_entries($zip);

	if (is_wp_error($entries)) {
		$zip->close();
		return $entries;
	}

	$extracted = $zip->extractTo(WP_CONTENT_DIR, $entries);
	$zip->close();

	if (!$extracted) {
		return new WP_Error('synchy_sync_extract_failed', __('Synchy could not extract the Sync package into wp-content.', 'synchy'));
	}

	return [
		'manifest_path' => wp_normalize_path(WP_CONTENT_DIR . '/.synchy-sync/db/manifest.json'),
		'sql_path' => wp_normalize_path(WP_CONTENT_DIR . '/.synchy-sync/db/delta.sql'),
		'meta_root' => wp_normalize_path(WP_CONTENT_DIR . '/.synchy-sync'),
	];
}

function synchy_clear_sync_caches(): void
{
	if (function_exists('wp_cache_flush')) {
		wp_cache_flush();
	}

	if (function_exists('wp_clean_themes_cache')) {
		wp_clean_themes_cache();
	}

	if (function_exists('delete_expired_transients')) {
		delete_expired_transients();
	}

	if (has_action('litespeed_purge_all')) {
		do_action('litespeed_purge_all');
	}

	if (has_action('litespeed_purge_all_object')) {
		do_action('litespeed_purge_all_object');
	}
}

function synchy_handle_remote_sync_request(WP_REST_Request $request)
{
	if (!class_exists('ZipArchive')) {
		return new WP_Error('synchy_sync_zip_missing', __('ZipArchive is not available on the destination site.', 'synchy'), ['status' => 500]);
	}

	if (function_exists('wp_raise_memory_limit')) {
		wp_raise_memory_limit('admin');
	}

	if (function_exists('set_time_limit')) {
		@set_time_limit(0);
	}

	$temp_dir = synchy_prepare_sync_temp_dir('incoming');

	if (is_wp_error($temp_dir)) {
		return new WP_Error($temp_dir->get_error_code(), $temp_dir->get_error_message(), ['status' => 500]);
	}

	$meta_root = '';

	try {
		$filename = sanitize_file_name((string) $request->get_header('X-Syncy-Filename'));

		if ($filename === '') {
			$filename = 'sync-package.zip';
		}

		$zip_path = wp_normalize_path(trailingslashit($temp_dir) . $filename);
		$body = $request->get_body();

		if ($body === '') {
			return new WP_Error('synchy_sync_request_empty', __('Synchy received an empty Sync package.', 'synchy'), ['status' => 400]);
		}

		if (file_put_contents($zip_path, $body) === false) {
			return new WP_Error('synchy_sync_request_write_failed', __('Synchy could not save the uploaded Sync package on the destination site.', 'synchy'), ['status' => 500]);
		}

		$extract = synchy_extract_sync_package_to_content($zip_path);

		if (is_wp_error($extract)) {
			return new WP_Error($extract->get_error_code(), $extract->get_error_message(), ['status' => 400]);
		}

		$meta_root = (string) ($extract['meta_root'] ?? '');
		$manifest_path = (string) ($extract['manifest_path'] ?? '');

		if ($manifest_path === '' || !is_readable($manifest_path)) {
			return new WP_Error('synchy_sync_manifest_missing', __('Synchy could not find the uploaded Sync manifest on the destination site.', 'synchy'), ['status' => 400]);
		}

		$manifest = json_decode((string) file_get_contents($manifest_path), true);

		if (!is_array($manifest)) {
			return new WP_Error('synchy_sync_manifest_invalid', __('Synchy could not decode the uploaded Sync manifest.', 'synchy'), ['status' => 400]);
		}

		$sql_path = wp_normalize_path(trailingslashit($temp_dir) . 'apply.sql');
		$prepared_sql = synchy_build_sync_sql_from_manifest($manifest, $sql_path);

		if (is_wp_error($prepared_sql)) {
			return new WP_Error($prepared_sql->get_error_code(), $prepared_sql->get_error_message(), ['status' => 500]);
		}

		$executed = synchy_execute_sync_sql_file($sql_path);

		if (is_wp_error($executed)) {
			return new WP_Error($executed->get_error_code(), $executed->get_error_message(), ['status' => 500]);
		}

		$applied_option_rows = synchy_apply_sync_option_rows((array) ($prepared_sql['optionRows'] ?? []));

		$synced_at = max(0, (int) ($manifest['syncedAt'] ?? time()));
		$files_synced = (int) ($manifest['files']['count'] ?? 0);
		$db_rows_synced = (int) ($prepared_sql['totalRows'] ?? 0);
		$mode = (string) ($manifest['mode'] ?? ($synced_at > 0 ? 'delta' : 'baseline'));

		synchy_set_sync_last_time($synced_at);
		synchy_set_sync_status([
			'status' => 'success',
			'mode' => $mode,
			'filesSynced' => $files_synced,
			'dbRowsSynced' => $db_rows_synced,
			'durationSeconds' => 0,
			'destinationUrl' => home_url('/'),
			'at' => gmdate('c'),
			'lastSyncTime' => $synced_at,
			'message' => sprintf(
				/* translators: 1: file count, 2: row count */
				__('Applied Sync with %1$d files and %2$d DB rows on the destination site.', 'synchy'),
				$files_synced,
				$db_rows_synced
			),
			'optionRowsApplied' => $applied_option_rows,
		]);

		synchy_clear_sync_caches();

		return rest_ensure_response([
			'success' => true,
			'mode' => $mode,
			'filesSynced' => $files_synced,
			'dbRowsSynced' => $db_rows_synced,
			'lastSyncTime' => $synced_at,
			'message' => sprintf(
				/* translators: 1: file count, 2: row count */
				__('Synced %1$d files and %2$d DB rows on the destination site.', 'synchy'),
				$files_synced,
				$db_rows_synced
			),
		]);
	} finally {
		if ($meta_root !== '' && is_dir($meta_root)) {
			synchy_rrmdir($meta_root);
		}

		if (is_string($temp_dir) && $temp_dir !== '' && is_dir($temp_dir)) {
			synchy_rrmdir($temp_dir);
		}
	}
}

function synchy_format_sync_duration(float $seconds): string
{
	$seconds = max(0.01, $seconds);

	return number_format($seconds, 2) . 's';
}

function synchy_preview_sync_changes(array $raw_options)
{
	$options = synchy_sanitize_site_sync_options($raw_options);
	$validation = synchy_validate_site_sync_options($options);
	$force_full = synchy_should_force_full_sync($_POST);

	if (is_wp_error($validation)) {
		return $validation;
	}

	$preview = synchy_build_sync_package($options, true, [], $force_full);

	if (is_wp_error($preview)) {
		return $preview;
	}

	$result = (array) ($preview['preview'] ?? []);
	$result['lastStatus'] = synchy_get_sync_status();

	return $result;
}

function synchy_run_sync_changes(array $raw_options)
{
	$options = synchy_sanitize_site_sync_options($raw_options);
	$selection = synchy_get_sync_preview_selection($_POST);
	$force_full = synchy_should_force_full_sync($_POST);
	$validation = synchy_validate_site_sync_options($options);

	if (is_wp_error($validation)) {
		synchy_set_sync_status([
			'status' => 'error',
			'message' => $validation->get_error_message(),
			'at' => gmdate('c'),
		]);

		return $validation;
	}

	$started = microtime(true);

	if ($force_full) {
		$payload = synchy_prepare_sync_payload($options, $selection, true);

		if (is_wp_error($payload)) {
			synchy_set_sync_status([
				'status' => 'error',
				'message' => $payload->get_error_message(),
				'at' => gmdate('c'),
			]);

			return $payload;
		}

		$job = synchy_build_full_sync_job($options, $payload);

		if (is_wp_error($job)) {
			synchy_set_sync_status([
				'status' => 'error',
				'message' => $job->get_error_message(),
				'at' => gmdate('c'),
			]);

			return $job;
		}

		$job['sync_time_base'] = (int) (($payload['summary']['syncedAt'] ?? time()) * 100);
		$job = synchy_update_sync_job($job);
		$job = synchy_schedule_full_sync_worker($job, 0);
		synchy_trigger_full_sync_worker_async((string) ($job['worker_token'] ?? ''));

		return synchy_get_sync_status();
	}

	$job = synchy_start_sync_job($options);
	$package = synchy_build_sync_package($options, false, $selection, $force_full);

	if (is_wp_error($package)) {
		synchy_mark_sync_job_error($job, $package->get_error_message());
		synchy_set_sync_status([
			'status' => 'error',
			'message' => $package->get_error_message(),
			'at' => gmdate('c'),
		]);

		return $package;
	}

	$summary = (array) ($package['preview'] ?? []);
	$job['files_count'] = (int) ($summary['filesCount'] ?? 0);
	$job['db_rows'] = (int) ($summary['dbRows'] ?? 0);
	$job['selected_scope_labels'] = (array) ($summary['selectedScopeLabels'] ?? []);

	if (!empty($package['no_changes'])) {
		$job['status'] = 'complete';
		$job['phase'] = 'complete';
		$job['progress'] = 100;
		$job['message'] = __('No Sync changes were detected for the selected scopes.', 'synchy');
		synchy_update_sync_job($job);

		$status = [
			'status' => 'idle',
			'mode' => (string) ($summary['mode'] ?? 'delta'),
			'filesSynced' => 0,
			'dbRowsSynced' => 0,
			'durationSeconds' => 0,
			'destinationUrl' => (string) ($options['destination_url'] ?? ''),
			'selectedScopeLabels' => (array) ($summary['selectedScopeLabels'] ?? []),
			'at' => gmdate('c'),
			'message' => __('No changes detected since the last successful Sync.', 'synchy'),
			'lastSyncTime' => synchy_get_sync_last_time(),
		];

		synchy_set_sync_status($status);

		return $status;
	}

	$temp_dir = (string) ($package['temp_dir'] ?? '');
	$job['phase'] = 'sending_package';
	$job['progress'] = 60;
	$job['message'] = sprintf(
		/* translators: 1: file count, 2: db row count */
		__('Sending %1$d files and %2$d DB rows to the destination site.', 'synchy'),
		(int) ($summary['filesCount'] ?? 0),
		(int) ($summary['dbRows'] ?? 0)
	);
	synchy_update_sync_job($job);

	$job['phase'] = 'applying_destination';
	$job['progress'] = 82;
	$job['message'] = __('Waiting for the destination site to apply the incoming Sync package.', 'synchy');
	synchy_update_sync_job($job);
	$remote = synchy_sync_remote_request(
		$options,
		max(0, (int) ($summary['syncedAt'] ?? $package['manifest']['syncedAt'] ?? 0)),
		(string) ($package['zip_path'] ?? '')
	);

	if ($temp_dir !== '' && is_dir($temp_dir)) {
		synchy_rrmdir($temp_dir);
	}

	if (is_wp_error($remote)) {
		synchy_mark_sync_job_error($job, $remote->get_error_message());
		$status = [
			'status' => 'error',
			'mode' => (string) ($summary['mode'] ?? 'delta'),
			'filesSynced' => (int) ($summary['filesCount'] ?? 0),
			'dbRowsSynced' => (int) ($summary['dbRows'] ?? 0),
			'durationSeconds' => round(microtime(true) - $started, 2),
			'destinationUrl' => (string) ($options['destination_url'] ?? ''),
			'selectedScopeLabels' => (array) ($summary['selectedScopeLabels'] ?? []),
			'at' => gmdate('c'),
			'message' => $remote->get_error_message(),
			'lastSyncTime' => synchy_get_sync_last_time(),
		];

		synchy_set_sync_status($status);

		return $remote;
	}

	$next_state = isset($package['next_state']) && is_array($package['next_state']) ? $package['next_state'] : [];
	$job['phase'] = 'finalizing';
	$job['progress'] = 95;
	$job['message'] = __('Saving the new Sync baseline and final run summary.', 'synchy');
	synchy_update_sync_job($job);
	$next_state['last_result'] = [
		'mode' => (string) ($summary['mode'] ?? 'delta'),
		'filesSynced' => (int) ($summary['filesCount'] ?? 0),
		'dbRowsSynced' => (int) ($summary['dbRows'] ?? 0),
		'at' => gmdate('c'),
	];

	$state_written = synchy_write_sync_state($next_state);
	$sync_time = max(0, (int) ($next_state['last_sync_time'] ?? time()));
	synchy_set_sync_last_time($sync_time);

	$duration = round(microtime(true) - $started, 2);
	$job['status'] = 'complete';
	$job['phase'] = 'complete';
	$job['progress'] = 100;
	$job['message'] = sprintf(
		/* translators: 1: file count, 2: db row count, 3: duration */
		__('Sync finished: %1$d files and %2$d DB rows in %3$s.', 'synchy'),
		(int) ($summary['filesCount'] ?? 0),
		(int) ($summary['dbRows'] ?? 0),
		synchy_format_sync_duration($duration)
	);
	synchy_update_sync_job($job);
	$status = [
		'status' => 'success',
		'mode' => (string) ($summary['mode'] ?? 'delta'),
		'filesSynced' => (int) ($summary['filesCount'] ?? 0),
		'dbRowsSynced' => (int) ($summary['dbRows'] ?? 0),
		'durationSeconds' => $duration,
		'destinationUrl' => (string) ($options['destination_url'] ?? ''),
		'selectedScopeLabels' => (array) ($summary['selectedScopeLabels'] ?? []),
		'at' => gmdate('c'),
		'lastSyncTime' => $sync_time,
		'message' => sprintf(
			/* translators: 1: file count, 2: db row count, 3: duration */
			__('Synced %1$d files and %2$d DB rows in %3$s.', 'synchy'),
			(int) ($summary['filesCount'] ?? 0),
			(int) ($summary['dbRows'] ?? 0),
			synchy_format_sync_duration($duration)
		),
		'remote' => $remote,
	];

	if (is_wp_error($state_written)) {
		$status['message'] .= ' ' . __('The live site finished, but Synchy could not update the local sync state file.', 'synchy');
	}

	synchy_set_sync_status($status);

	return $status;
}

function synchy_get_remote_push_root_path(): string
{
	$uploads = wp_upload_dir();

	if (!empty($uploads['error']) || empty($uploads['basedir'])) {
		return '';
	}

	return wp_normalize_path(trailingslashit((string) $uploads['basedir']) . 'synchy-site-sync');
}

function synchy_get_manual_import_root_path(): string
{
	$uploads = wp_upload_dir();

	if (!empty($uploads['error']) || empty($uploads['basedir'])) {
		return '';
	}

	return wp_normalize_path(trailingslashit((string) $uploads['basedir']) . 'synchy-import');
}

function synchy_build_import_error(string $code, string $message, string $step, array $completed_steps = []): WP_Error
{
	return new WP_Error(
		$code,
		$message,
		[
			'step' => $step,
			'completedSteps' => array_values(array_unique(array_filter($completed_steps, 'is_string'))),
		]
	);
}

function synchy_get_import_stage_definitions(): array
{
	return [
		'receive_installer' => [
			'label' => __('Receive installer.php', 'synchy'),
			'description' => __('Accept the Synchy installer PHP file from the browser upload first.', 'synchy'),
		],
		'stage_installer' => [
			'label' => __('Stage installer.php', 'synchy'),
			'description' => __('Store installer.php inside wp-content/uploads/synchy-import before root placement.', 'synchy'),
		],
		'place_installer_in_root' => [
			'label' => __('Place installer.php in Root', 'synchy'),
			'description' => __('Write installer.php into the WordPress root so you can verify the placement path first.', 'synchy'),
		],
		'receive_archive' => [
			'label' => __('Receive Package Zip', 'synchy'),
			'description' => __('Accept the optional Synchy zip archive when you are ready to place the full package.', 'synchy'),
		],
		'stage_archive' => [
			'label' => __('Stage Package Zip', 'synchy'),
			'description' => __('Store the archive safely inside wp-content/uploads/synchy-import before root placement.', 'synchy'),
		],
		'place_archive_in_root' => [
			'label' => __('Place Package Zip in Root', 'synchy'),
			'description' => __('Copy the archive into the WordPress root next to installer.php.', 'synchy'),
		],
		'ready' => [
			'label' => __('Ready to Restore', 'synchy'),
			'description' => __('Both installer.php and the package zip are in place and ready for the overwrite restore.', 'synchy'),
		],
	];
}

function synchy_get_import_stage_items(array $result): array
{
	$definitions = synchy_get_import_stage_definitions();
	$status = (string) ($result['status'] ?? '');
	$step = (string) ($result['step'] ?? '');
	$completed_steps = array_values(array_filter((array) ($result['completedSteps'] ?? []), 'is_string'));
	$items = [];

	foreach ($definitions as $key => $definition) {
		$items[$key] = [
			'key' => $key,
			'label' => (string) $definition['label'],
			'description' => (string) $definition['description'],
			'state' => 'pending',
		];
	}

	if ($status === 'ready') {
		foreach ($items as $key => $item) {
			$items[$key]['state'] = 'complete';
		}

		return array_values($items);
	}

	if ($status === 'installer_ready') {
		foreach ($completed_steps as $completed_step) {
			if (isset($items[$completed_step])) {
				$items[$completed_step]['state'] = 'complete';
			}
		}

		return array_values($items);
	}

	if ($status === 'staged_only') {
		foreach ($completed_steps as $completed_step) {
			if (isset($items[$completed_step])) {
				$items[$completed_step]['state'] = 'complete';
			}
		}

		if (isset($items[$step])) {
			$items[$step]['state'] = 'error';
		}

		return array_values($items);
	}

	if ($status === 'error') {
		foreach ($completed_steps as $completed_step) {
			if (isset($items[$completed_step])) {
				$items[$completed_step]['state'] = 'complete';
			}
		}

		if (isset($items[$step])) {
			$items[$step]['state'] = 'error';
		} else {
			$items['receive_installer']['state'] = 'error';
		}

		return array_values($items);
	}

	return array_values($items);
}

function synchy_validate_manual_import_upload(array $file, string $expected_extension)
{
	$error = (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE);

	if ($error !== UPLOAD_ERR_OK) {
		$message = match ($error) {
			UPLOAD_ERR_NO_FILE => sprintf(
				/* translators: %s: expected file extension */
				__('Select the .%s file before continuing.', 'synchy'),
				$expected_extension
			),
			UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => sprintf(
				/* translators: %s: expected file extension */
				__('The uploaded .%s file exceeds the server upload limit.', 'synchy'),
				$expected_extension
			),
			UPLOAD_ERR_PARTIAL => sprintf(
				/* translators: %s: expected file extension */
				__('The uploaded .%s file was only partially received. Upload it again.', 'synchy'),
				$expected_extension
			),
			default => __('Synchy could not read one of the uploaded import files.', 'synchy'),
		};

		return synchy_build_import_error('synchy_import_upload_error', $message, $expected_extension === 'php' ? 'receive_installer' : 'receive_archive');
	}

	$tmp_name = isset($file['tmp_name']) ? (string) $file['tmp_name'] : '';
	$name = sanitize_file_name((string) ($file['name'] ?? ''));

	if ($tmp_name === '' || !is_uploaded_file($tmp_name) || $name === '') {
		return synchy_build_import_error('synchy_import_upload_missing', __('Synchy could not validate the uploaded import file.', 'synchy'), $expected_extension === 'php' ? 'receive_installer' : 'receive_archive');
	}

	if (strtolower((string) pathinfo($name, PATHINFO_EXTENSION)) !== strtolower($expected_extension)) {
		return synchy_build_import_error(
			'synchy_import_upload_extension',
			sprintf(
				/* translators: %s: expected file extension */
				__('Upload a valid .%s file for this import field.', 'synchy'),
				$expected_extension
			),
			$expected_extension === 'php' ? 'receive_installer' : 'receive_archive'
		);
	}

	return [
		'tmp_name' => $tmp_name,
		'name' => $name,
	];
}

function synchy_stage_manual_import_upload(array $file, string $destination_path)
{
	$directory = dirname($destination_path);

	if (!wp_mkdir_p($directory)) {
		$step = basename($destination_path) === 'installer.php' ? 'stage_installer' : 'stage_archive';

		return synchy_build_import_error('synchy_import_stage_dir_failed', __('Synchy could not create the manual import staging folder.', 'synchy'), $step);
	}

	if (!move_uploaded_file((string) $file['tmp_name'], $destination_path)) {
		$step = basename($destination_path) === 'installer.php' ? 'stage_installer' : 'stage_archive';

		return synchy_build_import_error('synchy_import_stage_move_failed', __('Synchy could not move the uploaded import file into the staging folder.', 'synchy'), $step);
	}

	return [
		'path' => wp_normalize_path($destination_path),
		'filename' => basename($destination_path),
		'bytes' => (int) filesize($destination_path),
	];
}

function synchy_handle_manual_import_upload()
{
	$root = synchy_get_manual_import_root_path();
	$completed_steps = [];

	if ($root === '') {
		return synchy_build_import_error('synchy_import_root_missing', __('Synchy could not resolve the import staging folder inside uploads.', 'synchy'), 'stage_installer');
	}

	$installer_file = $_FILES['synchy_import_installer'] ?? null;
	$archive_file = $_FILES['synchy_import_archive'] ?? null;

	if (!is_array($installer_file)) {
		return synchy_build_import_error('synchy_import_files_missing', __('Upload installer.php before continuing.', 'synchy'), 'receive_installer');
	}

	$validated_installer = synchy_validate_manual_import_upload($installer_file, 'php');

	if (is_wp_error($validated_installer)) {
		return $validated_installer;
	}

	$completed_steps[] = 'receive_installer';
	$validated_archive = null;
	$archive_provided = is_array($archive_file) && (int) ($archive_file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE;

	$session_id = wp_generate_uuid4();
	$session_dir = wp_normalize_path(trailingslashit($root) . $session_id);
	$installer_destination = wp_normalize_path(trailingslashit($session_dir) . 'installer.php');
	$archive_destination = '';

	$staged_installer = synchy_stage_manual_import_upload($validated_installer, $installer_destination);

	if (is_wp_error($staged_installer)) {
		$error_data = $staged_installer->get_error_data();

		return synchy_build_import_error(
			$staged_installer->get_error_code(),
			$staged_installer->get_error_message(),
			(string) (is_array($error_data) ? ($error_data['step'] ?? 'stage_installer') : 'stage_installer'),
			$completed_steps
		);
	}

	$completed_steps[] = 'stage_installer';
	$session = [
		'session_id' => $session_id,
		'directory' => $session_dir,
		'artifacts' => [
			'installer' => [
				'path' => (string) $staged_installer['path'],
				'filename' => (string) $staged_installer['filename'],
			],
		],
	];

	$deploy = synchy_deploy_manual_import_package_to_root($session, $completed_steps);

	if (is_wp_error($deploy)) {
		return $deploy;
	}

	$completed_steps = array_values(array_unique(array_merge($completed_steps, (array) ($deploy['completedSteps'] ?? []))));

	$staged_archive = null;

	if ($archive_provided) {
		$validated_archive = synchy_validate_manual_import_upload($archive_file, 'zip');

		if (is_wp_error($validated_archive)) {
			$error_data = $validated_archive->get_error_data();

			return synchy_build_import_error(
				$validated_archive->get_error_code(),
				$validated_archive->get_error_message(),
				(string) (is_array($error_data) ? ($error_data['step'] ?? 'receive_archive') : 'receive_archive'),
				$completed_steps
			);
		}

		$completed_steps[] = 'receive_archive';
		$archive_destination = wp_normalize_path(trailingslashit($session_dir) . (string) $validated_archive['name']);
		$staged_archive = synchy_stage_manual_import_upload($validated_archive, $archive_destination);

		if (is_wp_error($staged_archive)) {
			$error_data = $staged_archive->get_error_data();

			return synchy_build_import_error(
				$staged_archive->get_error_code(),
				$staged_archive->get_error_message(),
				(string) (is_array($error_data) ? ($error_data['step'] ?? 'stage_archive') : 'stage_archive'),
				$completed_steps
			);
		}

		$completed_steps[] = 'stage_archive';
		$session['artifacts']['archive'] = [
			'path' => (string) $staged_archive['path'],
			'filename' => (string) $staged_archive['filename'],
		];

		$archive_deploy = synchy_deploy_manual_import_archive_to_root($session, $completed_steps);

		if (is_wp_error($archive_deploy)) {
			return $archive_deploy;
		}

		$deploy = array_merge($deploy, $archive_deploy);
		$completed_steps = array_values(array_unique(array_merge($completed_steps, (array) ($archive_deploy['completedSteps'] ?? []))));
	}

	$deploy['sessionId'] = $session_id;
	$deploy['stagingPath'] = $session_dir;
	$deploy['stagedArchivePath'] = $staged_archive !== null ? (string) $staged_archive['path'] : '';
	$deploy['stagedInstallerPath'] = (string) $staged_installer['path'];
	$deploy['archiveFilename'] = $staged_archive !== null ? (string) $staged_archive['filename'] : '';
	$deploy['installerFilename'] = (string) $staged_installer['filename'];
	$deploy['archiveProvided'] = $archive_provided;
	$deploy['completedSteps'] = $completed_steps;

	if (empty($deploy['step'])) {
		$deploy['step'] = match ((string) ($deploy['status'] ?? '')) {
			'ready' => 'ready',
			'installer_ready' => 'place_installer_in_root',
			'staged_only' => 'place_installer_in_root',
			default => 'place_installer_in_root',
		};
	}

	return $deploy;
}

function synchy_render_import_page(array $current): void
{
	$result = synchy_get_import_result();
	$export_history = synchy_get_export_history();
	$stages = synchy_get_import_stage_items($result);
	$root_path = synchy_get_site_root_path();
	$root_writable = is_dir($root_path) && is_writable($root_path);
	$staging_root = synchy_get_manual_import_root_path();
	$staging_available = $staging_root !== '' && (is_dir($staging_root) || wp_mkdir_p($staging_root));
	$upload_limit = size_format((int) wp_max_upload_size(), 2);
	$status = (string) ($result['status'] ?? '');
	$badge = __('Awaiting installer.php', 'synchy');
	$message = __('Upload installer.php first to verify where Synchy places it. Add the matching package zip when you are ready to place the full restore package.', 'synchy');

	if ($status === 'ready') {
		$badge = __('Root ready', 'synchy');
		$message = (string) ($result['message'] ?? __('Synchy placed installer.php and the package zip into the WordPress root.', 'synchy'));
	} elseif ($status === 'installer_ready') {
		$badge = __('Installer ready', 'synchy');
		$message = (string) ($result['message'] ?? __('Synchy placed installer.php into the WordPress root. Add the package zip next when you are ready.', 'synchy'));
	} elseif ($status === 'staged_only') {
		$badge = __('Staged only', 'synchy');
		$message = (string) ($result['message'] ?? __('Synchy uploaded the selected files, but you still need to move them into the WordPress root manually.', 'synchy'));
	} elseif ($status === 'error') {
		$badge = __('Error', 'synchy');
		$message = (string) ($result['message'] ?? __('Synchy could not process the uploaded import files.', 'synchy'));
	}
	?>
	<div class="wrap synchy-admin">
		<?php synchy_render_notice(); ?>
		<div class="synchy-shell">
			<div class="synchy-hero">
				<div>
					<p class="synchy-eyebrow"><?php esc_html_e('Destination Restore Setup', 'synchy'); ?></p>
					<h1><?php echo esc_html($current['headline']); ?></h1>
					<p class="synchy-description"><?php echo esc_html($current['description']); ?></p>
				</div>
				<div class="synchy-status">
					<span class="synchy-status__dot" aria-hidden="true"></span>
					<?php echo esc_html($root_writable ? __('Root writable', 'synchy') : __('Staging only', 'synchy')); ?>
				</div>
			</div>

			<div class="synchy-panel synchy-panel--danger synchy-panel--wide">
				<div class="synchy-stack synchy-stack--compact">
					<div>
						<p class="synchy-panel__eyebrow synchy-panel__eyebrow--danger"><?php esc_html_e('Not Ready Yet', 'synchy'); ?></p>
						<h2><?php esc_html_e('Import is reliable for installer placement, but large browser zip uploads are not finished.', 'synchy'); ?></h2>
						<p>
							<?php esc_html_e('installer.php placement works well. Large package zip uploads can still fail before WordPress sees the file when PHP, the host, or Cloudflare rejects the request.', 'synchy'); ?>
						</p>
					</div>
					<ul class="synchy-checklist">
						<li><?php esc_html_e('Working now: upload installer.php, stage it safely, and place it in the destination WordPress root.', 'synchy'); ?></li>
						<li><?php esc_html_e('Working now: show the exact root path, staging folder, and installer URL after placement.', 'synchy'); ?></li>
						<li><?php esc_html_e('Working now: smaller package zips can be staged and copied into the root when the browser upload succeeds.', 'synchy'); ?></li>
						<li><?php esc_html_e('Not ready yet: reliable large zip uploads for bigger sites when the package exceeds browser, proxy, or CDN limits.', 'synchy'); ?></li>
						<li><?php esc_html_e('Best current path for larger sites: place installer.php with Import, then use Upload to Live or manual file placement for the zip.', 'synchy'); ?></li>
					</ul>
				</div>
			</div>

			<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" enctype="multipart/form-data" class="synchy-form">
				<?php wp_nonce_field('synchy_stage_import_package'); ?>
				<input type="hidden" name="action" value="synchy_stage_import_package" />

				<div class="synchy-grid synchy-grid--import">
					<div class="synchy-panel">
						<h2><?php esc_html_e('What Import Does', 'synchy'); ?></h2>
						<ul class="synchy-checklist synchy-checklist--detail">
							<li>
								<strong><?php esc_html_e('Uploads installer.php first', 'synchy'); ?></strong>
								<span><?php esc_html_e('Start by placing installer.php so you can verify exactly where Synchy writes it on the destination site.', 'synchy'); ?></span>
							</li>
							<li>
								<strong><?php esc_html_e('Stages selected files safely first', 'synchy'); ?></strong>
								<span><?php esc_html_e('Synchy stores the uploaded installer and optional zip inside wp-content/uploads/synchy-import before any root deployment.', 'synchy'); ?></span>
							</li>
							<li>
								<strong><?php esc_html_e('Places installer.php in the WordPress root before the zip', 'synchy'); ?></strong>
								<span><?php esc_html_e('If the root is writable, Synchy writes installer.php into the site root first, then copies the package zip when you include it.', 'synchy'); ?></span>
							</li>
							<li>
								<strong><?php esc_html_e('Leaves restore execution to installer.php', 'synchy'); ?></strong>
								<span><?php esc_html_e('This screen does not run the restore. Its job is to place the package in the right location so you can launch installer.php.', 'synchy'); ?></span>
							</li>
						</ul>
					</div>

						<div class="synchy-panel synchy-panel--muted">
							<h2><?php esc_html_e('Upload Package Files', 'synchy'); ?></h2>
						<div class="synchy-field">
							<label class="synchy-label" for="synchy-import-installer"><?php esc_html_e('installer.php (Required)', 'synchy'); ?></label>
							<input id="synchy-import-installer" type="file" name="synchy_import_installer" accept=".php,application/x-httpd-php,text/x-php" required />
							<p class="synchy-field-note">
								<?php esc_html_e('Choose installer.php from the same Synchy export package. Synchy stages it as installer.php and tries to place it in the WordPress root first.', 'synchy'); ?>
							</p>
						</div>

						<div class="synchy-field">
							<label class="synchy-label" for="synchy-import-archive"><?php esc_html_e('Package Zip (Optional)', 'synchy'); ?></label>
							<input id="synchy-import-archive" type="file" name="synchy_import_archive" accept=".zip,application/zip" />
							<p class="synchy-field-note">
								<?php esc_html_e('Leave this empty if you only want to test where installer.php ends up. Add the matching zip when you are ready for a full restore package placement.', 'synchy'); ?>
							</p>
						</div>

							<div class="synchy-export-meta synchy-export-meta--wide">
								<div>
									<span class="synchy-export-meta__label"><?php esc_html_e('WordPress Root', 'synchy'); ?></span>
									<strong class="synchy-text-break"><?php echo esc_html($root_path); ?></strong>
								</div>
							<div>
								<span class="synchy-export-meta__label"><?php esc_html_e('Root Access', 'synchy'); ?></span>
								<strong><?php echo esc_html($root_writable ? __('Writable', 'synchy') : __('Not writable', 'synchy')); ?></strong>
							</div>
							<div>
								<span class="synchy-export-meta__label"><?php esc_html_e('Upload Limit', 'synchy'); ?></span>
								<strong><?php echo esc_html($upload_limit); ?></strong>
							</div>
							<div>
									<span class="synchy-export-meta__label"><?php esc_html_e('Import Staging Folder', 'synchy'); ?></span>
									<strong class="synchy-text-break"><?php echo esc_html($staging_available ? $staging_root : __('Unavailable', 'synchy')); ?></strong>
								</div>
							</div>

							<div class="synchy-run-export">
								<button type="submit" class="button button-primary button-large"><?php esc_html_e('Place Selected Files', 'synchy'); ?></button>
							</div>

							<div class="synchy-stage-status">
								<p class="synchy-stage-status__label"><?php esc_html_e('Import Stage Status', 'synchy'); ?></p>
								<div class="synchy-export-stages">
									<?php foreach ($stages as $stage) : ?>
										<div class="synchy-export-stage is-<?php echo esc_attr((string) $stage['state']); ?>">
											<span class="synchy-export-stage__indicator" aria-hidden="true"></span>
											<div class="synchy-export-stage__content">
												<strong><?php echo esc_html((string) $stage['label']); ?></strong>
												<span><?php echo esc_html((string) $stage['description']); ?></span>
											</div>
										</div>
									<?php endforeach; ?>
								</div>
							</div>
						</div>
					</div>

				<div class="synchy-panel synchy-panel--wide">
					<div class="synchy-stack synchy-stack--compact">
						<div class="synchy-stack__split">
							<h2><?php esc_html_e('Latest Import Result', 'synchy'); ?></h2>
							<span class="synchy-badge"><?php echo esc_html($badge); ?></span>
						</div>
						<p class="synchy-field-note"><?php echo esc_html($message); ?></p>
						<div class="synchy-export-meta synchy-export-meta--wide">
							<div>
								<span class="synchy-export-meta__label"><?php esc_html_e('Root Deploy Status', 'synchy'); ?></span>
								<strong><?php echo esc_html($status !== '' ? $status : __('Waiting for upload', 'synchy')); ?></strong>
							</div>
							<div>
								<span class="synchy-export-meta__label"><?php esc_html_e('Session', 'synchy'); ?></span>
								<strong class="synchy-text-break"><?php echo esc_html((string) ($result['sessionId'] ?? __('Not created yet', 'synchy'))); ?></strong>
							</div>
							<div>
								<span class="synchy-export-meta__label"><?php esc_html_e('Root Archive Path', 'synchy'); ?></span>
								<strong class="synchy-text-break"><?php echo esc_html((string) ($result['archivePath'] ?? __('No zip placed yet', 'synchy'))); ?></strong>
							</div>
							<div>
								<span class="synchy-export-meta__label"><?php esc_html_e('Root Installer Path', 'synchy'); ?></span>
								<strong class="synchy-text-break"><?php echo esc_html((string) ($result['installerPath'] ?? __('Not placed yet', 'synchy'))); ?></strong>
							</div>
							<div>
								<span class="synchy-export-meta__label"><?php esc_html_e('Staging Folder', 'synchy'); ?></span>
								<strong class="synchy-text-break"><?php echo esc_html((string) ($result['stagingPath'] ?? __('No upload staged yet', 'synchy'))); ?></strong>
							</div>
							<div>
								<span class="synchy-export-meta__label"><?php esc_html_e('Installer URL', 'synchy'); ?></span>
								<strong class="synchy-text-break">
									<?php if (!empty($result['installerUrl'])) : ?>
										<a href="<?php echo esc_url((string) $result['installerUrl']); ?>" target="_blank" rel="noreferrer noopener"><?php echo esc_html((string) $result['installerUrl']); ?></a>
									<?php else : ?>
										<?php esc_html_e('Available after root placement succeeds', 'synchy'); ?>
									<?php endif; ?>
								</strong>
							</div>
							<div>
								<span class="synchy-export-meta__label"><?php esc_html_e('Staged installer.php', 'synchy'); ?></span>
								<strong class="synchy-text-break"><?php echo esc_html((string) ($result['stagedInstallerPath'] ?? __('Not staged yet', 'synchy'))); ?></strong>
							</div>
							<div>
								<span class="synchy-export-meta__label"><?php esc_html_e('Staged Zip Path', 'synchy'); ?></span>
								<strong class="synchy-text-break"><?php echo esc_html((string) ($result['stagedArchivePath'] ?? __('No zip staged yet', 'synchy'))); ?></strong>
							</div>
						</div>
					</div>
				</div>

				<div class="synchy-grid synchy-grid--export">
					<div class="synchy-panel">
						<h2><?php esc_html_e('Requirements', 'synchy'); ?></h2>
						<ul class="synchy-checklist">
							<li><?php esc_html_e('Upload installer.php first. The package zip is optional until you are ready to place the full restore package.', 'synchy'); ?></li>
							<li><?php esc_html_e('This site must have enough PHP upload/post size to receive the archive in one browser upload.', 'synchy'); ?></li>
							<li><?php esc_html_e('If the WordPress root is not writable, Synchy will leave the files in the import staging folder and you will need to move them manually.', 'synchy'); ?></li>
						</ul>
					</div>

					<div class="synchy-panel synchy-panel--muted">
						<h2><?php esc_html_e('Next Step After Placement', 'synchy'); ?></h2>
						<ul class="synchy-checklist">
							<li><?php esc_html_e('Open installer.php in the site root.', 'synchy'); ?></li>
							<li><?php esc_html_e('Provide the destination URL and database connection details.', 'synchy'); ?></li>
							<li><?php esc_html_e('Run the restore to overwrite the destination database and files.', 'synchy'); ?></li>
						</ul>
					</div>
				</div>

				<?php synchy_render_export_history($export_history, 'synchy-import'); ?>
			</form>
		</div>
	</div>
	<?php
}

function synchy_sanitize_remote_push_session_id(string $session_id): string
{
	return (string) preg_replace('/[^a-z0-9-]/i', '', $session_id);
}

function synchy_get_remote_push_session_dir(string $session_id): string
{
	return wp_normalize_path(trailingslashit(synchy_get_remote_push_root_path()) . synchy_sanitize_remote_push_session_id($session_id));
}

function synchy_get_remote_push_session_meta_path(string $session_id): string
{
	return wp_normalize_path(trailingslashit(synchy_get_remote_push_session_dir($session_id)) . 'session.json');
}

function synchy_get_site_root_path(): string
{
	return wp_normalize_path(untrailingslashit(ABSPATH));
}

function synchy_get_remote_push_root_archive_path(string $filename): string
{
	$filename = sanitize_file_name($filename);

	if ($filename === '') {
		$filename = 'site.zip';
	}

	return wp_normalize_path(trailingslashit(synchy_get_site_root_path()) . $filename);
}

function synchy_get_remote_push_root_installer_path(): string
{
	return wp_normalize_path(trailingslashit(synchy_get_site_root_path()) . 'installer.php');
}

function synchy_render_root_installer(string $installer_source)
{
	$installer_contents = file_get_contents($installer_source);

	if ($installer_contents === false) {
		return new WP_Error(
			'synchy_import_read_installer_failed',
			__('Synchy could not read installer.php before placing it in the WordPress root.', 'synchy'),
			['step' => 'place_installer_in_root']
		);
	}

	$access_token = wp_generate_password(32, false, false);
	$tokenized_installer = str_replace('__SYNCHY_ACCESS_TOKEN__', synchy_escape_php_single_quoted_string($access_token), $installer_contents);

	return [
		'accessToken' => $access_token,
		'contents' => $tokenized_installer,
	];
}

function synchy_place_installer_in_root(string $installer_source, array $completed_steps = [])
{
	$root_path = synchy_get_site_root_path();

	if ($installer_source === '' || !is_readable($installer_source)) {
		return synchy_build_import_error(
			'synchy_import_missing_installer',
			__('Synchy could not find installer.php in the import staging folder.', 'synchy'),
			'place_installer_in_root',
			$completed_steps
		);
	}

	if (!is_dir($root_path) || !is_writable($root_path)) {
		return synchy_build_import_error(
			'synchy_import_root_not_writable',
			__('Synchy staged installer.php, but the WordPress root is not writable for root placement.', 'synchy'),
			'place_installer_in_root',
			$completed_steps
		);
	}

	$rendered = synchy_render_root_installer($installer_source);

	if (is_wp_error($rendered)) {
		return synchy_build_import_error(
			$rendered->get_error_code(),
			$rendered->get_error_message(),
			'place_installer_in_root',
			$completed_steps
		);
	}

	$installer_target = synchy_get_remote_push_root_installer_path();

	if (file_put_contents($installer_target, (string) $rendered['contents']) === false) {
		return synchy_build_import_error(
			'synchy_import_root_write_failed',
			__('Synchy staged installer.php, but it could not write installer.php into the WordPress root.', 'synchy'),
			'place_installer_in_root',
			$completed_steps
		);
	}

	$completed_steps[] = 'place_installer_in_root';

	return [
		'status' => 'installer_ready',
		'message' => __('Synchy staged installer.php and copied it into the destination WordPress root. Verify the location before uploading the package zip.', 'synchy'),
		'rootPath' => $root_path,
		'installerPath' => $installer_target,
		'installerUrl' => add_query_arg('token', (string) $rendered['accessToken'], site_url('/installer.php')),
		'step' => 'place_installer_in_root',
		'completedSteps' => $completed_steps,
	];
}

function synchy_place_archive_in_root(string $archive_source, string $archive_filename, array $completed_steps = [])
{
	$root_path = synchy_get_site_root_path();

	if ($archive_source === '' || !is_readable($archive_source)) {
		return synchy_build_import_error(
			'synchy_import_missing_archive',
			__('Synchy could not find the staged package zip before root placement.', 'synchy'),
			'place_archive_in_root',
			$completed_steps
		);
	}

	if (!is_dir($root_path) || !is_writable($root_path)) {
		return synchy_build_import_error(
			'synchy_import_root_not_writable',
			__('Synchy staged the package zip, but the WordPress root is not writable for root placement.', 'synchy'),
			'place_archive_in_root',
			$completed_steps
		);
	}

	$archive_target = synchy_get_remote_push_root_archive_path($archive_filename);

	if (@copy($archive_source, $archive_target) === false) {
		return synchy_build_import_error(
			'synchy_import_archive_copy_failed',
			__('Synchy staged the package zip, but it could not copy the archive into the WordPress root.', 'synchy'),
			'place_archive_in_root',
			$completed_steps
		);
	}

	$completed_steps[] = 'place_archive_in_root';

	return [
		'status' => 'ready',
		'message' => __('Synchy placed installer.php and the package zip into the destination WordPress root. Open installer.php to run the manual restore.', 'synchy'),
		'rootPath' => $root_path,
		'archivePath' => $archive_target,
		'archiveUrl' => site_url('/' . basename($archive_target)),
		'step' => 'ready',
		'completedSteps' => $completed_steps,
	];
}

function synchy_deploy_manual_import_package_to_root(array $session, array $completed_steps = [])
{
	$installer_source = wp_normalize_path((string) ($session['artifacts']['installer']['path'] ?? ''));

	return synchy_place_installer_in_root($installer_source, $completed_steps);
}

function synchy_deploy_manual_import_archive_to_root(array $session, array $completed_steps = [])
{
	$archive_source = wp_normalize_path((string) ($session['artifacts']['archive']['path'] ?? ''));
	$archive_filename = sanitize_file_name((string) ($session['artifacts']['archive']['filename'] ?? 'site.zip'));

	return synchy_place_archive_in_root($archive_source, $archive_filename, $completed_steps);
}

function synchy_deploy_remote_push_package_to_root(array $session): array
{
	$root_path = synchy_get_site_root_path();
	$archive_source = wp_normalize_path((string) ($session['artifacts']['archive']['path'] ?? ''));
	$installer_source = wp_normalize_path((string) ($session['artifacts']['installer']['path'] ?? ''));
	$archive_filename = sanitize_file_name((string) ($session['artifacts']['archive']['filename'] ?? 'site.zip'));

	if ($archive_source === '' || !is_readable($archive_source) || $installer_source === '' || !is_readable($installer_source)) {
		return [
			'status' => 'staged_only',
			'message' => __('Synchy staged the package, but the standalone installer artifacts are incomplete on the destination.', 'synchy'),
			'rootPath' => $root_path,
		];
	}

	if (!is_dir($root_path) || !is_writable($root_path)) {
		return [
			'status' => 'staged_only',
			'message' => __('Synchy staged the package, but the WordPress root is not writable for installer deployment.', 'synchy'),
			'rootPath' => $root_path,
		];
	}

	$archive_target = synchy_get_remote_push_root_archive_path($archive_filename);
	$installer_target = synchy_get_remote_push_root_installer_path();
	$rendered = synchy_render_root_installer($installer_source);

	if (is_wp_error($rendered)) {
		return [
			'status' => 'staged_only',
			'message' => $rendered->get_error_message(),
			'rootPath' => $root_path,
			'failedStep' => 'place_installer_in_root',
		];
	}

	if (file_put_contents($installer_target, (string) $rendered['contents']) === false) {
		return [
			'status' => 'staged_only',
			'message' => __('Synchy staged the package, but it could not write installer.php into the destination WordPress root.', 'synchy'),
			'rootPath' => $root_path,
			'failedStep' => 'place_installer_in_root',
		];
	}

	if (@copy($archive_source, $archive_target) === false) {
		return [
			'status' => 'staged_only',
			'message' => __('Synchy staged the package, but it could not copy the archive into the destination WordPress root.', 'synchy'),
			'rootPath' => $root_path,
			'installerPath' => $installer_target,
			'failedStep' => 'place_archive_in_root',
		];
	}

	return [
		'status' => 'ready',
		'message' => __('Synchy copied the archive and installer.php into the destination WordPress root. Open the installer URL to run the manual restore.', 'synchy'),
		'rootPath' => $root_path,
		'archivePath' => $archive_target,
		'installerPath' => $installer_target,
		'archiveUrl' => site_url('/' . basename($archive_target)),
		'installerUrl' => add_query_arg('token', (string) $rendered['accessToken'], site_url('/installer.php')),
	];
}

function synchy_read_remote_push_session(string $session_id): array
{
	$session_id = synchy_sanitize_remote_push_session_id($session_id);

	if ($session_id === '') {
		return [];
	}

	$meta_path = synchy_get_remote_push_session_meta_path($session_id);

	if (!is_readable($meta_path)) {
		return [];
	}

	$decoded = json_decode((string) file_get_contents($meta_path), true);

	return is_array($decoded) ? $decoded : [];
}

function synchy_write_remote_push_session(array $session)
{
	$session_id = synchy_sanitize_remote_push_session_id((string) ($session['session_id'] ?? ''));

	if ($session_id === '') {
		return new WP_Error('synchy_remote_session_invalid', __('Synchy could not save the destination sync session.', 'synchy'));
	}

	$session['session_id'] = $session_id;
	$session_dir = synchy_get_remote_push_session_dir($session_id);

	if (!wp_mkdir_p($session_dir)) {
		return new WP_Error('synchy_remote_session_write_failed', __('Synchy could not create the destination sync session folder.', 'synchy'));
	}

	$json = wp_json_encode($session, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

	if ($json === false || file_put_contents(synchy_get_remote_push_session_meta_path($session_id), $json) === false) {
		return new WP_Error('synchy_remote_session_write_failed', __('Synchy could not write the destination sync session metadata.', 'synchy'));
	}

	return $session;
}

function synchy_create_remote_push_session(array $payload)
{
	$root = synchy_get_remote_push_root_path();

	if ($root === '') {
		return new WP_Error('synchy_remote_session_root_failed', __('Synchy could not resolve the destination sync storage folder.', 'synchy'));
	}

	if (!wp_mkdir_p($root)) {
		return new WP_Error('synchy_remote_session_root_failed', __('Synchy could not create the destination sync storage folder.', 'synchy'));
	}

	$session_id = wp_generate_uuid4();
	$session_dir = synchy_get_remote_push_session_dir($session_id);

	if (!wp_mkdir_p($session_dir)) {
		return new WP_Error('synchy_remote_session_dir_failed', __('Synchy could not create the destination upload session folder.', 'synchy'));
	}

	$archive_filename = sanitize_file_name((string) ($payload['archiveFilename'] ?? 'site.zip'));
	$installer_filename = sanitize_file_name((string) ($payload['installerFilename'] ?? 'installer.php'));
	$manifest_filename = sanitize_file_name((string) ($payload['manifestFilename'] ?? ''));

	if ($archive_filename === '') {
		$archive_filename = 'site.zip';
	}

	if ($installer_filename === '') {
		$installer_filename = 'installer.php';
	}

	$session = [
		'session_id' => $session_id,
		'created_at' => gmdate('c'),
		'status' => 'receiving',
		'package_name' => sanitize_text_field((string) ($payload['packageName'] ?? 'synchy-site-sync')),
		'package_id' => sanitize_text_field((string) ($payload['packageId'] ?? '')),
		'source_home_url' => esc_url_raw((string) ($payload['sourceHomeUrl'] ?? '')),
		'source_site_url' => esc_url_raw((string) ($payload['sourceSiteUrl'] ?? '')),
		'directory' => $session_dir,
		'artifacts' => [
			'archive' => [
				'filename' => $archive_filename,
				'path' => wp_normalize_path(trailingslashit($session_dir) . $archive_filename),
				'bytes' => 0,
			],
			'installer' => [
				'filename' => $installer_filename,
				'path' => wp_normalize_path(trailingslashit($session_dir) . $installer_filename),
				'bytes' => 0,
			],
		],
	];

	if ($manifest_filename !== '') {
		$session['artifacts']['manifest'] = [
			'filename' => $manifest_filename,
			'path' => wp_normalize_path(trailingslashit($session_dir) . $manifest_filename),
			'bytes' => 0,
		];
	}

	$session = synchy_write_remote_push_session($session);

	if (is_wp_error($session)) {
		return $session;
	}

	$session['uploadChunkBytes'] = synchy_get_site_sync_upload_chunk_bytes();

	return $session;
}

function synchy_prepare_site_sync_local_artifacts(array $job, array $export_job)
{
	$artifact_paths = isset($export_job['artifact_paths']) && is_array($export_job['artifact_paths']) ? $export_job['artifact_paths'] : [];
	$artifacts = [];
	$total = 0;

	foreach (['archive', 'installer'] as $artifact) {
		$path = isset($artifact_paths[$artifact]) ? (string) $artifact_paths[$artifact] : '';

		if ($path === '' || !is_readable($path)) {
			return new WP_Error(
				'synchy_site_sync_missing_artifact',
				sprintf(
					/* translators: %s: artifact type */
					__('Synchy could not find the %s artifact after building the push package.', 'synchy'),
					$artifact
				)
			);
		}

		$size = (int) filesize($path);
		$artifacts[$artifact] = [
			'path' => $path,
			'filename' => basename($path),
			'size' => $size,
			'offset' => 0,
		];
		$total += $size;
	}

	$job['package_id'] = (string) ($export_job['package_id'] ?? '');
	$job['package_name'] = (string) ($export_job['package_name'] ?? '');
	$job['artifact_uploads'] = $artifacts;
	$job['bytes_total'] = $total;
	$job['bytes_uploaded'] = 0;
	$job['current_artifact'] = 'archive';

	return $job;
}

function synchy_start_site_sync_job(array $raw_options)
{
	$existing_job = synchy_get_running_site_sync_job();

	if ($existing_job !== []) {
		return new WP_Error('synchy_site_sync_running', __('A Synchy Upload to Live run is already running. Wait for it to finish before starting another one.', 'synchy'));
	}

	if (synchy_get_running_export_job() !== []) {
		return new WP_Error('synchy_site_sync_export_busy', __('Synchy is already building an export package. Wait for it to finish before starting Upload to Live.', 'synchy'));
	}

	$options = synchy_sanitize_site_sync_options($raw_options);
	$validation = synchy_validate_site_sync_options($options);

	if (is_wp_error($validation)) {
		return $validation;
	}

	$job = [
		'job_id' => wp_generate_uuid4(),
		'status' => 'running',
		'phase' => 'testing_connection',
		'message' => __('Testing the destination Synchy receiver.', 'synchy'),
		'progress' => 2,
		'created_at' => gmdate('c'),
		'options' => $options,
		'destination_url' => (string) $options['destination_url'],
		'remote_site' => [],
		'export_job_id' => '',
		'package_name' => '',
		'package_id' => '',
		'remote_session_id' => '',
		'artifact_uploads' => [],
		'current_artifact' => '',
		'bytes_total' => 0,
		'bytes_uploaded' => 0,
	];

	return synchy_update_site_sync_job($job);
}

function synchy_process_site_sync_job(array $job): array
{
	if (($job['status'] ?? '') !== 'running') {
		return $job;
	}

	if (function_exists('ignore_user_abort')) {
		ignore_user_abort(true);
	}

	if (function_exists('set_time_limit')) {
		@set_time_limit(90);
	}

	$options = isset($job['options']) && is_array($job['options']) ? $job['options'] : [];

	switch ((string) ($job['phase'] ?? '')) {
		case 'testing_connection':
			$connection = synchy_test_site_sync_connection($options);

			if (is_wp_error($connection)) {
				return synchy_mark_site_sync_job_error($job, $connection->get_error_message());
			}

			$job['remote_site'] = $connection;
			$job['phase'] = 'starting_export';
			$job['message'] = __('Destination verified. Starting a fresh Synchy package for Upload to Live.', 'synchy');
			$job['progress'] = 8;

			return synchy_update_site_sync_job($job);

		case 'starting_export':
			$export_options = synchy_get_site_sync_export_options($options);
			$export_job = synchy_start_export_job($export_options);

			if (is_wp_error($export_job)) {
				return synchy_mark_site_sync_job_error($job, $export_job->get_error_message());
			}

			$job['export_job_id'] = (string) ($export_job['job_id'] ?? '');
			$job['phase'] = 'exporting_package';
			$job['message'] = __('Building the Upload to Live package.', 'synchy');
			$job['progress'] = 10;

			return synchy_update_site_sync_job($job);

		case 'exporting_package':
			$export_job = synchy_get_export_job();

			if ($export_job === [] || (string) ($export_job['job_id'] ?? '') !== (string) ($job['export_job_id'] ?? '')) {
				return synchy_mark_site_sync_job_error($job, __('Synchy lost track of the export job for this Upload to Live run.', 'synchy'));
			}

			if (($export_job['status'] ?? '') === 'running') {
				$export_job = synchy_process_export_job($export_job);
			}

			if (($export_job['status'] ?? '') === 'error') {
				return synchy_mark_site_sync_job_error($job, (string) ($export_job['message'] ?? __('Synchy could not build the Upload to Live package.', 'synchy')));
			}

			if (($export_job['status'] ?? '') !== 'complete') {
				$job['message'] = (string) ($export_job['message'] ?? __('Building the Upload to Live package.', 'synchy'));
				$job['progress'] = max(10, min(55, 10 + (int) floor(((int) ($export_job['progress'] ?? 0)) * 0.45)));

				return synchy_update_site_sync_job($job);
			}

			$prepared_job = synchy_prepare_site_sync_local_artifacts($job, $export_job);

			if (is_wp_error($prepared_job)) {
				return synchy_mark_site_sync_job_error($job, $prepared_job->get_error_message());
			}

			$job = $prepared_job;

			$job['phase'] = 'starting_remote_session';
			$job['message'] = __('Local package complete. Opening the destination upload session.', 'synchy');
			$job['progress'] = 56;

			return synchy_update_site_sync_job($job);

		case 'starting_remote_session':
			$artifact_uploads = isset($job['artifact_uploads']) && is_array($job['artifact_uploads']) ? $job['artifact_uploads'] : [];

			$remote_session = synchy_site_sync_remote_request(
				$options,
				'push/session',
				'POST',
				[
					'timeout' => 30,
					'headers' => ['Content-Type' => 'application/json'],
					'body' => wp_json_encode(
						[
							'packageName' => $job['package_name'],
							'packageId' => $job['package_id'],
							'sourceHomeUrl' => home_url('/'),
							'sourceSiteUrl' => site_url('/'),
							'archiveFilename' => $artifact_uploads['archive']['filename'] ?? 'site.zip',
							'installerFilename' => $artifact_uploads['installer']['filename'] ?? 'installer.php',
						]
					),
					'data_format' => 'body',
				]
			);

			if (is_wp_error($remote_session)) {
				return synchy_mark_site_sync_job_error($job, $remote_session->get_error_message());
			}

			$job['remote_session_id'] = (string) ($remote_session['session_id'] ?? '');
			$job['upload_chunk_bytes'] = max(
				512 * KB_IN_BYTES,
				(int) ($remote_session['uploadChunkBytes'] ?? synchy_get_site_sync_upload_chunk_bytes())
			);
			$job['phase'] = 'uploading_archive';
			$job['current_artifact'] = 'archive';
			$job['message'] = __('Uploading the archive to the destination live site.', 'synchy');
			$job['progress'] = 60;

			return synchy_update_site_sync_job($job);

		case 'uploading_archive':
		case 'uploading_installer':
			$artifact = (string) ($job['current_artifact'] ?? '');
			$artifact_uploads = isset($job['artifact_uploads']) && is_array($job['artifact_uploads']) ? $job['artifact_uploads'] : [];
			$upload_state = isset($artifact_uploads[$artifact]) && is_array($artifact_uploads[$artifact]) ? $artifact_uploads[$artifact] : [];

			if ($artifact === '' || $upload_state === []) {
				return synchy_mark_site_sync_job_error($job, __('Synchy could not find the active upload state for Upload to Live.', 'synchy'));
			}

			$path = (string) ($upload_state['path'] ?? '');
			$size = (int) ($upload_state['size'] ?? 0);
			$offset = (int) ($upload_state['offset'] ?? 0);

			if ($path === '' || !is_readable($path)) {
				return synchy_mark_site_sync_job_error($job, __('Synchy could not read the local Upload to Live artifact before upload.', 'synchy'));
			}

			if ($offset >= $size) {
				if ($artifact === 'archive') {
					$job['current_artifact'] = 'installer';
					$job['phase'] = 'uploading_installer';
					$job['message'] = __('Archive upload complete. Sending installer.php to the destination.', 'synchy');

					return synchy_update_site_sync_job($job);
				}

				$job['phase'] = 'finalizing_remote_package';
				$job['message'] = __('Upload complete. Deploying the package and installer on the destination.', 'synchy');
				$job['progress'] = 96;

				return synchy_update_site_sync_job($job);
			}

			$chunk_size = max(512 * KB_IN_BYTES, (int) ($job['upload_chunk_bytes'] ?? synchy_get_site_sync_upload_chunk_bytes()));
			$chunk = file_get_contents($path, false, null, $offset, $chunk_size);

			if ($chunk === false || $chunk === '') {
				return synchy_mark_site_sync_job_error($job, __('Synchy could not read the next upload chunk for Upload to Live.', 'synchy'));
			}

			$upload_response = synchy_site_sync_remote_request(
				$options,
				sprintf(
					'push/upload?session_id=%1$s&artifact=%2$s&offset=%3$d&filename=%4$s',
					rawurlencode((string) $job['remote_session_id']),
					rawurlencode($artifact),
					$offset,
					rawurlencode((string) ($upload_state['filename'] ?? basename($path)))
				),
				'POST',
				[
					'timeout' => 120,
					'headers' => [
						'Content-Type' => 'application/octet-stream',
						'Content-Length' => (string) strlen($chunk),
					],
					'body' => $chunk,
					'data_format' => 'body',
				]
			);

			if (is_wp_error($upload_response)) {
				return synchy_mark_site_sync_job_error($job, $upload_response->get_error_message());
			}

			$offset += strlen($chunk);
			$artifact_uploads[$artifact]['offset'] = $offset;
			$job['artifact_uploads'] = $artifact_uploads;
			$job['bytes_uploaded'] = array_sum(array_map(static fn(array $item): int => (int) ($item['offset'] ?? 0), $artifact_uploads));
			$job['progress'] = $job['bytes_total'] > 0
				? 60 + (int) floor(35 * ($job['bytes_uploaded'] / (int) $job['bytes_total']))
				: 90;
			$job['message'] = sprintf(
				/* translators: 1: artifact label, 2: uploaded bytes, 3: total bytes */
				__('Uploading %1$s: %2$s of %3$s transferred.', 'synchy'),
				$artifact === 'archive' ? __('archive', 'synchy') : __('installer.php', 'synchy'),
				size_format($job['bytes_uploaded'], 2),
				size_format((int) $job['bytes_total'], 2)
			);

			if ($offset >= $size) {
				if ($artifact === 'archive') {
					$job['current_artifact'] = 'installer';
					$job['phase'] = 'uploading_installer';
					$job['message'] = __('Archive upload complete. Sending installer.php to the destination.', 'synchy');
				} else {
					$job['phase'] = 'finalizing_remote_package';
					$job['message'] = __('Upload complete. Deploying the package and installer on the destination.', 'synchy');
					$job['progress'] = 96;
				}
			}

			return synchy_update_site_sync_job($job);

		case 'finalizing_remote_package':
			$finalize = synchy_site_sync_remote_request(
				$options,
				'push/complete',
				'POST',
				[
					'timeout' => 30,
					'headers' => ['Content-Type' => 'application/json'],
					'body' => wp_json_encode(['session_id' => $job['remote_session_id']]),
					'data_format' => 'body',
				]
			);

			if (is_wp_error($finalize)) {
				return synchy_mark_site_sync_job_error($job, $finalize->get_error_message());
			}

			$job['status'] = 'complete';
			$job['phase'] = 'complete';
			$job['message'] = !empty($finalize['message'])
				? (string) $finalize['message']
				: __('Package delivered to the destination Synchy receiver.', 'synchy');
			$job['progress'] = 100;
			$job['remote_package'] = $finalize;

			synchy_set_notice('success', $job['message']);

			return synchy_update_site_sync_job($job);

		default:
			return synchy_mark_site_sync_job_error($job, __('Synchy encountered an unknown Upload to Live phase.', 'synchy'));
	}
}

function synchy_get_download_url(string $package_id, string $artifact_type): string
{
	return wp_nonce_url(
		admin_url(
			'admin-post.php?action=synchy_download_export&package=' . rawurlencode($package_id) . '&artifact=' . rawurlencode($artifact_type)
		),
		'synchy_download_export_' . $package_id . '_' . $artifact_type
	);
}

function synchy_get_delete_export_url(string $package_id, string $page_slug): string
{
	return wp_nonce_url(
		admin_url(
			'admin-post.php?action=synchy_delete_export&package=' . rawurlencode($package_id) . '&page=' . rawurlencode($page_slug)
		),
		'synchy_delete_export_' . $package_id
	);
}

function synchy_render_export_history(array $history, string $page_slug): void
{
	?>
	<div class="synchy-panel synchy-panel--wide">
		<div class="synchy-stack synchy-stack--compact">
			<div class="synchy-stack__split">
				<div>
					<h2><?php esc_html_e('Available Export History', 'synchy'); ?></h2>
					<p class="synchy-field-note">
						<?php esc_html_e('Synchy lists every retained export package whose archive is still available on disk. Delete removes the package files from this site.', 'synchy'); ?>
					</p>
				</div>
				<span class="synchy-badge">
					<?php
					printf(
						/* translators: %s: number of export packages */
						esc_html(_n('%s package', '%s packages', count($history), 'synchy')),
						esc_html(number_format_i18n(count($history)))
					);
					?>
				</span>
			</div>

			<?php if ($history === []) : ?>
				<p class="synchy-field-note"><?php esc_html_e('No Synchy exports are currently available on this site.', 'synchy'); ?></p>
			<?php else : ?>
				<div class="synchy-history-list">
					<?php foreach ($history as $entry) : ?>
						<?php
						$package_id = (string) ($entry['package_id'] ?? '');
						$package_name = (string) ($entry['package_name'] ?? $package_id);
						$artifacts = isset($entry['artifacts']) && is_array($entry['artifacts']) ? $entry['artifacts'] : [];
						$created = !empty($entry['created_at']) ? strtotime((string) $entry['created_at']) : false;
						?>
						<div class="synchy-history-item">
							<div class="synchy-stack synchy-stack--compact">
								<div class="synchy-stack__split">
									<div>
										<h3 class="synchy-history-item__title"><?php echo esc_html($package_name); ?></h3>
										<p class="synchy-field-note"><?php echo esc_html($package_id); ?></p>
									</div>
									<span class="synchy-badge">
										<?php
										echo esc_html(
											$created ? wp_date(get_option('date_format') . ' ' . get_option('time_format'), $created) : __('Unknown', 'synchy')
										);
										?>
									</span>
								</div>

								<div class="synchy-export-meta">
									<div>
										<strong><?php esc_html_e('Save path', 'synchy'); ?></strong>
										<span class="synchy-text-break"><?php echo esc_html((string) ($entry['output_directory'] ?? '')); ?></span>
									</div>
									<div>
										<strong><?php esc_html_e('Included files', 'synchy'); ?></strong>
										<span><?php echo esc_html(number_format_i18n((int) ($entry['file_count'] ?? 0))); ?></span>
									</div>
									<div>
										<strong><?php esc_html_e('Database tables', 'synchy'); ?></strong>
										<span><?php echo esc_html(number_format_i18n((int) ($entry['table_count'] ?? 0))); ?></span>
									</div>
									<div>
										<strong><?php esc_html_e('Archive size', 'synchy'); ?></strong>
										<span><?php echo esc_html(size_format((int) ($entry['archive_size'] ?? 0), 2)); ?></span>
									</div>
								</div>

								<div class="synchy-downloads">
									<?php foreach ($artifacts as $type => $artifact) : ?>
										<?php if (!synchy_is_export_artifact_readable($artifact)) : ?>
											<?php continue; ?>
										<?php endif; ?>
										<a class="button" href="<?php echo esc_url(synchy_get_download_url($package_id, (string) $type)); ?>">
											<?php echo esc_html((string) ($artifact['label'] ?? 'Download')); ?>
										</a>
									<?php endforeach; ?>
									<a
										class="button button-link-delete"
										href="<?php echo esc_url(synchy_get_delete_export_url($package_id, $page_slug)); ?>"
										onclick="return confirm('<?php echo esc_js(__('Delete this Synchy export and remove its files from disk?', 'synchy')); ?>');"
									>
										<?php esc_html_e('Delete Export', 'synchy'); ?>
									</a>
								</div>
							</div>
						</div>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>
		</div>
	</div>
	<?php
}

function synchy_get_admin_page_url(string $page_slug): string
{
	return admin_url('admin.php?page=' . rawurlencode($page_slug));
}

function synchy_format_dashboard_timestamp(string $timestamp): string
{
	$timestamp = trim($timestamp);

	if ($timestamp === '') {
		return __('Never', 'synchy');
	}

	$unix = strtotime($timestamp);

	if ($unix === false) {
		return __('Unknown', 'synchy');
	}

	$current = current_time('timestamp');
	$relative = human_time_diff($unix, $current);

	return sprintf(
		/* translators: 1: absolute datetime, 2: relative time */
		__('%1$s (%2$s ago)', 'synchy'),
		wp_date(get_option('date_format') . ' ' . get_option('time_format'), $unix),
		$relative
	);
}

function synchy_get_dashboard_import_summary(array $result): array
{
	$status = (string) ($result['status'] ?? '');

	return match ($status) {
		'ready' => [
			'label' => __('Ready to restore', 'synchy'),
			'detail' => !empty($result['installerUrl'])
				? __('installer.php and the package zip are in place.', 'synchy')
				: __('Package files were placed and are ready for restore.', 'synchy'),
		],
		'installer_ready' => [
			'label' => __('Installer ready', 'synchy'),
			'detail' => __('installer.php is in the root. Add the package zip next.', 'synchy'),
		],
		'staged_only' => [
			'label' => __('Staged only', 'synchy'),
			'detail' => __('Files were staged, but Synchy could not place them in the root automatically.', 'synchy'),
		],
		'error' => [
			'label' => __('Import error', 'synchy'),
			'detail' => (string) ($result['message'] ?? __('Synchy could not stage the import files.', 'synchy')),
		],
		default => [
			'label' => __('No import staged', 'synchy'),
			'detail' => __('Nothing is waiting in the Import workflow right now.', 'synchy'),
		],
	};
}

function synchy_get_dashboard_sync_summary(array $status): array
{
	$state = (string) ($status['status'] ?? '');
	$timestamp = (string) ($status['at'] ?? '');

	if ($state === '') {
		return [
			'label' => __('Never run', 'synchy'),
			'detail' => __('No Sync changes run has completed yet.', 'synchy'),
		];
	}

	$detail = (string) ($status['message'] ?? '');

	if (!empty($status['destinationUrl'])) {
		$detail = trim($detail . ' ' . sprintf(
			/* translators: %s: destination url */
			__('Destination: %s', 'synchy'),
			(string) $status['destinationUrl']
		));
	}

	return [
		'label' => synchy_format_dashboard_timestamp($timestamp),
		'detail' => $detail !== '' ? $detail : ucfirst($state),
	];
}

function synchy_get_dashboard_activity_items(): array
{
	$items = [];
	$export_job = synchy_get_running_export_job();

	if ($export_job !== []) {
		$items[] = [
			'label' => __('Export', 'synchy'),
			'progress' => max(0, min(100, (int) ($export_job['progress'] ?? 0))),
			'message' => (string) ($export_job['message'] ?? __('Export is running.', 'synchy')),
			'url' => synchy_get_admin_page_url('synchy-export'),
		];
	}

	$upload_job = synchy_get_running_site_sync_job();

	if ($upload_job !== []) {
		$items[] = [
			'label' => __('Upload to Live', 'synchy'),
			'progress' => max(0, min(100, (int) ($upload_job['progress'] ?? 0))),
			'message' => (string) ($upload_job['message'] ?? __('Upload to Live is running.', 'synchy')),
			'url' => synchy_get_admin_page_url('synchy-push-live-site'),
		];
	}

	return $items;
}

function synchy_render_dashboard_widget(): void
{
	$export_history = synchy_get_export_history();
	$latest_export = $export_history[0] ?? [];
	$recent_exports = array_slice($export_history, 0, 3);
	$import_result = synchy_get_import_result();
	$import_summary = synchy_get_dashboard_import_summary($import_result);
	$sync_summary = synchy_get_dashboard_sync_summary(synchy_get_sync_status());
	$activity_items = synchy_get_dashboard_activity_items();

	$latest_export_label = $latest_export === []
		? __('No exports yet', 'synchy')
		: synchy_format_dashboard_timestamp((string) ($latest_export['created_at'] ?? ''));

	$latest_export_detail = $latest_export === []
		? __('Create your first Synchy package from Export.', 'synchy')
		: sprintf(
			/* translators: 1: archive size, 2: file count */
			__('%1$s archive, %2$s files.', 'synchy'),
			size_format((int) ($latest_export['archive_size'] ?? 0), 2),
			number_format_i18n((int) ($latest_export['file_count'] ?? 0))
		);
	?>
	<div class="synchy-dashboard-widget">
		<div class="synchy-dashboard-widget__hero">
			<div>
				<p class="synchy-eyebrow"><?php esc_html_e('Backup Workflow', 'synchy'); ?></p>
				<h3><?php esc_html_e('Synchy', 'synchy'); ?></h3>
			</div>
			<span class="synchy-badge"><?php echo esc_html('v' . SYNCHY_VERSION); ?></span>
		</div>

		<div class="synchy-dashboard-widget__summary">
			<div class="synchy-dashboard-widget__stat">
				<span class="synchy-dashboard-widget__label"><?php esc_html_e('Latest Export', 'synchy'); ?></span>
				<strong><?php echo esc_html($latest_export_label); ?></strong>
				<span><?php echo esc_html($latest_export_detail); ?></span>
			</div>
			<div class="synchy-dashboard-widget__stat">
				<span class="synchy-dashboard-widget__label"><?php esc_html_e('Latest Import', 'synchy'); ?></span>
				<strong><?php echo esc_html($import_summary['label']); ?></strong>
				<span><?php echo esc_html($import_summary['detail']); ?></span>
			</div>
			<div class="synchy-dashboard-widget__stat">
				<span class="synchy-dashboard-widget__label"><?php esc_html_e('Last Sync', 'synchy'); ?></span>
				<strong><?php echo esc_html($sync_summary['label']); ?></strong>
				<span><?php echo esc_html($sync_summary['detail']); ?></span>
			</div>
		</div>

		<div class="synchy-dashboard-widget__section">
			<div class="synchy-stack__split">
				<strong><?php esc_html_e('Quick Actions', 'synchy'); ?></strong>
				<a class="button button-primary" href="<?php echo esc_url(synchy_get_admin_page_url('synchy-export')); ?>">
					<?php esc_html_e('Create Export', 'synchy'); ?>
				</a>
			</div>
			<div class="synchy-dashboard-widget__actions">
				<a class="button" href="<?php echo esc_url(synchy_get_admin_page_url('synchy-import')); ?>"><?php esc_html_e('Import', 'synchy'); ?></a>
				<a class="button" href="<?php echo esc_url(synchy_get_admin_page_url('synchy-push-live-site')); ?>"><?php esc_html_e('Upload to Live', 'synchy'); ?></a>
				<a class="button" href="<?php echo esc_url(synchy_get_admin_page_url('synchy-site-sync')); ?>"><?php esc_html_e('Sync', 'synchy'); ?></a>
				<a class="button" href="<?php echo esc_url(synchy_get_admin_page_url('synchy-settings')); ?>"><?php esc_html_e('About', 'synchy'); ?></a>
			</div>
		</div>

		<div class="synchy-dashboard-widget__section">
			<strong><?php esc_html_e('Current Activity', 'synchy'); ?></strong>
			<?php if ($activity_items === []) : ?>
				<p class="synchy-dashboard-widget__empty"><?php esc_html_e('No Synchy jobs are running right now.', 'synchy'); ?></p>
			<?php else : ?>
				<div class="synchy-dashboard-widget__activities">
					<?php foreach ($activity_items as $activity) : ?>
						<div class="synchy-dashboard-widget__activity">
							<div class="synchy-stack__split">
								<strong><?php echo esc_html((string) $activity['label']); ?></strong>
								<span class="synchy-badge"><?php echo esc_html((int) $activity['progress'] . '%'); ?></span>
							</div>
							<div class="synchy-progress__bar"><span style="width: <?php echo esc_attr((string) ((int) $activity['progress'])); ?>%;"></span></div>
							<p class="synchy-progress__detail"><?php echo esc_html((string) $activity['message']); ?></p>
							<p class="synchy-dashboard-widget__activity-link">
								<a href="<?php echo esc_url((string) $activity['url']); ?>"><?php esc_html_e('Open workflow', 'synchy'); ?></a>
							</p>
						</div>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>
		</div>

		<div class="synchy-dashboard-widget__section">
			<div class="synchy-stack__split">
				<strong><?php esc_html_e('Recent Exports', 'synchy'); ?></strong>
				<a href="<?php echo esc_url(synchy_get_admin_page_url('synchy-export')); ?>"><?php esc_html_e('Open Export', 'synchy'); ?></a>
			</div>
			<?php if ($recent_exports === []) : ?>
				<p class="synchy-dashboard-widget__empty"><?php esc_html_e('No Synchy export packages are available yet.', 'synchy'); ?></p>
			<?php else : ?>
				<ul class="synchy-dashboard-widget__list">
					<?php foreach ($recent_exports as $entry) : ?>
						<?php
						$package_id = (string) ($entry['package_id'] ?? '');
						$package_name = (string) ($entry['package_name'] ?? $package_id);
						?>
						<li class="synchy-dashboard-widget__list-item">
							<div>
								<strong><?php echo esc_html($package_name); ?></strong>
								<span><?php echo esc_html(synchy_format_dashboard_timestamp((string) ($entry['created_at'] ?? ''))); ?></span>
							</div>
							<?php if ($package_id !== '') : ?>
								<a class="button button-small" href="<?php echo esc_url(synchy_get_download_url($package_id, 'archive')); ?>">
									<?php esc_html_e('Archive', 'synchy'); ?>
								</a>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>
		</div>
	</div>
	<?php
}

function synchy_get_browse_root_path(): string
{
	return wp_normalize_path(untrailingslashit(ABSPATH));
}

function synchy_resolve_browse_directory(string $requested_path): string
{
	$root = synchy_get_browse_root_path();
	$requested_path = trim($requested_path);

	if ($requested_path === '' || $requested_path === './') {
		return $root;
	}

	if (synchy_is_absolute_path($requested_path)) {
		$absolute = wp_normalize_path(untrailingslashit($requested_path));

		if (is_dir($absolute) && synchy_is_path_within($absolute, $root)) {
			return $absolute;
		}

		return $root;
	}

	$absolute = wp_normalize_path(untrailingslashit(trailingslashit($root) . ltrim($requested_path, '/')));

	if (is_dir($absolute) && synchy_is_path_within($absolute, $root)) {
		return $absolute;
	}

	return $root;
}

function synchy_get_browse_payload(string $requested_path): array
{
	$root = synchy_get_browse_root_path();
	$current = synchy_resolve_browse_directory($requested_path);
	$relative = synchy_absolute_to_relative($current, $root);
	$display = $relative === '' ? './' : trailingslashit($relative);
	$directories = [];
	$items = scandir($current);

	if (is_array($items)) {
		foreach ($items as $item) {
			if ($item === '.' || $item === '..') {
				continue;
			}

			if (str_starts_with($item, '.')) {
				continue;
			}

			$child = wp_normalize_path($current . '/' . $item);

			if (!is_dir($child)) {
				continue;
			}

			$child_relative = synchy_absolute_to_relative($child, $root);
			$directories[] = [
				'name' => $item,
				'path' => trailingslashit($child_relative),
			];
		}
	}

	usort(
		$directories,
		static fn(array $a, array $b): int => strcasecmp((string) $a['name'], (string) $b['name'])
	);

	$parent = '';

	if ($current !== $root) {
		$parent_path = dirname($current);
		$parent = $parent_path === $root ? './' : trailingslashit(synchy_absolute_to_relative($parent_path, $root));
	}

	return [
		'currentPath' => $display,
		'currentAbsolutePath' => $current,
		'parentPath' => $parent,
		'directories' => $directories,
	];
}

function synchy_render_export_page(array $current): void
{
	$options = synchy_get_export_options();
	$groups = synchy_get_export_filter_groups();
	$included = synchy_get_export_included_items();
	$export_history = synchy_get_export_history();
	$running_job = synchy_get_running_export_job();
	$default_package_name = synchy_get_default_package_name();
	$package_preview_base = (string) $options['package_name'] !== ''
		? synchy_sanitize_package_name((string) $options['package_name'])
		: $default_package_name;
	$archive_preview = $package_preview_base . '.zip';
	$installer_preview = $package_preview_base . '-installer.php';
	$manifest_preview = $package_preview_base . '-manifest.json';
	?>
	<div class="wrap synchy-admin">
		<?php synchy_render_notice(); ?>
		<div class="synchy-shell">
			<div class="synchy-hero">
				<div>
					<p class="synchy-eyebrow"><?php esc_html_e('Export Design', 'synchy'); ?></p>
					<h1><?php echo esc_html($current['headline']); ?></h1>
					<p class="synchy-description"><?php echo esc_html($current['description']); ?></p>
				</div>
				<div class="synchy-status">
					<span class="synchy-status__dot" aria-hidden="true"></span>
					<?php echo esc_html($running_job === [] ? __('Export ready', 'synchy') : __('Export running', 'synchy')); ?>
				</div>
			</div>

			<form method="post" action="options.php" class="synchy-form" data-synchy-export-form>
				<?php settings_fields('synchy_export'); ?>

				<div class="synchy-grid synchy-grid--export">
					<div class="synchy-panel">
						<h2><?php esc_html_e('Full Export Includes', 'synchy'); ?></h2>
						<ul class="synchy-checklist synchy-checklist--detail">
							<?php foreach ($included as $item) : ?>
								<li>
									<strong><?php echo esc_html($item['label']); ?></strong>
									<span><?php echo esc_html($item['description']); ?></span>
								</li>
							<?php endforeach; ?>
						</ul>
					</div>

					<div class="synchy-panel synchy-panel--muted">
						<h2><?php esc_html_e('Package Output', 'synchy'); ?></h2>
						<div class="synchy-field">
							<label class="synchy-label" for="synchy-output-directory"><?php esc_html_e('Save path', 'synchy'); ?></label>
							<div class="synchy-input-row">
								<input
									id="synchy-output-directory"
									type="text"
									class="regular-text code"
									name="<?php echo esc_attr(SYNCHY_EXPORT_OPTIONS); ?>[output_directory]"
									value="<?php echo esc_attr((string) $options['output_directory']); ?>"
									data-synchy-output-directory
								/>
								<button type="button" class="button" data-synchy-browse><?php esc_html_e('Browse', 'synchy'); ?></button>
								<button type="button" class="button" data-synchy-use-default data-default-path="<?php echo esc_attr(synchy_get_default_output_directory()); ?>"><?php esc_html_e('Default', 'synchy'); ?></button>
							</div>
							<p class="synchy-field-note">
								<?php esc_html_e('Relative paths resolve from the WordPress root. The browser only lists folders inside this site.', 'synchy'); ?>
							</p>
						</div>

							<div class="synchy-field">
								<label class="synchy-label" for="synchy-package-name"><?php esc_html_e('Package name', 'synchy'); ?></label>
								<input
									id="synchy-package-name"
									type="text"
									class="regular-text"
									name="<?php echo esc_attr(SYNCHY_EXPORT_OPTIONS); ?>[package_name]"
									value="<?php echo esc_attr((string) $options['package_name']); ?>"
									placeholder="<?php echo esc_attr($default_package_name); ?>"
									data-synchy-package-name
								/>
								<p class="synchy-field-note">
									<?php
									printf(
										/* translators: %s: default package name */
										esc_html__('Leave this blank to use %s. Synchy adds the same base name to the zip, installer, and manifest files.', 'synchy'),
										esc_html($default_package_name)
									);
									?>
								</p>
							</div>

							<div class="synchy-package">
								<div><code data-synchy-archive-preview><?php echo esc_html($archive_preview); ?></code></div>
								<div><code data-synchy-installer-preview><?php echo esc_html($installer_preview); ?></code></div>
								<div><code data-synchy-manifest-preview><?php echo esc_html($manifest_preview); ?></code></div>
							</div>

							<div class="synchy-progress<?php echo $running_job === [] ? ' is-hidden' : ''; ?>" data-synchy-progress>
								<div class="synchy-progress__top">
									<strong data-synchy-progress-phase><?php echo esc_html(synchy_export_phase_label((string) ($running_job['phase'] ?? 'queued'))); ?></strong>
									<span data-synchy-progress-percent><?php echo esc_html((string) (int) ($running_job['progress'] ?? 0)); ?>%</span>
								</div>
								<div class="synchy-progress__bar">
									<span data-synchy-progress-bar style="width: <?php echo esc_attr((string) (int) ($running_job['progress'] ?? 0)); ?>%;"></span>
								</div>
							<p class="synchy-progress__message" data-synchy-progress-message><?php echo esc_html((string) ($running_job['message'] ?? '')); ?></p>
							<p class="synchy-progress__detail" data-synchy-progress-detail>
								<?php
								if ($running_job !== []) {
									printf(
										/* translators: 1: current file count, 2: total file count */
										esc_html__('Files processed: %1$s / %2$s', 'synchy'),
										esc_html(number_format_i18n((int) ($running_job['cursor'] ?? 0))),
										esc_html(number_format_i18n((int) ($running_job['file_count'] ?? 0)))
									);
								}
								?>
							</p>
							</div>

							<div class="synchy-run-export">
								<button type="button" class="button button-primary button-large" data-synchy-run-export><?php esc_html_e('Run Full Export', 'synchy'); ?></button>
							</div>

							<div class="synchy-stage-status">
								<p class="synchy-stage-status__label"><?php esc_html_e('Export Stage Status', 'synchy'); ?></p>
								<div class="synchy-export-stages" data-synchy-export-stages>
									<?php foreach (synchy_get_export_stage_items($running_job) as $stage) : ?>
										<div class="synchy-export-stage is-<?php echo esc_attr((string) $stage['state']); ?>">
											<span class="synchy-export-stage__indicator" aria-hidden="true"></span>
											<div class="synchy-export-stage__content">
												<strong><?php echo esc_html((string) $stage['label']); ?></strong>
												<span><?php echo esc_html((string) $stage['description']); ?></span>
											</div>
										</div>
									<?php endforeach; ?>
								</div>
							</div>
						</div>
					</div>

				<?php synchy_render_export_history($export_history, 'synchy-export'); ?>

				<div class="synchy-panel synchy-panel--wide">
					<h2><?php esc_html_e('Default Exclude Filters', 'synchy'); ?></h2>
					<p class="synchy-field-note">
						<?php esc_html_e('These filters define what Synchy should leave out of a full export by default. Your selected export destination is also excluded automatically at runtime.', 'synchy'); ?>
					</p>

					<div class="synchy-filter-list">
						<?php foreach ($groups as $key => $group) : ?>
							<div class="synchy-filter-card">
								<label class="synchy-toggle">
									<input
										type="checkbox"
										name="<?php echo esc_attr(SYNCHY_EXPORT_OPTIONS); ?>[<?php echo esc_attr($key); ?>]"
										value="1"
										<?php checked(!empty($options[$key])); ?>
									/>
									<span><?php echo esc_html($group['label']); ?></span>
								</label>
								<p><?php echo esc_html($group['description']); ?></p>
								<div class="synchy-patterns">
									<?php foreach ($group['patterns'] as $pattern) : ?>
										<code><?php echo esc_html($pattern); ?></code>
									<?php endforeach; ?>
								</div>
							</div>
						<?php endforeach; ?>
					</div>
				</div>

				<div class="synchy-grid synchy-grid--export">
					<div class="synchy-panel">
						<h2><?php esc_html_e('Custom Excludes', 'synchy'); ?></h2>
						<p class="synchy-field-note">
							<?php esc_html_e('Enter one path or glob per line. These will be added on top of the default filters.', 'synchy'); ?>
						</p>
						<textarea
							class="large-text code"
							rows="8"
							name="<?php echo esc_attr(SYNCHY_EXPORT_OPTIONS); ?>[custom_excludes]"
							placeholder=".env\nwp-content/synchy-temp/\ncustom-cache/"
						><?php echo esc_textarea((string) $options['custom_excludes']); ?></textarea>
					</div>

					<div class="synchy-panel synchy-panel--muted">
						<h2><?php esc_html_e('Notes', 'synchy'); ?></h2>
						<ul class="synchy-checklist">
							<li><?php esc_html_e('The chosen export folder is excluded from the backup automatically if it lives inside this WordPress install.', 'synchy'); ?></li>
							<li><?php esc_html_e('Duplicator backup folders remain excluded by default through wp-content/duplicator/.', 'synchy'); ?></li>
							<li><?php esc_html_e('Runtime dependencies like Composer vendor folders should not be stripped by default.', 'synchy'); ?></li>
							<li><?php esc_html_e('This package is not a Duplicator archive format. It will be restored through Synchy Import, not Duplicator Import.', 'synchy'); ?></li>
						</ul>
					</div>
				</div>

				<p class="submit">
					<button type="submit" class="button button-primary"><?php esc_html_e('Save Export Settings', 'synchy'); ?></button>
				</p>
			</form>
		</div>
	</div>

	<div class="synchy-modal is-hidden" data-synchy-directory-modal aria-hidden="true">
		<div class="synchy-modal__backdrop" data-synchy-modal-close></div>
		<div class="synchy-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="synchy-folder-browser-title">
			<div class="synchy-modal__header">
				<h2 id="synchy-folder-browser-title"><?php esc_html_e('Choose Export Folder', 'synchy'); ?></h2>
				<button type="button" class="button-link" data-synchy-modal-close><?php esc_html_e('Close', 'synchy'); ?></button>
			</div>
			<p class="synchy-modal__path" data-synchy-directory-current>./</p>
			<div class="synchy-modal__actions">
				<button type="button" class="button" data-synchy-directory-up><?php esc_html_e('Up One Level', 'synchy'); ?></button>
				<button type="button" class="button button-primary" data-synchy-directory-select><?php esc_html_e('Use This Folder', 'synchy'); ?></button>
			</div>
			<div class="synchy-directory-list" data-synchy-directory-list></div>
		</div>
	</div>
	<?php
}

function synchy_render_site_sync_page(array $current): void
{
	$options = synchy_get_site_sync_options();
	$running_job = synchy_get_running_site_sync_job();
	$stage_items = synchy_get_site_sync_stage_items($running_job);
	$password_hint = synchy_get_site_sync_password_hint($options);
	?>
	<div class="wrap synchy-admin">
		<?php synchy_render_notice(); ?>
		<div class="synchy-shell">
			<div class="synchy-hero">
				<div>
					<p class="synchy-eyebrow"><?php esc_html_e('Upload Workflow', 'synchy'); ?></p>
					<h1><?php echo esc_html($current['headline']); ?></h1>
					<p class="synchy-description"><?php echo esc_html($current['description']); ?></p>
				</div>
				<div class="synchy-status">
					<span class="synchy-status__dot" aria-hidden="true"></span>
					<?php echo esc_html($running_job === [] ? __('Destination ready', 'synchy') : __('Push running', 'synchy')); ?>
				</div>
			</div>

			<div class="synchy-panel synchy-panel--danger synchy-panel--wide">
				<div class="synchy-stack synchy-stack--compact">
					<div>
						<p class="synchy-panel__eyebrow synchy-panel__eyebrow--danger"><?php esc_html_e('Not Ready Yet', 'synchy'); ?></p>
						<h2><?php esc_html_e('Upload to Live is still a manual package-delivery workflow.', 'synchy'); ?></h2>
						<p>
							<?php esc_html_e('It is good for sending the full Synchy package and installer.php to the destination site. It is not yet a one-click live deployment or automatic remote restore.', 'synchy'); ?>
						</p>
					</div>
					<ul class="synchy-checklist">
						<li><?php esc_html_e('Working now: save the destination connection, verify authentication, and confirm the destination receiver is reachable.', 'synchy'); ?></li>
						<li><?php esc_html_e('Working now: build a fresh full-site package locally with the Synchy export engine.', 'synchy'); ?></li>
						<li><?php esc_html_e('Working now: upload the archive and installer.php to the destination site in chunks.', 'synchy'); ?></li>
						<li><?php esc_html_e('Working now: place installer.php and the package zip in the destination root when that root is writable by PHP.', 'synchy'); ?></li>
						<li><?php esc_html_e('Still manual: open installer.php on the destination site and run the overwrite/restore yourself.', 'synchy'); ?></li>
					</ul>
				</div>
			</div>

			<form method="post" action="options.php" class="synchy-form" data-synchy-site-sync-form>
				<?php settings_fields('synchy_site_sync'); ?>

				<div class="synchy-grid synchy-grid--upload-live">
					<div class="synchy-panel synchy-panel--muted">
							<h2><?php esc_html_e('Destination Connection', 'synchy'); ?></h2>
						<div class="synchy-field">
							<label class="synchy-label" for="synchy-destination-url"><?php esc_html_e('WordPress URL', 'synchy'); ?></label>
							<input
								id="synchy-destination-url"
								type="url"
								class="regular-text code"
								name="<?php echo esc_attr(SYNCHY_SITE_SYNC_OPTIONS); ?>[destination_url]"
								value="<?php echo esc_attr((string) $options['destination_url']); ?>"
								placeholder="https://live-site.com"
								data-synchy-site-sync-url
							/>
						</div>

						<div class="synchy-field">
							<label class="synchy-label" for="synchy-destination-username"><?php esc_html_e('Username', 'synchy'); ?></label>
							<input
								id="synchy-destination-username"
								type="text"
								class="regular-text"
								name="<?php echo esc_attr(SYNCHY_SITE_SYNC_OPTIONS); ?>[destination_username]"
								value="<?php echo esc_attr((string) $options['destination_username']); ?>"
								autocomplete="username"
								data-synchy-site-sync-username
							/>
						</div>

						<div class="synchy-field">
							<label class="synchy-label" for="synchy-destination-application-password"><?php esc_html_e('Application Password', 'synchy'); ?></label>
							<input
								id="synchy-destination-application-password"
								type="password"
								class="regular-text"
								name="<?php echo esc_attr(SYNCHY_SITE_SYNC_OPTIONS); ?>[destination_application_password]"
								value=""
								autocomplete="new-password"
								placeholder="<?php esc_attr_e('Leave blank to keep the saved password', 'synchy'); ?>"
								data-synchy-site-sync-password
							/>
							<p class="synchy-field-note"><?php echo esc_html($password_hint); ?></p>
						</div>

							<div class="synchy-field">
								<label class="synchy-toggle">
									<input
										type="checkbox"
										name="<?php echo esc_attr(SYNCHY_SITE_SYNC_OPTIONS); ?>[verify_ssl]"
										value="1"
										<?php checked(!empty($options['verify_ssl'])); ?>
									/>
									<span><?php esc_html_e('Verify HTTPS certificates', 'synchy'); ?></span>
								</label>
								<p class="synchy-field-note">
									<?php esc_html_e('Leave this on for real live sites. Turn it off only when you are testing against a local or self-signed destination.', 'synchy'); ?>
								</p>
							</div>

							<div class="synchy-progress<?php echo $running_job === [] ? ' is-hidden' : ''; ?>" data-synchy-site-sync-progress>
								<div class="synchy-progress__top">
									<strong data-synchy-site-sync-phase><?php echo esc_html(synchy_site_sync_phase_label((string) ($running_job['phase'] ?? ''))); ?></strong>
									<span data-synchy-site-sync-percent><?php echo esc_html((string) (int) ($running_job['progress'] ?? 0)); ?>%</span>
								</div>
							<div class="synchy-progress__bar">
								<span data-synchy-site-sync-bar style="width: <?php echo esc_attr((string) (int) ($running_job['progress'] ?? 0)); ?>%;"></span>
							</div>
							<p class="synchy-progress__message" data-synchy-site-sync-message><?php echo esc_html((string) ($running_job['message'] ?? '')); ?></p>
							<p class="synchy-progress__detail" data-synchy-site-sync-detail>
								<?php
								if ($running_job !== []) {
									echo esc_html(
										sprintf(
											/* translators: 1: uploaded bytes, 2: total bytes */
											__('Uploaded %1$s of %2$s', 'synchy'),
											size_format((int) ($running_job['bytes_uploaded'] ?? 0), 2),
											size_format((int) ($running_job['bytes_total'] ?? 0), 2)
										)
									);
								}
								?>
							</p>
							<p class="synchy-progress__detail" data-synchy-site-sync-timing></p>
								<p class="synchy-field-note" data-synchy-site-sync-warning>
									<?php esc_html_e('Keep this tab open while the live push is running. Refreshing or leaving the page interrupts the upload.', 'synchy'); ?>
								</p>
							</div>

							<div class="synchy-run-export">
								<div class="synchy-input-row">
								<button type="submit" class="button" data-synchy-save-site-sync><?php esc_html_e('Save Connection', 'synchy'); ?></button>
								<button type="button" class="button" data-synchy-test-site-sync><?php esc_html_e('Test Connection', 'synchy'); ?></button>
									<button type="button" class="button button-primary button-large" data-synchy-run-site-sync><?php esc_html_e('Upload to Live', 'synchy'); ?></button>
								</div>
							</div>

							<div class="synchy-stage-status">
								<p class="synchy-stage-status__label"><?php esc_html_e('Upload Stage Status', 'synchy'); ?></p>
								<div class="synchy-export-stages" data-synchy-site-sync-stages>
									<?php foreach ($stage_items as $stage) : ?>
										<div class="synchy-export-stage is-<?php echo esc_attr((string) $stage['state']); ?>">
											<span class="synchy-export-stage__indicator" aria-hidden="true"></span>
											<div class="synchy-export-stage__content">
												<strong><?php echo esc_html((string) $stage['label']); ?></strong>
												<span><?php echo esc_html((string) $stage['description']); ?></span>
											</div>
										</div>
									<?php endforeach; ?>
								</div>
							</div>
					</div>

					<div class="synchy-stack">
						<div class="synchy-panel synchy-site-sync-result is-hidden" data-synchy-site-sync-result>
							<div class="synchy-stack synchy-stack--compact">
								<div class="synchy-stack__split">
									<h2><?php esc_html_e('Destination Check', 'synchy'); ?></h2>
									<span class="synchy-badge" data-synchy-site-sync-result-badge><?php esc_html_e('Pending', 'synchy'); ?></span>
								</div>
								<p class="synchy-field-note" data-synchy-site-sync-result-message><?php esc_html_e('Use Test Connection to verify the destination Synchy receiver.', 'synchy'); ?></p>
								<div class="synchy-export-meta synchy-export-meta--wide" data-synchy-site-sync-result-meta></div>
							</div>
						</div>

						<div class="synchy-panel">
							<h2><?php esc_html_e('Destination Requirements', 'synchy'); ?></h2>
							<ul class="synchy-checklist">
								<li><?php esc_html_e('Synchy must be installed and active on the destination site.', 'synchy'); ?></li>
								<li><?php esc_html_e('The destination user must be able to manage options so Synchy can verify and receive the push package.', 'synchy'); ?></li>
								<li><?php esc_html_e('Application Passwords should be created on the live site user profile and used here instead of the raw wp-admin password.', 'synchy'); ?></li>
								<li><?php esc_html_e('If you want Synchy to place installer.php and the zip directly in the destination root, that WordPress root must be writable by PHP.', 'synchy'); ?></li>
							</ul>
						</div>

						<div class="synchy-panel synchy-panel--muted">
							<h2><?php esc_html_e('Current Limits', 'synchy'); ?></h2>
							<ul class="synchy-checklist">
								<li><?php esc_html_e('This live-push build authenticates, packages, uploads, and deploys a standalone installer to the destination root when that root is writable.', 'synchy'); ?></li>
								<li><?php esc_html_e('The actual overwrite is still a manual installer run on the destination. One-click remote apply is not connected yet.', 'synchy'); ?></li>
								<li><?php esc_html_e('If the destination root is not writable, Synchy leaves the package in wp-content/uploads/synchy-site-sync and you must move the zip and installer.php manually.', 'synchy'); ?></li>
								<li><?php esc_html_e('HTTPS chunk uploads depend on the destination host accepting request bodies at your configured chunk size.', 'synchy'); ?></li>
							</ul>
						</div>
					</div>
				</div>

				<div class="synchy-panel synchy-panel--wide synchy-panel--muted">
					<div class="synchy-stack synchy-stack--compact">
						<div>
							<h2><?php esc_html_e('What This Build Does', 'synchy'); ?></h2>
							<p class="synchy-field-note"><?php echo esc_html($current['description']); ?></p>
						</div>
						<ul class="synchy-checklist synchy-checklist--detail">
							<li>
								<strong><?php esc_html_e('Authenticates against the destination site', 'synchy'); ?></strong>
								<span><?php esc_html_e('Synchy connects with the destination username and WordPress application password over the REST API.', 'synchy'); ?></span>
							</li>
							<li>
								<strong><?php esc_html_e('Builds a fresh full-site package locally', 'synchy'); ?></strong>
								<span><?php esc_html_e('The same export engine powers this live push so you always send a complete package generated from the local site.', 'synchy'); ?></span>
							</li>
							<li>
								<strong><?php esc_html_e('Uploads the package to the destination Synchy receiver', 'synchy'); ?></strong>
								<span><?php esc_html_e('Archive and installer.php are transferred in chunks so large packages can move through normal HTTPS requests.', 'synchy'); ?></span>
							</li>
							<li>
								<strong><?php esc_html_e('Deploys a manual restore installer to the destination root', 'synchy'); ?></strong>
								<span><?php esc_html_e('After upload, Synchy tries to place the zip and installer.php in the destination WordPress root so you can launch the restore manually.', 'synchy'); ?></span>
							</li>
						</ul>
					</div>
				</div>

			</form>
		</div>
	</div>
	<?php
}

function synchy_render_schedule_page(array $current): void
{
	?>
	<div class="wrap synchy-admin">
		<?php synchy_render_notice(); ?>
		<div class="synchy-shell">
			<div class="synchy-hero">
				<div>
					<p class="synchy-eyebrow"><?php esc_html_e('Automation Workflow', 'synchy'); ?></p>
					<h1><?php echo esc_html($current['headline']); ?></h1>
					<p class="synchy-description"><?php echo esc_html($current['description']); ?></p>
				</div>
				<div class="synchy-status">
					<span class="synchy-status__dot" aria-hidden="true"></span>
					<?php esc_html_e('Not ready', 'synchy'); ?>
				</div>
			</div>

			<div class="synchy-panel synchy-panel--danger synchy-panel--wide">
				<div class="synchy-stack synchy-stack--compact">
					<div>
						<p class="synchy-panel__eyebrow synchy-panel__eyebrow--danger"><?php esc_html_e('Not Ready Yet', 'synchy'); ?></p>
						<h2><?php esc_html_e('Scheduled backups are not connected yet.', 'synchy'); ?></h2>
						<p>
							<?php esc_html_e('This area does not create or run automated jobs yet. Use the manual workflows below until scheduling is built and validated.', 'synchy'); ?>
						</p>
					</div>
					<ul class="synchy-checklist">
						<li><?php esc_html_e('Working now: Export builds a full package on demand with archive history and downloads.', 'synchy'); ?></li>
						<li><?php esc_html_e('Working now: Import places installer.php and smaller packages on the destination for manual restore.', 'synchy'); ?></li>
						<li><?php esc_html_e('Working now: Upload to Live sends the full package to another WordPress site and stages the manual restore there.', 'synchy'); ?></li>
						<li><?php esc_html_e('Not ready yet: recurring schedules, retention automation, unattended remote jobs, and email/reporting around scheduled runs.', 'synchy'); ?></li>
					</ul>
				</div>
			</div>

			<div class="synchy-grid">
				<div class="synchy-panel">
					<h2><?php esc_html_e('Use These Instead', 'synchy'); ?></h2>
					<ul class="synchy-checklist">
						<li><?php esc_html_e('Use Export when you want a fresh manual backup package right now.', 'synchy'); ?></li>
						<li><?php esc_html_e('Use Import on the destination site when you want to place installer.php or a smaller package manually.', 'synchy'); ?></li>
						<li><?php esc_html_e('Use Upload to Live when you want Synchy to deliver the package and installer to another site for manual restore.', 'synchy'); ?></li>
					</ul>
				</div>

				<div class="synchy-panel synchy-panel--muted">
					<h2><?php esc_html_e('What Is Still Missing', 'synchy'); ?></h2>
					<ul class="synchy-checklist">
						<li><?php esc_html_e('Choosing schedules like hourly, daily, or weekly.', 'synchy'); ?></li>
						<li><?php esc_html_e('Queueing jobs reliably in WP-Cron or a server cron runner.', 'synchy'); ?></li>
						<li><?php esc_html_e('Automatic cleanup, retention, notifications, and failed-run recovery.', 'synchy'); ?></li>
					</ul>
				</div>
			</div>
		</div>
	</div>
	<?php
}

function synchy_render_incremental_site_sync_page(array $current): void
{
	$options = synchy_get_site_sync_options();
	$running_job = synchy_get_running_sync_job();
	$connection_state = synchy_get_current_sync_connection_state($options);
	$sync_stage_items = synchy_get_sync_stage_items($running_job);
	$password_hint = synchy_get_site_sync_password_hint($options);
	$scope_definitions = synchy_get_sync_scope_definitions();
	$scope_status = synchy_get_sync_scope_status($options);
	$last_sync_time = synchy_get_sync_last_time();
	$status = synchy_get_sync_status();
	$status_state = (string) ($status['status'] ?? '');
	$status_badge = __('Awaiting baseline', 'synchy');
	$status_message = __('No Sync has completed yet. The first Sync sends a baseline for the selected folders and database tables. Later Sync runs send deltas only.', 'synchy');
	$status_destination = (string) ($status['destinationUrl'] ?? $options['destination_url'] ?? __('Not set', 'synchy'));
	$status_mode = ucfirst((string) ($status['mode'] ?? ($last_sync_time > 0 ? 'delta' : 'baseline')));
	$status_duration = !empty($status['durationSeconds']) ? synchy_format_sync_duration((float) $status['durationSeconds']) : __('N/A', 'synchy');
	$connection_state_status = (string) ($connection_state['status'] ?? '');
	$connection_badge = __('Pending', 'synchy');
	$connection_message = __('Use Test Connection to verify the destination Synchy receiver.', 'synchy');
	$connection_inline_badge = __('Not checked', 'synchy');
	$connection_inline_class = 'synchy-badge synchy-badge--muted';
	$connection_remote_site = isset($connection_state['remoteSite']) && is_array($connection_state['remoteSite']) ? $connection_state['remoteSite'] : [];
	$connection_panel_classes = 'synchy-panel synchy-site-sync-result is-hidden';
	$status_summary = sprintf(
		/* translators: 1: last sync timestamp, 2: destination URL, 3: files synced, 4: DB rows synced, 5: mode, 6: duration */
		__('Last Sync: %1$s | %2$s | %3$s files | %4$s DB rows | %5$s | %6$s', 'synchy'),
		$last_sync_time > 0 ? get_date_from_gmt(gmdate('Y-m-d H:i:s', $last_sync_time), get_option('date_format') . ' ' . get_option('time_format')) : __('Never', 'synchy'),
		$status_destination,
		number_format_i18n((int) ($status['filesSynced'] ?? 0)),
		number_format_i18n((int) ($status['dbRowsSynced'] ?? 0)),
		$status_mode,
		$status_duration
	);
	$run_button_label = $scope_status['hasPendingBaseline'] ? __('Start Baseline', 'synchy') : __('Push Changes', 'synchy');

	if ($status_state === 'success') {
		$status_badge = __('Success', 'synchy');
		$status_message = (string) ($status['message'] ?? __('The most recent Sync completed successfully.', 'synchy'));
	} elseif ($status_state === 'error') {
		$status_badge = __('Error', 'synchy');
		$status_message = (string) ($status['message'] ?? __('The most recent Sync failed.', 'synchy'));
		$status_summary = $status_message;
	} elseif ($status_state === 'idle') {
		$status_badge = __('No changes', 'synchy');
		$status_message = (string) ($status['message'] ?? __('No file or database changes were detected for Sync.', 'synchy'));
	} elseif (!$scope_status['hasPendingBaseline']) {
		$status_badge = __('Delta ready', 'synchy');
	}

	if ($connection_state_status === 'connected') {
		$connection_badge = __('Connection ready', 'synchy');
		$connection_message = (string) ($connection_state['message'] ?? __('Destination site is ready for Sync.', 'synchy'));
		$connection_inline_badge = __('Connected', 'synchy');
		$connection_inline_class = 'synchy-badge synchy-badge--connected';
		$connection_panel_classes = 'synchy-panel synchy-site-sync-result';
	} elseif ($connection_state_status === 'error') {
		$connection_badge = __('Connection failed', 'synchy');
		$connection_message = (string) ($connection_state['message'] ?? __('Synchy could not connect to the destination site.', 'synchy'));
		$connection_inline_badge = __('Failed', 'synchy');
		$connection_inline_class = 'synchy-badge synchy-badge--warning';
		$connection_panel_classes = 'synchy-panel synchy-site-sync-result';
	} elseif ((string) ($options['destination_url'] ?? '') === '' || (string) ($options['destination_username'] ?? '') === '' || (string) ($options['destination_application_password'] ?? '') === '') {
		$connection_inline_badge = __('Incomplete', 'synchy');
	}
	?>
	<div class="wrap synchy-admin">
		<?php synchy_render_notice(); ?>
		<div class="synchy-shell">
			<div class="synchy-hero">
				<div>
					<p class="synchy-eyebrow"><?php esc_html_e('Selective Delta Workflow', 'synchy'); ?></p>
					<h1><?php echo esc_html($current['headline']); ?></h1>
					<p class="synchy-description"><?php echo esc_html($current['description']); ?></p>
				</div>
				<div class="synchy-status">
					<span class="synchy-status__dot" aria-hidden="true"></span>
					<?php
					echo esc_html(
						$running_job !== []
							? __('Sync running', 'synchy')
							: ($scope_status['hasPendingBaseline'] ? __('Baseline ready', 'synchy') : __('Delta ready', 'synchy'))
					);
					?>
				</div>
			</div>

			<form method="post" action="options.php" class="synchy-form" data-synchy-sync-form>
				<?php settings_fields('synchy_site_sync'); ?>
				<input type="hidden" name="<?php echo esc_attr(SYNCHY_SITE_SYNC_OPTIONS); ?>[sync_scope_selection_present]" value="1" />

				<div class="synchy-grid synchy-grid--upload-live">
					<div class="synchy-panel synchy-panel--muted">
						<h2><?php esc_html_e('Destination Connection', 'synchy'); ?></h2>
						<div class="synchy-field">
							<label class="synchy-label" for="synchy-sync-destination-url"><?php esc_html_e('WordPress URL', 'synchy'); ?></label>
							<div class="synchy-field-inline">
								<input
									id="synchy-sync-destination-url"
									type="url"
									class="regular-text code synchy-field-inline__input"
									name="<?php echo esc_attr(SYNCHY_SITE_SYNC_OPTIONS); ?>[destination_url]"
									value="<?php echo esc_attr((string) $options['destination_url']); ?>"
									placeholder="https://live-site.com"
									data-synchy-sync-url
								/>
								<button type="submit" class="button" data-synchy-save-sync disabled><?php esc_html_e('Save Connection', 'synchy'); ?></button>
							</div>
						</div>

						<div class="synchy-field">
							<label class="synchy-label" for="synchy-sync-destination-username"><?php esc_html_e('Username', 'synchy'); ?></label>
							<div class="synchy-field-inline">
								<input
									id="synchy-sync-destination-username"
									type="text"
									class="regular-text synchy-field-inline__input"
									name="<?php echo esc_attr(SYNCHY_SITE_SYNC_OPTIONS); ?>[destination_username]"
									value="<?php echo esc_attr((string) $options['destination_username']); ?>"
									autocomplete="username"
									data-synchy-sync-username
								/>
								<button type="button" class="button" data-synchy-test-sync><?php esc_html_e('Test Connection', 'synchy'); ?></button>
							</div>
						</div>

						<div class="synchy-field">
							<div class="synchy-field-label-row">
								<label class="synchy-label" for="synchy-sync-destination-password"><?php esc_html_e('Application Password', 'synchy'); ?></label>
								<span class="<?php echo esc_attr($connection_inline_class); ?>" data-synchy-sync-inline-status><?php echo esc_html($connection_inline_badge); ?></span>
							</div>
							<input
								id="synchy-sync-destination-password"
								type="password"
								class="regular-text"
								name="<?php echo esc_attr(SYNCHY_SITE_SYNC_OPTIONS); ?>[destination_application_password]"
								value=""
								autocomplete="new-password"
								placeholder="<?php esc_attr_e('Leave blank to keep the saved password', 'synchy'); ?>"
								data-synchy-sync-password
								data-has-saved-password="<?php echo !empty($options['destination_application_password']) ? '1' : '0'; ?>"
							/>
							<p class="synchy-field-note"><?php echo esc_html($password_hint); ?></p>
						</div>

						<div class="synchy-field">
							<label class="synchy-toggle">
								<input
									type="checkbox"
									name="<?php echo esc_attr(SYNCHY_SITE_SYNC_OPTIONS); ?>[verify_ssl]"
									value="1"
									<?php checked(!empty($options['verify_ssl'])); ?>
									data-synchy-sync-verify-ssl
								/>
								<span><?php esc_html_e('Verify HTTPS certificates', 'synchy'); ?></span>
							</label>
						</div>

						<div class="synchy-field">
							<div class="synchy-stack synchy-stack--compact">
								<div>
									<label class="synchy-label"><?php esc_html_e('Baseline & Push Changes', 'synchy'); ?></label>
									<p class="synchy-field-note">
										<?php esc_html_e('Choose exactly what this Sync should control on the selected destination. Unchecked scopes are ignored.', 'synchy'); ?>
									</p>
								</div>
								<div class="synchy-run-export">
									<div class="synchy-input-row">
										<button type="button" class="button" data-synchy-preview-sync><?php esc_html_e('Preview Changes', 'synchy'); ?></button>
										<button type="button" class="button button-primary button-large" data-synchy-run-sync disabled><?php echo esc_html($run_button_label); ?></button>
										<button type="button" class="button" data-synchy-run-full-sync disabled><?php esc_html_e('Full Sync', 'synchy'); ?></button>
										<button type="button" class="button" data-synchy-pause-sync disabled><?php esc_html_e('Pause Sync', 'synchy'); ?></button>
										<button type="button" class="button" data-synchy-resume-sync disabled><?php esc_html_e('Resume Sync', 'synchy'); ?></button>
										<button
											type="button"
											class="button"
											data-synchy-mark-baseline
										>
											<?php esc_html_e('Mark Manual Baseline Complete', 'synchy'); ?>
										</button>
									</div>
									<p class="synchy-field-note" data-synchy-sync-target-note>
										<?php
										printf(
											/* translators: %s: destination URL */
											esc_html__('Sync sends changes only to %s.', 'synchy'),
											esc_html((string) ($options['destination_url'] ?: __('the destination URL above', 'synchy')))
										);
										?>
									</p>
								</div>
								<div class="synchy-sync-scope-table">
									<?php foreach ($scope_definitions as $scope_id => $scope) : ?>
										<?php $tracked_items = synchy_get_sync_scope_tracked_items((string) $scope_id); ?>
										<input
											type="hidden"
											name="<?php echo esc_attr(SYNCHY_SITE_SYNC_OPTIONS); ?>[<?php echo esc_attr((string) $scope['option_key']); ?>]"
											value="<?php echo !empty($options[(string) $scope['option_key']]) ? '1' : '0'; ?>"
											data-synchy-sync-scope
											data-scope-id="<?php echo esc_attr((string) $scope_id); ?>"
										/>
										<div class="synchy-sync-scope-table__row" data-synchy-sync-scope-row data-scope-id="<?php echo esc_attr((string) $scope_id); ?>">
											<div class="synchy-sync-scope-table__name">
												<strong><?php echo esc_html((string) $scope['label']); ?></strong>
												<span><?php echo esc_html((string) $scope['description']); ?></span>
												<?php if ($tracked_items !== []) : ?>
													<details class="synchy-sync-scope-table__tracked">
														<summary>
															<?php
															printf(
																/* translators: %d: number of tracked items */
																esc_html__('Tracked items (%d)', 'synchy'),
																count($tracked_items)
															);
															?>
														</summary>
														<ul class="synchy-sync-scope-table__tracked-list">
															<?php foreach ($tracked_items as $tracked_item) : ?>
																<li class="synchy-text-break"><?php echo esc_html((string) $tracked_item); ?></li>
															<?php endforeach; ?>
														</ul>
													</details>
												<?php endif; ?>
											</div>
											<div class="synchy-sync-scope-table__status">
												<span class="synchy-badge synchy-badge--muted" data-synchy-sync-scope-status>
													<?php
													echo esc_html(
														in_array((string) $scope_id, $scope_status['pendingBaselineScopeIds'], true)
															? __('Needs baseline', 'synchy')
															: __('Ready for preview', 'synchy')
													);
													?>
												</span>
											</div>
										</div>
									<?php endforeach; ?>
								</div>
							</div>
						</div>

					</div>
					<div class="synchy-stack">
						<div class="<?php echo esc_attr($connection_panel_classes); ?>" data-synchy-sync-connection-result>
							<div class="synchy-stack synchy-stack--compact">
								<div class="synchy-stack__split">
									<h2><?php esc_html_e('Connection Check', 'synchy'); ?></h2>
									<span class="synchy-badge" data-synchy-sync-connection-badge><?php echo esc_html($connection_badge); ?></span>
								</div>
								<p class="synchy-field-note" data-synchy-sync-connection-message><?php echo esc_html($connection_message); ?></p>
								<div class="synchy-export-meta" data-synchy-sync-connection-meta>
									<?php if ($connection_state_status === 'connected') : ?>
										<div>
											<span class="synchy-export-meta__label"><?php esc_html_e('Site', 'synchy'); ?></span>
											<strong><?php echo esc_html((string) ($connection_remote_site['name'] ?? '')); ?></strong>
										</div>
										<div>
											<span class="synchy-export-meta__label"><?php esc_html_e('Destination', 'synchy'); ?></span>
											<strong><?php echo esc_html((string) ($connection_remote_site['siteUrl'] ?? '')); ?></strong>
										</div>
										<div>
											<span class="synchy-export-meta__label"><?php esc_html_e('Local plugin version', 'synchy'); ?></span>
											<strong><?php echo esc_html(SYNCHY_VERSION); ?></strong>
										</div>
										<div>
											<span class="synchy-export-meta__label"><?php esc_html_e('Plugin version', 'synchy'); ?></span>
											<strong><?php echo esc_html((string) ($connection_remote_site['pluginVersion'] ?? '')); ?></strong>
										</div>
										<div>
											<span class="synchy-export-meta__label"><?php esc_html_e('Authenticated as', 'synchy'); ?></span>
											<strong><?php echo esc_html((string) ($connection_remote_site['authenticatedAs'] ?? '')); ?></strong>
										</div>
									<?php endif; ?>
								</div>
								<div class="synchy-stack synchy-stack--compact">
									<button type="button" class="button is-hidden" data-synchy-update-remote-synchy><?php esc_html_e('Update Live Synchy', 'synchy'); ?></button>
									<p class="synchy-field-note" data-synchy-update-remote-note><?php esc_html_e('Run or wait for the connection check to compare Synchy versions.', 'synchy'); ?></p>
								</div>
							</div>
						</div>

						<div class="synchy-panel synchy-panel--muted" data-synchy-sync-status-panel>
							<div class="synchy-stack synchy-stack--compact">
								<div class="synchy-stack__split">
									<h2><?php esc_html_e('Status', 'synchy'); ?></h2>
									<span class="synchy-badge" data-synchy-sync-status-badge><?php echo esc_html($status_badge); ?></span>
								</div>
								<p class="synchy-status-line" data-synchy-sync-status-summary><?php echo esc_html($status_summary); ?></p>
								<div class="synchy-stage-status synchy-stage-status--compact">
									<p class="synchy-stage-status__label"><?php esc_html_e('Sync Stage Status', 'synchy'); ?></p>
									<div class="synchy-export-stages synchy-export-stages--inline" data-synchy-sync-stages>
										<?php foreach ($sync_stage_items as $stage) : ?>
											<div class="synchy-export-stage is-<?php echo esc_attr((string) $stage['state']); ?>">
												<span class="synchy-export-stage__indicator" aria-hidden="true"></span>
												<div class="synchy-export-stage__content">
													<strong><?php echo esc_html((string) $stage['label']); ?></strong>
												</div>
											</div>
										<?php endforeach; ?>
									</div>
								</div>
							</div>
						</div>

						<div class="synchy-panel synchy-site-sync-result" data-synchy-sync-pending-panel>
							<div class="synchy-stack synchy-stack--compact">
								<div class="synchy-stack__split">
									<h2><?php esc_html_e('Pending Changes', 'synchy'); ?></h2>
									<span class="synchy-badge" data-synchy-sync-preview-badge><?php echo esc_html($last_sync_time > 0 ? __('Delta', 'synchy') : __('Baseline', 'synchy')); ?></span>
								</div>
								<p class="synchy-field-note" data-synchy-sync-preview-message><?php esc_html_e('Run Preview Changes to see how many files and database rows Synchy will sync before anything is sent.', 'synchy'); ?></p>
								<p class="synchy-field-note is-hidden" data-synchy-sync-batch-counter></p>
								<div class="synchy-sync-tree is-hidden" data-synchy-sync-preview-tree></div>
							</div>
						</div>

					</div>
				</div>

			</form>
		</div>
	</div>
	<?php
}

function synchy_render_settings_page(array $current): void
{
	$github = synchy_get_github_update_config();
	$export_options = synchy_get_export_options();
	$latest_release = synchy_get_github_release_data();
	$latest_version = $latest_release instanceof WP_Error ? '' : (string) ($latest_release['version'] ?? '');
	$latest_release_url = $latest_release instanceof WP_Error ? (string) ($github['html_url'] ?? '') : (string) ($latest_release['html_url'] ?? '');
	$latest_release_error = $latest_release instanceof WP_Error ? $latest_release->get_error_message() : '';
	$update_available = $latest_version !== '' && version_compare($latest_version, SYNCHY_VERSION, '>');
	$check_updates_url = synchy_get_check_updates_url(admin_url('admin.php?page=synchy-settings'));
	$plugin_upgrade_url = $update_available ? synchy_get_plugin_upgrade_url() : '';
	?>
	<div class="wrap synchy-admin">
		<?php synchy_render_notice(); ?>
		<div class="synchy-shell">
			<div class="synchy-hero">
				<div>
					<p class="synchy-eyebrow"><?php esc_html_e('Plugin Info', 'synchy'); ?></p>
					<h1><?php echo esc_html($current['headline']); ?></h1>
					<p class="synchy-description"><?php echo esc_html($current['description']); ?></p>
				</div>
				<div class="synchy-status">
					<span class="synchy-status__dot" aria-hidden="true"></span>
					<?php echo esc_html(sprintf(__('v%s', 'synchy'), SYNCHY_VERSION)); ?>
				</div>
			</div>

			<div class="synchy-grid synchy-grid--export">
				<div class="synchy-panel">
					<h2><?php esc_html_e('Settings Snapshot', 'synchy'); ?></h2>
					<div class="synchy-export-meta">
						<div>
							<span class="synchy-export-meta__label"><?php esc_html_e('Current Version', 'synchy'); ?></span>
							<strong><?php echo esc_html(SYNCHY_VERSION); ?></strong>
						</div>
						<div>
							<span class="synchy-export-meta__label"><?php esc_html_e('Default Export Folder', 'synchy'); ?></span>
							<strong><?php echo esc_html((string) $export_options['output_directory']); ?></strong>
						</div>
						<div>
							<span class="synchy-export-meta__label"><?php esc_html_e('GitHub Repository', 'synchy'); ?></span>
							<strong>
								<?php if (!empty($github['html_url'])) : ?>
									<a href="<?php echo esc_url((string) $github['html_url']); ?>" target="_blank" rel="noreferrer noopener"><?php echo esc_html((string) $github['repository']); ?></a>
								<?php else : ?>
									<?php esc_html_e('Not configured', 'synchy'); ?>
								<?php endif; ?>
							</strong>
						</div>
						<div>
							<span class="synchy-export-meta__label"><?php esc_html_e('Release Asset', 'synchy'); ?></span>
							<strong><?php echo esc_html((string) ($github['asset_name'] ?? '')); ?></strong>
						</div>
						<div>
							<span class="synchy-export-meta__label"><?php esc_html_e('Update Branch', 'synchy'); ?></span>
							<strong><?php echo esc_html((string) ($github['branch'] ?? 'main')); ?></strong>
						</div>
						<div>
							<span class="synchy-export-meta__label"><?php esc_html_e('Latest Release', 'synchy'); ?></span>
							<strong>
								<?php if ($latest_version !== '' && $latest_release_url !== '') : ?>
									<a href="<?php echo esc_url($latest_release_url); ?>" target="_blank" rel="noreferrer noopener"><?php echo esc_html($latest_version); ?></a>
								<?php elseif ($latest_version !== '') : ?>
									<?php echo esc_html($latest_version); ?>
								<?php else : ?>
									<?php esc_html_e('Unavailable', 'synchy'); ?>
								<?php endif; ?>
							</strong>
						</div>
						<div>
							<span class="synchy-export-meta__label"><?php esc_html_e('Update Status', 'synchy'); ?></span>
							<strong>
								<?php
								if ($latest_release_error !== '') {
									esc_html_e('GitHub check failed', 'synchy');
								} elseif ($update_available) {
									printf(
										/* translators: %s: latest release version */
										esc_html__('Update available: v%s', 'synchy'),
										esc_html($latest_version)
									);
								} else {
									esc_html_e('Up to date', 'synchy');
								}
								?>
							</strong>
						</div>
					</div>
					<p>
						<a href="<?php echo esc_url($check_updates_url); ?>" class="button"><?php esc_html_e('Check for Updates', 'synchy'); ?></a>
						<?php if ($plugin_upgrade_url !== '') : ?>
							<a href="<?php echo esc_url($plugin_upgrade_url); ?>" class="button button-primary"><?php echo esc_html(sprintf(__('Update to v%s', 'synchy'), $latest_version)); ?></a>
						<?php endif; ?>
						<a href="<?php echo esc_url(self_admin_url('plugins.php')); ?>" class="button"><?php esc_html_e('Open Plugins', 'synchy'); ?></a>
					</p>
					<?php if ($latest_release_error !== '') : ?>
						<p class="synchy-field-note"><?php echo esc_html($latest_release_error); ?></p>
					<?php elseif ($update_available) : ?>
						<p class="synchy-field-note">
							<?php
							printf(
								/* translators: 1: current version, 2: latest version */
								esc_html__('Synchy is on v%1$s and GitHub has v%2$s ready to install.', 'synchy'),
								esc_html(SYNCHY_VERSION),
								esc_html($latest_version)
							);
							?>
						</p>
					<?php else : ?>
						<p class="synchy-field-note"><?php esc_html_e('Use the manual check if you want to force WordPress to refresh Synchy release data from GitHub right now.', 'synchy'); ?></p>
					<?php endif; ?>
				</div>

				<div class="synchy-panel synchy-panel--muted">
					<h2><?php esc_html_e('About Synchy', 'synchy'); ?></h2>
					<p><?php esc_html_e('Synchy is being built as a WordPress backup, restore, and deployment tool with a clear split between manual package workflows and future incremental sync workflows.', 'synchy'); ?></p>
					<ul class="synchy-checklist">
						<li><?php esc_html_e('Export builds a portable archive plus installer package.', 'synchy'); ?></li>
						<li><?php esc_html_e('Import is the destination-side overwrite path for full package restores.', 'synchy'); ?></li>
						<li><?php esc_html_e('Upload to Live sends a full package to another WordPress install and stages the manual restore there.', 'synchy'); ?></li>
						<li><?php esc_html_e('Sync is the separate work area for incremental post-push changes without another full backup/restore cycle.', 'synchy'); ?></li>
					</ul>
				</div>
			</div>

			<div class="synchy-grid synchy-grid--export">
				<div class="synchy-panel">
					<h2><?php esc_html_e('Current Direction', 'synchy'); ?></h2>
					<ul class="synchy-checklist">
						<li><?php esc_html_e('Keep full-package backup and restore dependable first.', 'synchy'); ?></li>
						<li><?php esc_html_e('Use GitHub Releases as the update source for installed Synchy sites.', 'synchy'); ?></li>
						<li><?php esc_html_e('Move future live-site sync toward smaller incremental changes after an initial full push.', 'synchy'); ?></li>
					</ul>
				</div>

				<div class="synchy-panel synchy-panel--muted">
					<h2><?php esc_html_e('Next Plugin-Level Settings', 'synchy'); ?></h2>
					<p><?php esc_html_e('This screen is also the home for future global Synchy settings, such as update behavior, default destinations, retention rules, and system-level diagnostics.', 'synchy'); ?></p>
				</div>
			</div>
		</div>
	</div>
	<?php
}

function synchy_render_page(string $page_slug): void
{
	if (!current_user_can('manage_options')) {
		return;
	}

	$pages = synchy_get_pages();
	$current = null;
	$export_page = null;

	foreach ($pages as $page) {
		if ($page['slug'] === $page_slug) {
			$current = $page;
		}

		if ($page['slug'] === 'synchy-export') {
			$export_page = $page;
		}
	}

	if ($current === null) {
		$current = $pages[0];
	}

	if ($export_page === null) {
		$export_page = $current;
	}

	if ($page_slug === SYNCHY_SLUG) {
		synchy_render_export_page($export_page);
		return;
	}

	if ($page_slug === 'synchy-export') {
		synchy_render_export_page($current);
		return;
	}

	if ($page_slug === 'synchy-import') {
		synchy_render_import_page($current);
		return;
	}

	if ($page_slug === 'synchy-push-live-site') {
		synchy_render_site_sync_page($current);
		return;
	}

	if ($page_slug === 'synchy-scheduled-backups') {
		synchy_render_schedule_page($current);
		return;
	}

	if ($page_slug === 'synchy-site-sync') {
		synchy_render_incremental_site_sync_page($current);
		return;
	}

	if ($page_slug === 'synchy-settings') {
		synchy_render_settings_page($current);
		return;
	}

	$cards = [
		__('Export on-demand backups', 'synchy'),
		__('Import and overwrite safely', 'synchy'),
		__('Scheduled backup runs', 'synchy'),
		__('Push full backups live', 'synchy'),
		__('Incremental site sync after the first push', 'synchy'),
	];
	?>
	<div class="wrap synchy-admin">
		<div class="synchy-shell">
			<div class="synchy-hero">
				<div>
					<p class="synchy-eyebrow"><?php esc_html_e('Plugin Template', 'synchy'); ?></p>
					<h1><?php echo esc_html($current['headline']); ?></h1>
					<p class="synchy-description"><?php echo esc_html($current['description']); ?></p>
				</div>
				<div class="synchy-status">
					<span class="synchy-status__dot" aria-hidden="true"></span>
					<?php esc_html_e('Coming soon', 'synchy'); ?>
				</div>
			</div>

			<div class="synchy-grid">
				<div class="synchy-panel">
					<h2><?php esc_html_e('Planned Scope', 'synchy'); ?></h2>
					<ul class="synchy-checklist">
						<?php foreach ($cards as $card) : ?>
							<li><?php echo esc_html($card); ?></li>
						<?php endforeach; ?>
					</ul>
				</div>

				<div class="synchy-panel synchy-panel--muted">
					<h2><?php esc_html_e('Next Step', 'synchy'); ?></h2>
					<p><?php esc_html_e('This screen is a placeholder for future Synchy functionality. The export workflow is now the active build area.', 'synchy'); ?></p>
				</div>
			</div>
		</div>
	</div>
	<?php
}

add_action('admin_menu', function (): void {
	$pages = synchy_get_pages();
	$first = array_shift($pages);

	add_menu_page(
		__('Synchy', 'synchy'),
		__('Synchy', 'synchy'),
		'manage_options',
		$first['slug'],
		static function () use ($first): void {
			synchy_render_page($first['slug']);
		},
		'dashicons-backup',
		58
	);

	foreach ($pages as $page) {
		add_submenu_page(
			SYNCHY_SLUG,
			$page['title'],
			$page['menu_title'],
			'manage_options',
			$page['slug'],
			static function () use ($page): void {
				synchy_render_page($page['slug']);
			}
		);
	}

	// WordPress auto-adds a duplicate first submenu item that mirrors the top-level page.
	remove_submenu_page($first['slug'], $first['slug']);
});

add_action('wp_dashboard_setup', function (): void {
	if (!current_user_can('manage_options')) {
		return;
	}

	add_meta_box(
		'synchy_dashboard_widget',
		__('Synchy', 'synchy'),
		'synchy_render_dashboard_widget',
		'dashboard',
		'side',
		'high'
	);
});

add_action('synchy_run_full_sync_worker_event', function (string $worker_token): void {
	synchy_run_full_sync_worker_by_token($worker_token);
}, 10, 1);

add_action('admin_init', function (): void {
	register_setting(
		'synchy_export',
		SYNCHY_EXPORT_OPTIONS,
		[
			'type' => 'array',
			'sanitize_callback' => 'synchy_sanitize_export_options',
			'default' => synchy_get_export_defaults(),
		]
	);

	register_setting(
		'synchy_site_sync',
		SYNCHY_SITE_SYNC_OPTIONS,
		[
			'type' => 'array',
			'sanitize_callback' => 'synchy_sanitize_site_sync_options',
			'default' => synchy_get_site_sync_defaults(),
		]
	);
});

add_action('wp_ajax_synchy_start_export', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to run Synchy exports.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_export_ajax', 'nonce');

	$options = isset($_POST[SYNCHY_EXPORT_OPTIONS]) ? synchy_sanitize_export_options(wp_unslash($_POST[SYNCHY_EXPORT_OPTIONS])) : synchy_get_export_options();
	$job = synchy_start_export_job($options);

	if (is_wp_error($job)) {
		wp_send_json_error(['message' => $job->get_error_message()], 400);
	}

	wp_send_json_success(['job' => synchy_build_job_response($job)]);
});

add_action('wp_ajax_synchy_continue_export', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to run Synchy exports.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_export_ajax', 'nonce');

	$job_id = isset($_POST['job_id']) ? sanitize_text_field(wp_unslash((string) $_POST['job_id'])) : '';
	$job = synchy_get_export_job();

	if ($job === [] || $job_id === '' || $job_id !== (string) ($job['job_id'] ?? '')) {
		wp_send_json_error(['message' => __('Synchy could not find the requested export job.', 'synchy')], 404);
	}

	$job = synchy_process_export_job($job);

	wp_send_json_success(['job' => synchy_build_job_response($job)]);
});

add_action('wp_ajax_synchy_browse_export_directories', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to browse Synchy export folders.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_export_ajax', 'nonce');

	$path = isset($_POST['path']) ? sanitize_text_field(wp_unslash((string) $_POST['path'])) : '';
	wp_send_json_success(synchy_get_browse_payload($path));
});

add_action('wp_ajax_synchy_test_site_sync_connection', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to test Synchy Upload to Live connections.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_site_sync_ajax', 'nonce');

	$options = isset($_POST[SYNCHY_SITE_SYNC_OPTIONS]) ? synchy_sanitize_site_sync_options(wp_unslash($_POST[SYNCHY_SITE_SYNC_OPTIONS])) : synchy_get_site_sync_options();
	$result = synchy_test_site_sync_connection($options);

	if (is_wp_error($result)) {
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	wp_send_json_success(['remoteSite' => $result]);
});

add_action('wp_ajax_synchy_start_site_sync_push', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to start Synchy Upload to Live runs.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_site_sync_ajax', 'nonce');

	$options = isset($_POST[SYNCHY_SITE_SYNC_OPTIONS]) ? synchy_sanitize_site_sync_options(wp_unslash($_POST[SYNCHY_SITE_SYNC_OPTIONS])) : synchy_get_site_sync_options();
	$job = synchy_start_site_sync_job($options);

	if (is_wp_error($job)) {
		wp_send_json_error(['message' => $job->get_error_message()], 400);
	}

	wp_send_json_success(['job' => synchy_build_site_sync_job_response($job)]);
});

add_action('wp_ajax_synchy_continue_site_sync_push', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to continue Synchy Upload to Live runs.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_site_sync_ajax', 'nonce');

	$job_id = isset($_POST['job_id']) ? sanitize_text_field(wp_unslash((string) $_POST['job_id'])) : '';
	$job = synchy_get_site_sync_job();

	if ($job === [] || $job_id === '' || $job_id !== (string) ($job['job_id'] ?? '')) {
		wp_send_json_error(['message' => __('Synchy could not find the requested Upload to Live job.', 'synchy')], 404);
	}

	$job = synchy_process_site_sync_job($job);

	wp_send_json_success(['job' => synchy_build_site_sync_job_response($job)]);
});

add_action('wp_ajax_synchy_preview_sync_changes', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to preview Synchy Sync changes.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_sync_ajax', 'nonce');

	$options = isset($_POST[SYNCHY_SITE_SYNC_OPTIONS]) ? synchy_sanitize_site_sync_options(wp_unslash($_POST[SYNCHY_SITE_SYNC_OPTIONS])) : synchy_get_site_sync_options();
	$result = synchy_preview_sync_changes($options);

	if (is_wp_error($result)) {
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	wp_send_json_success([
		'preview' => $result,
		'scopeStatus' => synchy_get_sync_scope_status($options),
	]);
});

add_action('wp_ajax_synchy_test_sync_connection', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to test Synchy Sync connections.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_sync_ajax', 'nonce');

	$options = isset($_POST[SYNCHY_SITE_SYNC_OPTIONS]) ? synchy_sanitize_site_sync_options(wp_unslash($_POST[SYNCHY_SITE_SYNC_OPTIONS])) : synchy_get_site_sync_options();
	$result = synchy_test_site_sync_connection($options);

	if (is_wp_error($result)) {
		synchy_store_sync_connection_error($options, $result->get_error_message());
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	synchy_store_sync_connection_success($options, $result);
	wp_send_json_success(['remoteSite' => $result]);
});

add_action('wp_ajax_synchy_update_remote_synchy', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to update Synchy on the destination site.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_sync_ajax', 'nonce');

	$options = isset($_POST[SYNCHY_SITE_SYNC_OPTIONS]) ? synchy_sanitize_site_sync_options(wp_unslash($_POST[SYNCHY_SITE_SYNC_OPTIONS])) : synchy_get_site_sync_options();
	$result = synchy_update_remote_synchy($options);

	if (is_wp_error($result)) {
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	$remote_site = synchy_test_site_sync_connection($options);

	if (!is_wp_error($remote_site)) {
		synchy_store_sync_connection_success($options, $remote_site);
	}

	wp_send_json_success([
		'message' => (string) ($result['message'] ?? __('Synchy updated the destination plugin successfully.', 'synchy')),
		'remoteSite' => is_wp_error($remote_site) ? [] : $remote_site,
	]);
});

add_action('wp_ajax_synchy_mark_sync_baseline_complete', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to mark a Synchy Sync baseline.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_sync_ajax', 'nonce');

	$options = isset($_POST[SYNCHY_SITE_SYNC_OPTIONS]) ? synchy_sanitize_site_sync_options(wp_unslash($_POST[SYNCHY_SITE_SYNC_OPTIONS])) : synchy_get_site_sync_options();
	$result = synchy_mark_sync_baseline_complete($options);

	if (is_wp_error($result)) {
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	wp_send_json_success([
		'status' => (array) ($result['status'] ?? []),
		'scopeStatus' => synchy_get_sync_scope_status($options),
	]);
});

add_action('wp_ajax_synchy_get_sync_job_status', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to view Synchy Sync status.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_sync_ajax', 'nonce');

	wp_send_json_success([
		'job' => synchy_build_sync_job_response(synchy_get_visible_sync_job()),
	]);
});

add_action('wp_ajax_synchy_continue_full_sync', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to continue a Synchy full Sync.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_sync_ajax', 'nonce');

	$options = isset($_POST[SYNCHY_SITE_SYNC_OPTIONS]) ? synchy_sanitize_site_sync_options(wp_unslash($_POST[SYNCHY_SITE_SYNC_OPTIONS])) : synchy_get_site_sync_options();
	$result = synchy_continue_full_sync_job($options);

	if (is_wp_error($result)) {
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	wp_send_json_success([
		'status' => synchy_get_sync_status(),
		'job' => synchy_build_sync_job_response(synchy_get_sync_job()),
		'scopeStatus' => synchy_get_sync_scope_status($options),
	]);
});

add_action('wp_ajax_synchy_run_full_sync_worker', function (): void {
	$token = isset($_POST['token']) ? sanitize_text_field(wp_unslash((string) $_POST['token'])) : '';
	$result = synchy_run_full_sync_worker_by_token($token);

	if (is_wp_error($result)) {
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	wp_send_json_success(['job' => synchy_build_sync_job_response(is_array($result) ? $result : synchy_get_sync_job())]);
});

add_action('wp_ajax_nopriv_synchy_run_full_sync_worker', function (): void {
	$token = isset($_POST['token']) ? sanitize_text_field(wp_unslash((string) $_POST['token'])) : '';
	$result = synchy_run_full_sync_worker_by_token($token);

	if (is_wp_error($result)) {
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	wp_send_json_success(['job' => synchy_build_sync_job_response(is_array($result) ? $result : synchy_get_sync_job())]);
});

add_action('wp_ajax_synchy_pause_full_sync', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to pause a Synchy full Sync.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_sync_ajax', 'nonce');

	$result = synchy_pause_full_sync_job();

	if (is_wp_error($result)) {
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	wp_send_json_success([
		'job' => synchy_build_sync_job_response($result),
	]);
});

add_action('wp_ajax_synchy_resume_full_sync', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to resume a Synchy full Sync.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_sync_ajax', 'nonce');

	$options = isset($_POST[SYNCHY_SITE_SYNC_OPTIONS]) ? synchy_sanitize_site_sync_options(wp_unslash($_POST[SYNCHY_SITE_SYNC_OPTIONS])) : synchy_get_site_sync_options();
	$result = synchy_resume_full_sync_job($options);

	if (is_wp_error($result)) {
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	wp_send_json_success([
		'status' => synchy_get_sync_status(),
		'job' => synchy_build_sync_job_response(synchy_get_sync_job()),
		'scopeStatus' => synchy_get_sync_scope_status($options),
	]);
});

add_action('wp_ajax_synchy_run_sync_changes', function (): void {
	if (!current_user_can('manage_options')) {
		wp_send_json_error(['message' => __('You are not allowed to run Synchy Sync changes.', 'synchy')], 403);
	}

	check_ajax_referer('synchy_sync_ajax', 'nonce');

	$options = isset($_POST[SYNCHY_SITE_SYNC_OPTIONS]) ? synchy_sanitize_site_sync_options(wp_unslash($_POST[SYNCHY_SITE_SYNC_OPTIONS])) : synchy_get_site_sync_options();
	$result = synchy_run_sync_changes($options);

	if (is_wp_error($result)) {
		wp_send_json_error(['message' => $result->get_error_message()], 400);
	}

	wp_send_json_success([
		'status' => $result,
		'job' => synchy_build_sync_job_response(synchy_get_sync_job()),
		'scopeStatus' => synchy_get_sync_scope_status($options),
	]);
});

add_action('admin_post_synchy_download_export', function (): void {
	if (!current_user_can('manage_options')) {
		wp_die(esc_html__('You are not allowed to download Synchy exports.', 'synchy'));
	}

	$package_id = isset($_GET['package']) ? sanitize_text_field(wp_unslash((string) $_GET['package'])) : '';
	$artifact = isset($_GET['artifact']) ? sanitize_text_field(wp_unslash((string) $_GET['artifact'])) : '';
	$allowed = ['archive', 'installer', 'manifest'];

	if ($package_id === '' || !in_array($artifact, $allowed, true)) {
		wp_die(esc_html__('The requested Synchy export file is invalid.', 'synchy'));
	}

	check_admin_referer('synchy_download_export_' . $package_id . '_' . $artifact);

	$export = synchy_find_export_history_item($package_id);

	if ($export === []) {
		wp_die(esc_html__('That export is no longer available through Synchy.', 'synchy'));
	}

	$artifact_meta = $export['artifacts'][$artifact] ?? null;

	if (!is_array($artifact_meta) || empty($artifact_meta['path']) || !is_readable((string) $artifact_meta['path'])) {
		wp_die(esc_html__('The requested Synchy export file could not be found.', 'synchy'));
	}

	$file_path = wp_normalize_path((string) $artifact_meta['path']);
	$filename = basename($file_path);
	$mime = match ($artifact) {
		'archive' => 'application/zip',
		'manifest' => 'application/json',
		default => 'application/x-httpd-php',
	};

	nocache_headers();
	header('Content-Type: ' . $mime);
	header('Content-Length: ' . (string) filesize($file_path));
	header('Content-Disposition: attachment; filename="' . $filename . '"');

	readfile($file_path);
	exit;
});

add_action('admin_post_synchy_delete_export', function (): void {
	if (!current_user_can('manage_options')) {
		wp_die(esc_html__('You are not allowed to delete Synchy exports.', 'synchy'));
	}

	$package_id = isset($_GET['package']) ? sanitize_text_field(wp_unslash((string) $_GET['package'])) : '';
	$page = isset($_GET['page']) ? sanitize_key(wp_unslash((string) $_GET['page'])) : 'synchy-export';
	$allowed_pages = ['synchy-export', 'synchy-import'];

	if (!in_array($page, $allowed_pages, true)) {
		$page = 'synchy-export';
	}

	if ($package_id === '') {
		synchy_set_notice('error', __('The Synchy export to delete was not specified.', 'synchy'));
		wp_safe_redirect(admin_url('admin.php?page=' . $page));
		exit;
	}

	check_admin_referer('synchy_delete_export_' . $package_id);

	$deleted = synchy_delete_export_history_item($package_id);

	if (is_wp_error($deleted)) {
		synchy_set_notice('error', $deleted->get_error_message());
	} else {
		synchy_set_notice(
			'success',
			sprintf(
				/* translators: %s: export package name */
				__('Deleted Synchy export %s.', 'synchy'),
				$deleted['package_name']
			)
		);
	}

	wp_safe_redirect(admin_url('admin.php?page=' . $page));
	exit;
});

add_action('admin_post_synchy_stage_import_package', function (): void {
	if (!current_user_can('manage_options')) {
		wp_die(esc_html__('You are not allowed to stage Synchy import packages.', 'synchy'));
	}

	check_admin_referer('synchy_stage_import_package');

	$result = synchy_handle_manual_import_upload();

	if (is_wp_error($result)) {
		$error_data = $result->get_error_data();
		synchy_set_import_result([
			'status' => 'error',
			'message' => $result->get_error_message(),
			'rootPath' => synchy_get_site_root_path(),
			'step' => is_array($error_data) ? (string) ($error_data['step'] ?? '') : '',
			'completedSteps' => is_array($error_data) ? array_values(array_filter((array) ($error_data['completedSteps'] ?? []), 'is_string')) : [],
			'at' => gmdate('c'),
		]);
		synchy_set_notice('error', $result->get_error_message());
		wp_safe_redirect(admin_url('admin.php?page=synchy-import'));
		exit;
	}

	$result['at'] = gmdate('c');
	synchy_set_import_result($result);

	$notice_type = (string) ($result['status'] ?? '') === 'ready' ? 'success' : 'error';
	synchy_set_notice($notice_type, (string) ($result['message'] ?? __('Synchy processed the uploaded import package.', 'synchy')));

	wp_safe_redirect(admin_url('admin.php?page=synchy-import'));
	exit;
});

add_action('rest_api_init', function (): void {
	$permission = static function () {
		if (current_user_can('manage_options')) {
			return true;
		}

		return new WP_Error(
			'synchy_rest_forbidden',
			__('You are not allowed to access Synchy Upload to Live receiver endpoints.', 'synchy'),
			['status' => rest_authorization_required_code()]
		);
	};

	$sync_permission = static function () {
		if (current_user_can('manage_options')) {
			return true;
		}

		return new WP_Error(
			'synchy_sync_rest_forbidden',
			__('You are not allowed to access Synchy Sync endpoints.', 'synchy'),
			['status' => rest_authorization_required_code()]
		);
	};

	register_rest_route(
		'syncy/v1',
		'/sync',
		[
			'methods' => 'POST',
			'callback' => 'synchy_handle_remote_sync_request',
			'permission_callback' => $sync_permission,
		]
	);

	register_rest_route(
		'synchy/v1',
		'/push/ping',
		[
			'methods' => 'GET',
			'callback' => static function () {
				$user = wp_get_current_user();

				return rest_ensure_response(
					[
						'name' => get_bloginfo('name'),
						'siteUrl' => home_url('/'),
						'pluginVersion' => SYNCHY_VERSION,
						'wordpressVersion' => get_bloginfo('version'),
						'authenticatedAs' => $user instanceof WP_User ? (string) $user->user_login : '',
						'receiverMode' => 'root_installer_package_upload',
					]
				);
			},
			'permission_callback' => $permission,
		]
	);

	register_rest_route(
		'synchy/v1',
		'/push/status',
		[
			'methods' => 'GET',
			'callback' => static function () {
				return rest_ensure_response(
					[
						'status' => synchy_get_sync_status(),
					]
				);
			},
			'permission_callback' => $permission,
		]
	);

	register_rest_route(
		'synchy/v1',
		'/plugin/update-self',
		[
			'methods' => 'POST',
			'callback' => static function (WP_REST_Request $request) {
				$body = $request->get_body();

				if ($body === '') {
					return new WP_Error('synchy_self_update_empty', __('Synchy received an empty destination plugin update package.', 'synchy'), ['status' => 400]);
				}

				$temp_dir = synchy_prepare_sync_temp_dir('plugin-self-update-upload');

				if (is_wp_error($temp_dir)) {
					return $temp_dir;
				}

				try {
					$filename = sanitize_file_name((string) $request->get_header('X-Synchy-Filename'));

					if ($filename === '') {
						$filename = 'synchy.zip';
					}

					$zip_path = wp_normalize_path(trailingslashit($temp_dir) . $filename);

					if (file_put_contents($zip_path, $body) === false) {
						return new WP_Error('synchy_self_update_write_failed', __('Synchy could not save the destination plugin update package.', 'synchy'), ['status' => 500]);
					}

					$result = synchy_apply_self_update_package($zip_path);

					if (is_wp_error($result)) {
						return $result;
					}

					return rest_ensure_response([
						'success' => true,
						'message' => __('Synchy updated the destination plugin files successfully.', 'synchy'),
						'pluginVersion' => SYNCHY_VERSION,
					]);
				} finally {
					if (is_dir($temp_dir)) {
						synchy_rrmdir($temp_dir);
					}
				}
			},
			'permission_callback' => $permission,
		]
	);

	register_rest_route(
		'synchy/v1',
		'/push/session',
		[
			'methods' => 'POST',
			'callback' => static function (WP_REST_Request $request) {
				$session = synchy_create_remote_push_session(
					[
						'packageName' => (string) $request->get_param('packageName'),
						'packageId' => (string) $request->get_param('packageId'),
						'sourceHomeUrl' => (string) $request->get_param('sourceHomeUrl'),
						'sourceSiteUrl' => (string) $request->get_param('sourceSiteUrl'),
						'archiveFilename' => (string) $request->get_param('archiveFilename'),
						'installerFilename' => (string) $request->get_param('installerFilename'),
						'manifestFilename' => (string) $request->get_param('manifestFilename'),
					]
				);

				if (is_wp_error($session)) {
					return $session;
				}

				return rest_ensure_response(
					[
						'session_id' => $session['session_id'],
						'uploadChunkBytes' => $session['uploadChunkBytes'],
						'packageName' => $session['package_name'],
					]
				);
			},
			'permission_callback' => $permission,
		]
	);

	register_rest_route(
		'synchy/v1',
		'/push/upload',
		[
			'methods' => 'POST',
			'callback' => static function (WP_REST_Request $request) {
				$session_id = synchy_sanitize_remote_push_session_id((string) $request->get_param('session_id'));
				$artifact = sanitize_key((string) $request->get_param('artifact'));
				$offset = max(0, (int) $request->get_param('offset'));
				$allowed_artifacts = ['archive', 'installer', 'manifest'];

				if ($session_id === '' || !in_array($artifact, $allowed_artifacts, true)) {
					return new WP_Error('synchy_push_upload_invalid', __('The Synchy upload request is missing a valid session or artifact.', 'synchy'), ['status' => 400]);
				}

				$session = synchy_read_remote_push_session($session_id);

				if ($session === []) {
					return new WP_Error('synchy_push_upload_missing_session', __('Synchy could not find the destination upload session.', 'synchy'), ['status' => 404]);
				}

				$artifact_meta = $session['artifacts'][$artifact] ?? null;

				if (!is_array($artifact_meta) || empty($artifact_meta['path'])) {
					return new WP_Error('synchy_push_upload_missing_artifact', __('Synchy could not resolve the destination artifact path.', 'synchy'), ['status' => 500]);
				}

				$path = wp_normalize_path((string) $artifact_meta['path']);
				$current_size = file_exists($path) ? (int) filesize($path) : 0;

				if ($offset !== $current_size) {
					return new WP_Error(
						'synchy_push_upload_offset_mismatch',
						__('Synchy detected an upload offset mismatch while receiving the package.', 'synchy'),
						['status' => 409, 'expectedOffset' => $current_size]
					);
				}

				$body = $request->get_body();

				if ($body === '') {
					return new WP_Error('synchy_push_upload_empty', __('Synchy received an empty upload chunk.', 'synchy'), ['status' => 400]);
				}

				if (file_put_contents($path, $body, FILE_APPEND) === false) {
					return new WP_Error('synchy_push_upload_write_failed', __('Synchy could not write the uploaded package chunk.', 'synchy'), ['status' => 500]);
				}

				clearstatcache(true, $path);

				$session['status'] = 'receiving';
				$session['artifacts'][$artifact]['bytes'] = (int) filesize($path);
				$session = synchy_write_remote_push_session($session);

				if (is_wp_error($session)) {
					return $session;
				}

				return rest_ensure_response(
					[
						'session_id' => $session_id,
						'artifact' => $artifact,
						'bytes' => (int) $session['artifacts'][$artifact]['bytes'],
					]
				);
			},
			'permission_callback' => $permission,
		]
	);

	register_rest_route(
		'synchy/v1',
		'/push/complete',
		[
			'methods' => 'POST',
			'callback' => static function (WP_REST_Request $request) {
				$session_id = synchy_sanitize_remote_push_session_id((string) $request->get_param('session_id'));
				$session = synchy_read_remote_push_session($session_id);

				if ($session_id === '' || $session === []) {
					return new WP_Error('synchy_push_complete_missing_session', __('Synchy could not find the destination upload session to finalize.', 'synchy'), ['status' => 404]);
				}

				$archive_path = (string) ($session['artifacts']['archive']['path'] ?? '');
				$installer_path = (string) ($session['artifacts']['installer']['path'] ?? '');
				$manifest_path = (string) ($session['artifacts']['manifest']['path'] ?? '');

				if ($archive_path === '' || !is_readable($archive_path)) {
					return new WP_Error('synchy_push_complete_missing_archive', __('Synchy could not find the uploaded archive on the destination site.', 'synchy'), ['status' => 400]);
				}

				$has_installer = $installer_path !== '' && is_readable($installer_path);
				$has_manifest = $manifest_path !== '' && is_readable($manifest_path);

				if (!$has_installer && !$has_manifest) {
					return new WP_Error('synchy_push_complete_missing_installer', __('Synchy could not find installer.php for the uploaded destination package.', 'synchy'), ['status' => 400]);
				}

				$manifest = [];

				if ($has_manifest) {
					$manifest = json_decode((string) file_get_contents($manifest_path), true);

					if (!is_array($manifest)) {
						return new WP_Error('synchy_push_complete_invalid_manifest', __('Synchy could not decode the uploaded manifest on the destination site.', 'synchy'), ['status' => 400]);
					}
				}

				$session['status'] = 'ready';
				$session['completed_at'] = gmdate('c');
				$session['manifest_summary'] = [
					'package_id' => (string) ($session['package_id'] ?? ($manifest['package_id'] ?? '')),
					'package_name' => (string) ($session['package_name'] ?? ($manifest['package_name'] ?? '')),
					'source_home_url' => (string) ($session['source_home_url'] ?? ($manifest['site']['home_url'] ?? '')),
				];
				$session['root_deploy'] = $has_installer
					? synchy_deploy_remote_push_package_to_root($session)
					: [
						'status' => 'staged_only',
						'message' => __('Synchy staged the package, but this session did not include installer.php for root deployment.', 'synchy'),
						'rootPath' => synchy_get_site_root_path(),
					];
				$session = synchy_write_remote_push_session($session);

				if (is_wp_error($session)) {
					return $session;
				}

				return rest_ensure_response(
					[
						'session_id' => $session_id,
						'status' => 'ready',
						'packageName' => (string) ($session['package_name'] ?? ''),
						'packageId' => (string) ($session['manifest_summary']['package_id'] ?? ''),
						'destinationPath' => (string) ($session['directory'] ?? ''),
						'deployStatus' => (string) ($session['root_deploy']['status'] ?? 'staged_only'),
						'message' => (string) ($session['root_deploy']['message'] ?? __('Package delivered to the destination Synchy receiver.', 'synchy')),
						'installerUrl' => (string) ($session['root_deploy']['installerUrl'] ?? ''),
						'installerPath' => (string) ($session['root_deploy']['installerPath'] ?? ''),
						'archivePath' => (string) ($session['root_deploy']['archivePath'] ?? ''),
						'rootPath' => (string) ($session['root_deploy']['rootPath'] ?? ''),
					]
				);
			},
			'permission_callback' => $permission,
		]
	);
});

add_action('admin_enqueue_scripts', function (string $hook_suffix): void {
	$is_synchy_screen = strpos($hook_suffix, 'synchy') !== false;
	$is_dashboard_screen = $hook_suffix === 'index.php';

	if (!$is_synchy_screen && !$is_dashboard_screen) {
		return;
	}

	$style_path = plugin_dir_path(__FILE__) . 'assets/admin.css';

	if (file_exists($style_path)) {
		wp_enqueue_style(
			'synchy-admin',
			plugin_dir_url(__FILE__) . 'assets/admin.css',
			[],
			(string) filemtime($style_path)
		);
	}

	if ($is_dashboard_screen) {
		return;
	}

	$page = isset($_GET['page']) ? sanitize_key((string) $_GET['page']) : '';

	if ($page === 'synchy-push-live-site') {
		$site_sync_script_path = plugin_dir_path(__FILE__) . 'assets/site-sync.js';

		if (!file_exists($site_sync_script_path)) {
			return;
		}

		wp_enqueue_script(
			'synchy-site-sync',
			plugin_dir_url(__FILE__) . 'assets/site-sync.js',
			[],
			(string) filemtime($site_sync_script_path),
			true
		);

			wp_localize_script(
				'synchy-site-sync',
				'synchySiteSyncConfig',
				[
					'ajaxUrl' => admin_url('admin-ajax.php'),
					'nonce' => wp_create_nonce('synchy_site_sync_ajax'),
					'currentJob' => synchy_build_site_sync_job_response(synchy_get_running_site_sync_job()),
					'defaultStages' => synchy_get_site_sync_stage_items([]),
					'strings' => [
						'uploaded' => __('Uploaded', 'synchy'),
						'timeSpent' => __('Time spent', 'synchy'),
					'timeRemaining' => __('Time remaining', 'synchy'),
					'completedIn' => __('Completed in', 'synchy'),
					'connectionReady' => __('Connection ready', 'synchy'),
					'connectionError' => __('Connection failed', 'synchy'),
					'pushAction' => __('Upload to Live', 'synchy'),
					'unknownError' => __('Synchy hit an unexpected live push error.', 'synchy'),
				],
			]
		);

		return;
	}

	if ($page === 'synchy-site-sync') {
		$sync_script_path = plugin_dir_path(__FILE__) . 'assets/sync.js';

		if (!file_exists($sync_script_path)) {
			return;
		}

		wp_enqueue_script(
			'synchy-sync',
			plugin_dir_url(__FILE__) . 'assets/sync.js',
			[],
			(string) filemtime($sync_script_path),
			true
		);

		wp_localize_script(
			'synchy-sync',
			'synchySyncConfig',
			[
				'ajaxUrl' => admin_url('admin-ajax.php'),
				'nonce' => wp_create_nonce('synchy_sync_ajax'),
				'localPluginVersion' => SYNCHY_VERSION,
				'currentJob' => synchy_build_sync_job_response(synchy_get_visible_sync_job()),
				'connectionState' => synchy_get_current_sync_connection_state(synchy_get_site_sync_options()),
				'defaultStages' => synchy_get_sync_stage_items([]),
				'scopeStatus' => synchy_get_sync_scope_status(synchy_get_site_sync_options()),
				'strings' => [
					'connectionReady' => __('Connection ready', 'synchy'),
					'connectionError' => __('Connection failed', 'synchy'),
					'connected' => __('Connected', 'synchy'),
					'failed' => __('Failed', 'synchy'),
					'needsRetest' => __('Needs retest', 'synchy'),
					'notChecked' => __('Not checked', 'synchy'),
					'incomplete' => __('Incomplete', 'synchy'),
					'previewReady' => __('Preview ready', 'synchy'),
					'previewError' => __('Preview failed', 'synchy'),
					'startBaseline' => __('Start Baseline', 'synchy'),
					'pushChanges' => __('Push Changes', 'synchy'),
					'fullSync' => __('Full Sync', 'synchy'),
					'pauseSync' => __('Pause Sync', 'synchy'),
					'resumeSync' => __('Resume Sync', 'synchy'),
					'markManualBaseline' => __('Mark Manual Baseline Complete', 'synchy'),
					'syncingAction' => __('Syncing...', 'synchy'),
					'paused' => __('Paused', 'synchy'),
					'resumeReady' => __('Resume ready', 'synchy'),
					'success' => __('Success', 'synchy'),
					'error' => __('Error', 'synchy'),
					'noChanges' => __('No changes', 'synchy'),
					'awaitingBaseline' => __('Awaiting baseline', 'synchy'),
					'baseline' => __('Baseline', 'synchy'),
					'delta' => __('Delta', 'synchy'),
					'lastRun' => __('Last run', 'synchy'),
					'lastSync' => __('Last successful Sync', 'synchy'),
					'destination' => __('Destination', 'synchy'),
					'localPluginVersion' => __('Local plugin version', 'synchy'),
					'files' => __('Files', 'synchy'),
					'dbRows' => __('DB rows', 'synchy'),
					'duration' => __('Duration', 'synchy'),
					'site' => __('Site', 'synchy'),
					'pluginVersion' => __('Plugin version', 'synchy'),
					'authenticatedAs' => __('Authenticated as', 'synchy'),
					'selectedScopes' => __('Selected scopes', 'synchy'),
					'needsBaseline' => __('Needs baseline', 'synchy'),
					'pendingBaseline' => __('Still need baseline', 'synchy'),
					'pendingChanges' => __('Pending changes', 'synchy'),
					'readyForPreview' => __('Ready for preview', 'synchy'),
					'noChangesInScope' => __('No changes', 'synchy'),
					'changedFiles' => __('Changed files', 'synchy'),
					'dbTables' => __('Database tables', 'synchy'),
					'previewSelectionTitle' => __('Pending Changes', 'synchy'),
					'previewSelectionHelp' => __('Review the pending file sections and database tables, then uncheck anything you do not want to send.', 'synchy'),
					'sampleRowIds' => __('Sample row IDs', 'synchy'),
					'syncRunning' => __('Sync running', 'synchy'),
					'selectedChanges' => __('Selected changes', 'synchy'),
					'tableUpdates' => __('Table updates', 'synchy'),
					'sampleFiles' => __('Sample files', 'synchy'),
					'never' => __('Never', 'synchy'),
					'na' => __('N/A', 'synchy'),
					'previewDefault' => __('Run Preview Changes to review changed files and database rows before syncing.', 'synchy'),
					'unknownError' => __('Synchy hit an unexpected Sync error.', 'synchy'),
					'confirmSync' => __('Sync the previewed changes to the destination site now?', 'synchy'),
					'confirmFullSync' => __('Run a full Sync for the selected scopes and send all tracked files and rows to the destination site now?', 'synchy'),
					'confirmResumeSync' => __('Resume the remaining full Sync batches now?', 'synchy'),
					'confirmBaseline' => __('Mark the selected scopes as already baselined after a successful manual full restore to the destination site?', 'synchy'),
					'selectAtLeastOneScope' => __('Select at least one file or database scope first.', 'synchy'),
					'batches' => __('Batches', 'synchy'),
					'batchesComplete' => __('batches complete', 'synchy'),
					'currentBatch' => __('Current batch', 'synchy'),
					'pausePending' => __('Pause requested', 'synchy'),
					'updateAvailable' => __('Destination update available:', 'synchy'),
					'destinationUpToDate' => __('Destination Synchy is up to date.', 'synchy'),
					'updateCheckPending' => __('Run or wait for the connection check to compare Synchy versions.', 'synchy'),
					'confirmUpdateRemoteSynchy' => __('Update Synchy on the destination site from this local plugin copy now?', 'synchy'),
					'destinationUpdated' => __('Destination Synchy updated.', 'synchy'),
				],
			]
		);

		return;
	}

	if ($page !== 'synchy-export') {
		return;
	}

	$script_path = plugin_dir_path(__FILE__) . 'assets/export.js';

	if (!file_exists($script_path)) {
		return;
	}

	wp_enqueue_script(
		'synchy-export',
		plugin_dir_url(__FILE__) . 'assets/export.js',
		[],
		(string) filemtime($script_path),
		true
	);

	wp_localize_script(
		'synchy-export',
		'synchyExportConfig',
		[
			'ajaxUrl' => admin_url('admin-ajax.php'),
			'nonce' => wp_create_nonce('synchy_export_ajax'),
			'currentJob' => synchy_build_job_response(synchy_get_running_export_job()),
			'defaultPackageName' => synchy_get_default_package_name(),
			'defaultStages' => synchy_get_export_stage_items([]),
			'strings' => [
				'filesProcessed' => __('Files processed:', 'synchy'),
				'unknownError' => __('Synchy hit an unexpected error while exporting.', 'synchy'),
				'preparingLabel' => __('Preparing', 'synchy'),
				'startingExport' => __('Starting export job...', 'synchy'),
				'errorPhaseLabel' => __('Error', 'synchy'),
				'completeTitle' => __('Synchy export complete', 'synchy'),
				'errorTitle' => __('Synchy export needs attention', 'synchy'),
			],
		]
	);
});
