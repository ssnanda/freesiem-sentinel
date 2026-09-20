<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Lean software inventory sent to freeSIEM Core in the heartbeat: what is installed
 * and at which version, plus whether an update is waiting. Names and versions only —
 * no findings, no file contents, no settings. Core uses it to match known
 * vulnerabilities. Reads WordPress' cached update data; makes no network calls.
 */
class Freesiem_Inventory
{
	public const SENT_OPTION = 'freesiem_sentinel_inventory_sent';

	public static function build(): array
	{
		if (!function_exists('get_plugins')) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugin_updates = get_site_transient('update_plugins');
		$theme_updates = get_site_transient('update_themes');
		$core_updates = get_site_transient('update_core');

		$active = array_fill_keys((array) get_option('active_plugins', []), true);
		if (is_multisite()) {
			$active += array_fill_keys(array_keys((array) get_site_option('active_sitewide_plugins', [])), true);
		}

		$plugins = [];
		foreach (get_plugins() as $file => $plugin) {
			$slug = dirname($file) === '.' ? basename($file, '.php') : dirname($file);
			$update = is_object($plugin_updates) && isset($plugin_updates->response[$file]) ? $plugin_updates->response[$file] : null;

			$plugins[] = [
				'slug' => $slug,
				'name' => (string) ($plugin['Name'] ?? $slug),
				'version' => (string) ($plugin['Version'] ?? ''),
				'active' => isset($active[$file]),
				'update_available' => $update !== null,
				'new_version' => $update !== null ? (string) ($update->new_version ?? '') : '',
			];
		}

		$current_theme = get_stylesheet();
		$parent_theme = get_template();
		$themes = [];
		foreach (wp_get_themes() as $slug => $theme) {
			$update = is_object($theme_updates) && isset($theme_updates->response[$slug]) ? $theme_updates->response[$slug] : null;

			$themes[] = [
				'slug' => (string) $slug,
				'name' => (string) $theme->get('Name'),
				'version' => (string) $theme->get('Version'),
				// A parent theme is in use whenever its child is active.
				'active' => $slug === $current_theme || $slug === $parent_theme,
				'update_available' => $update !== null,
				'new_version' => $update !== null ? (string) (is_array($update) ? ($update['new_version'] ?? '') : ($update->new_version ?? '')) : '',
			];
		}

		$core_new = '';
		if (is_object($core_updates) && !empty($core_updates->updates) && is_array($core_updates->updates)) {
			foreach ($core_updates->updates as $update) {
				if (($update->response ?? '') === 'upgrade') {
					$core_new = (string) ($update->current ?? '');
					break;
				}
			}
		}

		return [
			'wordpress' => [
				'version' => (string) get_bloginfo('version'),
				'update_available' => $core_new !== '',
				'new_version' => $core_new,
			],
			'plugins' => $plugins,
			'themes' => $themes,
			'collected_at' => gmdate('c'),
		];
	}

	// Change detector: ignores the collection time.
	public static function fingerprint(array $inventory): string
	{
		unset($inventory['collected_at']);

		return hash('sha256', (string) wp_json_encode($inventory));
	}

	// Send when something changed, and at least once a day either way.
	public static function should_send(string $fingerprint): bool
	{
		$sent = (array) get_option(self::SENT_OPTION, []);

		return $fingerprint !== (string) ($sent['hash'] ?? '') || (time() - (int) ($sent['at'] ?? 0)) >= DAY_IN_SECONDS;
	}

	public static function mark_sent(string $fingerprint): void
	{
		update_option(self::SENT_OPTION, ['hash' => $fingerprint, 'at' => time()], false);
	}
}
