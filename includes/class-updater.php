<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Updater
{
	public function register(): void
	{
		add_filter('pre_set_site_transient_update_plugins', [$this, 'inject_update'], 20);
		add_filter('plugins_api', [$this, 'plugins_api'], 20, 3);
		add_filter('plugin_action_links_' . freesiem_sentinel_get_plugin_basename(), [$this, 'plugin_action_links']);
		add_action('admin_post_freesiem_sentinel_check_updates', [$this, 'handle_manual_update_check']);
		add_action('upgrader_process_complete', [$this, 'clear_after_upgrade'], 10, 2);
	}

	public function get_github_update_config(): array
	{
		$repository = $this->parse_github_repository((string) apply_filters('freesiem_sentinel_github_repository', FREESIEM_SENTINEL_GITHUB_REPOSITORY));
		$branch = sanitize_text_field((string) apply_filters('freesiem_sentinel_github_branch', FREESIEM_SENTINEL_GITHUB_BRANCH));
		$asset_name = sanitize_file_name((string) apply_filters('freesiem_sentinel_github_release_asset', FREESIEM_SENTINEL_GITHUB_RELEASE_ASSET));

		return [
			'enabled' => $repository !== '',
			'repository' => freesiem_sentinel_safe_string($repository),
			'branch' => $branch !== '' ? $branch : 'main',
			'asset_name' => freesiem_sentinel_safe_string($asset_name),
			'html_url' => $repository !== '' ? 'https://github.com/' . freesiem_sentinel_safe_string($repository) : '',
			'api_url' => $repository !== '' ? 'https://api.github.com/repos/' . freesiem_sentinel_safe_string($repository) . '/releases/latest' : '',
		];
	}

	public function get_github_release_data(bool $force = false)
	{
		$config = $this->get_github_update_config();

		if (empty($config['enabled'])) {
			return new WP_Error('freesiem_updater_disabled', __('GitHub updates are not configured for freeSIEM Sentinel.', 'freesiem-sentinel'));
		}

		$cache_key = $this->get_cache_key($config);

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
					'User-Agent' => 'freeSIEM-Sentinel/' . FREESIEM_SENTINEL_VERSION . '; ' . wp_parse_url(home_url('/'), PHP_URL_HOST),
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
			return new WP_Error('freesiem_release_request_failed', __('freeSIEM Sentinel could not read the latest GitHub release.', 'freesiem-sentinel'));
		}

		$version = ltrim((string) ($release['tag_name'] ?? ''), 'vV');
		$package_url = $this->find_release_asset_url($release, (string) $config['asset_name']);

		if ($version === '' || $package_url === '') {
			return new WP_Error('freesiem_release_invalid', __('freeSIEM Sentinel could not find a valid zip asset in the latest release.', 'freesiem-sentinel'));
		}

		$data = [
			'version' => $version,
			'package_url' => $package_url,
			'html_url' => (string) ($release['html_url'] ?? $config['html_url']),
			'name' => (string) ($release['name'] ?? 'freeSIEM Sentinel'),
			'body' => (string) ($release['body'] ?? ''),
			'published_at' => (string) ($release['published_at'] ?? ''),
			'repository_url' => (string) $config['html_url'],
		];

		set_site_transient($cache_key, $data, 6 * HOUR_IN_SECONDS);
		freesiem_sentinel_update_settings(['updater_cache' => $data]);

		return $data;
	}

	public function refresh_plugin_update_state()
	{
		$this->clear_github_update_cache();
		$release = $this->get_github_release_data(true);

		if (is_wp_error($release)) {
			return $release;
		}

		if (function_exists('wp_update_plugins')) {
			wp_update_plugins();
		}

		return [
			'release' => $release,
			'update_available' => version_compare((string) ($release['version'] ?? FREESIEM_SENTINEL_VERSION), FREESIEM_SENTINEL_VERSION, '>'),
		];
	}

	public function inject_update($transient)
	{
		if (!is_object($transient)) {
			$transient = new stdClass();
		}

		$release = $this->get_github_release_data();

		if (is_wp_error($release)) {
			return $transient;
		}

		$payload = $this->build_update_payload($release);

		if (version_compare((string) $release['version'], FREESIEM_SENTINEL_VERSION, '>')) {
			if (!isset($transient->response) || !is_array($transient->response)) {
				$transient->response = [];
			}

			$transient->response[freesiem_sentinel_get_plugin_basename()] = $payload;
			return $transient;
		}

		if (!isset($transient->no_update) || !is_array($transient->no_update)) {
			$transient->no_update = [];
		}

		$transient->no_update[freesiem_sentinel_get_plugin_basename()] = $payload;

		return $transient;
	}

	public function plugins_api($result, string $action, $args)
	{
		if ($action !== 'plugin_information' || !is_object($args) || (($args->slug ?? '') !== freesiem_sentinel_get_plugin_slug())) {
			return $result;
		}

		$release = $this->get_github_release_data();

		if (is_wp_error($release)) {
			return $result;
		}

		return (object) [
			'name' => 'freeSIEM Sentinel',
			'slug' => freesiem_sentinel_get_plugin_slug(),
			'version' => (string) ($release['version'] ?? FREESIEM_SENTINEL_VERSION),
			'author' => '<a href="' . esc_url(freesiem_sentinel_safe_string($release['repository_url'] ?? '')) . '">freeSIEM Sentinel</a>',
			'author_profile' => (string) ($release['repository_url'] ?? ''),
			'homepage' => (string) ($release['html_url'] ?? $release['repository_url'] ?? ''),
			'download_link' => (string) ($release['package_url'] ?? ''),
			'last_updated' => (string) ($release['published_at'] ?? ''),
			'sections' => [
				'description' => '<p>' . esc_html__('freeSIEM Sentinel updates are served from the configured GitHub releases feed.', 'freesiem-sentinel') . '</p>',
				'changelog' => trim(freesiem_sentinel_safe_string($release['body'] ?? '')) !== '' ? wpautop(esc_html(freesiem_sentinel_safe_string($release['body'] ?? ''))) : '<p>' . esc_html__('No changelog was provided in the latest release.', 'freesiem-sentinel') . '</p>',
			],
			'banners' => [],
		];
	}

	public function plugin_action_links(array $actions): array
	{
		$links = [
			'check_updates' => '<a href="' . esc_url(freesiem_sentinel_safe_string($this->get_check_updates_url(self_admin_url('plugins.php')))) . '">' . esc_html__('Check for Updates', 'freesiem-sentinel') . '</a>',
			'about' => '<a href="' . esc_url(freesiem_sentinel_safe_string(freesiem_sentinel_admin_page_url('freesiem-about'))) . '">' . esc_html__('About', 'freesiem-sentinel') . '</a>',
		];

		return array_merge($links, $actions);
	}

	public function handle_manual_update_check(): void
	{
		if (!freesiem_sentinel_current_user_can_manage()) {
			wp_die(esc_html__('You are not allowed to check plugin updates.', 'freesiem-sentinel'));
		}

		freesiem_sentinel_require_admin_post_nonce();

		$redirect_to = isset($_GET['redirect_to']) ? wp_unslash((string) $_GET['redirect_to']) : '';
		$redirect_to = wp_validate_redirect($redirect_to, freesiem_sentinel_admin_page_url('freesiem-about'));
		$result = $this->refresh_plugin_update_state();

		if (is_wp_error($result)) {
			freesiem_sentinel_set_notice('error', $result->get_error_message());
			wp_safe_redirect($redirect_to);
			exit;
		}

		$release = is_array($result['release'] ?? null) ? $result['release'] : [];
		$version = (string) ($release['version'] ?? '');

		if (!empty($result['update_available']) && $version !== '') {
			freesiem_sentinel_set_notice('success', sprintf(__('New GitHub release found: v%s.', 'freesiem-sentinel'), $version));
		} else {
			freesiem_sentinel_set_notice('success', sprintf(__('freeSIEM Sentinel is already on the latest GitHub release (v%s).', 'freesiem-sentinel'), FREESIEM_SENTINEL_VERSION));
		}

		wp_safe_redirect($redirect_to);
		exit;
	}

	public function clear_after_upgrade($upgrader, array $hook_extra): void
	{
		if (($hook_extra['type'] ?? '') !== 'plugin' || empty($hook_extra['plugins']) || !is_array($hook_extra['plugins'])) {
			return;
		}

		if (!in_array(freesiem_sentinel_get_plugin_basename(), $hook_extra['plugins'], true)) {
			return;
		}

		$this->clear_github_update_cache();
	}

	public function clear_github_update_cache(): void
	{
		$config = $this->get_github_update_config();

		if (!empty($config['enabled'])) {
			delete_site_transient($this->get_cache_key($config));
		}

		delete_site_transient('update_plugins');

		if (function_exists('wp_clean_plugins_cache')) {
			wp_clean_plugins_cache(true);
		}
	}

	public function get_check_updates_url(string $redirect_to = ''): string
	{
		$url = add_query_arg(
			freesiem_sentinel_safe_query_args(['action' => 'freesiem_sentinel_check_updates']),
			admin_url('admin-post.php')
		);
		$redirect_to = freesiem_sentinel_safe_string($redirect_to);

		if ($redirect_to !== '') {
			$url = add_query_arg(
				freesiem_sentinel_safe_query_args(['redirect_to' => $redirect_to]),
				(string) $url
			);
		}

		return wp_nonce_url((string) $url, FREESIEM_SENTINEL_NONCE_ACTION);
	}

	public function get_plugin_upgrade_url(): string
	{
		return wp_nonce_url(
			self_admin_url('update.php?action=upgrade-plugin&plugin=' . rawurlencode(freesiem_sentinel_get_plugin_basename())),
			'upgrade-plugin_' . freesiem_sentinel_get_plugin_basename()
		);
	}

	private function get_cache_key(array $config): string
	{
		return 'freesiem_sentinel_release_' . md5(freesiem_sentinel_safe_string($config['repository'] ?? '') . '|' . freesiem_sentinel_safe_string($config['asset_name'] ?? ''));
	}

	private function build_update_payload(array $release): object
	{
		return (object) [
			'id' => freesiem_sentinel_safe_string($release['html_url'] ?? ''),
			'slug' => freesiem_sentinel_get_plugin_slug(),
			'plugin' => freesiem_sentinel_get_plugin_basename(),
			'new_version' => freesiem_sentinel_safe_string($release['version'] ?? FREESIEM_SENTINEL_VERSION),
			'url' => freesiem_sentinel_safe_string($release['html_url'] ?? ''),
			'package' => freesiem_sentinel_safe_string($release['package_url'] ?? ''),
			'icons' => [],
			'banners' => [],
			'banners_rtl' => [],
			'tested' => '',
			'requires' => '',
			'requires_php' => '',
		];
	}

	private function parse_github_repository(string $value): string
	{
		$value = trim(preg_replace('#\.git$#i', '', freesiem_sentinel_safe_string($value)) ?? '');

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

	private function find_release_asset_url(array $release, string $asset_name): string
	{
		$assets = is_array($release['assets'] ?? null) ? $release['assets'] : [];

		if ($asset_name !== '') {
			foreach ($assets as $asset) {
				if (is_array($asset) && (string) ($asset['name'] ?? '') === $asset_name && !empty($asset['browser_download_url'])) {
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
}
