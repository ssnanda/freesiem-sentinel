<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Admin
{
	private Freesiem_Plugin $plugin;

	public function __construct(Freesiem_Plugin $plugin)
	{
		$this->plugin = $plugin;
	}

	public function register(): void
	{
		add_action('admin_menu', [$this, 'register_menu']);
		add_action('admin_notices', 'freesiem_sentinel_render_notices');
		add_action('admin_post_freesiem_sentinel_save_settings', [$this, 'handle_save_settings']);
		add_action('admin_post_freesiem_sentinel_run_local_scan', [$this, 'handle_run_local_scan']);
		add_action('admin_post_freesiem_sentinel_request_remote_scan', [$this, 'handle_request_remote_scan']);
		add_action('admin_post_freesiem_sentinel_sync_results', [$this, 'handle_sync_results']);
		add_action('admin_post_freesiem_sentinel_reconnect', [$this, 'handle_reconnect']);
	}

	public function register_menu(): void
	{
		add_menu_page(
			__('freeSIEM', 'freesiem-sentinel'),
			__('freeSIEM', 'freesiem-sentinel'),
			'manage_options',
			'freesiem-sentinel',
			[$this, 'render_dashboard_page'],
			'dashicons-shield-alt'
		);

		add_submenu_page('freesiem-sentinel', __('Dashboard', 'freesiem-sentinel'), __('Dashboard', 'freesiem-sentinel'), 'manage_options', 'freesiem-sentinel', [$this, 'render_dashboard_page']);
		add_submenu_page('freesiem-sentinel', __('Results', 'freesiem-sentinel'), __('Results', 'freesiem-sentinel'), 'manage_options', 'freesiem-sentinel-results', [$this, 'render_results_page']);
		add_submenu_page('freesiem-sentinel', __('About', 'freesiem-sentinel'), __('About', 'freesiem-sentinel'), 'manage_options', 'freesiem-sentinel-about', [$this, 'render_about_page']);
	}

	public function handle_save_settings(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$email = isset($_POST['email']) ? sanitize_email(wp_unslash((string) $_POST['email'])) : '';
		$backend_url = isset($_POST['backend_url']) ? freesiem_sentinel_sanitize_backend_url(wp_unslash((string) $_POST['backend_url'])) : FREESIEM_SENTINEL_BACKEND_URL;
		$settings = freesiem_sentinel_update_settings([
			'email' => $email,
			'backend_url' => $backend_url,
		]);

		if ($email === '') {
			freesiem_sentinel_set_notice('error', __('Email is required to register this site with freeSIEM Core.', 'freesiem-sentinel'));
			$this->redirect('admin.php?page=freesiem-sentinel');
		}

		$result = $this->plugin->register_site($settings['email']);

		if (is_wp_error($result)) {
			freesiem_sentinel_set_notice('error', $result->get_error_message());
			$this->redirect('admin.php?page=freesiem-sentinel');
		}

		freesiem_sentinel_set_notice('success', __('Site registration completed successfully.', 'freesiem-sentinel'));
		$this->redirect('admin.php?page=freesiem-sentinel');
	}

	public function handle_run_local_scan(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->run_local_scan(true);
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Local scan completed and uploaded.', 'freesiem-sentinel'));
		$this->redirect('admin.php?page=freesiem-sentinel');
	}

	public function handle_request_remote_scan(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->request_remote_scan();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Remote scan request sent.', 'freesiem-sentinel'));
		$this->redirect('admin.php?page=freesiem-sentinel');
	}

	public function handle_sync_results(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->sync_results();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Results synced from freeSIEM Core.', 'freesiem-sentinel'));
		$this->redirect('admin.php?page=freesiem-sentinel-results');
	}

	public function handle_reconnect(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->reconnect();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Site reconnected successfully.', 'freesiem-sentinel'));
		$this->redirect('admin.php?page=freesiem-sentinel');
	}

	public function render_dashboard_page(): void
	{
		$settings = freesiem_sentinel_get_settings();
		$cache = $this->plugin->get_results()->get_cache();
		$summary = is_array($cache['summary']) ? $cache['summary'] : [];
		$updater = $this->plugin->get_updater()->get_github_release_data();
		$release = is_wp_error($updater) ? [] : $updater;
		$connection_ok = !empty($settings['site_id']) && !empty($settings['api_key']) && !empty($settings['hmac_secret']);
		$severity_counts = is_array($cache['severity_counts']) ? $cache['severity_counts'] : [];

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('freeSIEM Sentinel', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('WordPress agent for freeSIEM Core ownership verification, local scanning, remote commands, and secure telemetry sync.', 'freesiem-sentinel') . '</p>';
		$this->render_card_grid_start();
		$this->render_stat_card(__('Connection', 'freesiem-sentinel'), $connection_ok ? __('Connected', 'freesiem-sentinel') : __('Not Connected', 'freesiem-sentinel'), __('Registration status', 'freesiem-sentinel'), strtoupper((string) $settings['registration_status']));
		$this->render_stat_card(__('Site ID', 'freesiem-sentinel'), (string) ($settings['site_id'] ?: 'Pending'), __('Plugin UUID', 'freesiem-sentinel'), (string) ($settings['plugin_uuid'] ?: 'Pending'));
		$this->render_stat_card(__('Heartbeat', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) $settings['last_heartbeat_at']), __('Last sync', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) $settings['last_sync_at']));
		$this->render_stat_card(__('Scores', 'freesiem-sentinel'), 'Overall: ' . esc_html((string) ($summary['overall_score'] ?? ($summary['local_score'] ?? 'N/A'))), __('Remote / Local', 'freesiem-sentinel'), esc_html((string) ($summary['remote_score'] ?? 'N/A')) . ' / ' . esc_html((string) ($summary['local_score'] ?? 'N/A')));
		echo '</div>';

		echo '<div style="display:grid;grid-template-columns:2fr 1fr;gap:20px;margin-top:20px;">';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Agent Setup', 'freesiem-sentinel') . '</h2>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_save_settings" />';
		echo '<table class="form-table" role="presentation">';
		echo '<tr><th scope="row"><label for="freesiem-email">' . esc_html__('Email', 'freesiem-sentinel') . '</label></th><td><input class="regular-text" id="freesiem-email" name="email" type="email" value="' . esc_attr((string) $settings['email']) . '" required /></td></tr>';
		echo '<tr><th scope="row"><label for="freesiem-backend-url">' . esc_html__('Backend URL', 'freesiem-sentinel') . '</label></th><td><input class="regular-text code" id="freesiem-backend-url" name="backend_url" type="url" value="' . esc_attr((string) $settings['backend_url']) . '" /></td></tr>';
		echo '</table>';
		submit_button(__('Register / Save', 'freesiem-sentinel'));
		echo '</form>';
		echo '<p><strong>' . esc_html__('Site URL:', 'freesiem-sentinel') . '</strong> ' . esc_html(site_url('/')) . '</p>';
		echo '<p><strong>' . esc_html__('Home URL:', 'freesiem-sentinel') . '</strong> ' . esc_html(home_url('/')) . '</p>';
		echo '<p><strong>' . esc_html__('Last local scan:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_format_datetime((string) $settings['last_local_scan_at'])) . '</p>';
		echo '<p><strong>' . esc_html__('Last remote scan:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_format_datetime((string) $settings['last_remote_scan_at'])) . '</p>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Actions', 'freesiem-sentinel') . '</h2>';
		echo '<p><a class="button button-primary button-hero" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_run_local_scan')) . '">' . esc_html__('Run Local Scan', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary button-hero" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_request_remote_scan')) . '">' . esc_html__('Request Remote Scan', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary button-hero" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_sync_results')) . '">' . esc_html__('Sync Results', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary button-hero" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_reconnect')) . '">' . esc_html__('Reconnect', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary button-hero" href="' . esc_url($this->plugin->get_updater()->get_check_updates_url(admin_url('admin.php?page=freesiem-sentinel-about'))) . '">' . esc_html__('Check for Updates', 'freesiem-sentinel') . '</a></p>';
		echo '<hr />';
		echo '<h3>' . esc_html__('Severity Counts', 'freesiem-sentinel') . '</h3>';
		echo '<p>' . esc_html(sprintf('Critical %d | High %d | Medium %d | Low %d | Info %d', (int) ($severity_counts['critical'] ?? 0), (int) ($severity_counts['high'] ?? 0), (int) ($severity_counts['medium'] ?? 0), (int) ($severity_counts['low'] ?? 0), (int) ($severity_counts['info'] ?? 0))) . '</p>';
		if ($release !== []) {
			echo '<p><strong>' . esc_html__('Latest release:', 'freesiem-sentinel') . '</strong> ' . esc_html((string) ($release['version'] ?? '')) . '</p>';
		}
		echo '</div>';
		echo '</div>';
		echo '</div>';
	}

	public function render_results_page(): void
	{
		$cache = $this->plugin->get_results()->get_cache();
		$summary = is_array($cache['summary']) ? $cache['summary'] : [];
		$findings = is_array($cache['local_findings']) ? $cache['local_findings'] : [];
		$recommendations = is_array($cache['recommendations']) ? array_filter($cache['recommendations']) : [];
		$top_issues = is_array($cache['top_issues']) ? $cache['top_issues'] : [];

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Results', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Local findings and the latest summary received from freeSIEM Core.', 'freesiem-sentinel') . '</p>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Summary', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('Overall score:', 'freesiem-sentinel') . '</strong> ' . esc_html((string) ($summary['overall_score'] ?? ($summary['local_score'] ?? 'N/A'))) . '</p>';
		echo '<p><strong>' . esc_html__('Local score:', 'freesiem-sentinel') . '</strong> ' . esc_html((string) ($summary['local_score'] ?? 'N/A')) . '</p>';
		echo '<p><strong>' . esc_html__('Remote score:', 'freesiem-sentinel') . '</strong> ' . esc_html((string) ($summary['remote_score'] ?? 'N/A')) . '</p>';
		echo '<p><strong>' . esc_html__('Fetched:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_format_datetime((string) ($cache['fetched_at'] ?? ''))) . '</p>';
		echo '</div>';

		echo '<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Top Issues', 'freesiem-sentinel') . '</h2>';
		if ($top_issues === []) {
			echo '<p>' . esc_html__('No findings cached yet.', 'freesiem-sentinel') . '</p>';
		} else {
			echo '<ul>';
			foreach ($top_issues as $issue) {
				if (!is_array($issue)) {
					continue;
				}
				echo '<li><strong>' . esc_html((string) ($issue['title'] ?? '')) . '</strong> [' . esc_html(strtoupper((string) ($issue['severity'] ?? 'info'))) . ']</li>';
			}
			echo '</ul>';
		}
		echo '</div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Recommendations', 'freesiem-sentinel') . '</h2>';
		if ($recommendations === []) {
			echo '<p>' . esc_html__('No recommendations available yet.', 'freesiem-sentinel') . '</p>';
		} else {
			echo '<ul>';
			foreach ($recommendations as $recommendation) {
				echo '<li>' . esc_html((string) $recommendation) . '</li>';
			}
			echo '</ul>';
		}
		echo '</div>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Findings', 'freesiem-sentinel') . '</h2>';
		if ($findings === []) {
			echo '<p>' . esc_html__('Run a local scan to populate findings.', 'freesiem-sentinel') . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Severity', 'freesiem-sentinel') . '</th><th>' . esc_html__('Title', 'freesiem-sentinel') . '</th><th>' . esc_html__('Category', 'freesiem-sentinel') . '</th><th>' . esc_html__('Recommendation', 'freesiem-sentinel') . '</th><th>' . esc_html__('Detected', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
			foreach ($findings as $finding) {
				if (!is_array($finding)) {
					continue;
				}
				echo '<tr>';
				echo '<td>' . esc_html(strtoupper((string) ($finding['severity'] ?? 'info'))) . '</td>';
				echo '<td><strong>' . esc_html((string) ($finding['title'] ?? '')) . '</strong><br /><span>' . esc_html((string) ($finding['description'] ?? '')) . '</span></td>';
				echo '<td>' . esc_html((string) ($finding['category'] ?? '')) . '</td>';
				echo '<td>' . esc_html((string) ($finding['recommendation'] ?? '')) . '</td>';
				echo '<td>' . esc_html(freesiem_sentinel_format_datetime((string) ($finding['detected_at'] ?? ''))) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
		echo '</div>';
	}

	public function render_about_page(): void
	{
		$settings = freesiem_sentinel_get_settings();
		$release = $this->plugin->get_updater()->get_github_release_data();
		$release = is_wp_error($release) ? [] : $release;

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('About freeSIEM Sentinel', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Release, backend, and agent identity details for this WordPress deployment.', 'freesiem-sentinel') . '</p>';
		$this->render_card_grid_start();
		$this->render_stat_card(__('Plugin Version', 'freesiem-sentinel'), FREESIEM_SENTINEL_VERSION, __('Latest Release', 'freesiem-sentinel'), (string) ($release['version'] ?? 'Unavailable'));
		$this->render_stat_card(__('Backend URL', 'freesiem-sentinel'), (string) $settings['backend_url'], __('Registration', 'freesiem-sentinel'), strtoupper((string) $settings['registration_status']));
		$this->render_stat_card(__('Site ID', 'freesiem-sentinel'), (string) ($settings['site_id'] ?: 'Pending'), __('Plugin UUID', 'freesiem-sentinel'), (string) ($settings['plugin_uuid'] ?: 'Pending'));
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-top:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Credentials', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('API Key:', 'freesiem-sentinel') . '</strong> <code>' . esc_html(freesiem_sentinel_mask_secret((string) $settings['api_key'])) . '</code></p>';
		echo '<p><strong>' . esc_html__('HMAC Secret:', 'freesiem-sentinel') . '</strong> <code>' . esc_html(freesiem_sentinel_mask_secret((string) $settings['hmac_secret'])) . '</code></p>';
		echo '<p><strong>' . esc_html__('Check for Updates:', 'freesiem-sentinel') . '</strong> <a class="button button-secondary" href="' . esc_url($this->plugin->get_updater()->get_check_updates_url(admin_url('admin.php?page=freesiem-sentinel-about'))) . '">' . esc_html__('Check for Updates', 'freesiem-sentinel') . '</a></p>';
		if (!empty($release['published_at'])) {
			echo '<p><strong>' . esc_html__('Release Published:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_format_datetime((string) $release['published_at'])) . '</p>';
		}
		if (!empty($release['html_url'])) {
			echo '<p><strong>' . esc_html__('Release URL:', 'freesiem-sentinel') . '</strong> <a href="' . esc_url((string) $release['html_url']) . '" target="_blank" rel="noopener noreferrer">' . esc_html((string) $release['html_url']) . '</a></p>';
		}
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-top:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Updater Cache', 'freesiem-sentinel') . '</h2>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html(wp_json_encode($settings['updater_cache'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) . '</pre>';
		echo '</div>';
		echo '</div>';
	}

	private function render_card_grid_start(): void
	{
		echo '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px;">';
	}

	private function render_stat_card(string $title, string $value, string $label, string $meta): void
	{
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<p style="margin:0 0 8px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#50575e;">' . esc_html($title) . '</p>';
		echo '<p style="margin:0;font-size:24px;font-weight:600;word-break:break-word;">' . esc_html($value) . '</p>';
		echo '<p style="margin:12px 0 0;color:#50575e;"><strong>' . esc_html($label) . ':</strong> ' . esc_html($meta) . '</p>';
		echo '</div>';
	}

	private function assert_manage_permissions(): void
	{
		if (!freesiem_sentinel_current_user_can_manage()) {
			wp_die(esc_html__('You are not allowed to manage freeSIEM Sentinel.', 'freesiem-sentinel'));
		}
	}

	private function redirect(string $path): void
	{
		wp_safe_redirect(admin_url($path));
		exit;
	}
}
