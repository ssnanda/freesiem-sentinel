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
		$summary = freesiem_sentinel_safe_array($cache['summary'] ?? []);
		$updater = $this->plugin->get_updater()->get_github_release_data();
		$release = is_wp_error($updater) ? [] : freesiem_sentinel_safe_array($updater);
		$connection_ok = !empty($settings['site_id']) && !empty($settings['api_key']) && !empty($settings['hmac_secret']);
		$severity_counts = freesiem_sentinel_safe_array($cache['severity_counts'] ?? []);
		$filesystem = freesiem_sentinel_safe_array($cache['local_inventory']['filesystem'] ?? []);
		$notices = freesiem_sentinel_safe_array($cache['notices'] ?? []);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('freeSIEM Sentinel', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('WordPress agent for freeSIEM Core ownership verification, local scanning, remote commands, and secure telemetry sync.', 'freesiem-sentinel') . '</p>';
		$this->render_card_grid_start();
		$this->render_stat_card(__('Connection', 'freesiem-sentinel'), $connection_ok ? __('Connected', 'freesiem-sentinel') : __('Not Connected', 'freesiem-sentinel'), __('Registration status', 'freesiem-sentinel'), strtoupper(freesiem_sentinel_safe_string($settings['registration_status'] ?? '')));
		$this->render_stat_card(__('Site ID', 'freesiem-sentinel'), freesiem_sentinel_safe_string($settings['site_id'] ?? 'Pending') ?: 'Pending', __('Plugin UUID', 'freesiem-sentinel'), freesiem_sentinel_safe_string($settings['plugin_uuid'] ?? 'Pending') ?: 'Pending');
		$this->render_stat_card(__('Heartbeat', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) ($settings['last_heartbeat_at'] ?? '')), __('Last sync', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) ($settings['last_sync_at'] ?? '')));
		$this->render_stat_card(__('Last Local Scan', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) ($settings['last_local_scan_at'] ?? '')), __('Last Remote Scan', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) ($settings['last_remote_scan_at'] ?? '')));
		$this->render_stat_card(__('Scores', 'freesiem-sentinel'), 'Overall: ' . freesiem_sentinel_safe_string($summary['overall_score'] ?? ($summary['local_score'] ?? 'N/A')), __('Remote / Local', 'freesiem-sentinel'), freesiem_sentinel_safe_string($summary['remote_score'] ?? 'N/A') . ' / ' . freesiem_sentinel_safe_string($summary['local_score'] ?? 'N/A'));
		echo '</div>';

		echo '<div style="display:grid;grid-template-columns:2fr 1fr;gap:20px;margin-top:20px;">';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Agent Setup', 'freesiem-sentinel') . '</h2>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_save_settings" />';
		echo '<table class="form-table" role="presentation">';
		echo '<tr><th scope="row"><label for="freesiem-email">' . esc_html__('Email', 'freesiem-sentinel') . '</label></th><td><input class="regular-text" id="freesiem-email" name="email" type="email" value="' . esc_attr(freesiem_sentinel_safe_string($settings['email'] ?? '')) . '" required /></td></tr>';
		echo '<tr><th scope="row"><label for="freesiem-backend-url">' . esc_html__('Backend URL', 'freesiem-sentinel') . '</label></th><td><input class="regular-text code" id="freesiem-backend-url" name="backend_url" type="url" value="' . esc_attr(freesiem_sentinel_safe_string($settings['backend_url'] ?? '')) . '" /></td></tr>';
		echo '</table>';
		submit_button(__('Register / Save', 'freesiem-sentinel'));
		echo '</form>';
		echo '<p><strong>' . esc_html__('Site URL:', 'freesiem-sentinel') . '</strong> ' . esc_html(site_url('/')) . '</p>';
		echo '<p><strong>' . esc_html__('Home URL:', 'freesiem-sentinel') . '</strong> ' . esc_html(home_url('/')) . '</p>';
		$this->render_score_badges($summary, $severity_counts);
		$this->render_notices_panel($notices);
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Actions', 'freesiem-sentinel') . '</h2>';
		echo '<p><a class="button button-primary button-hero" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_run_local_scan')) . '">' . esc_html__('Run Local Scan', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary button-hero" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_request_remote_scan')) . '">' . esc_html__('Request Remote Scan', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary button-hero" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_sync_results')) . '">' . esc_html__('Sync Results', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary button-hero" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_reconnect')) . '">' . esc_html__('Reconnect', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary button-hero" href="' . esc_url(freesiem_sentinel_safe_string($this->plugin->get_updater()->get_check_updates_url(admin_url('admin.php?page=freesiem-sentinel-about')))) . '">' . esc_html__('Check for Updates', 'freesiem-sentinel') . '</a></p>';
		echo '<hr />';
		echo '<h3>' . esc_html__('Severity Counts', 'freesiem-sentinel') . '</h3>';
		$this->render_severity_counts($severity_counts);
		if ($release !== []) {
			echo '<p><strong>' . esc_html__('Latest release:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_safe_string($release['version'] ?? '')) . '</p>';
		}
		if ($filesystem !== []) {
			echo '<hr />';
			echo '<h3>' . esc_html__('Filesystem Scan Snapshot', 'freesiem-sentinel') . '</h3>';
			echo '<p><strong>' . esc_html__('Inspected files:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_safe_string($filesystem['inspected_files'] ?? '0')) . '</p>';
			echo '<p><strong>' . esc_html__('Flagged files:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_safe_string($filesystem['flagged_files'] ?? '0')) . '</p>';
			echo '<p><strong>' . esc_html__('Partial scan:', 'freesiem-sentinel') . '</strong> ' . esc_html(!empty($filesystem['partial']) ? __('Yes', 'freesiem-sentinel') : __('No', 'freesiem-sentinel')) . '</p>';
		}
		echo '</div>';
		echo '</div>';
		echo '</div>';
	}

	public function render_results_page(): void
	{
		$cache = $this->plugin->get_results()->get_cache();
		$summary = freesiem_sentinel_safe_array($cache['summary'] ?? []);
		$all_findings = array_values(freesiem_sentinel_safe_array($cache['local_findings'] ?? []));
		$recommendations = array_values(array_filter(freesiem_sentinel_safe_array($cache['recommendations'] ?? [])));
		$top_issues = freesiem_sentinel_safe_array($cache['top_issues'] ?? []);
		$filesystem = freesiem_sentinel_safe_array($cache['local_inventory']['filesystem'] ?? []);
		$severity_counts = freesiem_sentinel_safe_array($cache['severity_counts'] ?? []);
		$search = isset($_GET['s']) ? sanitize_text_field(wp_unslash((string) $_GET['s'])) : '';
		$selected_severities = $this->get_results_severity_filters();
		$findings = $this->filter_findings($all_findings, $search, $selected_severities);
		$finding_ref = isset($_GET['finding']) ? sanitize_text_field(wp_unslash((string) $_GET['finding'])) : '';
		$finding = $finding_ref !== '' ? $this->find_finding_by_reference($all_findings, $finding_ref) : null;

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Results', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Local findings and the latest summary received from freeSIEM Core.', 'freesiem-sentinel') . '</p>';

		if (is_array($finding)) {
			$this->render_finding_detail_page($finding);
			echo '</div>';
			return;
		}

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Summary', 'freesiem-sentinel') . '</h2>';
		$this->render_score_badges($summary, $severity_counts);
		echo '<p><strong>' . esc_html__('Fetched:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_format_datetime((string) ($cache['fetched_at'] ?? ''))) . '</p>';
		if ($filesystem !== []) {
			echo '<p><strong>' . esc_html__('Filesystem scan:', 'freesiem-sentinel') . '</strong> ' . esc_html(sprintf(__('Inspected %1$s files, flagged %2$s, partial %3$s', 'freesiem-sentinel'), freesiem_sentinel_safe_string($filesystem['inspected_files'] ?? '0'), freesiem_sentinel_safe_string($filesystem['flagged_files'] ?? '0'), !empty($filesystem['partial']) ? __('yes', 'freesiem-sentinel') : __('no', 'freesiem-sentinel'))) . '</p>';
		}
		echo '</div>';

		echo '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap;">';
		echo '<a class="button button-primary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_run_local_scan')) . '">' . esc_html__('Run Local Scan Again', 'freesiem-sentinel') . '</a>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<form method="get" action="' . esc_url(admin_url('admin.php')) . '" style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;">';
		echo '<input type="hidden" name="page" value="freesiem-sentinel-results" />';
		echo '<div><label for="freesiem-search" style="display:block;font-weight:600;margin-bottom:6px;">' . esc_html__('Search Findings', 'freesiem-sentinel') . '</label><input id="freesiem-search" class="regular-text" type="search" name="s" value="' . esc_attr($search) . '" /></div>';
		echo '<div><span style="display:block;font-weight:600;margin-bottom:6px;">' . esc_html__('Severity Filters', 'freesiem-sentinel') . '</span>';
		foreach (['critical' => __('Critical', 'freesiem-sentinel'), 'high' => __('High', 'freesiem-sentinel'), 'medium' => __('Medium', 'freesiem-sentinel'), 'low' => __('Low', 'freesiem-sentinel'), 'info' => __('Info', 'freesiem-sentinel')] as $key => $label) {
			echo '<label style="margin-right:10px;display:inline-flex;align-items:center;gap:4px;"><input type="checkbox" name="severity[]" value="' . esc_attr($key) . '"' . checked(in_array($key, $selected_severities, true), true, false) . ' />' . esc_html($label) . '</label>';
		}
		echo '</div>';
		echo '<div><button type="submit" class="button button-secondary">' . esc_html__('Search', 'freesiem-sentinel') . '</button></div>';
		echo '</form>';
		echo '</div>';

		echo '<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Top Issues', 'freesiem-sentinel') . '</h2>';
		if ($top_issues === []) {
			$this->render_empty_state(__('No top issues yet', 'freesiem-sentinel'), __('Run a local scan or sync results from freeSIEM Core to populate this area.', 'freesiem-sentinel'));
		} else {
			echo '<ul>';
			foreach ($top_issues as $issue) {
				if (!is_array($issue)) {
					continue;
				}
				echo '<li><strong>' . esc_html(freesiem_sentinel_safe_string($issue['title'] ?? '')) . '</strong> [' . esc_html(strtoupper(freesiem_sentinel_safe_string($issue['severity'] ?? 'info'))) . ']</li>';
			}
			echo '</ul>';
		}
		echo '</div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Recommendations', 'freesiem-sentinel') . '</h2>';
		if ($recommendations === []) {
			$this->render_empty_state(__('No recommendations yet', 'freesiem-sentinel'), __('Recommendations will appear here after local or remote analysis is available.', 'freesiem-sentinel'));
		} else {
			echo '<ul>';
			foreach ($recommendations as $recommendation) {
				echo '<li>' . esc_html(freesiem_sentinel_safe_string($recommendation)) . '</li>';
			}
			echo '</ul>';
		}
		echo '</div>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Findings', 'freesiem-sentinel') . '</h2>';
		if ($findings === []) {
			$this->render_empty_state(__('No findings match the current view', 'freesiem-sentinel'), __('Adjust the search or severity filters, or run a new local scan.', 'freesiem-sentinel'));
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Severity', 'freesiem-sentinel') . '</th><th>' . esc_html__('Title', 'freesiem-sentinel') . '</th><th>' . esc_html__('Category', 'freesiem-sentinel') . '</th><th>' . esc_html__('Recommendation', 'freesiem-sentinel') . '</th><th>' . esc_html__('Detected', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
			foreach ($findings as $index => $finding) {
				if (!is_array($finding)) {
					continue;
				}

				$reference = $this->build_finding_reference($finding, $index);
				$detail_url = add_query_arg(
					[
						'page' => 'freesiem-sentinel-results',
						'finding' => $reference,
					],
					admin_url('admin.php')
				);

				echo '<tr>';
				echo '<td><a href="' . esc_url($detail_url) . '" style="' . esc_attr($this->severity_badge_style((string) ($finding['severity'] ?? 'info'))) . '">' . esc_html(strtoupper(freesiem_sentinel_safe_string($finding['severity'] ?? 'info'))) . '</a></td>';
				echo '<td><a href="' . esc_url($detail_url) . '" style="display:block;color:inherit;text-decoration:none;"><strong>' . esc_html(freesiem_sentinel_safe_string($finding['title'] ?? '')) . '</strong><br /><span>' . esc_html(freesiem_sentinel_safe_string($finding['description'] ?? '')) . '</span></a></td>';
				echo '<td><a href="' . esc_url($detail_url) . '" style="display:block;color:inherit;text-decoration:none;">' . esc_html(freesiem_sentinel_safe_string($finding['category'] ?? '')) . '</a></td>';
				echo '<td><a href="' . esc_url($detail_url) . '" style="display:block;color:inherit;text-decoration:none;">' . esc_html(freesiem_sentinel_safe_string($finding['recommendation'] ?? '')) . '</a></td>';
				echo '<td><a href="' . esc_url($detail_url) . '" style="display:block;color:inherit;text-decoration:none;">' . esc_html(freesiem_sentinel_format_datetime((string) ($finding['detected_at'] ?? ''))) . '</a></td>';
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
		$release = is_wp_error($release) ? [] : freesiem_sentinel_safe_array($release);
		$release_body = trim(freesiem_sentinel_safe_string($release['body'] ?? ''));

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('About freeSIEM Sentinel', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Release, backend, and agent identity details for this WordPress deployment.', 'freesiem-sentinel') . '</p>';
		$this->render_card_grid_start();
		$this->render_stat_card(__('Plugin Version', 'freesiem-sentinel'), FREESIEM_SENTINEL_VERSION, __('Latest Release', 'freesiem-sentinel'), freesiem_sentinel_safe_string($release['version'] ?? 'Unavailable'));
		$this->render_stat_card(__('Backend URL', 'freesiem-sentinel'), freesiem_sentinel_safe_string($settings['backend_url'] ?? ''), __('Registration', 'freesiem-sentinel'), strtoupper(freesiem_sentinel_safe_string($settings['registration_status'] ?? '')));
		$this->render_stat_card(__('Site ID', 'freesiem-sentinel'), freesiem_sentinel_safe_string($settings['site_id'] ?? 'Pending') ?: 'Pending', __('Plugin UUID', 'freesiem-sentinel'), freesiem_sentinel_safe_string($settings['plugin_uuid'] ?? 'Pending') ?: 'Pending');
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-top:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Credentials', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('API Key:', 'freesiem-sentinel') . '</strong> <code>' . esc_html(freesiem_sentinel_mask_secret((string) ($settings['api_key'] ?? ''))) . '</code></p>';
		echo '<p><strong>' . esc_html__('HMAC Secret:', 'freesiem-sentinel') . '</strong> <code>' . esc_html(freesiem_sentinel_mask_secret((string) ($settings['hmac_secret'] ?? ''))) . '</code></p>';
		echo '<p><strong>' . esc_html__('Check for Updates:', 'freesiem-sentinel') . '</strong> <a class="button button-secondary" href="' . esc_url(freesiem_sentinel_safe_string($this->plugin->get_updater()->get_check_updates_url(admin_url('admin.php?page=freesiem-sentinel-about')))) . '">' . esc_html__('Check for Updates', 'freesiem-sentinel') . '</a></p>';
		if (!empty($release['published_at'])) {
			echo '<p><strong>' . esc_html__('Release Published:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_format_datetime((string) ($release['published_at'] ?? ''))) . '</p>';
		}
		if (!empty($release['html_url'])) {
			echo '<p><strong>' . esc_html__('Release URL:', 'freesiem-sentinel') . '</strong> <a href="' . esc_url(freesiem_sentinel_safe_string($release['html_url'] ?? '')) . '" target="_blank" rel="noopener noreferrer">' . esc_html(freesiem_sentinel_safe_string($release['html_url'] ?? '')) . '</a></p>';
		}
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-top:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Updater Cache', 'freesiem-sentinel') . '</h2>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html(freesiem_sentinel_safe_json_pretty($settings['updater_cache'] ?? [])) . '</pre>';
		echo '</div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-top:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Latest Release Notes', 'freesiem-sentinel') . '</h2>';
		if ($release_body === '') {
			$this->render_empty_state(__('No release notes available', 'freesiem-sentinel'), __('The latest GitHub release did not include a changelog body.', 'freesiem-sentinel'));
		} else {
			echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html($release_body) . '</pre>';
		}
		echo '</div>';
		echo '</div>';
	}

	private function render_card_grid_start(): void
	{
		echo '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px;">';
	}

	private function render_stat_card(string $title, string $value, string $label, string $meta): void
	{
		$title = freesiem_sentinel_safe_string($title);
		$value = freesiem_sentinel_safe_string($value);
		$label = freesiem_sentinel_safe_string($label);
		$meta = freesiem_sentinel_safe_string($meta);

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<p style="margin:0 0 8px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#50575e;">' . esc_html($title) . '</p>';
		echo '<p style="margin:0;font-size:24px;font-weight:600;word-break:break-word;">' . esc_html($value) . '</p>';
		echo '<p style="margin:12px 0 0;color:#50575e;"><strong>' . esc_html($label) . ':</strong> ' . esc_html($meta) . '</p>';
		echo '</div>';
	}

	private function render_score_badges(array $summary, array $severity_counts): void
	{
		echo '<div style="display:flex;flex-wrap:wrap;gap:10px;margin:16px 0;">';
		$badges = [
			sprintf(__('Overall %s', 'freesiem-sentinel'), freesiem_sentinel_safe_string($summary['overall_score'] ?? ($summary['local_score'] ?? 'N/A'))),
			sprintf(__('Local %s', 'freesiem-sentinel'), freesiem_sentinel_safe_string($summary['local_score'] ?? 'N/A')),
			sprintf(__('Remote %s', 'freesiem-sentinel'), freesiem_sentinel_safe_string($summary['remote_score'] ?? 'N/A')),
			sprintf(__('High+ %d', 'freesiem-sentinel'), (int) (($severity_counts['critical'] ?? 0) + ($severity_counts['high'] ?? 0))),
		];

		foreach ($badges as $badge) {
			echo '<span style="display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;background:#f0f6fc;border:1px solid #c3d0dd;font-weight:600;">' . esc_html($badge) . '</span>';
		}

		echo '</div>';
	}

	private function render_severity_counts(array $severity_counts): void
	{
		echo '<ul style="margin:0;padding-left:18px;">';
		foreach (['critical', 'high', 'medium', 'low', 'info'] as $severity) {
			echo '<li>' . esc_html(ucfirst($severity) . ': ' . (int) ($severity_counts[$severity] ?? 0)) . '</li>';
		}
		echo '</ul>';
	}

	private function render_notices_panel(array $notices): void
	{
		echo '<h3>' . esc_html__('Core Notices', 'freesiem-sentinel') . '</h3>';

		if ($notices === []) {
			$this->render_empty_state(__('No notices yet', 'freesiem-sentinel'), __('Heartbeat notices from freeSIEM Core will appear here.', 'freesiem-sentinel'));
			return;
		}

		echo '<ul>';
		foreach ($notices as $notice) {
			if (!is_array($notice)) {
				continue;
			}

			$type = strtoupper(freesiem_sentinel_safe_string($notice['type'] ?? 'INFO'));
			$message = freesiem_sentinel_safe_string($notice['message'] ?? '');

			if ($message === '') {
				continue;
			}

			echo '<li><strong>' . esc_html($type) . ':</strong> ' . esc_html($message) . '</li>';
		}
		echo '</ul>';
	}

	private function render_empty_state(string $title, string $description): void
	{
		$title = freesiem_sentinel_safe_string($title);
		$description = freesiem_sentinel_safe_string($description);

		echo '<div style="padding:12px 14px;border:1px dashed #c3c4c7;border-radius:8px;background:#f9f9f9;">';
		echo '<p style="margin:0 0 6px;font-weight:600;">' . esc_html($title) . '</p>';
		echo '<p style="margin:0;color:#50575e;">' . esc_html($description) . '</p>';
		echo '</div>';
	}

	private function get_results_severity_filters(): array
	{
		$raw = isset($_GET['severity']) ? wp_unslash($_GET['severity']) : ['critical', 'high'];
		$values = is_array($raw) ? $raw : [$raw];
		$values = array_map(static fn($value): string => sanitize_key((string) $value), $values);
		$values = array_values(array_intersect($values, ['critical', 'high', 'medium', 'low', 'info']));

		return $values === [] ? ['critical', 'high'] : $values;
	}

	private function filter_findings(array $findings, string $search, array $severities): array
	{
		$search = strtolower($search);

		return array_values(array_filter($findings, static function ($finding) use ($search, $severities): bool {
			if (!is_array($finding)) {
				return false;
			}

			$severity = freesiem_sentinel_normalize_severity((string) ($finding['severity'] ?? 'info'));

			if (!in_array($severity, $severities, true)) {
				return false;
			}

			if ($search === '') {
				return true;
			}

			$haystack = strtolower(
				implode(
					' ',
					[
						freesiem_sentinel_safe_string($finding['title'] ?? ''),
						freesiem_sentinel_safe_string($finding['category'] ?? ''),
						freesiem_sentinel_safe_string($finding['description'] ?? ''),
						freesiem_sentinel_safe_string($finding['recommendation'] ?? ''),
						freesiem_sentinel_safe_string($finding['finding_key'] ?? ''),
						freesiem_sentinel_safe_string($finding['evidence']['path'] ?? ''),
						freesiem_sentinel_safe_json_pretty($finding['evidence'] ?? []),
					]
				)
			);

			return str_contains($haystack, $search);
		}));
	}

	private function build_finding_reference(array $finding, int $index): string
	{
		$seed = implode('|', [
			(string) $index,
			freesiem_sentinel_safe_string($finding['finding_key'] ?? ''),
			freesiem_sentinel_safe_string($finding['detected_at'] ?? ''),
			freesiem_sentinel_safe_string($finding['title'] ?? ''),
		]);

		return substr(sha1($seed), 0, 16);
	}

	private function find_finding_by_reference(array $findings, string $reference): ?array
	{
		foreach (array_values($findings) as $index => $finding) {
			if (!is_array($finding)) {
				continue;
			}

			if ($this->build_finding_reference($finding, $index) === $reference) {
				$finding['_reference'] = $reference;
				$finding['_index'] = $index;
				return $finding;
			}
		}

		return null;
	}

	private function render_finding_detail_page(array $finding): void
	{
		$back_url = add_query_arg(['page' => 'freesiem-sentinel-results'], admin_url('admin.php'));
		$severity = freesiem_sentinel_normalize_severity((string) ($finding['severity'] ?? 'info'));
		$evidence = freesiem_sentinel_safe_array($finding['evidence'] ?? []);
		$path = freesiem_sentinel_safe_string($evidence['path'] ?? '');

		echo '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;">';
		echo '<a class="button button-secondary" href="' . esc_url($back_url) . '">' . esc_html__('Back to Results', 'freesiem-sentinel') . '</a>';
		echo '<a class="button button-primary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_run_local_scan')) . '">' . esc_html__('Run Local Scan Again', 'freesiem-sentinel') . '</a>';
		echo '</div>';

		echo '<div style="background:#fff;padding:24px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<p><span style="' . esc_attr($this->severity_badge_style($severity)) . '">' . esc_html(strtoupper($severity)) . '</span></p>';
		echo '<h2 style="margin-top:0;">' . esc_html(freesiem_sentinel_safe_string($finding['title'] ?? '')) . '</h2>';
		echo '<p>' . esc_html(freesiem_sentinel_safe_string($finding['description'] ?? '')) . '</p>';
		echo '<table class="form-table" role="presentation">';
		$this->render_detail_row(__('Finding Key', 'freesiem-sentinel'), freesiem_sentinel_safe_string($finding['finding_key'] ?? ''));
		$this->render_detail_row(__('Category', 'freesiem-sentinel'), freesiem_sentinel_safe_string($finding['category'] ?? ''));
		$this->render_detail_row(__('Recommendation', 'freesiem-sentinel'), freesiem_sentinel_safe_string($finding['recommendation'] ?? ''));
		$this->render_detail_row(__('Detected At', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) ($finding['detected_at'] ?? '')));
		$this->render_detail_row(__('Score', 'freesiem-sentinel'), freesiem_sentinel_safe_string($finding['score'] ?? ''));
		$this->render_detail_row(__('Source', 'freesiem-sentinel'), $this->derive_finding_source($finding));
		if ($path !== '') {
			$this->render_detail_row(__('Path', 'freesiem-sentinel'), $path);
		}
		if (!empty($evidence['previous_hash']) || !empty($evidence['current_hash'])) {
			$this->render_detail_row(__('Previous Hash', 'freesiem-sentinel'), freesiem_sentinel_safe_string($evidence['previous_hash'] ?? ''));
			$this->render_detail_row(__('Current Hash', 'freesiem-sentinel'), freesiem_sentinel_safe_string($evidence['current_hash'] ?? ''));
		}
		if (!empty($evidence['previous_modified_time']) || !empty($evidence['current_modified_time'])) {
			$this->render_detail_row(__('Previous Modified Time', 'freesiem-sentinel'), freesiem_sentinel_safe_string($evidence['previous_modified_time'] ?? ''));
			$this->render_detail_row(__('Current Modified Time', 'freesiem-sentinel'), freesiem_sentinel_safe_string($evidence['current_modified_time'] ?? ''));
		}
		echo '</table>';
		echo '<h3>' . esc_html__('Evidence', 'freesiem-sentinel') . '</h3>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html(freesiem_sentinel_safe_json_pretty($evidence)) . '</pre>';
		echo '</div>';
	}

	private function render_detail_row(string $label, string $value): void
	{
		echo '<tr><th scope="row">' . esc_html(freesiem_sentinel_safe_string($label)) . '</th><td>' . esc_html(freesiem_sentinel_safe_string($value)) . '</td></tr>';
	}

	private function derive_finding_source(array $finding): string
	{
		$category = freesiem_sentinel_safe_string($finding['category'] ?? '');

		return match ($category) {
			'filesystem' => 'filesystem',
			'file_integrity' => 'file_integrity',
			default => 'local',
		};
	}

	private function severity_badge_style(string $severity): string
	{
		$severity = freesiem_sentinel_normalize_severity($severity);
		$palette = match ($severity) {
			'critical' => 'background:#8b1e1e;color:#fff;border:1px solid #6b0b0b;',
			'high' => 'background:#b42318;color:#fff;border:1px solid #912018;',
			'medium' => 'background:#f79009;color:#111;border:1px solid #d97706;',
			'low' => 'background:#dbeafe;color:#1d4ed8;border:1px solid #93c5fd;',
			default => 'background:#f3f4f6;color:#374151;border:1px solid #d1d5db;',
		};

		return 'display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;font-weight:700;text-decoration:none;' . $palette;
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
