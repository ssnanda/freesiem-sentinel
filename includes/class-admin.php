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
		add_action('admin_post_freesiem_sentinel_run_configured_scan', [$this, 'handle_run_configured_scan']);
		add_action('admin_post_freesiem_sentinel_request_remote_scan', [$this, 'handle_request_remote_scan']);
		add_action('admin_post_freesiem_sentinel_sync_results', [$this, 'handle_sync_results']);
		add_action('admin_post_freesiem_sentinel_reconnect', [$this, 'handle_reconnect']);
		add_action('admin_post_freesiem_sentinel_test_connection', [$this, 'handle_test_connection']);
	}

	public function register_menu(): void
	{
		add_menu_page(
			__('freeSIEM', 'freesiem-sentinel'),
			__('freeSIEM', 'freesiem-sentinel'),
			'manage_options',
			'freesiem-dashboard',
			[$this, 'render_dashboard_page'],
			'dashicons-shield-alt'
		);

		add_submenu_page('freesiem-dashboard', __('Dashboard', 'freesiem-sentinel'), __('Dashboard', 'freesiem-sentinel'), 'manage_options', 'freesiem-dashboard', [$this, 'render_dashboard_page']);
		add_submenu_page('freesiem-dashboard', __('Local Scan', 'freesiem-sentinel'), __('Local Scan', 'freesiem-sentinel'), 'manage_options', 'freesiem-local-scan', [$this, 'render_local_scan_page']);
		add_submenu_page('freesiem-dashboard', __('Remote & Agent', 'freesiem-sentinel'), __('Remote & Agent', 'freesiem-sentinel'), 'manage_options', 'freesiem-remote', [$this, 'render_remote_page']);
		add_submenu_page('freesiem-dashboard', __('Results', 'freesiem-sentinel'), __('Results', 'freesiem-sentinel'), 'manage_options', 'freesiem-results', [$this, 'render_results_page']);
		add_submenu_page('freesiem-dashboard', __('About', 'freesiem-sentinel'), __('About', 'freesiem-sentinel'), 'manage_options', 'freesiem-about', [$this, 'render_about_page']);
	}

	public function handle_save_settings(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$current = freesiem_sentinel_get_settings();
		$email = isset($_POST['email']) ? sanitize_email(wp_unslash((string) $_POST['email'])) : '';
		$backend_url_raw = isset($_POST['backend_url']) ? wp_unslash((string) $_POST['backend_url']) : '';
		$backend_url = trim($backend_url_raw) === ''
			? freesiem_sentinel_safe_string($current['backend_url'] ?? FREESIEM_SENTINEL_BACKEND_URL)
			: freesiem_sentinel_sanitize_backend_url($backend_url_raw);

		$settings = freesiem_sentinel_update_settings([
			'email' => $email,
			'backend_url' => $backend_url,
		]);

		if ($email === '') {
			freesiem_sentinel_set_notice('error', __('Email is required to register this site with freeSIEM Core.', 'freesiem-sentinel'));
			$this->redirect_to_page('freesiem-remote');
		}

		$result = $this->plugin->register_site($settings['email']);

		if (is_wp_error($result)) {
			freesiem_sentinel_set_notice('error', $result->get_error_message());
			$this->redirect_to_page('freesiem-remote');
		}

		freesiem_sentinel_set_notice('success', __('Site registration completed successfully.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_run_configured_scan(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$options = $this->sanitize_scan_preferences($_POST);
		freesiem_sentinel_update_settings(['scan_preferences' => $options]);

		$result = $this->plugin->run_local_scan_with_options(true, $options);
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Local scan completed with the selected options.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-local-scan');
	}

	public function handle_request_remote_scan(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->request_remote_scan();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Remote scan request sent.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_sync_results(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->sync_results();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Results synced from freeSIEM Core.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-results');
	}

	public function handle_reconnect(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->reconnect();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Site reconnected successfully.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_test_connection(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->test_connection();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Connection test completed successfully.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function render_dashboard_page(): void
	{
		$settings = freesiem_sentinel_get_settings();
		$cache = $this->plugin->get_results()->get_cache();
		$summary = freesiem_sentinel_safe_array($cache['summary'] ?? []);
		$severity_counts = freesiem_sentinel_safe_array($cache['severity_counts'] ?? []);
		$connection_ok = !empty($settings['site_id']) && !empty($settings['api_key']) && !empty($settings['hmac_secret']);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Dashboard', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Overview of your freeSIEM agent posture and the latest synchronized results.', 'freesiem-sentinel') . '</p>';
		$this->render_card_grid_start();
		$this->render_stat_card(__('Connection', 'freesiem-sentinel'), $connection_ok ? __('Connected to freeSIEM Core', 'freesiem-sentinel') : __('Not Connected', 'freesiem-sentinel'), __('Registration', 'freesiem-sentinel'), strtoupper(freesiem_sentinel_safe_string($settings['registration_status'] ?? '')));
		$this->render_stat_card(__('Site ID', 'freesiem-sentinel'), freesiem_sentinel_safe_string($settings['site_id'] ?? 'Pending') ?: 'Pending', __('Last Heartbeat', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) ($settings['last_heartbeat_at'] ?? '')));
		$this->render_stat_card(__('Last Local Scan', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) ($settings['last_local_scan_at'] ?? '')), __('Last Remote Scan', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) ($settings['last_remote_scan_at'] ?? '')));
		$this->render_stat_card(__('Scores', 'freesiem-sentinel'), freesiem_sentinel_safe_string($summary['overall_score'] ?? ($summary['local_score'] ?? 'N/A')), __('Local / Remote', 'freesiem-sentinel'), freesiem_sentinel_safe_string($summary['local_score'] ?? 'N/A') . ' / ' . freesiem_sentinel_safe_string($summary['remote_score'] ?? 'N/A'));
		echo '</div>';

		echo '<div style="display:grid;grid-template-columns:2fr 1fr;gap:20px;margin-top:20px;">';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Current Posture', 'freesiem-sentinel') . '</h2>';
		$this->render_score_badges($summary, $severity_counts);
		$this->render_severity_counts($severity_counts);
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Actions', 'freesiem-sentinel') . '</h2>';
		echo '<p><a class="button button-primary" href="' . esc_url(freesiem_sentinel_admin_page_url('freesiem-local-scan')) . '">' . esc_html__('Run Local Scan', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_page_url('freesiem-remote')) . '">' . esc_html__('Remote Scan & Agent Setup', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_page_url('freesiem-results')) . '">' . esc_html__('View Results', 'freesiem-sentinel') . '</a></p>';
		echo '</div>';
		echo '</div>';
		echo '</div>';
	}

	public function render_local_scan_page(): void
	{
		$settings = freesiem_sentinel_get_settings();
		$prefs = freesiem_sentinel_safe_array($settings['scan_preferences'] ?? []);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Local Scan', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Choose what the next local scan should inspect before you run it.', 'freesiem-sentinel') . '</p>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;max-width:900px;">';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_run_configured_scan" />';
		echo '<table class="form-table" role="presentation">';
		echo '<tr><th scope="row">' . esc_html__('Scan Modules', 'freesiem-sentinel') . '</th><td>';
		echo '<label style="display:block;margin-bottom:8px;"><input type="checkbox" name="scan_wordpress" value="1"' . checked(!empty($prefs['scan_wordpress']), true, false) . ' /> ' . esc_html__('WordPress Configuration Scan', 'freesiem-sentinel') . '</label>';
		echo '<label style="display:block;margin-bottom:8px;"><input type="checkbox" name="scan_filesystem" value="1"' . checked(!empty($prefs['scan_filesystem']), true, false) . ' /> ' . esc_html__('Filesystem Scan', 'freesiem-sentinel') . '</label>';
		echo '<label style="display:block;"><input type="checkbox" name="scan_fim" value="1"' . checked(!empty($prefs['scan_fim']), true, false) . ' /> ' . esc_html__('File Integrity Monitoring', 'freesiem-sentinel') . '</label>';
		echo '</td></tr>';
		echo '<tr><th scope="row">' . esc_html__('Advanced Options', 'freesiem-sentinel') . '</th><td>';
		echo '<p><label>' . esc_html__('Max files', 'freesiem-sentinel') . ' <input type="number" min="100" max="5000" step="100" name="max_files" value="' . esc_attr(freesiem_sentinel_safe_string($prefs['max_files'] ?? '1000')) . '" /></label></p>';
		echo '<p><label>' . esc_html__('Depth limit', 'freesiem-sentinel') . ' <input type="number" min="1" max="10" step="1" name="max_depth" value="' . esc_attr(freesiem_sentinel_safe_string($prefs['max_depth'] ?? '5')) . '" /></label></p>';
		echo '<p><label><input type="checkbox" name="include_uploads" value="1"' . checked(!empty($prefs['include_uploads']), true, false) . ' /> ' . esc_html__('Include uploads in heuristic filesystem scanning', 'freesiem-sentinel') . '</label></p>';
		echo '</td></tr>';
		echo '</table>';
		submit_button(__('Run Local Scan', 'freesiem-sentinel'));
		echo '</form>';
		echo '</div>';
		echo '</div>';
	}

	public function render_remote_page(): void
	{
		$settings = freesiem_sentinel_get_settings();
		$connection_ok = !empty($settings['site_id']) && !empty($settings['api_key']) && !empty($settings['hmac_secret']);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Remote & Agent', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Manage agent registration, remote actions, and connectivity without exposing internal endpoint details.', 'freesiem-sentinel') . '</p>';
		echo '<div style="display:grid;grid-template-columns:2fr 1fr;gap:20px;">';
		echo '<div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Agent Setup', 'freesiem-sentinel') . '</h2>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_save_settings" />';
		echo '<table class="form-table" role="presentation">';
		echo '<tr><th scope="row"><label for="freesiem-remote-email">' . esc_html__('Email', 'freesiem-sentinel') . '</label></th><td><input class="regular-text" id="freesiem-remote-email" name="email" type="email" value="' . esc_attr(freesiem_sentinel_safe_string($settings['email'] ?? '')) . '" required /></td></tr>';
		echo '</table>';
		echo '<details><summary>' . esc_html__('Advanced connection settings', 'freesiem-sentinel') . '</summary>';
		echo '<p style="margin-top:12px;">' . esc_html__('The freeSIEM Core endpoint is configured internally. To override it, enter a replacement value here.', 'freesiem-sentinel') . '</p>';
		echo '<p><input class="regular-text code" name="backend_url" type="password" value="" placeholder="' . esc_attr__('Stored internally', 'freesiem-sentinel') . '" autocomplete="off" /></p>';
		echo '</details>';
		submit_button(__('Register / Save', 'freesiem-sentinel'));
		echo '</form>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Remote Actions', 'freesiem-sentinel') . '</h2>';
		echo '<p><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_request_remote_scan')) . '">' . esc_html__('Request Remote Scan', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_sync_results')) . '">' . esc_html__('Sync Results', 'freesiem-sentinel') . '</a></p>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Connection Actions', 'freesiem-sentinel') . '</h2>';
		echo '<p><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_reconnect')) . '">' . esc_html__('Reconnect', 'freesiem-sentinel') . '</a></p>';
		echo '<p><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_test_connection')) . '">' . esc_html__('Test Connection', 'freesiem-sentinel') . '</a></p>';
		echo '</div>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Status', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('Connection:', 'freesiem-sentinel') . '</strong> ' . esc_html($connection_ok ? __('Connected to freeSIEM Core', 'freesiem-sentinel') : __('Not Connected', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Site ID:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_safe_string($settings['site_id'] ?? 'Pending') ?: 'Pending') . '</p>';
		echo '<p><strong>' . esc_html__('Registration status:', 'freesiem-sentinel') . '</strong> ' . esc_html(strtoupper(freesiem_sentinel_safe_string($settings['registration_status'] ?? ''))) . '</p>';
		echo '<p><strong>' . esc_html__('Plan:', 'freesiem-sentinel') . '</strong> ' . esc_html(ucfirst($this->plugin->get_plan())) . '</p>';
		echo '</div>';
		echo '</div>';
		echo '</div>';
	}

	public function render_results_page(): void
	{
		$settings = freesiem_sentinel_get_settings();
		$cache = $this->plugin->get_results()->get_cache();
		$summary = freesiem_sentinel_safe_array($cache['summary'] ?? []);
		$all_findings = array_values(freesiem_sentinel_safe_array($cache['local_findings'] ?? []));
		$recommendations = array_values(array_filter(freesiem_sentinel_safe_array($cache['recommendations'] ?? [])));
		$top_issues = freesiem_sentinel_safe_array($cache['top_issues'] ?? []);
		$filesystem = freesiem_sentinel_safe_array($cache['local_inventory']['filesystem'] ?? []);
		$integrity = freesiem_sentinel_safe_array($cache['local_inventory']['file_integrity'] ?? []);
		$severity_counts = freesiem_sentinel_safe_array($cache['severity_counts'] ?? []);
		$fim_diff_cache = freesiem_sentinel_safe_array($settings['fim_diff_cache'] ?? []);
		$integrity_changes = array_values(array_filter(freesiem_sentinel_safe_array($fim_diff_cache['changes'] ?? []), 'is_array'));
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
		if ($integrity !== []) {
			echo '<p><strong>' . esc_html__('Integrity monitor:', 'freesiem-sentinel') . '</strong> ' . esc_html(sprintf(__('Hashed %1$s files, new %2$s, modified %3$s, deleted %4$s, partial %5$s', 'freesiem-sentinel'), freesiem_sentinel_safe_string($integrity['hashed_files'] ?? '0'), freesiem_sentinel_safe_string($integrity['new_files_count'] ?? '0'), freesiem_sentinel_safe_string($integrity['modified_files_count'] ?? '0'), freesiem_sentinel_safe_string($integrity['deleted_files_count'] ?? '0'), !empty($integrity['partial']) ? __('yes', 'freesiem-sentinel') : __('no', 'freesiem-sentinel'))) . '</p>';
		}
		echo '</div>';

		echo '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap;">';
		echo '<a class="button button-primary" href="' . esc_url(freesiem_sentinel_admin_page_url('freesiem-local-scan')) . '">' . esc_html__('Run Local Scan Again', 'freesiem-sentinel') . '</a>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<form method="get" action="' . esc_url(admin_url('admin.php')) . '" style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;">';
		echo '<input type="hidden" name="page" value="freesiem-results" />';
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

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Recent Integrity Changes', 'freesiem-sentinel') . '</h2>';
		if ($integrity === []) {
			$this->render_empty_state(__('Integrity monitor unavailable on current plan', 'freesiem-sentinel'), __('Upgrade the plan to Pro to enable file integrity monitoring and change tracking.', 'freesiem-sentinel'));
		} elseif ($integrity_changes === []) {
			$this->render_empty_state(__('No integrity changes in the latest diff', 'freesiem-sentinel'), __('The latest integrity comparison did not detect any new, modified, or deleted monitored files.', 'freesiem-sentinel'));
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Change', 'freesiem-sentinel') . '</th><th>' . esc_html__('Path', 'freesiem-sentinel') . '</th><th>' . esc_html__('Modified', 'freesiem-sentinel') . '</th><th>' . esc_html__('Hash', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
			foreach ($integrity_changes as $change) {
				$change_type = freesiem_sentinel_safe_string($change['change_type'] ?? 'modified');
				$path = freesiem_sentinel_safe_string($change['path'] ?? '');
				$current_hash = freesiem_sentinel_safe_string($change['current_hash'] ?? '');
				$previous_hash = freesiem_sentinel_safe_string($change['previous_hash'] ?? '');
				echo '<tr>';
				echo '<td><span style="' . esc_attr($this->change_badge_style($change_type)) . '">' . esc_html(strtoupper($change_type)) . '</span></td>';
				echo '<td><code>' . esc_html($path) . '</code></td>';
				echo '<td>' . esc_html(freesiem_sentinel_safe_string($change['current_modified_time'] ?? $change['previous_modified_time'] ?? '')) . '</td>';
				echo '<td><code>' . esc_html($current_hash !== '' ? substr($current_hash, 0, 16) : substr($previous_hash, 0, 16)) . '</code></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
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
						'page' => 'freesiem-results',
						'finding' => $reference,
					],
					admin_url('admin.php')
				);

				echo '<tr>';
				echo '<td><a href="' . esc_url((string) $detail_url) . '" style="' . esc_attr($this->severity_badge_style((string) ($finding['severity'] ?? 'info'))) . '">' . esc_html(strtoupper(freesiem_sentinel_safe_string($finding['severity'] ?? 'info'))) . '</a></td>';
				echo '<td><a href="' . esc_url((string) $detail_url) . '" style="display:block;color:inherit;text-decoration:none;"><strong>' . esc_html(freesiem_sentinel_safe_string($finding['title'] ?? '')) . '</strong><br /><span>' . esc_html(freesiem_sentinel_safe_string($finding['description'] ?? '')) . '</span></a></td>';
				echo '<td><a href="' . esc_url((string) $detail_url) . '" style="display:block;color:inherit;text-decoration:none;">' . esc_html(freesiem_sentinel_safe_string($finding['category'] ?? '')) . '</a></td>';
				echo '<td><a href="' . esc_url((string) $detail_url) . '" style="display:block;color:inherit;text-decoration:none;">' . esc_html(freesiem_sentinel_safe_string($finding['recommendation'] ?? '')) . '</a></td>';
				echo '<td><a href="' . esc_url((string) $detail_url) . '" style="display:block;color:inherit;text-decoration:none;">' . esc_html(freesiem_sentinel_format_datetime((string) ($finding['detected_at'] ?? ''))) . '</a></td>';
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
		$release_body = trim(safe($release['body'] ?? ''));
		$release_available = !empty($release['available']);
		$release_version = safe($release['version'] ?? '');

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('About freeSIEM Sentinel', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Release, plan, and agent identity details for this WordPress deployment.', 'freesiem-sentinel') . '</p>';
		$this->render_card_grid_start();
		$this->render_stat_card(__('Plugin Version', 'freesiem-sentinel'), FREESIEM_SENTINEL_VERSION, __('Latest Release', 'freesiem-sentinel'), $release_available ? $release_version : __('No releases available', 'freesiem-sentinel'));
		$this->render_stat_card(__('Connected To', 'freesiem-sentinel'), __('freeSIEM Core', 'freesiem-sentinel'), __('Registration', 'freesiem-sentinel'), strtoupper(freesiem_sentinel_safe_string($settings['registration_status'] ?? '')));
		$this->render_stat_card(__('Site ID', 'freesiem-sentinel'), freesiem_sentinel_safe_string($settings['site_id'] ?? 'Pending') ?: 'Pending', __('Plan', 'freesiem-sentinel'), ucfirst($this->plugin->get_plan()));
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-top:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Credentials', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('API Key:', 'freesiem-sentinel') . '</strong> <code>' . esc_html(freesiem_sentinel_mask_secret((string) ($settings['api_key'] ?? ''))) . '</code></p>';
		echo '<p><strong>' . esc_html__('HMAC Secret:', 'freesiem-sentinel') . '</strong> <code>' . esc_html(freesiem_sentinel_mask_secret((string) ($settings['hmac_secret'] ?? ''))) . '</code></p>';
		echo '<p><strong>' . esc_html__('Check for Updates:', 'freesiem-sentinel') . '</strong> <a class="button button-secondary" href="' . esc_url(freesiem_sentinel_safe_string($this->plugin->get_updater()->get_check_updates_url(freesiem_sentinel_admin_page_url('freesiem-about')))) . '">' . esc_html__('Check for Updates', 'freesiem-sentinel') . '</a></p>';
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
		if (!$release_available) {
			$this->render_empty_state(__('No releases available', 'freesiem-sentinel'), __('Create a GitHub release and attach freesiem-sentinel.zip to enable packaged updates.', 'freesiem-sentinel'));
		} elseif ($release_body === '') {
			$this->render_empty_state(__('No release notes available', 'freesiem-sentinel'), __('The latest GitHub release did not include a changelog body.', 'freesiem-sentinel'));
		} else {
			echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html($release_body) . '</pre>';
		}
		echo '</div>';
		echo '</div>';
	}

	private function sanitize_scan_preferences(array $input): array
	{
		$settings = freesiem_sentinel_get_settings();
		$current = freesiem_sentinel_safe_array($settings['scan_preferences'] ?? []);

		return [
			'scan_wordpress' => empty($input['scan_wordpress']) ? 0 : 1,
			'scan_filesystem' => empty($input['scan_filesystem']) ? 0 : 1,
			'scan_fim' => Freesiem_Features::is_enabled('fim') && !empty($input['scan_fim']) ? 1 : 0,
			'include_uploads' => empty($input['include_uploads']) ? 0 : 1,
			'max_files' => max(100, min(5000, (int) ($input['max_files'] ?? ($current['max_files'] ?? 1000)))),
			'max_depth' => max(1, min(10, (int) ($input['max_depth'] ?? ($current['max_depth'] ?? 5)))),
		];
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

	private function render_empty_state(string $title, string $description): void
	{
		echo '<div style="padding:12px 14px;border:1px dashed #c3c4c7;border-radius:8px;background:#f9f9f9;">';
		echo '<p style="margin:0 0 6px;font-weight:600;">' . esc_html(freesiem_sentinel_safe_string($title)) . '</p>';
		echo '<p style="margin:0;color:#50575e;">' . esc_html(freesiem_sentinel_safe_string($description)) . '</p>';
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
		$search = strtolower((string) $search);

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

			$haystack = strtolower(implode(' ', [
				freesiem_sentinel_safe_string($finding['title'] ?? ''),
				freesiem_sentinel_safe_string($finding['category'] ?? ''),
				freesiem_sentinel_safe_string($finding['description'] ?? ''),
				freesiem_sentinel_safe_string($finding['recommendation'] ?? ''),
				freesiem_sentinel_safe_string($finding['finding_key'] ?? ''),
				freesiem_sentinel_safe_string($finding['evidence']['path'] ?? ''),
				freesiem_sentinel_safe_json_pretty($finding['evidence'] ?? []),
			]));

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
				return $finding;
			}
		}

		return null;
	}

	private function render_finding_detail_page(array $finding): void
	{
		$back_url = freesiem_sentinel_admin_page_url('freesiem-results');
		$severity = freesiem_sentinel_normalize_severity((string) ($finding['severity'] ?? 'info'));
		$evidence = freesiem_sentinel_safe_array($finding['evidence'] ?? []);
		$path = freesiem_sentinel_safe_string($evidence['path'] ?? '');

		echo '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;">';
		echo '<a class="button button-secondary" href="' . esc_url((string) $back_url) . '">' . esc_html__('Back to Results', 'freesiem-sentinel') . '</a>';
		echo '<a class="button button-primary" href="' . esc_url(freesiem_sentinel_admin_page_url('freesiem-local-scan')) . '">' . esc_html__('Run Local Scan Again', 'freesiem-sentinel') . '</a>';
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
		if (!empty($evidence['change_type'])) {
			$this->render_detail_row(__('Change Type', 'freesiem-sentinel'), strtoupper(freesiem_sentinel_safe_string($evidence['change_type'] ?? '')));
		}
		if (array_key_exists('previous_size', $evidence) || array_key_exists('current_size', $evidence)) {
			$this->render_detail_row(__('Previous Size', 'freesiem-sentinel'), freesiem_sentinel_safe_string($evidence['previous_size'] ?? ''));
			$this->render_detail_row(__('Current Size', 'freesiem-sentinel'), freesiem_sentinel_safe_string($evidence['current_size'] ?? ''));
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

	private function change_badge_style(string $change_type): string
	{
		$palette = match (strtolower((string) $change_type)) {
			'new' => 'background:#8b1e1e;color:#fff;border:1px solid #6b0b0b;',
			'deleted' => 'background:#b42318;color:#fff;border:1px solid #912018;',
			default => 'background:#f79009;color:#111;border:1px solid #d97706;',
		};

		return 'display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;font-weight:700;text-decoration:none;' . $palette;
	}

	private function assert_manage_permissions(): void
	{
		if (!freesiem_sentinel_current_user_can_manage()) {
			wp_die(esc_html__('You are not allowed to manage freeSIEM Sentinel.', 'freesiem-sentinel'));
		}
	}

	private function redirect_to_page(string $page): void
	{
		wp_safe_redirect(freesiem_sentinel_admin_page_url($page));
		exit;
	}
}
