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
		add_action('admin_post_freesiem_sentinel_save_cloud_connect_backend', [$this, 'handle_save_cloud_connect_backend']);
		add_action('admin_post_freesiem_sentinel_cloud_connect_start', [$this, 'handle_cloud_connect_start']);
		add_action('admin_post_freesiem_sentinel_cloud_connect_verify', [$this, 'handle_cloud_connect_verify']);
		add_action('admin_post_freesiem_sentinel_cloud_connect_reset', [$this, 'handle_cloud_connect_reset']);
		add_action('admin_post_freesiem_sentinel_cloud_connect_disconnect', [$this, 'handle_cloud_connect_disconnect']);
		add_action('admin_post_freesiem_sentinel_cloud_connect_test', [$this, 'handle_cloud_connect_test']);
		add_action('admin_post_freesiem_sentinel_save_settings', [$this, 'handle_save_settings']);
		add_action('admin_post_freesiem_sentinel_run_configured_scan', [$this, 'handle_run_configured_scan']);
		add_action('admin_post_freesiem_sentinel_clear_results', [$this, 'handle_clear_results']);
		add_action('admin_post_freesiem_sentinel_start_cloud_connect', [$this, 'handle_start_cloud_connect']);
		add_action('admin_post_freesiem_sentinel_verify_cloud_connect', [$this, 'handle_verify_cloud_connect']);
		add_action('admin_post_freesiem_sentinel_save_cloud_preferences', [$this, 'handle_save_cloud_preferences']);
		add_action('admin_post_freesiem_sentinel_add_cloud_user', [$this, 'handle_add_cloud_user']);
		add_action('admin_post_freesiem_sentinel_delete_cloud_user', [$this, 'handle_delete_cloud_user']);
		add_action('admin_post_freesiem_sentinel_request_remote_scan', [$this, 'handle_request_remote_scan']);
		add_action('admin_post_freesiem_sentinel_sync_results', [$this, 'handle_sync_results']);
		add_action('admin_post_freesiem_sentinel_reconnect', [$this, 'handle_reconnect']);
		add_action('admin_post_freesiem_sentinel_disconnect_cloud', [$this, 'handle_disconnect_cloud']);
		add_action('admin_post_freesiem_sentinel_test_connection', [$this, 'handle_test_connection']);
	}

	public function register_menu(): void
	{
		add_menu_page(
			__('freeSIEM', 'freesiem-sentinel'),
			__('freeSIEM', 'freesiem-sentinel'),
			'manage_options',
			'freesiem-portal',
			[$this, 'render_dashboard_page'],
			'dashicons-shield-alt'
		);

		add_submenu_page('freesiem-portal', __('Scan', 'freesiem-sentinel'), __('Scan', 'freesiem-sentinel'), 'manage_options', 'freesiem-scan', [$this, 'render_scan_page']);
		add_submenu_page('freesiem-portal', __('Cloud', 'freesiem-sentinel'), __('Cloud', 'freesiem-sentinel'), 'manage_options', 'freesiem-remote', [$this, 'render_remote_page']);
		add_submenu_page('freesiem-portal', __('About', 'freesiem-sentinel'), __('About', 'freesiem-sentinel'), 'manage_options', 'freesiem-about', [$this, 'render_about_page']);
	}

	public function handle_save_cloud_connect_backend(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$raw_value = isset($_POST['cloud_backend_base_url']) ? wp_unslash((string) $_POST['cloud_backend_base_url']) : '';
		$sanitized = freesiem_sentinel_sanitize_cloud_backend_base_url($raw_value);

		if (trim($raw_value) !== '' && $sanitized === '') {
			freesiem_sentinel_set_notice('error', __('Enter a valid HTTPS Cloud backend URL or leave the field blank for production.', 'freesiem-sentinel'));
			$this->redirect_to_page('freesiem-remote');
		}

		freesiem_sentinel_update_settings([
			'cloud_backend_base_url' => $sanitized,
		]);

		freesiem_sentinel_set_notice('success', $sanitized === ''
			? __('Cloud backend reset to production.', 'freesiem-sentinel')
			: __('Cloud backend updated for testing.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_cloud_connect_start(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$email = isset($_POST['email']) ? sanitize_email(wp_unslash((string) $_POST['email'])) : '';
		$phone = isset($_POST['phone']) ? freesiem_sentinel_sanitize_phone_number(wp_unslash((string) $_POST['phone'])) : '';

		if (!is_email($email)) {
			freesiem_sentinel_set_notice('error', __('Enter a valid email address to continue.', 'freesiem-sentinel'));
			$this->redirect_to_page('freesiem-remote');
		}

		if ($phone === '') {
			freesiem_sentinel_set_notice('error', __('Enter a valid US phone number to continue.', 'freesiem-sentinel'));
			$this->redirect_to_page('freesiem-remote');
		}

		$result = $this->plugin->start_cloud_connect($email, $phone);

		if (is_wp_error($result)) {
			freesiem_sentinel_set_notice('error', $result->get_error_message());
			$this->redirect_to_page('freesiem-remote');
		}

		freesiem_sentinel_set_notice('success', __('Verification code sent. Enter it below to finish connecting this site.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_cloud_connect_verify(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$code = isset($_POST['verification_code']) ? preg_replace('/\D+/', '', wp_unslash((string) $_POST['verification_code'])) : '';
		$code = is_string($code) ? $code : '';

		if ($code === '') {
			freesiem_sentinel_set_notice('error', __('Enter the verification code to continue.', 'freesiem-sentinel'));
			$this->redirect_to_page('freesiem-remote');
		}

		$result = $this->plugin->verify_cloud_connect($code);

		if (is_wp_error($result)) {
			freesiem_sentinel_set_notice('error', $result->get_error_message());
			$this->redirect_to_page('freesiem-remote');
		}

		freesiem_sentinel_set_notice('success', __('freeSIEM Cloud Connect is now active for this site.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_cloud_connect_reset(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		Freesiem_Cloud_Connect_State::reset_pending();
		freesiem_sentinel_set_notice('success', __('Pending verification was canceled and the local connect state was reset.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_cloud_connect_test(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$result = $this->plugin->heartbeat_cloud_connect();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Connection test completed successfully.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_cloud_connect_disconnect(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$result = $this->plugin->disconnect_cloud_connect();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Disconnected from freeSIEM Cloud Connect.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
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
		$is_error = is_wp_error($result) || !empty($result['status']);
		$message = is_wp_error($result) ? $result->get_error_message() : safe($result['message'] ?? __('Scan completed.', 'freesiem-sentinel'));
		freesiem_sentinel_set_notice($is_error ? 'error' : 'success', $message);
		$this->redirect_to_page('freesiem-scan', ['show_results' => '1']);
	}

	public function handle_request_remote_scan(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->request_remote_scan();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Remote scan request sent.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_clear_results(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$this->plugin->clear_scan_results();
		freesiem_sentinel_set_notice('success', __('Stored scan results were cleared.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-scan');
	}

	public function handle_start_cloud_connect(): void
	{
		$_POST['phone'] = $_POST['phone_number'] ?? '';
		$this->handle_cloud_connect_start();
	}

	public function handle_verify_cloud_connect(): void
	{
		$_POST['verification_code'] = $_POST['confirmation_code'] ?? '';
		$this->handle_cloud_connect_verify();
	}

	public function handle_save_cloud_preferences(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		freesiem_sentinel_update_settings([
			'allow_remote_scan' => empty($_POST['allow_remote_scan']) ? 0 : 1,
			'scan_frequency' => isset($_POST['scan_frequency']) ? sanitize_key(wp_unslash((string) $_POST['scan_frequency'])) : 'daily',
			'user_sync_enabled' => empty($_POST['user_sync_enabled']) ? 0 : 1,
		]);

		freesiem_sentinel_set_notice('success', __('Cloud automation preferences were saved.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_add_cloud_user(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$email = isset($_POST['cloud_user_email']) ? sanitize_email(wp_unslash((string) $_POST['cloud_user_email'])) : '';

		if ($email === '') {
			freesiem_sentinel_set_notice('error', __('Enter a valid user email address to add it to Cloud user sync.', 'freesiem-sentinel'));
			$this->redirect_to_page('freesiem-remote');
		}

		$settings = freesiem_sentinel_get_settings();
		$users = array_values(array_unique(array_filter(array_merge(
			freesiem_sentinel_safe_array($settings['cloud_users'] ?? []),
			[$email]
		))));

		freesiem_sentinel_update_settings(['cloud_users' => $users]);
		freesiem_sentinel_set_notice('success', __('Cloud user added.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_delete_cloud_user(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$email = isset($_GET['email']) ? sanitize_email(wp_unslash((string) $_GET['email'])) : '';
		$settings = freesiem_sentinel_get_settings();
		$users = array_values(array_filter(
			freesiem_sentinel_safe_array($settings['cloud_users'] ?? []),
			static fn(string $user_email): bool => $user_email !== $email
		));

		freesiem_sentinel_update_settings(['cloud_users' => $users]);
		freesiem_sentinel_set_notice('success', __('Cloud user removed.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_sync_results(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->sync_results();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Results synced from freeSIEM Core.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-scan', ['show_results' => '1']);
	}

	public function handle_reconnect(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		$result = $this->plugin->reconnect();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Site reconnected successfully.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_disconnect_cloud(): void
	{
		$this->handle_cloud_connect_disconnect();
	}

	public function handle_test_connection(): void
	{
		$this->handle_cloud_connect_test();
	}

	public function render_dashboard_page(): void
	{
		$settings = freesiem_sentinel_get_settings();
		$cache = $this->plugin->get_results()->get_cache();
		$summary = freesiem_sentinel_safe_array($cache['summary'] ?? []);
		$severity_counts = array_merge(
			['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0],
			freesiem_sentinel_safe_array($cache['severity_counts'] ?? [])
		);
		$top_issues = array_values(freesiem_sentinel_safe_array($cache['top_issues'] ?? []));
		$recommendations = array_values(array_filter(freesiem_sentinel_safe_array($cache['recommendations'] ?? [])));
		$inventory = freesiem_sentinel_safe_array($cache['local_inventory'] ?? []);
		$filesystem = freesiem_sentinel_safe_array($inventory['filesystem'] ?? []);
		$connection_ok = !empty($settings['site_id']) && !empty($settings['api_key']) && !empty($settings['hmac_secret']);
		$show_results_url = $this->build_scan_url(['show_results' => '1']) . '#freesiem-results-section';
		$remote_url = freesiem_sentinel_admin_page_url('freesiem-remote');

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Portal', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Your freeSIEM control center for current risk, scan activity, and next actions.', 'freesiem-sentinel') . '</p>';

		echo '<div style="background:linear-gradient(135deg,#09111c,#15253b);padding:22px;border-radius:16px;color:#fff;margin:20px 0 24px;">';
		echo '<h2 style="margin:0 0 10px;color:#fff;">' . esc_html__('Security Risk Overview', 'freesiem-sentinel') . '</h2>';
		echo '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;">';
		foreach ([
			'critical' => ['label' => __('Critical', 'freesiem-sentinel'), 'bg' => '#7f1d1d', 'border' => '#b91c1c', 'text' => '#fff'],
			'high' => ['label' => __('High', 'freesiem-sentinel'), 'bg' => '#9a3412', 'border' => '#ea580c', 'text' => '#fff'],
			'medium' => ['label' => __('Medium', 'freesiem-sentinel'), 'bg' => '#92400e', 'border' => '#f59e0b', 'text' => '#fff7ed'],
			'low' => ['label' => __('Low', 'freesiem-sentinel'), 'bg' => '#1d4ed8', 'border' => '#60a5fa', 'text' => '#eff6ff'],
			'info' => ['label' => __('Info', 'freesiem-sentinel'), 'bg' => '#334155', 'border' => '#94a3b8', 'text' => '#f8fafc'],
		] as $severity => $config) {
			$url = $this->build_scan_url([
				'show_results' => '1',
				'severity' => [$severity],
			]) . '#freesiem-results-section';
			echo '<a href="' . esc_url($url) . '" style="display:block;padding:16px 18px;border-radius:14px;background:' . esc_attr($config['bg']) . ';border:1px solid ' . esc_attr($config['border']) . ';text-decoration:none;color:' . esc_attr($config['text']) . ';">';
			echo '<span style="display:block;font-size:12px;letter-spacing:.08em;text-transform:uppercase;opacity:.85;">' . esc_html($config['label']) . '</span>';
			echo '<strong style="display:block;font-size:30px;line-height:1.1;margin-top:8px;">' . esc_html(safe($severity_counts[$severity] ?? '0')) . '</strong>';
			echo '</a>';
		}
		echo '</div>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:16px;margin-bottom:24px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Quick Actions', 'freesiem-sentinel') . '</h2>';
		echo '<div style="display:flex;gap:12px;flex-wrap:wrap;">';
		echo '<a class="button button-primary" style="padding:10px 18px;" href="' . esc_url(freesiem_sentinel_admin_page_url('freesiem-scan')) . '">' . esc_html__('Run Scan', 'freesiem-sentinel') . '</a>';
		echo '<a class="button button-secondary" style="padding:10px 18px;" href="' . esc_url($show_results_url) . '">' . esc_html__('View Results', 'freesiem-sentinel') . '</a>';
		echo '<a class="button button-secondary" style="padding:10px 18px;" href="' . esc_url($remote_url) . '">' . esc_html__('Cloud', 'freesiem-sentinel') . '</a>';
		echo '</div>';
		echo '</div>';

		echo '<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px;">';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:16px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Top Issues', 'freesiem-sentinel') . '</h2>';
		if ($top_issues === []) {
			$this->render_empty_state(__('No scan has been run yet.', 'freesiem-sentinel'), __('Run a scan to surface the most important issues to review next.', 'freesiem-sentinel'));
		} else {
			echo '<ul style="margin:0;padding-left:18px;">';
			foreach ($top_issues as $index => $issue) {
				if (!is_array($issue)) {
					continue;
				}
				$url = $this->build_scan_url([
					'show_results' => '1',
					'finding' => $this->build_finding_reference($issue, $index),
				]);
				echo '<li style="margin-bottom:10px;"><a href="' . esc_url($url) . '" style="text-decoration:none;"><strong>' . esc_html(freesiem_sentinel_safe_string($issue['title'] ?? '')) . '</strong></a><br /><span>' . esc_html(freesiem_sentinel_safe_string($issue['recommendation'] ?? '')) . '</span></li>';
			}
			echo '</ul>';
		}
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:16px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Recommendations', 'freesiem-sentinel') . '</h2>';
		if ($recommendations === []) {
			$this->render_empty_state(__('No recommendations yet.', 'freesiem-sentinel'), __('Recommendations will appear here after scan or sync data is available.', 'freesiem-sentinel'));
		} else {
			echo '<ul style="margin:0;padding-left:18px;">';
			foreach ($recommendations as $recommendation) {
				echo '<li style="margin-bottom:8px;">' . esc_html(freesiem_sentinel_safe_string($recommendation)) . '</li>';
			}
			echo '</ul>';
		}
		echo '</div>';
		echo '</div>';

		echo '<div style="display:grid;grid-template-columns:1.2fr .8fr;gap:20px;">';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:16px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Last Scan Summary', 'freesiem-sentinel') . '</h2>';
		echo '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;">';
		$this->render_summary_stat(__('Last Scan Time', 'freesiem-sentinel'), $this->summary_value_or_fallback($settings['last_local_scan_at'] ?? '', true));
		$this->render_summary_stat(__('Overall Score', 'freesiem-sentinel'), $this->summary_value_or_fallback($summary['overall_score'] ?? ($summary['local_score'] ?? ''), false));
		$this->render_summary_stat(__('Files Discovered', 'freesiem-sentinel'), $this->summary_value_or_fallback($filesystem['discovered_files'] ?? '', false));
		$this->render_summary_stat(__('Files Analyzed', 'freesiem-sentinel'), $this->summary_value_or_fallback($filesystem['inspected_files'] ?? '', false));
		$this->render_summary_stat(__('Flagged Files', 'freesiem-sentinel'), $this->summary_value_or_fallback($filesystem['flagged_files'] ?? '', false));
		echo '</div>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:16px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Site Status', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('Site ID', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->friendly_site_id($settings['site_id'] ?? '')) . '</p>';
		echo '<p><strong>' . esc_html__('Agent Status', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->agent_status_label($connection_ok)) . '</p>';
		echo '<p><strong>' . esc_html__('Last Heartbeat', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->summary_value_or_fallback($settings['last_heartbeat_at'] ?? '', true)) . '</p>';
		echo '<p><strong>' . esc_html__('Registration State', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->registration_state_label($settings['registration_status'] ?? '')) . '</p>';
		echo '</div>';
		echo '</div>';
		echo '</div>';
	}

	public function render_scan_page(): void
	{
		$settings = freesiem_sentinel_get_settings();
		$prefs = freesiem_sentinel_safe_array($settings['scan_preferences'] ?? []);
		$view = $this->get_scan_results_view();
		$cache = $view['cache'];
		$summary = $view['summary'];
		$filesystem = $view['filesystem'];
		$scan_profile = freesiem_sentinel_safe_array($view['inventory']['scan_profile'] ?? []);
		$scan_metrics = array_merge(
			[
				'files_discovered' => '',
				'files_analyzed' => '',
				'files_flagged' => '',
				'duration_seconds' => '',
				'scan_modules' => [],
			],
			freesiem_sentinel_safe_array($summary),
			freesiem_sentinel_safe_array($view['inventory']['scan_metrics'] ?? [])
		);
		$clear_results_url = freesiem_sentinel_admin_post_url('freesiem_sentinel_clear_results');

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Scan', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Configure a scan, run it, and investigate findings from one workflow.', 'freesiem-sentinel') . '</p>';

		echo '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;align-items:start;margin-bottom:20px;">';
		echo '<div style="background:#fff;padding:18px 20px;border:1px solid #dcdcde;border-radius:16px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Scan Configuration', 'freesiem-sentinel') . '</h2>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_run_configured_scan" />';
		echo '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">';
		echo '<div>';
		echo '<h3 style="margin:0 0 10px;font-size:16px;">' . esc_html__('Scan Modules', 'freesiem-sentinel') . '</h3>';
		echo '<label style="display:block;margin-bottom:8px;font-size:14px;"><input type="checkbox" name="scan_wordpress" value="1"' . checked(!empty($prefs['scan_wordpress']), true, false) . ' /> ' . esc_html__('WordPress Configuration Scan', 'freesiem-sentinel') . '</label>';
		echo '<label style="display:block;margin-bottom:8px;font-size:14px;"><input type="checkbox" name="scan_filesystem" value="1"' . checked(!empty($prefs['scan_filesystem']), true, false) . ' /> ' . esc_html__('Filesystem Scan', 'freesiem-sentinel') . '</label>';
		echo '<label style="display:block;"><input type="checkbox" name="scan_fim" value="1"' . checked(!empty($prefs['scan_fim']), true, false) . ' /> ' . esc_html__('File Integrity Monitoring', 'freesiem-sentinel') . '</label>';
		echo '</div>';
		echo '<div>';
		echo '<h3 style="margin:0 0 10px;font-size:16px;">' . esc_html__('Advanced Options', 'freesiem-sentinel') . '</h3>';
		echo '<p style="margin:0 0 10px;"><label>' . esc_html__('Max files', 'freesiem-sentinel') . '<br /><input type="number" min="100" max="5000" step="100" name="max_files" value="' . esc_attr(freesiem_sentinel_safe_string($prefs['max_files'] ?? '1000')) . '" /></label></p>';
		echo '<p style="margin:0 0 10px;"><label>' . esc_html__('Depth limit', 'freesiem-sentinel') . '<br /><input type="number" min="1" max="10" step="1" name="max_depth" value="' . esc_attr(freesiem_sentinel_safe_string($prefs['max_depth'] ?? '5')) . '" /></label></p>';
		echo '<p style="margin:0;"><label><input type="checkbox" name="include_uploads" value="1"' . checked(!empty($prefs['include_uploads']), true, false) . ' /> ' . esc_html__('Include uploads', 'freesiem-sentinel') . '</label></p>';
		echo '</div>';
		echo '</div>';
		echo '<p style="margin:16px 0 0;display:flex;gap:10px;flex-wrap:wrap;">';
		echo '<button type="submit" class="button button-primary">' . esc_html__('Run Scan', 'freesiem-sentinel') . '</button>';
		echo '<a class="button button-secondary" href="' . esc_url($this->build_scan_url(['show_results' => '1']) . '#freesiem-results-section') . '">' . esc_html__('View Scan Results', 'freesiem-sentinel') . '</a>';
		echo '<a class="button button-secondary" onclick="return confirm(\''
			. esc_js(__('Clear the stored scan results and findings?', 'freesiem-sentinel'))
			. '\');" href="' . esc_url($clear_results_url) . '">' . esc_html__('Clear Results', 'freesiem-sentinel') . '</a>';
		echo '</p>';
		echo '</form>';
		echo '</div>';

		echo '<div style="background:#fff;padding:18px 20px;border:1px solid #dcdcde;border-radius:16px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Scan Summary', 'freesiem-sentinel') . '</h2>';
		if (empty($settings['last_local_scan_at'])) {
			$this->render_empty_state(__('No scan has been run yet.', 'freesiem-sentinel'), __('Run your first scan to review findings, file changes, and summary metrics here.', 'freesiem-sentinel'));
		} else {
			echo '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;">';
			$this->render_summary_stat(__('Last Scan Time', 'freesiem-sentinel'), freesiem_sentinel_format_datetime((string) ($settings['last_local_scan_at'] ?? '')));
			$this->render_summary_stat(__('Overall Score', 'freesiem-sentinel'), $this->summary_value_or_fallback($summary['overall_score'] ?? ($summary['local_score'] ?? ''), false));
			$this->render_summary_stat(__('Files Discovered', 'freesiem-sentinel'), $this->summary_value_or_fallback($scan_metrics['files_discovered'] ?? ($filesystem['discovered_files'] ?? ''), false));
			$this->render_summary_stat(__('Files Analyzed', 'freesiem-sentinel'), $this->summary_value_or_fallback($scan_metrics['files_analyzed'] ?? ($filesystem['inspected_files'] ?? ''), false));
			$this->render_summary_stat(__('Flagged Files', 'freesiem-sentinel'), $this->summary_value_or_fallback($scan_metrics['files_flagged'] ?? ($filesystem['flagged_files'] ?? ''), false));
			$this->render_summary_stat(__('Scan Duration', 'freesiem-sentinel'), $this->format_duration($scan_metrics['duration_seconds'] ?? ''));
			echo '</div>';
			if (!empty($scan_metrics['scan_modules']) || !empty($scan_profile)) {
				echo '<p style="margin:12px 0 0;color:#50575e;"><strong>' . esc_html__('Modules Used', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->format_scan_modules(!empty($scan_metrics['scan_modules']) ? ['scan_modules' => $scan_metrics['scan_modules']] : $scan_profile)) . '</p>';
			}
			if (!empty($filesystem['partial'])) {
				echo '<p style="margin:10px 0 0;color:#50575e;">' . esc_html__('Some directories were skipped or capped by the current scan limits.', 'freesiem-sentinel') . '</p>';
			}
		}
		echo '</div>';
		echo '</div>';

		$this->render_scan_results_section($view);
		echo '</div>';
	}

	public function render_local_scan_page(): void
	{
		$this->render_scan_page();
	}

	public function render_results_page(): void
	{
		$this->render_scan_page();
	}

	public function render_remote_page(): void
	{
		$settings = freesiem_sentinel_get_settings();
		$state = (string) ($settings['connection_state'] ?? 'disconnected');
		$is_connected = Freesiem_Cloud_Connect_State::is_connected($settings);
		$email = safe($settings['email'] ?? '');
		$phone = freesiem_sentinel_format_phone((string) ($settings['phone'] ?? ''));
		$site_id = safe($settings['site_id'] ?? '');
		$last_heartbeat = $this->summary_value_or_fallback($settings['last_heartbeat_at'] ?? '', true);
		$last_heartbeat_result = safe($settings['last_heartbeat_result'] ?? '');
		$effective_backend = freesiem_sentinel_get_effective_cloud_backend_base_url($settings);
		$configured_backend = freesiem_sentinel_sanitize_cloud_backend_base_url((string) ($settings['cloud_backend_base_url'] ?? ''));
		$connected_backend = freesiem_sentinel_sanitize_cloud_backend_base_url((string) ($settings['connected_backend_base_url'] ?? ''));
		$is_custom_backend = freesiem_sentinel_is_custom_cloud_backend($settings);
		$backend_mismatch = $is_connected && $connected_backend !== '' && untrailingslashit($connected_backend) !== untrailingslashit($effective_backend);
		$cloud_users = array_values(freesiem_sentinel_safe_array($settings['cloud_users'] ?? []));

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('freeSIEM Cloud', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Connect this site to freeSIEM Core, verify ownership, and manage signed Cloud Connect communication.', 'freesiem-sentinel') . '</p>';

		if ($is_custom_backend) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__('Using a custom/test Cloud backend. Leave the override blank to use production Cloud.', 'freesiem-sentinel') . '</p></div>';
		}

		if ($backend_mismatch) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__('The currently configured backend differs from the backend used when this site connected. Disconnect and reconnect if you want credentials tied to the new backend.', 'freesiem-sentinel') . '</p></div>';
		}

		echo '<div style="display:grid;grid-template-columns:minmax(0,2fr) minmax(280px,1fr);gap:20px;align-items:start;">';
		echo '<div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;">';
		echo '<h2 style="margin:0;">' . esc_html__('Cloud Connect', 'freesiem-sentinel') . '</h2>';
		echo '<span style="display:inline-block;padding:6px 10px;border-radius:999px;background:' . esc_attr($is_custom_backend ? '#fef3c7' : '#dcfce7') . ';color:' . esc_attr($is_custom_backend ? '#92400e' : '#166534') . ';font-weight:600;">' . esc_html($is_custom_backend ? __('Test / Custom Backend', 'freesiem-sentinel') : __('Production Backend', 'freesiem-sentinel')) . '</span>';
		echo '</div>';

		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:16px;padding:16px;border:1px solid #dcdcde;border-radius:12px;background:#f8fafc;">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_save_cloud_connect_backend" />';
		echo '<table class="form-table" role="presentation" style="margin-top:0;">';
		echo '<tr><th scope="row"><label for="freesiem-cloud-backend-base-url">' . esc_html__('Cloud Backend Base URL', 'freesiem-sentinel') . '</label></th><td><input class="regular-text code" id="freesiem-cloud-backend-base-url" name="cloud_backend_base_url" type="url" value="' . esc_attr($configured_backend) . '" placeholder="https://localhost:8443" />';
			echo '<p class="description">' . esc_html__('For development/testing only. Leave blank to use production Cloud.', 'freesiem-sentinel') . '</p></td></tr>';
		echo '</table>';
		submit_button(__('Save Backend URL', 'freesiem-sentinel'), 'secondary', '', false);
		echo '</form>';

		if (in_array($state, ['suspended', 'revoked'], true)) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__('This Cloud Connect session is no longer active. Disconnect locally, then reconnect to establish a new session.', 'freesiem-sentinel') . '</p></div>';
		}

		if ($is_connected) {
			echo '<div style="margin-top:16px;padding:16px;border-radius:12px;background:#ecfdf5;border:1px solid #a7f3d0;">';
			echo '<p style="margin:0 0 10px;font-weight:700;color:#166534;">' . esc_html__('Connected', 'freesiem-sentinel') . '</p>';
			echo '<p style="margin:0 0 8px;">' . esc_html__('This site can send signed heartbeats to freeSIEM Core.', 'freesiem-sentinel') . '</p>';
			echo '<p style="margin:0;"><strong>' . esc_html__('Site ID', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->friendly_site_id($site_id)) . '</p>';
			echo '</div>';
		} elseif ($state === 'pending_verification') {
			echo '<p style="margin-top:16px;">' . esc_html__('A verification code was sent to the provided contact. Enter it below to finish connecting this site.', 'freesiem-sentinel') . '</p>';
			echo '<p><strong>' . esc_html__('Email', 'freesiem-sentinel') . ':</strong> ' . esc_html($email) . '</p>';
			echo '<p><strong>' . esc_html__('Phone', 'freesiem-sentinel') . ':</strong> ' . esc_html($phone) . '</p>';
			if (!empty($settings['connect_expires_at'])) {
				echo '<p><strong>' . esc_html__('Code Expires', 'freesiem-sentinel') . ':</strong> ' . esc_html(freesiem_sentinel_format_datetime((string) $settings['connect_expires_at'])) . '</p>';
			}
			echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:16px;">';
			wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
			echo '<input type="hidden" name="action" value="freesiem_sentinel_cloud_connect_verify" />';
			echo '<table class="form-table" role="presentation">';
			echo '<tr><th scope="row"><label for="freesiem-cloud-connect-code">' . esc_html__('Verification Code', 'freesiem-sentinel') . '</label></th><td><input class="regular-text" id="freesiem-cloud-connect-code" name="verification_code" type="text" inputmode="numeric" autocomplete="one-time-code" value="" required /></td></tr>';
			echo '</table>';
			submit_button(__('Verify', 'freesiem-sentinel'), 'primary', '', false);
			echo ' <a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_cloud_connect_reset')) . '">' . esc_html__('Cancel / Reset', 'freesiem-sentinel') . '</a>';
			echo '</form>';
		} else {
			echo '<p style="margin-top:16px;">' . esc_html__('Connect this site to freeSIEM Core to enable verified enrollment and signed heartbeats.', 'freesiem-sentinel') . '</p>';
			echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
			wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
			echo '<input type="hidden" name="action" value="freesiem_sentinel_cloud_connect_start" />';
			echo '<table class="form-table" role="presentation">';
			echo '<tr><th scope="row"><label for="freesiem-cloud-connect-email">' . esc_html__('Email', 'freesiem-sentinel') . '</label></th><td><input class="regular-text" id="freesiem-cloud-connect-email" name="email" type="email" value="' . esc_attr($email) . '" required /></td></tr>';
			echo '<tr><th scope="row"><label for="freesiem-cloud-connect-phone">' . esc_html__('US Phone Number', 'freesiem-sentinel') . '</label></th><td><input class="regular-text" id="freesiem-cloud-connect-phone" name="phone" type="tel" value="' . esc_attr($phone) . '" placeholder="+1 (555) 234-5678" required /></td></tr>';
			echo '</table>';
			submit_button(__('Connect', 'freesiem-sentinel'));
			echo '</form>';
		}
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Automation & Access Control', 'freesiem-sentinel') . '</h2>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_save_cloud_preferences" />';
		echo '<p><label><input type="checkbox" name="allow_remote_scan" value="1"' . checked(!empty($settings['allow_remote_scan']), true, false) . ' /> ' . esc_html__('Allow Remote Scans', 'freesiem-sentinel') . '</label></p>';
		echo '<p><strong>' . esc_html__('Scan Frequency', 'freesiem-sentinel') . '</strong></p>';
		echo '<p><label><input type="radio" name="scan_frequency" value="manual"' . checked(($settings['scan_frequency'] ?? 'daily') === 'manual', true, false) . ' /> ' . esc_html__('Manual only', 'freesiem-sentinel') . '</label></p>';
		echo '<p><label><input type="radio" name="scan_frequency" value="daily"' . checked(($settings['scan_frequency'] ?? 'daily') === 'daily', true, false) . ' /> ' . esc_html__('Once daily', 'freesiem-sentinel') . '</label></p>';
		echo '<p><label><input type="radio" name="scan_frequency" value="6hours"' . checked(($settings['scan_frequency'] ?? 'daily') === '6hours', true, false) . ' /> ' . esc_html__('Every 6 hours', 'freesiem-sentinel') . '</label></p>';
		echo '<p><label><input type="radio" name="scan_frequency" value="hourly"' . checked(($settings['scan_frequency'] ?? 'daily') === 'hourly', true, false) . ' /> ' . esc_html__('Every hour', 'freesiem-sentinel') . '</label></p>';
		echo '<p><label><input type="checkbox" name="user_sync_enabled" value="1"' . checked(!empty($settings['user_sync_enabled']), true, false) . ' /> ' . esc_html__('Enable User Sync (Multi-site management)', 'freesiem-sentinel') . '</label><br /><span style="color:#50575e;">' . esc_html__('Access freeSIEM Cloud to manage multiple sites and users.', 'freesiem-sentinel') . '</span></p>';
		submit_button(__('Save Cloud Preferences', 'freesiem-sentinel'));
		echo '</form>';
		if (!empty($settings['user_sync_enabled'])) {
			echo '<div style="margin-top:18px;padding:14px;border:1px solid #dbe3ea;border-radius:12px;background:#f8fafc;">';
			echo '<h3 style="margin-top:0;">' . esc_html__('User Sync', 'freesiem-sentinel') . '</h3>';
			echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:14px;">';
			wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
			echo '<input type="hidden" name="action" value="freesiem_sentinel_add_cloud_user" />';
			echo '<p style="margin:0;"><label for="freesiem-cloud-user-email" style="display:block;font-weight:600;margin-bottom:6px;">' . esc_html__('Add user email', 'freesiem-sentinel') . '</label><input class="regular-text" id="freesiem-cloud-user-email" name="cloud_user_email" type="email" value="" /></p>';
			echo '<p style="margin:0;"><button type="submit" class="button button-secondary">' . esc_html__('Add User', 'freesiem-sentinel') . '</button></p>';
			echo '</form>';
			if ($cloud_users === []) {
				$this->render_empty_state(__('No synced users yet.', 'freesiem-sentinel'), __('Add a user here to prepare multi-site management access.', 'freesiem-sentinel'));
			} else {
				echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('User', 'freesiem-sentinel') . '</th><th>' . esc_html__('Action', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
				foreach ($cloud_users as $cloud_user) {
					$delete_url = freesiem_sentinel_admin_post_url('freesiem_sentinel_delete_cloud_user', ['email' => $cloud_user]);
					echo '<tr>';
					echo '<td>' . esc_html($cloud_user) . '</td>';
					echo '<td><a class="button button-secondary" onclick="return confirm(\''
						. esc_js(__('Remove this user from Cloud sync?', 'freesiem-sentinel'))
						. '\');" href="' . esc_url($delete_url) . '">' . esc_html__('Delete User', 'freesiem-sentinel') . '</a></td>';
					echo '</tr>';
				}
				echo '</tbody></table>';
			}
			echo '</div>';
		}
		echo '</div>';
		echo '</div>';

		echo '<div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Status', 'freesiem-sentinel') . '</h2>';
		echo '<table class="widefat striped" style="border:none;box-shadow:none;"><tbody>';
		echo '<tr><td><strong>' . esc_html__('Environment', 'freesiem-sentinel') . '</strong></td><td>' . esc_html($is_custom_backend ? __('Custom/Test', 'freesiem-sentinel') : __('Production', 'freesiem-sentinel')) . '</td></tr>';
		echo '<tr><td><strong>' . esc_html__('Current Configured Backend', 'freesiem-sentinel') . '</strong></td><td><code>' . esc_html($effective_backend) . '</code></td></tr>';
		echo '<tr><td><strong>' . esc_html__('Active Connection Backend', 'freesiem-sentinel') . '</strong></td><td>' . esc_html($connected_backend !== '' ? $connected_backend : __('Not connected yet', 'freesiem-sentinel')) . '</td></tr>';
		echo '<tr><td><strong>' . esc_html__('Connection State', 'freesiem-sentinel') . '</strong></td><td>' . esc_html($this->format_connection_state($state)) . '</td></tr>';
		echo '<tr><td><strong>' . esc_html__('Connected Email', 'freesiem-sentinel') . '</strong></td><td>' . esc_html($email !== '' ? $email : __('Not set', 'freesiem-sentinel')) . '</td></tr>';
		echo '<tr><td><strong>' . esc_html__('Connected Phone', 'freesiem-sentinel') . '</strong></td><td>' . esc_html($phone !== '' ? $phone : __('Not set', 'freesiem-sentinel')) . '</td></tr>';
		echo '<tr><td><strong>' . esc_html__('Site ID', 'freesiem-sentinel') . '</strong></td><td>' . esc_html($site_id !== '' ? $this->friendly_site_id($site_id) : __('Not assigned', 'freesiem-sentinel')) . '</td></tr>';
		echo '<tr><td><strong>' . esc_html__('Last Heartbeat', 'freesiem-sentinel') . '</strong></td><td>' . esc_html($last_heartbeat) . '</td></tr>';
		echo '<tr><td><strong>' . esc_html__('Last Result', 'freesiem-sentinel') . '</strong></td><td>' . esc_html($last_heartbeat_result !== '' ? $last_heartbeat_result : __('No heartbeat sent yet.', 'freesiem-sentinel')) . '</td></tr>';
		echo '<tr><td><strong>' . esc_html__('Remote Scan Allowed', 'freesiem-sentinel') . '</strong></td><td>' . esc_html(!empty($settings['allow_remote_scan']) ? __('Yes', 'freesiem-sentinel') : __('No', 'freesiem-sentinel')) . '</td></tr>';
		echo '<tr><td><strong>' . esc_html__('Scan Frequency', 'freesiem-sentinel') . '</strong></td><td>' . esc_html(safe($settings['scan_frequency'] ?? 'daily')) . '</td></tr>';
		echo '<tr><td><strong>' . esc_html__('User Sync Enabled', 'freesiem-sentinel') . '</strong></td><td>' . esc_html(!empty($settings['user_sync_enabled']) ? __('Yes', 'freesiem-sentinel') : __('No', 'freesiem-sentinel')) . '</td></tr>';
		echo '</tbody></table>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Actions', 'freesiem-sentinel') . '</h2>';
		if ($is_connected) {
			echo '<p><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_cloud_connect_test')) . '">' . esc_html__('Test Connection', 'freesiem-sentinel') . '</a></p>';
			echo '<p><a class="button button-secondary" onclick="return confirm(\''
				. esc_js(__('Disconnect this site from freeSIEM Cloud?', 'freesiem-sentinel'))
				. '\');" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_cloud_connect_disconnect')) . '">' . esc_html__('Disconnect', 'freesiem-sentinel') . '</a></p>';
		} elseif ($state === 'pending_verification') {
			echo '<p><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_cloud_connect_reset')) . '">' . esc_html__('Cancel / Reset', 'freesiem-sentinel') . '</a></p>';
		} elseif (in_array($state, ['suspended', 'revoked'], true)) {
			echo '<p><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_cloud_connect_disconnect')) . '">' . esc_html__('Disconnect / Reset', 'freesiem-sentinel') . '</a></p>';
		} else {
			$this->render_empty_state(__('No actions available yet.', 'freesiem-sentinel'), __('Start a connection to enable verification, heartbeat tests, and disconnect controls.', 'freesiem-sentinel'));
		}
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Stored Credentials', 'freesiem-sentinel') . '</h2>';
		echo '<p>' . esc_html__('API credentials are stored locally and never shown in plain text here.', 'freesiem-sentinel') . '</p>';
		echo '<p><strong>' . esc_html__('API Key', 'freesiem-sentinel') . ':</strong> <code>' . esc_html(freesiem_sentinel_mask_secret((string) ($settings['api_key'] ?? ''))) . '</code></p>';
		echo '<p><strong>' . esc_html__('HMAC Secret', 'freesiem-sentinel') . ':</strong> <code>' . esc_html(freesiem_sentinel_mask_secret((string) ($settings['hmac_secret'] ?? ''))) . '</code></p>';
		echo '</div>';
		echo '</div>';
		echo '</div>';
		echo '</div>';
	}

	public function render_cloud_connect_page(): void
	{
		$this->render_remote_page();
	}

	public function render_about_page(): void
	{
		$settings = freesiem_sentinel_get_settings();
		$release = $this->plugin->get_updater()->get_github_release_data();
		$release = is_wp_error($release) ? [] : freesiem_sentinel_safe_array($release);
		$release_body = trim(safe($release['body'] ?? ''));
		$release_available = !empty($release['available']);
		$release_version = safe($release['version'] ?? '');
		$update_available = $release_available && version_compare($release_version, FREESIEM_SENTINEL_VERSION, '>');

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('About freeSIEM Sentinel', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Release, plan, and agent identity details for this WordPress deployment.', 'freesiem-sentinel') . '</p>';
		$this->render_card_grid_start();
		$this->render_stat_card(__('Plugin Version', 'freesiem-sentinel'), FREESIEM_SENTINEL_VERSION, __('Latest Release', 'freesiem-sentinel'), $release_available ? $release_version : __('No releases available', 'freesiem-sentinel'));
		$this->render_stat_card(__('Connected To', 'freesiem-sentinel'), __('freeSIEM Core', 'freesiem-sentinel'), __('Registration', 'freesiem-sentinel'), strtoupper(freesiem_sentinel_safe_string($settings['registration_status'] ?? '')));
		$this->render_stat_card(__('Site ID', 'freesiem-sentinel'), $this->friendly_site_id($settings['site_id'] ?? ''), __('Plan', 'freesiem-sentinel'), ucfirst($this->plugin->get_plan()));
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-top:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Updates & Credentials', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('Plugin Updates', 'freesiem-sentinel') . ':</strong> ' . esc_html($update_available ? sprintf(__('Version %s is available.', 'freesiem-sentinel'), $release_version) : __('You are on the latest available version.', 'freesiem-sentinel')) . '</p>';
		if ($update_available) {
			echo '<p><a class="button button-primary" href="' . esc_url($this->plugin->get_updater()->get_plugin_upgrade_url()) . '">' . esc_html__('Update Plugin', 'freesiem-sentinel') . '</a></p>';
		} else {
			echo '<p><button type="button" class="button button-secondary" disabled="disabled">' . esc_html__('Update Plugin', 'freesiem-sentinel') . '</button></p>';
		}
		echo '<p><strong>' . esc_html__('Automatic Updates', 'freesiem-sentinel') . ':</strong> ' . esc_html__('Enabled by default for this plugin.', 'freesiem-sentinel') . '</p>';
		echo '<p style="color:#50575e;">' . esc_html__('WordPress checks for plugin updates on its normal update schedule, roughly every 12 hours, and also whenever you click Check for Updates here. If a newer GitHub release is found, the Update Plugin button appears immediately on this page. Automatic updates are then applied during WordPress background update runs.', 'freesiem-sentinel') . '</p>';
		echo '<p><strong>' . esc_html__('API Key:', 'freesiem-sentinel') . '</strong> <code>' . esc_html(freesiem_sentinel_mask_secret((string) ($settings['api_key'] ?? ''))) . '</code></p>';
		echo '<p><strong>' . esc_html__('HMAC Secret:', 'freesiem-sentinel') . '</strong> <code>' . esc_html(freesiem_sentinel_mask_secret((string) ($settings['hmac_secret'] ?? ''))) . '</code></p>';
		echo '<p><strong>' . esc_html__('Check for Updates:', 'freesiem-sentinel') . '</strong> <a class="button button-secondary" href="' . esc_url(freesiem_sentinel_safe_string($this->plugin->get_updater()->get_check_updates_url(freesiem_sentinel_admin_page_url('freesiem-about')))) . '">' . esc_html__('Check for Updates', 'freesiem-sentinel') . '</a></p>';
		if (!empty($release['published_at'])) {
			echo '<p><strong>' . esc_html__('Release Published:', 'freesiem-sentinel') . '</strong> ' . esc_html(freesiem_sentinel_format_datetime((string) ($release['published_at'] ?? ''))) . '</p>';
		}
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

	private function render_scan_results_section(array $view): void
	{
		$all_findings = $view['all_findings'];
		$findings = $view['findings'];
		$filesystem = $view['filesystem'];
		$integrity = $view['integrity'];
		$integrity_changes = $view['integrity_changes'];
		$search = $view['search'];
		$selected_severities = $view['selected_severities'];
		$finding = $view['finding'];
		$active_change_type = freesiem_sentinel_safe_string($view['change_filters']['change_type'] ?? '');
		$active_change_path = freesiem_sentinel_safe_string($view['change_filters']['change_path'] ?? '');
		$scan_metrics = array_merge(
			[
				'files_discovered' => '',
				'files_analyzed' => '',
				'files_flagged' => '',
				'duration_seconds' => '',
				'scan_modules' => [],
			],
			freesiem_sentinel_safe_array($view['summary']),
			freesiem_sentinel_safe_array($view['inventory']['scan_metrics'] ?? [])
		);

		echo '<div id="freesiem-results-section" style="background:#fff;padding:24px;border:1px solid #dcdcde;border-radius:16px;">';
		echo '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:20px;">';
		echo '<h2 style="margin:0;">' . esc_html__('Scan Results', 'freesiem-sentinel') . '</h2>';
		echo '</div>';

		if (is_array($finding)) {
			$this->render_finding_detail_page($finding);
			echo '</div>';
			return;
		}

		echo '<div style="display:grid;grid-template-columns:1.2fr .8fr;gap:20px;margin-bottom:20px;">';
		echo '<div>';
		echo '<h3 style="margin-top:0;">' . esc_html__('Summary', 'freesiem-sentinel') . '</h3>';
		if ($all_findings === [] && empty($view['settings']['last_local_scan_at'])) {
			$this->render_empty_state(__('No scan has been run yet.', 'freesiem-sentinel'), __('Run a scan to populate findings and file change details.', 'freesiem-sentinel'));
		} else {
			echo '<p><strong>' . esc_html__('Files discovered', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->summary_value_or_fallback($scan_metrics['files_discovered'] ?? ($filesystem['discovered_files'] ?? ''), false)) . '</p>';
			echo '<p><strong>' . esc_html__('Files analyzed', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->summary_value_or_fallback($scan_metrics['files_analyzed'] ?? ($filesystem['inspected_files'] ?? ''), false)) . '</p>';
			echo '<p><strong>' . esc_html__('Flagged files', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->summary_value_or_fallback($scan_metrics['files_flagged'] ?? ($filesystem['flagged_files'] ?? ''), false)) . '</p>';
			echo '<p><strong>' . esc_html__('Scan duration', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->format_duration($scan_metrics['duration_seconds'] ?? '')) . '</p>';
			echo '<p><strong>' . esc_html__('File integrity changes', 'freesiem-sentinel') . ':</strong> ' . esc_html(sprintf('%s new, %s modified, %s deleted', safe($integrity['new_files_count'] ?? '0'), safe($integrity['modified_files_count'] ?? '0'), safe($integrity['deleted_files_count'] ?? '0'))) . '</p>';
			echo '<p><strong>' . esc_html__('Scan modules used', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->format_scan_modules(!empty($scan_metrics['scan_modules']) ? ['scan_modules' => $scan_metrics['scan_modules']] : freesiem_sentinel_safe_array($view['inventory']['scan_profile'] ?? []))) . '</p>';
		}
		echo '</div>';

		echo '<div>';
		echo '<h3 style="margin-top:0;">' . esc_html__('File Changes Detected', 'freesiem-sentinel') . '</h3>';
		if ($integrity_changes === []) {
			$this->render_empty_state(__('No file changes detected in the latest scan.', 'freesiem-sentinel'), __('File additions, deletions, and monitored updates will appear here after a scan finds them.', 'freesiem-sentinel'));
		} else {
			if ($active_change_type !== '' || $active_change_path !== '') {
				echo '<p style="margin-top:0;"><strong>' . esc_html__('Active filters', 'freesiem-sentinel') . ':</strong> ';
				if ($active_change_type !== '') {
					echo '<code>' . esc_html($active_change_type) . '</code> ';
				}
				if ($active_change_path !== '') {
					echo '<code>' . esc_html($active_change_path) . '</code> ';
				}
				echo '<a href="' . esc_url($this->build_scan_url(['show_results' => '1']) . '#freesiem-results-section') . '">' . esc_html__('Clear file filters', 'freesiem-sentinel') . '</a></p>';
			}
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Change', 'freesiem-sentinel') . '</th><th>' . esc_html__('Path', 'freesiem-sentinel') . '</th><th>' . esc_html__('Hash', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
			foreach (array_slice($integrity_changes, 0, 5) as $change) {
				$change_type = freesiem_sentinel_safe_string($change['change_type'] ?? 'modified');
				$path = freesiem_sentinel_safe_string($change['path'] ?? '');
				$current_hash = freesiem_sentinel_safe_string($change['current_hash'] ?? '');
				$previous_hash = freesiem_sentinel_safe_string($change['previous_hash'] ?? '');
				$change_type_url = $this->build_scan_url([
					'show_results' => '1',
					'change_type' => $change_type,
					'change_path' => $active_change_path,
				]) . '#freesiem-results-section';
				$path_url = $this->build_scan_url([
					'show_results' => '1',
					'change_type' => $active_change_type,
					'change_path' => $path,
				]) . '#freesiem-results-section';
				echo '<tr>';
				echo '<td><a href="' . esc_url($change_type_url) . '" style="text-decoration:none;"><span style="' . esc_attr($this->change_badge_style($change_type)) . '">' . esc_html(ucfirst($change_type)) . '</span></a></td>';
				echo '<td><a href="' . esc_url($path_url) . '" style="text-decoration:none;"><code>' . esc_html($path) . '</code></a></td>';
				echo '<td><code>' . esc_html($current_hash !== '' ? substr($current_hash, 0, 16) : substr($previous_hash, 0, 16)) . '</code></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
		echo '</div>';

		echo '<div style="background:#f8fafc;padding:16px;border:1px solid #dbe3ea;border-radius:12px;margin-bottom:20px;">';
		echo '<form method="get" action="' . esc_url(admin_url('admin.php')) . '" style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;">';
		echo '<input type="hidden" name="page" value="freesiem-scan" />';
		echo '<input type="hidden" name="show_results" value="1" />';
		echo '<div><label for="freesiem-search" style="display:block;font-weight:600;margin-bottom:6px;">' . esc_html__('Search Findings', 'freesiem-sentinel') . '</label><input id="freesiem-search" class="regular-text" type="search" name="s" value="' . esc_attr($search) . '" /></div>';
		echo '<div><span style="display:block;font-weight:600;margin-bottom:6px;">' . esc_html__('Severity Filters', 'freesiem-sentinel') . '</span>';
		foreach (['critical' => __('Critical', 'freesiem-sentinel'), 'high' => __('High', 'freesiem-sentinel'), 'medium' => __('Medium', 'freesiem-sentinel'), 'low' => __('Low', 'freesiem-sentinel'), 'info' => __('Info', 'freesiem-sentinel')] as $key => $label) {
			echo '<label style="margin-right:10px;display:inline-flex;align-items:center;gap:4px;"><input type="checkbox" name="severity[]" value="' . esc_attr($key) . '"' . checked(in_array($key, $selected_severities, true), true, false) . ' />' . esc_html($label) . '</label>';
		}
		echo '</div>';
		echo '<div><button type="submit" class="button button-secondary">' . esc_html__('Apply Filters', 'freesiem-sentinel') . '</button></div>';
		echo '</form>';
		echo '</div>';

		echo '<div>';
		echo '<h3 style="margin-top:0;">' . esc_html__('Findings', 'freesiem-sentinel') . '</h3>';
		if ($findings === []) {
			$this->render_empty_state(__('No findings match your current filters.', 'freesiem-sentinel'), __('Adjust the search terms or severity filters to widen the results.', 'freesiem-sentinel'));
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Severity', 'freesiem-sentinel') . '</th><th>' . esc_html__('Title', 'freesiem-sentinel') . '</th><th>' . esc_html__('Category', 'freesiem-sentinel') . '</th><th>' . esc_html__('Recommendation', 'freesiem-sentinel') . '</th><th>' . esc_html__('Path', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
			foreach ($findings as $index => $finding_row) {
				if (!is_array($finding_row)) {
					continue;
				}

				$reference = $this->build_finding_reference($finding_row, $index);
				$detail_url = $this->build_scan_url([
					'show_results' => '1',
					'finding' => $reference,
				]);
				$path = freesiem_sentinel_safe_string($finding_row['evidence']['path'] ?? '');
				$summary_value = $path !== '' ? $path : $this->evidence_summary($finding_row);

				echo '<tr>';
				echo '<td><a href="' . esc_url($detail_url) . '" style="' . esc_attr($this->severity_badge_style((string) ($finding_row['severity'] ?? 'info'))) . '">' . esc_html(strtoupper(freesiem_sentinel_safe_string($finding_row['severity'] ?? 'info'))) . '</a></td>';
				echo '<td><a href="' . esc_url($detail_url) . '" style="display:block;color:inherit;text-decoration:none;"><strong>' . esc_html(freesiem_sentinel_safe_string($finding_row['title'] ?? '')) . '</strong><br /><span>' . esc_html(freesiem_sentinel_safe_string($finding_row['description'] ?? '')) . '</span></a></td>';
				echo '<td><a href="' . esc_url($detail_url) . '" style="display:block;color:inherit;text-decoration:none;">' . esc_html(freesiem_sentinel_safe_string($finding_row['category'] ?? '')) . '</a></td>';
				echo '<td><a href="' . esc_url($detail_url) . '" style="display:block;color:inherit;text-decoration:none;">' . esc_html(freesiem_sentinel_safe_string($finding_row['recommendation'] ?? '')) . '</a></td>';
				echo '<td><a href="' . esc_url($detail_url) . '" style="display:block;color:inherit;text-decoration:none;"><code>' . esc_html($summary_value) . '</code></a></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
		echo '</div>';
	}

	private function get_scan_results_view(): array
	{
		$settings = freesiem_sentinel_get_settings();
		$cache = $this->plugin->get_results()->get_cache();
		$summary = freesiem_sentinel_safe_array($cache['summary'] ?? []);
		$inventory = freesiem_sentinel_safe_array($cache['local_inventory'] ?? []);
		$filesystem = freesiem_sentinel_safe_array($inventory['filesystem'] ?? []);
		$integrity = freesiem_sentinel_safe_array($inventory['file_integrity'] ?? []);
		$all_findings = array_values(freesiem_sentinel_safe_array($cache['local_findings'] ?? []));
		$search = isset($_GET['s']) ? sanitize_text_field(wp_unslash((string) $_GET['s'])) : '';
		$selected_severities = $this->get_results_severity_filters();
		$findings = $this->filter_findings($all_findings, $search, $selected_severities);
		$finding_ref = isset($_GET['finding']) ? sanitize_text_field(wp_unslash((string) $_GET['finding'])) : '';
		$finding = $finding_ref !== '' ? $this->find_finding_by_reference($all_findings, $finding_ref) : null;
		$fim_diff_cache = freesiem_sentinel_safe_array($settings['fim_diff_cache'] ?? []);
		$integrity_changes = array_values(array_filter(freesiem_sentinel_safe_array($fim_diff_cache['changes'] ?? []), 'is_array'));
		$change_filters = [
			'change_type' => isset($_GET['change_type']) ? sanitize_key(wp_unslash((string) $_GET['change_type'])) : '',
			'change_path' => isset($_GET['change_path']) ? sanitize_text_field(wp_unslash((string) $_GET['change_path'])) : '',
		];
		$integrity_changes = $this->filter_integrity_changes($integrity_changes, $change_filters);

		return [
			'settings' => $settings,
			'cache' => $cache,
			'summary' => $summary,
			'inventory' => $inventory,
			'filesystem' => $filesystem,
			'integrity' => $integrity,
			'all_findings' => $all_findings,
			'findings' => $findings,
			'search' => $search,
			'selected_severities' => $selected_severities,
			'finding' => $finding,
			'integrity_changes' => $integrity_changes,
			'change_filters' => $change_filters,
		];
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

	private function render_summary_stat(string $label, string $value): void
	{
		static $palette_index = 0;
		$palettes = [
			['bg' => '#ecfeff', 'border' => '#a5f3fc'],
			['bg' => '#eff6ff', 'border' => '#bfdbfe'],
			['bg' => '#fef3c7', 'border' => '#fcd34d'],
			['bg' => '#ecfccb', 'border' => '#bef264'],
			['bg' => '#fee2e2', 'border' => '#fca5a5'],
			['bg' => '#f5f3ff', 'border' => '#c4b5fd'],
		];
		$palette = $palettes[$palette_index % count($palettes)];
		$palette_index++;

		echo '<div style="padding:14px;border:1px solid ' . esc_attr($palette['border']) . ';border-radius:12px;background:' . esc_attr($palette['bg']) . ';">';
		echo '<span style="display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#64748b;">' . esc_html($label) . '</span>';
		echo '<strong style="display:block;font-size:20px;line-height:1.2;margin-top:6px;">' . esc_html($value) . '</strong>';
		echo '</div>';
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
		$back_url = $this->build_scan_url(['show_results' => '1']) . '#freesiem-results-section';
		$severity = freesiem_sentinel_normalize_severity((string) ($finding['severity'] ?? 'info'));
		$evidence = freesiem_sentinel_safe_array($finding['evidence'] ?? []);
		$path = freesiem_sentinel_safe_string($evidence['path'] ?? '');

		echo '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;">';
		echo '<a class="button button-secondary" href="' . esc_url($back_url) . '">' . esc_html__('Back to Scan Results', 'freesiem-sentinel') . '</a>';
		echo '<a class="button button-primary" href="' . esc_url(freesiem_sentinel_admin_page_url('freesiem-scan')) . '">' . esc_html__('Run Scan Again', 'freesiem-sentinel') . '</a>';
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

	private function summary_value_or_fallback($value, bool $is_datetime): string
	{
		if ($is_datetime) {
			$string_value = safe($value);
			return $string_value === '' ? __('No scan yet', 'freesiem-sentinel') : freesiem_sentinel_format_datetime($string_value);
		}

		$string_value = safe($value);
		return $string_value === '' ? __('No scan yet', 'freesiem-sentinel') : $string_value;
	}

	private function friendly_site_id($site_id): string
	{
		$site_id = safe($site_id);
		return $site_id === '' ? __('Pending Setup', 'freesiem-sentinel') : $site_id;
	}

	private function agent_status_label(bool $connected): string
	{
		return $connected ? __('Connected to freeSIEM Cloud', 'freesiem-sentinel') : __('Pending Setup', 'freesiem-sentinel');
	}

	private function registration_state_label($status): string
	{
		$status = sanitize_key((string) $status);

		return match ($status) {
			'registered', 'connected', 'active' => __('Connected', 'freesiem-sentinel'),
			default => __('Pending Setup', 'freesiem-sentinel'),
		};
	}

	private function format_scan_modules(array $scan_profile): string
	{
		if (!empty($scan_profile['scan_modules']) && is_array($scan_profile['scan_modules'])) {
			return implode(', ', array_map('freesiem_sentinel_safe_string', $scan_profile['scan_modules']));
		}

		$labels = [];

		if (!empty($scan_profile['scan_wordpress'])) {
			$labels[] = __('WordPress Config', 'freesiem-sentinel');
		}
		if (!empty($scan_profile['scan_filesystem'])) {
			$labels[] = __('Filesystem', 'freesiem-sentinel');
		}
		if (!empty($scan_profile['scan_fim'])) {
			$labels[] = __('File Integrity', 'freesiem-sentinel');
		}

		return $labels === [] ? __('No modules selected', 'freesiem-sentinel') : implode(', ', $labels);
	}

	private function filter_integrity_changes(array $changes, array $filters): array
	{
		$change_type = freesiem_sentinel_safe_string($filters['change_type'] ?? '');
		$change_path = freesiem_sentinel_safe_string($filters['change_path'] ?? '');

		return array_values(array_filter($changes, static function ($change) use ($change_type, $change_path): bool {
			if (!is_array($change)) {
				return false;
			}

			if ($change_type !== '' && freesiem_sentinel_safe_string($change['change_type'] ?? '') !== $change_type) {
				return false;
			}

			if ($change_path !== '' && freesiem_sentinel_safe_string($change['path'] ?? '') !== $change_path) {
				return false;
			}

			return true;
		}));
	}

	private function format_duration($duration): string
	{
		if ($duration === '' || $duration === null) {
			return __('No scan yet', 'freesiem-sentinel');
		}

		$duration = (float) $duration;

		if ($duration <= 0) {
			return __('No scan yet', 'freesiem-sentinel');
		}

		return sprintf(__('%s seconds', 'freesiem-sentinel'), number_format_i18n($duration, 2));
	}

	private function build_scan_url(array $args = []): string
	{
		return freesiem_sentinel_admin_page_url('freesiem-scan', $args);
	}

	private function evidence_summary(array $finding): string
	{
		$evidence = freesiem_sentinel_safe_array($finding['evidence'] ?? []);
		$parts = array_filter([
			freesiem_sentinel_safe_string($evidence['change_type'] ?? ''),
			freesiem_sentinel_safe_string($evidence['extension'] ?? ''),
		]);

		return $parts === [] ? __('View details', 'freesiem-sentinel') : implode(' | ', $parts);
	}

	private function format_connection_state(string $state): string
	{
		return ucwords(str_replace('_', ' ', $state === '' ? 'disconnected' : $state));
	}

	private function is_cloud_connected(array $settings): bool
	{
		return Freesiem_Cloud_Connect_State::is_connected($settings);
	}

	private function assert_manage_permissions(): void
	{
		if (!freesiem_sentinel_current_user_can_manage()) {
			wp_die(esc_html__('You are not allowed to manage freeSIEM Sentinel.', 'freesiem-sentinel'));
		}
	}

	private function redirect_to_page(string $page, array $args = []): void
	{
		wp_safe_redirect(freesiem_sentinel_admin_page_url($page, $args));
		exit;
	}
}
