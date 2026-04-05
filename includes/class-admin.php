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
		add_action('admin_init', [$this->plugin, 'maybe_process_pending_task_maintenance']);
		add_action('admin_notices', 'freesiem_sentinel_render_notices');
		add_action('admin_post_freesiem_sentinel_save_cloud_connect_contact', [$this, 'handle_save_cloud_connect_contact']);
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
		add_action('admin_post_freesiem_sentinel_request_remote_scan', [$this, 'handle_request_remote_scan']);
		add_action('admin_post_freesiem_sentinel_sync_results', [$this, 'handle_sync_results']);
		add_action('admin_post_freesiem_sentinel_reconnect', [$this, 'handle_reconnect']);
		add_action('admin_post_freesiem_sentinel_disconnect_cloud', [$this, 'handle_disconnect_cloud']);
		add_action('admin_post_freesiem_sentinel_test_connection', [$this, 'handle_test_connection']);
		add_action('admin_post_freesiem_sentinel_approve_task', [$this, 'handle_approve_task']);
		add_action('admin_post_freesiem_sentinel_deny_task', [$this, 'handle_deny_task']);
		add_action('admin_post_freesiem_sentinel_tfa_enroll', [$this, 'handle_tfa_enroll']);
		add_action('admin_post_freesiem_sentinel_tfa_reset', [$this, 'handle_tfa_reset']);
		add_action('admin_post_freesiem_sentinel_tfa_complete_setup', [$this, 'handle_tfa_complete_setup']);
		add_action('admin_post_freesiem_sentinel_tfa_change_password', [$this, 'handle_tfa_change_password']);
		add_action('admin_post_freesiem_sentinel_save_ssl_settings', [$this, 'handle_save_ssl_settings']);
		add_action('admin_post_freesiem_sentinel_run_ssl_preflight', [$this, 'handle_run_ssl_preflight']);
		add_action('admin_post_freesiem_sentinel_run_ssl_dry_run', [$this, 'handle_run_ssl_dry_run']);
		add_action('admin_post_freesiem_sentinel_issue_ssl_certificate', [$this, 'handle_issue_ssl_certificate']);
		add_action('admin_post_freesiem_sentinel_renew_ssl_certificate', [$this, 'handle_renew_ssl_certificate']);
		add_action('admin_post_freesiem_sentinel_detect_nginx_config', [$this, 'handle_detect_nginx_config']);
		add_action('admin_post_freesiem_sentinel_apply_ssl_to_nginx', [$this, 'handle_apply_ssl_to_nginx']);
		add_action('admin_post_freesiem_sentinel_install_certbot', [$this, 'handle_install_certbot']);
		add_action('admin_post_freesiem_sentinel_save_login_protection', [$this, 'handle_save_login_protection']);
		add_action('admin_post_freesiem_sentinel_save_stealth_mode', [$this, 'handle_save_stealth_mode']);
		add_action('admin_post_freesiem_sentinel_clear_logs', [$this, 'handle_clear_logs']);
		add_action('wp_login_failed', [$this, 'handle_login_failed_event']);
		add_action('wp_login', [$this, 'handle_login_success_event'], 10, 2);
		add_action('init', [$this, 'maybe_handle_stealth_mode'], 1);
		add_filter('authenticate', [$this, 'maybe_enforce_login_lockout'], 30, 3);
		add_filter('login_url', [$this, 'filter_login_url'], 10, 3);
		add_action('freesiem_sentinel_tfa_success', [$this, 'handle_tfa_success_event'], 10, 2);
		add_action('freesiem_sentinel_tfa_failure', [$this, 'handle_tfa_failure_event'], 10, 2);
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

		add_submenu_page('freesiem-portal', __('Dashboard', 'freesiem-sentinel'), __('Dashboard', 'freesiem-sentinel'), 'manage_options', 'freesiem-portal', [$this, 'render_dashboard_page']);
		add_submenu_page('freesiem-portal', __('Cloud', 'freesiem-sentinel'), __('Cloud', 'freesiem-sentinel'), 'manage_options', 'freesiem-remote', [$this, 'render_remote_page']);
		add_submenu_page('freesiem-portal', __('SSL / HTTPS', 'freesiem-sentinel'), __('SSL / HTTPS', 'freesiem-sentinel'), 'manage_options', 'freesiem-ssl', [$this, 'render_ssl_page']);
		add_submenu_page('freesiem-portal', __('TFA (2FA)', 'freesiem-sentinel'), __('TFA (2FA)', 'freesiem-sentinel'), 'manage_options', 'freesiem-tfa', [$this, 'render_tfa_page']);
		add_submenu_page('freesiem-portal', __('Login Protection', 'freesiem-sentinel'), __('Login Protection', 'freesiem-sentinel'), 'manage_options', 'freesiem-login-protection', [$this, 'render_login_protection_page']);
		add_submenu_page('freesiem-portal', __('Stealth Mode', 'freesiem-sentinel'), __('Stealth Mode', 'freesiem-sentinel'), 'manage_options', 'freesiem-stealth-mode', [$this, 'render_stealth_mode_page']);
		add_submenu_page('freesiem-portal', __('Logs', 'freesiem-sentinel'), __('Logs', 'freesiem-sentinel'), 'manage_options', 'freesiem-logs', [$this, 'render_logs_page']);
		add_submenu_page('freesiem-portal', __('Pending Tasks', 'freesiem-sentinel'), __('Pending Tasks', 'freesiem-sentinel'), 'read', 'freesiem-pending-tasks', [$this, 'render_pending_tasks_page']);
		add_submenu_page('freesiem-portal', __('About', 'freesiem-sentinel'), __('About', 'freesiem-sentinel'), 'manage_options', 'freesiem-about', [$this, 'render_about_page']);
		add_submenu_page(null, __('Scan', 'freesiem-sentinel'), __('Scan', 'freesiem-sentinel'), 'manage_options', 'freesiem-scan', [$this, 'render_scan_page']);
	}

	public function handle_save_cloud_connect_contact(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$email = isset($_POST['email']) ? sanitize_email(wp_unslash((string) $_POST['email'])) : '';
		$phone = isset($_POST['phone']) ? freesiem_sentinel_sanitize_phone_number(wp_unslash((string) $_POST['phone'])) : '';

		if (!is_email($email)) {
			freesiem_sentinel_set_notice('error', __('Enter a valid email address to save.', 'freesiem-sentinel'));
			$this->redirect_to_page('freesiem-remote');
		}

		if ($phone === '') {
			freesiem_sentinel_set_notice('error', __('Enter a valid US phone number to save.', 'freesiem-sentinel'));
			$this->redirect_to_page('freesiem-remote');
		}

		freesiem_sentinel_update_settings(['email' => $email, 'phone' => $phone]);

		freesiem_sentinel_set_notice('success', __('Cloud contact details saved locally.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_cloud_connect_start(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$settings = freesiem_sentinel_get_settings();
		$email = sanitize_email((string) ($settings['email'] ?? ''));
		$phone = freesiem_sentinel_sanitize_phone_number((string) ($settings['phone'] ?? ''));

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

		$result = $this->plugin->test_connection();
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Connection test completed successfully.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-remote');
	}

	public function handle_cloud_connect_disconnect(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$result = $this->plugin->disconnect_cloud_connect();
		if (is_wp_error($result)) {
			freesiem_sentinel_set_notice('error', $result->get_error_message());
		} elseif (!empty($result['local_only'])) {
			freesiem_sentinel_set_notice('warning', sprintf(__('Local Cloud credentials were cleared, but freeSIEM Core responded with: %s', 'freesiem-sentinel'), $result['message'] ?? __('request rejected', 'freesiem-sentinel')));
		} else {
			freesiem_sentinel_set_notice('success', __('Disconnected from freeSIEM Cloud Connect.', 'freesiem-sentinel'));
		}
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

		$preferences = [
			'allow_remote_scan' => empty($_POST['allow_remote_scan']) ? 0 : 1,
			'scan_frequency' => isset($_POST['scan_frequency']) ? sanitize_key(wp_unslash((string) $_POST['scan_frequency'])) : 'daily',
			'user_sync_enabled' => empty($_POST['user_sync_enabled']) ? 0 : 1,
			'enable_pending_task_queue' => empty($_POST['enable_pending_task_queue']) ? 0 : 1,
			'auto_approve_enabled_default' => empty($_POST['auto_approve_enabled_default']) ? 0 : 1,
			'auto_approve_after_minutes_default' => max(1, min(1440, (int) ($_POST['auto_approve_after_minutes_default'] ?? 30))),
			'require_manual_approval_for_list_users' => empty($_POST['require_manual_approval_for_list_users']) ? 0 : 1,
			'require_manual_approval_for_create_user' => empty($_POST['require_manual_approval_for_create_user']) ? 0 : 1,
			'require_manual_approval_for_update_user' => empty($_POST['require_manual_approval_for_update_user']) ? 0 : 1,
			'require_manual_approval_for_password_reset' => empty($_POST['require_manual_approval_for_password_reset']) ? 0 : 1,
			'require_manual_approval_for_delete_user' => empty($_POST['require_manual_approval_for_delete_user']) ? 0 : 1,
			'allow_auto_approve_list_users' => empty($_POST['allow_auto_approve_list_users']) ? 0 : 1,
			'allow_auto_approve_create_user' => empty($_POST['allow_auto_approve_create_user']) ? 0 : 1,
			'allow_auto_approve_update_user' => empty($_POST['allow_auto_approve_update_user']) ? 0 : 1,
			'allow_auto_approve_password_reset' => empty($_POST['allow_auto_approve_password_reset']) ? 0 : 1,
			'allow_auto_approve_delete_user' => empty($_POST['allow_auto_approve_delete_user']) ? 0 : 1,
			'notify_admins_on_pending_task' => empty($_POST['notify_admins_on_pending_task']) ? 0 : 1,
			'include_pending_tasks_in_heartbeat' => empty($_POST['include_pending_tasks_in_heartbeat']) ? 0 : 1,
			'heartbeat_include_recent_completed_tasks' => empty($_POST['heartbeat_include_recent_completed_tasks']) ? 0 : 1,
			'roles_allowed_to_approve_tasks' => isset($_POST['roles_allowed_to_approve_tasks']) && is_array($_POST['roles_allowed_to_approve_tasks'])
				? array_map(static fn($role): string => sanitize_key(wp_unslash((string) $role)), $_POST['roles_allowed_to_approve_tasks'])
				: ['administrator'],
		];
		$result = $this->plugin->save_cloud_preferences($preferences);

		if (is_wp_error($result)) {
			freesiem_sentinel_set_notice('warning', $result->get_error_message());
			$this->redirect_to_page('freesiem-remote');
		}

		$message = !empty($result['synced'])
			? __('Cloud automation preferences were saved and synced to freeSIEM Core.', 'freesiem-sentinel')
			: __('Cloud automation preferences were saved locally and will sync after connection.', 'freesiem-sentinel');
		freesiem_sentinel_set_notice('success', $message);
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

	public function handle_approve_task(): void
	{
		$this->assert_task_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$task_id = isset($_REQUEST['task_id']) ? (int) $_REQUEST['task_id'] : 0;
		$result = $this->plugin->get_pending_tasks()->approve_task($task_id, get_current_user_id());

		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Pending task approved and executed locally.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-pending-tasks', ['task_id' => (string) $task_id]);
	}

	public function handle_deny_task(): void
	{
		$this->assert_task_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$task_id = isset($_REQUEST['task_id']) ? (int) $_REQUEST['task_id'] : 0;
		$reason = isset($_POST['deny_reason']) ? sanitize_textarea_field(wp_unslash((string) $_POST['deny_reason'])) : '';
		$result = $this->plugin->get_pending_tasks()->deny_task($task_id, get_current_user_id(), $reason);

		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Pending task denied locally.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-pending-tasks', ['task_id' => (string) $task_id]);
	}

	public function handle_tfa_enroll(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$user_id = isset($_REQUEST['user_id']) ? (int) $_REQUEST['user_id'] : 0;
		$result = $this->plugin->get_tfa_service()->start_local_enrollment($user_id);
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('TFA enrollment is ready. Complete setup with the verification code below.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-tfa', ['user_id' => (string) $user_id]);
	}

	public function handle_tfa_reset(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$user_id = isset($_REQUEST['user_id']) ? (int) $_REQUEST['user_id'] : 0;
		$result = $this->plugin->get_tfa_service()->reset_local_tfa($user_id);
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('Local TFA was reset for the selected user.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-tfa', ['user_id' => (string) $user_id]);
	}

	public function handle_tfa_complete_setup(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
		$code = isset($_POST['tfa_code']) ? wp_unslash((string) $_POST['tfa_code']) : '';
		$result = $this->plugin->get_tfa_service()->complete_pending_setup($user_id, $code);
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('TFA is now enabled for the selected user.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-tfa', ['user_id' => (string) $user_id]);
	}

	public function handle_tfa_change_password(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
		$password = isset($_POST['password']) ? wp_unslash((string) $_POST['password']) : '';
		$result = $this->plugin->get_tfa_service()->change_local_password($user_id, $password);
		freesiem_sentinel_set_notice(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : __('The local WordPress password was updated.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-tfa', ['user_id' => (string) $user_id]);
	}

	public function handle_save_ssl_settings(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$existing_settings = freesiem_sentinel_get_ssl_settings();
		$environment = freesiem_sentinel_get_ssl_environment_snapshot($existing_settings);
		$recommended_webroot = freesiem_sentinel_recommend_ssl_webroot_path($existing_settings, $environment);
		$submitted_webroot = isset($_POST['webroot_path']) ? trim((string) wp_unslash($_POST['webroot_path'])) : '';

		$settings = freesiem_sentinel_update_ssl_settings([
			'enable_management_ui' => 1,
			'acme_contact_email' => isset($_POST['acme_contact_email']) ? sanitize_email(wp_unslash((string) $_POST['acme_contact_email'])) : '',
			'hostname_override' => '',
			'allow_local_override' => 0,
			'challenge_method' => isset($_POST['challenge_method']) ? sanitize_key(wp_unslash((string) $_POST['challenge_method'])) : 'webroot-http-01',
			'webroot_path' => $submitted_webroot !== '' ? $submitted_webroot : $recommended_webroot,
			'check_port_80' => 1,
			'check_port_443' => 1,
			'force_https' => empty($_POST['force_https']) ? 0 : 1,
			'hsts_enabled' => empty($_POST['hsts_enabled']) ? 0 : 1,
			'auto_renew' => empty($_POST['auto_renew']) ? 0 : 1,
			'use_staging' => empty($_POST['use_staging']) ? 0 : 1,
			'detailed_logs' => empty($_POST['detailed_logs']) ? 0 : 1,
		]);

		$readiness = freesiem_sentinel_calculate_ssl_readiness($settings);
		freesiem_sentinel_add_ssl_log(
			'info',
			__('SSL settings were saved.', 'freesiem-sentinel'),
			'settings',
			[
				'readiness_state' => $readiness['state'],
				'challenge_method' => (string) ($settings['challenge_method'] ?? 'webroot-http-01'),
				'force_https' => !empty($settings['force_https']) ? 'enabled' : 'disabled',
			]
		);
		freesiem_sentinel_add_ssl_log(
			'info',
			sprintf(__('SSL readiness recalculated: %s.', 'freesiem-sentinel'), $readiness['label']),
			'readiness',
			['readiness_state' => $readiness['state']]
		);
		freesiem_sentinel_set_notice('success', __('SSL settings saved.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-ssl', ['tab' => 'overview']);
	}

	public function handle_run_ssl_preflight(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$preflight = freesiem_sentinel_run_ssl_preflight();
		$readiness = freesiem_sentinel_calculate_ssl_readiness();
		freesiem_sentinel_add_ssl_log('info', $preflight['summary'] ?? __('SSL preflight was run.', 'freesiem-sentinel'), 'preflight', [
			'readiness_state' => $readiness['state'],
			'fail_count' => (string) ((int) ($preflight['counts']['fail'] ?? 0)),
		]);
		freesiem_sentinel_set_notice('success', $preflight['summary'] ?? __('SSL preflight completed.', 'freesiem-sentinel'));
		$redirect_tab = isset($_POST['redirect_tab']) ? sanitize_key((string) wp_unslash($_POST['redirect_tab'])) : 'preflight';
		$this->redirect_to_page('freesiem-ssl', ['tab' => in_array($redirect_tab, ['overview', 'preflight', 'dry-run', 'logs'], true) ? $redirect_tab : 'preflight']);
	}

	public function handle_run_ssl_dry_run(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$dry_run = freesiem_sentinel_run_ssl_dry_run();
		freesiem_sentinel_add_ssl_log('info', $dry_run['summary'] ?? __('SSL dry run validation completed.', 'freesiem-sentinel'), 'dry_run', [
			'readiness_state' => (string) ($dry_run['readiness_state'] ?? 'not_configured'),
			'would_attempt_status' => (string) (($dry_run['context']['would_attempt_status'] ?? 'warn')),
		]);
		freesiem_sentinel_set_notice('success', $dry_run['summary'] ?? __('SSL dry run validation completed.', 'freesiem-sentinel'));
		$redirect_tab = isset($_POST['redirect_tab']) ? sanitize_key((string) wp_unslash($_POST['redirect_tab'])) : 'dry-run';
		$this->redirect_to_page('freesiem-ssl', ['tab' => in_array($redirect_tab, ['overview', 'preflight', 'dry-run', 'logs'], true) ? $redirect_tab : 'dry-run']);
	}

	public function handle_issue_ssl_certificate(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		freesiem_sentinel_add_ssl_log('info', __('Issue certificate was requested from wp-admin.', 'freesiem-sentinel'), 'issue_request');
		$result = freesiem_sentinel_execute_ssl_issue();
		freesiem_sentinel_add_ssl_log($this->ssl_result_log_level((string) ($result['status'] ?? 'failed')), (string) ($result['summary'] ?? __('Certificate issuance completed.', 'freesiem-sentinel')), 'issue', [
			'status' => (string) ($result['status'] ?? 'failed'),
			'action_type' => (string) ($result['action_type'] ?? 'issue'),
			'result_code' => (string) ($result['result_code'] ?? ''),
			'force_reissue' => !empty($result['force_reissue']) ? 'yes' : 'no',
		]);

		if (!empty($result['verification']['status']) && in_array((string) $result['verification']['status'], ['warning', 'failed'], true)) {
			freesiem_sentinel_add_ssl_log($this->ssl_result_log_level((string) $result['verification']['status']), (string) ($result['verification']['summary'] ?? __('Certificate verification returned a warning.', 'freesiem-sentinel')), 'verification');
		}

		$notice_level = !empty($result['success']) ? 'success' : ((string) ($result['status'] ?? '') === 'warning' ? 'warning' : 'error');
		if ((string) ($result['status'] ?? '') === 'no_action_needed') {
			$notice_level = 'warning';
		}
		freesiem_sentinel_set_notice($notice_level, (string) ($result['summary'] ?? __('Certificate issuance completed.', 'freesiem-sentinel')));
		$this->redirect_to_page('freesiem-ssl', ['tab' => 'overview']);
	}

	public function handle_renew_ssl_certificate(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		freesiem_sentinel_add_ssl_log('info', __('Renew certificate was requested from wp-admin.', 'freesiem-sentinel'), 'renew_request');
		$result = freesiem_sentinel_execute_ssl_renew();
		freesiem_sentinel_add_ssl_log($this->ssl_result_log_level((string) ($result['status'] ?? 'failed')), (string) ($result['summary'] ?? __('Certificate renewal completed.', 'freesiem-sentinel')), 'renew', [
			'status' => (string) ($result['status'] ?? 'failed'),
			'action_type' => (string) ($result['action_type'] ?? 'renew'),
			'result_code' => (string) ($result['result_code'] ?? ''),
		]);

		if (!empty($result['verification']['status']) && in_array((string) $result['verification']['status'], ['warning', 'failed'], true)) {
			freesiem_sentinel_add_ssl_log($this->ssl_result_log_level((string) $result['verification']['status']), (string) ($result['verification']['summary'] ?? __('Certificate verification returned a warning.', 'freesiem-sentinel')), 'verification');
		}

		$notice_level = !empty($result['success']) ? 'success' : ((string) ($result['status'] ?? '') === 'warning' ? 'warning' : 'error');
		if ((string) ($result['status'] ?? '') === 'no_action_needed') {
			$notice_level = 'warning';
		}
		freesiem_sentinel_set_notice($notice_level, (string) ($result['summary'] ?? __('Certificate renewal completed.', 'freesiem-sentinel')));
		$this->redirect_to_page('freesiem-ssl', ['tab' => 'overview']);
	}

	public function handle_apply_ssl_to_nginx(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$ssl_settings = freesiem_sentinel_get_ssl_settings();
		$enable_redirect = !empty($ssl_settings['force_https']) || !empty($_POST['enable_nginx_https_redirect']);
		freesiem_sentinel_add_ssl_log('info', __('Apply SSL to nginx was requested from wp-admin.', 'freesiem-sentinel'), 'nginx_apply_attempt', [
			'redirect_enabled' => $enable_redirect ? 'yes' : 'no',
		]);

		$result = freesiem_sentinel_apply_ssl_to_nginx($enable_redirect);
		$apply_category = !empty($result['success']) ? 'nginx_apply_success' : (((string) ($result['status'] ?? '') === 'failed_rolled_back') ? 'nginx_rollback' : 'nginx_apply_failure');
		freesiem_sentinel_add_ssl_log($this->ssl_result_log_level((string) ($result['status'] ?? 'failed')), (string) ($result['summary'] ?? __('Nginx SSL apply completed.', 'freesiem-sentinel')), $apply_category, [
			'status' => (string) ($result['status'] ?? 'failed'),
			'target_path' => (string) (($result['integration']['target_path'] ?? '')),
			'backup_path' => (string) ($result['backup_path'] ?? ''),
			'confidence' => (string) (($result['integration']['detection_confidence'] ?? '')),
		]);

		if (!empty($result['test'])) {
			freesiem_sentinel_add_ssl_log(!empty($result['test']['success']) ? 'success' : 'error', !empty($result['test']['success']) ? __('Nginx syntax test passed.', 'freesiem-sentinel') : __('Nginx syntax test failed.', 'freesiem-sentinel'), 'nginx_test', [
				'result' => !empty($result['test']['stderr_summary']) ? (string) $result['test']['stderr_summary'] : (string) ($result['test']['stdout_summary'] ?? ''),
			]);
		}

		if (!empty($result['reload'])) {
			freesiem_sentinel_add_ssl_log(!empty($result['reload']['success']) ? 'success' : 'error', !empty($result['reload']['success']) ? __('Nginx reload completed.', 'freesiem-sentinel') : __('Nginx reload failed.', 'freesiem-sentinel'), 'nginx_reload', [
				'result' => !empty($result['reload']['stderr_summary']) ? (string) $result['reload']['stderr_summary'] : (string) ($result['reload']['stdout_summary'] ?? ''),
			]);
		}

		$notice = (string) ($result['summary'] ?? __('Nginx SSL apply completed.', 'freesiem-sentinel'));
		if ((string) ($result['status'] ?? '') === 'manual_required' && !empty($result['manual_commands']) && is_array($result['manual_commands'])) {
			$notice .= ' ' . sprintf(
				__('Run as root: %1$s ; %2$s', 'freesiem-sentinel'),
				(string) ($result['manual_commands'][0] ?? 'nginx -t'),
				(string) ($result['manual_commands'][1] ?? 'nginx -s reload')
			);
		}
		if (!empty($result['success']) && !is_ssl() && strtolower((string) wp_parse_url(home_url('/'), PHP_URL_SCHEME)) !== 'https') {
			$notice .= ' ' . __('SSL is active at nginx, but WordPress URLs still need to be switched to HTTPS manually or in a later phase.', 'freesiem-sentinel');
		}

		$notice_level = !empty($result['success']) ? 'success' : (((string) ($result['status'] ?? '') === 'manual_required') ? 'warning' : 'error');
		freesiem_sentinel_set_notice($notice_level, $notice);
		$this->redirect_to_page('freesiem-ssl', ['tab' => 'overview']);
	}

	public function handle_detect_nginx_config(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		freesiem_sentinel_add_ssl_log('info', __('Active nginx config detection was requested from wp-admin.', 'freesiem-sentinel'), 'nginx_detect_attempt');
		$ssl_settings = freesiem_sentinel_get_ssl_settings();
		$environment = freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
		$ssl_state = freesiem_sentinel_get_ssl_state();
		$integration = freesiem_sentinel_detect_nginx_integration($ssl_settings, $environment, $ssl_state);
		freesiem_sentinel_update_ssl_state([
			'nginx_integration_mode' => (string) ($integration['mode'] ?? 'manual_required'),
			'nginx_detection_source' => (string) ($integration['detection_source'] ?? 'nginx_t'),
			'nginx_detection_confidence' => (string) ($integration['detection_confidence'] ?? 'ambiguous'),
			'nginx_matched_server_name' => (string) ($integration['matched_server_name'] ?? ''),
			'nginx_config_path' => (string) ($integration['target_path'] ?? ''),
			'nginx_last_detect_result' => (string) ($integration['detection_result'] ?? __('Nginx detection completed.', 'freesiem-sentinel')),
			'nginx_last_detect_at' => freesiem_sentinel_get_iso8601_time(),
		]);
		$level = match ((string) ($integration['detection_confidence'] ?? 'ambiguous')) {
			'exact' => 'success',
			'probable' => 'warning',
			default => 'error',
		};
		$category = (string) ($integration['detection_confidence'] ?? '') === 'ambiguous' ? 'nginx_detect_ambiguous' : 'nginx_detect_success';
		freesiem_sentinel_add_ssl_log($level, (string) ($integration['detection_result'] ?? __('Nginx detection completed.', 'freesiem-sentinel')), $category, [
			'config_path' => (string) ($integration['target_path'] ?? ''),
			'matched_domain' => (string) ($integration['matched_server_name'] ?? ''),
			'confidence' => (string) ($integration['detection_confidence'] ?? 'ambiguous'),
		]);
		if (!empty($integration['permissions_blocked'])) {
			$guidance = freesiem_sentinel_get_nginx_permission_guidance($integration, $environment);
			freesiem_sentinel_add_ssl_log('warning', __('Automatic nginx apply is currently blocked by filesystem permissions.', 'freesiem-sentinel'), 'nginx_permission_guidance', [
				'paths' => array_values(array_map(static fn(array $item): string => (string) ($item['path'] ?? ''), (array) ($guidance['items'] ?? []))),
				'web_user' => (string) ($guidance['web_user']['user'] ?? ''),
			]);
		}

		$notice_level = (string) ($integration['detection_confidence'] ?? '') === 'exact' ? 'success' : ((string) ($integration['detection_confidence'] ?? '') === 'probable' ? 'warning' : 'error');
		freesiem_sentinel_set_notice($notice_level, (string) ($integration['detection_result'] ?? __('Nginx detection completed.', 'freesiem-sentinel')));
		$this->redirect_to_page('freesiem-ssl', ['tab' => 'overview']);
	}

	public function handle_install_certbot(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		if (empty($_POST['confirm_certbot_install'])) {
			freesiem_sentinel_set_notice('error', __('Confirm that you understand certbot installation requires server-level permissions before continuing.', 'freesiem-sentinel'));
			$this->redirect_to_page('freesiem-ssl', ['tab' => 'overview']);
		}

		$environment = freesiem_sentinel_detect_ssl_install_environment();
		freesiem_sentinel_add_ssl_log('info', __('Certbot install environment was detected.', 'freesiem-sentinel'), 'environment_detected', [
			'os_family' => (string) ($environment['os_family'] ?? 'unknown'),
			'install_method' => (string) ($environment['install_method'] ?? ''),
			'root_status' => (string) ($environment['root_status'] ?? 'unknown'),
		]);
		freesiem_sentinel_add_ssl_log('info', __('Certbot install was requested from wp-admin.', 'freesiem-sentinel'), 'install_attempt', [
			'install_method' => (string) ($environment['install_method'] ?? ''),
		]);

		$result = freesiem_sentinel_install_certbot();
		freesiem_sentinel_add_ssl_log(
			!empty($result['success']) ? 'success' : 'error',
			(string) ($result['summary'] ?? __('Certbot installation completed.', 'freesiem-sentinel')),
			!empty($result['success']) ? 'install_success' : 'install_failure',
			[
				'install_method' => (string) (($result['install_environment']['install_method'] ?? '')),
				'root_status' => (string) (($result['install_environment']['root_status'] ?? 'unknown')),
			]
		);

		$readiness = freesiem_sentinel_calculate_ssl_readiness();
		freesiem_sentinel_add_ssl_log('info', sprintf(__('SSL readiness recalculated: %s.', 'freesiem-sentinel'), $readiness['label']), 'readiness', [
			'readiness_state' => (string) ($readiness['state'] ?? 'not_configured'),
		]);

		freesiem_sentinel_set_notice(!empty($result['success']) ? 'success' : 'error', (string) ($result['summary'] ?? __('Certbot installation completed.', 'freesiem-sentinel')));
		$this->redirect_to_page('freesiem-ssl', ['tab' => 'overview']);
	}

	public function handle_save_login_protection(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		freesiem_sentinel_update_login_protection_settings([
			'enabled' => empty($_POST['enabled']) ? 0 : 1,
			'max_failed_attempts' => isset($_POST['max_failed_attempts']) ? (int) $_POST['max_failed_attempts'] : 5,
			'lockout_duration_minutes' => isset($_POST['lockout_duration_minutes']) ? (int) $_POST['lockout_duration_minutes'] : 15,
			'track_failed_login_count' => empty($_POST['track_failed_login_count']) ? 0 : 1,
			'log_successful_logins' => empty($_POST['log_successful_logins']) ? 0 : 1,
			'log_failed_logins' => empty($_POST['log_failed_logins']) ? 0 : 1,
		]);

		freesiem_sentinel_set_notice('success', __('Login Protection settings saved.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-login-protection');
	}

	public function handle_save_stealth_mode(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();

		$settings = freesiem_sentinel_update_stealth_mode_settings([
			'enabled' => empty($_POST['enabled']) ? 0 : 1,
			'custom_login_slug' => isset($_POST['custom_login_slug']) ? sanitize_title(wp_unslash((string) $_POST['custom_login_slug'])) : 'sentinel-login',
			'block_direct_wp_login' => empty($_POST['block_direct_wp_login']) ? 0 : 1,
			'redirect_wp_admin_guests' => empty($_POST['redirect_wp_admin_guests']) ? 0 : 1,
		]);

		freesiem_sentinel_set_notice('success', sprintf(__('Stealth Mode settings saved. Current login URL: %s', 'freesiem-sentinel'), freesiem_sentinel_get_stealth_login_url($settings)));
		$this->redirect_to_page('freesiem-stealth-mode');
	}

	public function handle_clear_logs(): void
	{
		$this->assert_manage_permissions();
		freesiem_sentinel_require_admin_post_nonce();
		freesiem_sentinel_clear_log_rows();
		freesiem_sentinel_set_notice('success', __('Sentinel logs cleared.', 'freesiem-sentinel'));
		$this->redirect_to_page('freesiem-logs');
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
		echo '<h1>' . esc_html__('Dashboard', 'freesiem-sentinel') . '</h1>';
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

	public function render_login_protection_page(): void
	{
		$this->assert_manage_permissions();
		$settings = freesiem_sentinel_get_login_protection_settings();
		$current_state = freesiem_sentinel_get_login_lockout_state();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Login Protection', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Configure lightweight login attempt tracking and lockout behavior for WordPress sign-in events.', 'freesiem-sentinel') . '</p>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_save_login_protection" />';
		echo '<table class="form-table" role="presentation">';
		$this->render_ssl_checkbox_field('enabled', __('Enable login protection', 'freesiem-sentinel'), !empty($settings['enabled']), __('When enabled, Sentinel tracks failed logins and temporarily locks out repeated attempts.', 'freesiem-sentinel'));
		echo '<tr><th scope="row"><label for="freesiem-max-failed-attempts">' . esc_html__('Max failed login attempts', 'freesiem-sentinel') . '</label></th><td><input id="freesiem-max-failed-attempts" type="number" min="1" max="20" name="max_failed_attempts" value="' . esc_attr((string) ($settings['max_failed_attempts'] ?? 5)) . '" class="small-text" /></td></tr>';
		echo '<tr><th scope="row"><label for="freesiem-lockout-duration">' . esc_html__('Lockout duration (minutes)', 'freesiem-sentinel') . '</label></th><td><input id="freesiem-lockout-duration" type="number" min="1" max="1440" name="lockout_duration_minutes" value="' . esc_attr((string) ($settings['lockout_duration_minutes'] ?? 15)) . '" class="small-text" /></td></tr>';
		$this->render_ssl_checkbox_field('track_failed_login_count', __('Track failed login count', 'freesiem-sentinel'), !empty($settings['track_failed_login_count']), __('Stores the current failed-attempt counter per username/IP key for lockout evaluation.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('log_successful_logins', __('Log successful logins', 'freesiem-sentinel'), !empty($settings['log_successful_logins']), __('Adds wp_login events to the Sentinel Logs page.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('log_failed_logins', __('Log failed logins', 'freesiem-sentinel'), !empty($settings['log_failed_logins']), __('Adds wp_login_failed and lockout events to the Sentinel Logs page.', 'freesiem-sentinel'));
		echo '</table>';
		submit_button(__('Save Login Protection Settings', 'freesiem-sentinel'));
		echo '</form>';
		echo '<p><strong>' . esc_html__('Current failed-attempt state', 'freesiem-sentinel') . ':</strong> ' . esc_html(sprintf(__('count=%1$d locked_until=%2$s', 'freesiem-sentinel'), (int) ($current_state['count'] ?? 0), !empty($current_state['locked_until']) ? gmdate('Y-m-d H:i:s', (int) $current_state['locked_until']) : __('not locked', 'freesiem-sentinel'))) . '</p>';
		echo '</div>';
	}

	public function render_stealth_mode_page(): void
	{
		$this->assert_manage_permissions();
		$settings = freesiem_sentinel_get_stealth_mode_settings();
		$current_login_url = freesiem_sentinel_get_stealth_login_url($settings);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Stealth Mode', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Configure a safer login entry URL without introducing fragile rewrite-rule changes.', 'freesiem-sentinel') . '</p>';
		echo '<div class="notice notice-warning inline"><p>' . esc_html__('Changing login access can lock you out. Keep another administrator session open before enabling Stealth Mode changes.', 'freesiem-sentinel') . '</p></div>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_save_stealth_mode" />';
		echo '<table class="form-table" role="presentation">';
		$this->render_ssl_checkbox_field('enabled', __('Enable stealth mode', 'freesiem-sentinel'), !empty($settings['enabled']), __('Turns on Sentinel login obfuscation handling for the custom login URL below.', 'freesiem-sentinel'));
		echo '<tr><th scope="row"><label for="freesiem-stealth-slug">' . esc_html__('Custom login slug', 'freesiem-sentinel') . '</label></th><td><input id="freesiem-stealth-slug" type="text" name="custom_login_slug" value="' . esc_attr((string) ($settings['custom_login_slug'] ?? 'sentinel-login')) . '" class="regular-text" /><p class="description">' . esc_html__('Sentinel uses this as a safe query-based login token rather than adding rewrite rules.', 'freesiem-sentinel') . '</p></td></tr>';
		$this->render_ssl_checkbox_field('block_direct_wp_login', __('Block direct wp-login.php access', 'freesiem-sentinel'), !empty($settings['block_direct_wp_login']), __('When enabled, direct wp-login.php requests without the Sentinel login token are redirected away.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('redirect_wp_admin_guests', __('Redirect unauthenticated wp-admin users', 'freesiem-sentinel'), !empty($settings['redirect_wp_admin_guests']), __('When enabled, guests trying to access wp-admin are sent to the Sentinel login URL.', 'freesiem-sentinel'));
		echo '</table>';
		submit_button(__('Save Stealth Mode Settings', 'freesiem-sentinel'));
		echo '</form>';
		echo '<p><strong>' . esc_html__('Current login URL', 'freesiem-sentinel') . ':</strong> <code>' . esc_html($current_login_url) . '</code></p>';
		echo '<p style="color:#646970;">' . esc_html__('Stealth Mode currently uses a query-based login URL for safety. This avoids rewrite-rule complexity while still allowing direct wp-login.php blocking and guest wp-admin redirects.', 'freesiem-sentinel') . '</p>';
		echo '</div>';
	}

	public function render_logs_page(): void
	{
		$this->assert_manage_permissions();
		$selected_type = isset($_GET['event_type']) ? sanitize_key((string) wp_unslash($_GET['event_type'])) : '';
		$rows = freesiem_sentinel_get_log_rows($selected_type, 200);
		$types = freesiem_sentinel_get_log_event_types();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Logs', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Review lightweight login, stealth, TFA, and related Sentinel events.', 'freesiem-sentinel') . '</p>';
		echo '<form method="get" style="margin:0 0 14px 0;display:flex;gap:10px;align-items:center;flex-wrap:wrap;">';
		echo '<input type="hidden" name="page" value="freesiem-logs" />';
		echo '<label for="freesiem-log-type">' . esc_html__('Event type', 'freesiem-sentinel') . '</label>';
		echo '<select id="freesiem-log-type" name="event_type"><option value="">' . esc_html__('All events', 'freesiem-sentinel') . '</option>';
		foreach ($types as $type) {
			echo '<option value="' . esc_attr($type) . '" ' . selected($selected_type, $type, false) . '>' . esc_html($type) . '</option>';
		}
		echo '</select>';
		submit_button(__('Filter', 'freesiem-sentinel'), 'secondary', '', false);
		echo '</form>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin:0 0 14px 0;">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_clear_logs" />';
		submit_button(__('Clear Logs', 'freesiem-sentinel'), 'delete', '', false, ['onclick' => "return confirm('" . esc_js(__('Clear all Sentinel log rows?', 'freesiem-sentinel')) . "');"]);
		echo '</form>';
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Timestamp', 'freesiem-sentinel') . '</th><th>' . esc_html__('Event Type', 'freesiem-sentinel') . '</th><th>' . esc_html__('Username', 'freesiem-sentinel') . '</th><th>' . esc_html__('IP', 'freesiem-sentinel') . '</th><th>' . esc_html__('Message / Details', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
		if ($rows === []) {
			echo '<tr><td colspan="5">' . esc_html__('No log events recorded yet.', 'freesiem-sentinel') . '</td></tr>';
		} else {
			foreach ($rows as $row) {
				$message = (string) ($row['message'] ?? '');
				$context = !empty($row['context']) ? json_decode((string) $row['context'], true) : null;
				if (is_array($context) && $context !== []) {
					$message .= ' ' . wp_json_encode($context);
				}
				echo '<tr>';
				echo '<td>' . esc_html(freesiem_sentinel_format_datetime((string) ($row['created_at'] ?? ''))) . '</td>';
				echo '<td>' . esc_html((string) ($row['event_type'] ?? '')) . '</td>';
				echo '<td>' . esc_html((string) ($row['username'] ?? '')) . '</td>';
				echo '<td>' . esc_html((string) ($row['ip_address'] ?? '')) . '</td>';
				echo '<td>' . esc_html($message) . '</td>';
				echo '</tr>';
			}
		}
		echo '</tbody></table>';
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
		$can_connect = is_email($email) && freesiem_sentinel_is_valid_us_phone((string) ($settings['phone'] ?? ''));
		$site_id = safe($settings['site_id'] ?? '');
		$last_heartbeat = $this->summary_value_or_fallback($settings['last_heartbeat_at'] ?? '', true);
		$last_heartbeat_result = safe($settings['last_heartbeat_result'] ?? '');

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('freeSIEM Cloud', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Connect this site to freeSIEM Core, verify ownership, and manage signed Cloud Connect communication.', 'freesiem-sentinel') . '</p>';

		echo '<div style="display:grid;grid-template-columns:minmax(0,2fr) minmax(280px,1fr);gap:20px;align-items:start;">';
		echo '<div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Cloud Connect', 'freesiem-sentinel') . '</h2>';

		if (in_array($state, ['suspended', 'revoked'], true)) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__('This Cloud Connect session is no longer active. Disconnect locally, then reconnect to establish a new session.', 'freesiem-sentinel') . '</p></div>';
		}

		if ($is_connected) {
			echo '<div style="margin-top:16px;padding:16px;border-radius:12px;background:#ecfdf5;border:1px solid #a7f3d0;">';
			echo '<p style="margin:0 0 10px;font-weight:700;color:#166534;">' . esc_html__('Connected', 'freesiem-sentinel') . '</p>';
			echo '<p style="margin:0 0 8px;">' . esc_html__('This site can send signed heartbeats to freeSIEM Core.', 'freesiem-sentinel') . '</p>';
			echo '<p style="margin:0;"><strong>' . esc_html__('Site ID', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->friendly_site_id($site_id)) . '</p>';
			echo '</div>';
			echo '<p style="margin-top:16px;"><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_cloud_connect_test')) . '">' . esc_html__('Test Connection', 'freesiem-sentinel') . '</a> ';
			echo '<a class="button button-secondary" onclick="return confirm(\''
				. esc_js(__('Disconnect this site from freeSIEM Cloud?', 'freesiem-sentinel'))
				. '\');" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_cloud_connect_disconnect')) . '">' . esc_html__('Disconnect', 'freesiem-sentinel') . '</a></p>';
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
			echo '<p style="margin-top:16px;">' . esc_html__('Save this site contact info locally first, then connect using the saved email and phone number.', 'freesiem-sentinel') . '</p>';
			echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
			wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
			echo '<input type="hidden" name="action" value="freesiem_sentinel_save_cloud_connect_contact" />';
			echo '<table class="form-table" role="presentation">';
			echo '<tr><th scope="row"><label for="freesiem-cloud-connect-email">' . esc_html__('Email', 'freesiem-sentinel') . '</label></th><td><input class="regular-text" id="freesiem-cloud-connect-email" name="email" type="email" value="' . esc_attr($email) . '" required /></td></tr>';
			echo '<tr><th scope="row"><label for="freesiem-cloud-connect-phone">' . esc_html__('US Phone Number', 'freesiem-sentinel') . '</label></th><td><input class="regular-text" id="freesiem-cloud-connect-phone" name="phone" type="tel" value="' . esc_attr($phone) . '" placeholder="+1 (555) 234-5678" required /></td></tr>';
			echo '</table>';
			submit_button(__('Save', 'freesiem-sentinel'), 'secondary', '', false);
			echo '</form>';
			echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:12px;">';
			wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
			echo '<input type="hidden" name="action" value="freesiem_sentinel_cloud_connect_start" />';
			submit_button(__('Connect', 'freesiem-sentinel'), 'primary', '', false, $can_connect ? [] : ['disabled' => 'disabled']);
			if (!$can_connect) {
				echo '<p class="description" style="margin-top:8px;">' . esc_html__('Save a valid email and US phone number to enable Connect.', 'freesiem-sentinel') . '</p>';
			}
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
		echo '<p><label><input type="checkbox" name="user_sync_enabled" value="1"' . checked(!empty($settings['user_sync_enabled']), true, false) . ' /> ' . esc_html__('Enable Centralized User Sync', 'freesiem-sentinel') . '</label><br /><span style="color:#50575e;">' . esc_html__('Enable centralized user sync so this site can share managed users with the freeSIEM client portal. This allows authorized users to be synced across multiple WordPress sites and managed centrally, including password updates and future security controls like TFA.', 'freesiem-sentinel') . '</span></p>';
		echo '<hr style="margin:20px 0;" />';
		echo '<h3 style="margin-top:0;">' . esc_html__('Pending Task Approvals', 'freesiem-sentinel') . '</h3>';
		echo '<p><label><input type="checkbox" name="enable_pending_task_queue" value="1"' . checked(!empty($settings['enable_pending_task_queue']), true, false) . ' /> ' . esc_html__('Enable the Pending Tasks approval queue', 'freesiem-sentinel') . '</label></p>';
		echo '<p><label><input type="checkbox" name="auto_approve_enabled_default" value="1"' . checked(!empty($settings['auto_approve_enabled_default']), true, false) . ' /> ' . esc_html__('Allow eligible tasks to auto-approve after a timeout', 'freesiem-sentinel') . '</label></p>';
		echo '<p><label>' . esc_html__('Default auto-approve timeout (minutes)', 'freesiem-sentinel') . '<br /><input type="number" min="1" max="1440" name="auto_approve_after_minutes_default" value="' . esc_attr((string) ($settings['auto_approve_after_minutes_default'] ?? 30)) . '" /></label></p>';
		echo '<p style="margin-bottom:8px;"><strong>' . esc_html__('Require Manual Approval', 'freesiem-sentinel') . '</strong></p>';
		foreach ([
			'require_manual_approval_for_list_users' => __('List users', 'freesiem-sentinel'),
			'require_manual_approval_for_create_user' => __('Create user', 'freesiem-sentinel'),
			'require_manual_approval_for_update_user' => __('Update user', 'freesiem-sentinel'),
			'require_manual_approval_for_password_reset' => __('Send password reset', 'freesiem-sentinel'),
			'require_manual_approval_for_delete_user' => __('Delete user', 'freesiem-sentinel'),
		] as $key => $label) {
			echo '<p style="margin:0 0 6px;"><label><input type="checkbox" name="' . esc_attr($key) . '" value="1"' . checked(!empty($settings[$key]), true, false) . ' /> ' . esc_html($label) . '</label></p>';
		}
		echo '<p style="margin:16px 0 8px;"><strong>' . esc_html__('Allow Auto-Approve', 'freesiem-sentinel') . '</strong></p>';
		foreach ([
			'allow_auto_approve_list_users' => __('List users', 'freesiem-sentinel'),
			'allow_auto_approve_create_user' => __('Create user', 'freesiem-sentinel'),
			'allow_auto_approve_update_user' => __('Update user', 'freesiem-sentinel'),
			'allow_auto_approve_password_reset' => __('Send password reset', 'freesiem-sentinel'),
			'allow_auto_approve_delete_user' => __('Delete user', 'freesiem-sentinel'),
		] as $key => $label) {
			echo '<p style="margin:0 0 6px;"><label><input type="checkbox" name="' . esc_attr($key) . '" value="1"' . checked(!empty($settings[$key]), true, false) . ' /> ' . esc_html($label) . '</label></p>';
		}
		$roles = function_exists('wp_roles') && wp_roles() ? wp_roles()->roles : [];
		echo '<p style="margin:16px 0 8px;"><strong>' . esc_html__('Roles Allowed To Approve Tasks', 'freesiem-sentinel') . '</strong></p>';
		foreach ($roles as $role_key => $role) {
			echo '<p style="margin:0 0 6px;"><label><input type="checkbox" name="roles_allowed_to_approve_tasks[]" value="' . esc_attr((string) $role_key) . '"' . checked(in_array((string) $role_key, (array) ($settings['roles_allowed_to_approve_tasks'] ?? []), true), true, false) . ' /> ' . esc_html(translate_user_role((string) ($role['name'] ?? $role_key))) . '</label></p>';
		}
		echo '<p><label><input type="checkbox" name="notify_admins_on_pending_task" value="1"' . checked(!empty($settings['notify_admins_on_pending_task']), true, false) . ' /> ' . esc_html__('Notify the site admin email when a task enters the queue', 'freesiem-sentinel') . '</label></p>';
		echo '<p><label><input type="checkbox" name="include_pending_tasks_in_heartbeat" value="1"' . checked(!empty($settings['include_pending_tasks_in_heartbeat']), true, false) . ' /> ' . esc_html__('Include pending task data in heartbeats', 'freesiem-sentinel') . '</label></p>';
		echo '<p><label><input type="checkbox" name="heartbeat_include_recent_completed_tasks" value="1"' . checked(!empty($settings['heartbeat_include_recent_completed_tasks']), true, false) . ' /> ' . esc_html__('Include recent completed and denied task updates in heartbeats', 'freesiem-sentinel') . '</label></p>';
		submit_button(__('Save Cloud Preferences', 'freesiem-sentinel'));
		echo '</form>';
		echo '</div>';
		echo '</div>';

		echo '<div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Status', 'freesiem-sentinel') . '</h2>';
		echo '<table class="widefat striped" style="border:none;box-shadow:none;"><tbody>';
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

	public function render_pending_tasks_page(): void
	{
		$this->assert_task_permissions();

		$service = $this->plugin->get_pending_tasks();
		$task_id = isset($_GET['task_id']) ? (int) $_GET['task_id'] : 0;
		$status_filter = isset($_GET['status']) ? sanitize_key(wp_unslash((string) $_GET['status'])) : '';
		$search = isset($_GET['s']) ? sanitize_text_field(wp_unslash((string) $_GET['s'])) : '';
		$task = $task_id > 0 ? $service->get_task($task_id) : null;

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('Pending Tasks', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Review signed remote user-management requests from freeSIEM Core before they execute locally in WordPress.', 'freesiem-sentinel') . '</p>';

		if (is_array($task)) {
			$this->render_pending_task_detail($task);
			echo '</div>';
			return;
		}

		$tasks = $service->list_tasks([
			'status' => $status_filter,
			'search' => $search,
			'limit' => 100,
		]);
		$summary = $service->build_heartbeat_payload(freesiem_sentinel_get_settings());

		echo '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:20px 0;">';
		$this->render_summary_stat(__('Pending', 'freesiem-sentinel'), (string) (($summary['task_status_summary']['pending'] ?? 0)));
		$this->render_summary_stat(__('Approved', 'freesiem-sentinel'), (string) (($summary['task_status_summary']['approved'] ?? 0)));
		$this->render_summary_stat(__('Auto Approved', 'freesiem-sentinel'), (string) (($summary['task_status_summary']['auto_approved'] ?? 0)));
		$this->render_summary_stat(__('Completed', 'freesiem-sentinel'), (string) (($summary['task_status_summary']['completed'] ?? 0)));
		$this->render_summary_stat(__('Failed', 'freesiem-sentinel'), (string) (($summary['task_status_summary']['failed'] ?? 0)));
		echo '</div>';

		echo '<div style="background:#fff;padding:16px 18px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<form method="get" action="' . esc_url(admin_url('admin.php')) . '" style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end;">';
		echo '<input type="hidden" name="page" value="freesiem-pending-tasks" />';
		echo '<p style="margin:0;"><label>' . esc_html__('Status', 'freesiem-sentinel') . '<br /><select name="status"><option value="">' . esc_html__('All statuses', 'freesiem-sentinel') . '</option>';
		foreach ($service->get_status_options() as $status) {
			echo '<option value="' . esc_attr($status) . '"' . selected($status_filter === $status, true, false) . '>' . esc_html(ucwords(str_replace('_', ' ', $status))) . '</option>';
		}
		echo '</select></label></p>';
		echo '<p style="margin:0;"><label>' . esc_html__('Search', 'freesiem-sentinel') . '<br /><input class="regular-text" type="search" name="s" value="' . esc_attr($search) . '" /></label></p>';
		echo '<p style="margin:0;"><button type="submit" class="button button-secondary">' . esc_html__('Filter Tasks', 'freesiem-sentinel') . '</button></p>';
		echo '</form>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Task Queue', 'freesiem-sentinel') . '</h2>';

		if ($tasks === []) {
			$this->render_empty_state(__('No tasks yet.', 'freesiem-sentinel'), __('Pending task requests from freeSIEM Core will appear here as they are submitted.', 'freesiem-sentinel'));
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Task ID', 'freesiem-sentinel') . '</th><th>' . esc_html__('Core Task ID', 'freesiem-sentinel') . '</th><th>' . esc_html__('Action', 'freesiem-sentinel') . '</th><th>' . esc_html__('Target', 'freesiem-sentinel') . '</th><th>' . esc_html__('Requested At', 'freesiem-sentinel') . '</th><th>' . esc_html__('Auto Approve At', 'freesiem-sentinel') . '</th><th>' . esc_html__('Status', 'freesiem-sentinel') . '</th><th>' . esc_html__('Source', 'freesiem-sentinel') . '</th><th>' . esc_html__('Actions', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
			foreach ($tasks as $row) {
				$view_url = freesiem_sentinel_admin_page_url('freesiem-pending-tasks', ['task_id' => (string) ($row['id'] ?? 0)]);
				$approve_url = freesiem_sentinel_admin_post_url('freesiem_sentinel_approve_task', ['task_id' => (string) ($row['id'] ?? 0)]);
				echo '<tr>';
				echo '<td><a href="' . esc_url($view_url) . '">#' . esc_html((string) ($row['id'] ?? 0)) . '</a></td>';
				echo '<td><code>' . esc_html((string) ($row['core_task_id'] ?? '')) . '</code></td>';
				echo '<td>' . esc_html(ucwords(str_replace('_', ' ', (string) ($row['action_type'] ?? '')))) . '</td>';
				echo '<td>' . esc_html($this->task_target_summary($row)) . '</td>';
				echo '<td>' . esc_html(freesiem_sentinel_format_datetime((string) ($row['requested_at'] ?? ''))) . '</td>';
				echo '<td>' . esc_html(!empty($row['auto_approve_at']) ? freesiem_sentinel_format_datetime((string) $row['auto_approve_at']) : __('Manual only', 'freesiem-sentinel')) . '</td>';
				echo '<td><span style="' . esc_attr($this->task_status_badge_style((string) ($row['status'] ?? 'pending'))) . '">' . esc_html(ucwords(str_replace('_', ' ', (string) ($row['status'] ?? 'pending')))) . '</span></td>';
				echo '<td>' . esc_html((string) ($row['source_core_identifier'] ?? 'freeSIEM Core')) . '</td>';
				echo '<td><a class="button button-secondary" href="' . esc_url($view_url) . '">' . esc_html__('View', 'freesiem-sentinel') . '</a> ';
				if (($row['status'] ?? '') === 'pending') {
					echo '<a class="button button-primary" href="' . esc_url($approve_url) . '">' . esc_html__('Approve', 'freesiem-sentinel') . '</a>';
				}
				echo '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
		echo '</div>';
	}

	public function render_tfa_page(): void
	{
		$this->assert_manage_permissions();

		$service = $this->plugin->get_tfa_service();
		$selected_user_id = isset($_GET['user_id']) ? (int) $_GET['user_id'] : 0;
		$selected_user = $selected_user_id > 0 ? get_user_by('id', $selected_user_id) : null;
		$selected_state = $selected_user instanceof WP_User ? $service->get_user_tfa_state((int) $selected_user->ID) : null;
		$selected_secret = $selected_user instanceof WP_User && is_array($selected_state) && $selected_state['tfa_status'] === Freesiem_TFA_Service::STATUS_PENDING_SETUP
			? $service->get_secret((int) $selected_user->ID)
			: '';
		$selected_otpauth = $selected_user instanceof WP_User && is_string($selected_secret) && $selected_secret !== ''
			? $service->build_otpauth_uri($selected_user, $selected_secret)
			: '';
		$users = get_users(['orderby' => 'login', 'order' => 'ASC']);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('TFA (2FA)', 'freesiem-sentinel') . '</h1>';
		echo '<p>' . esc_html__('Manage local and Core-managed TFA state for WordPress users without exposing secrets in APIs, logs, or status payloads.', 'freesiem-sentinel') . '</p>';

		echo '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:20px 0;">';
		$this->render_summary_stat(__('Enabled', 'freesiem-sentinel'), (string) count(array_filter($users, fn($user): bool => $user instanceof WP_User && $service->get_user_tfa_state((int) $user->ID)['tfa_status'] === Freesiem_TFA_Service::STATUS_ENABLED)));
		$this->render_summary_stat(__('Pending Setup', 'freesiem-sentinel'), (string) count(array_filter($users, fn($user): bool => $user instanceof WP_User && $service->get_user_tfa_state((int) $user->ID)['tfa_status'] === Freesiem_TFA_Service::STATUS_PENDING_SETUP)));
		$this->render_summary_stat(__('Core Managed', 'freesiem-sentinel'), (string) count(array_filter($users, fn($user): bool => $user instanceof WP_User && $service->is_core_managed((int) $user->ID))));
		$this->render_summary_stat(__('Local Managed', 'freesiem-sentinel'), (string) count(array_filter($users, fn($user): bool => $user instanceof WP_User && !$service->is_core_managed((int) $user->ID))));
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('User TFA Status', 'freesiem-sentinel') . '</h2>';
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Username', 'freesiem-sentinel') . '</th><th>' . esc_html__('Email', 'freesiem-sentinel') . '</th><th>' . esc_html__('Status', 'freesiem-sentinel') . '</th><th>' . esc_html__('Source', 'freesiem-sentinel') . '</th><th>' . esc_html__('Managed By', 'freesiem-sentinel') . '</th><th>' . esc_html__('Last Verified', 'freesiem-sentinel') . '</th><th>' . esc_html__('Actions', 'freesiem-sentinel') . '</th></tr></thead><tbody>';

		foreach ($users as $user) {
			if (!$user instanceof WP_User) {
				continue;
			}

			$state = $service->get_user_tfa_state((int) $user->ID);
			$view_url = freesiem_sentinel_admin_page_url('freesiem-tfa', ['user_id' => (string) $user->ID]);
			$enroll_url = freesiem_sentinel_admin_post_url('freesiem_sentinel_tfa_enroll', ['user_id' => (string) $user->ID]);
			$reset_url = freesiem_sentinel_admin_post_url('freesiem_sentinel_tfa_reset', ['user_id' => (string) $user->ID]);
			echo '<tr>';
			echo '<td><a href="' . esc_url($view_url) . '"><strong>' . esc_html((string) $user->user_login) . '</strong></a></td>';
			echo '<td>' . esc_html((string) $user->user_email) . '</td>';
			echo '<td><span style="' . esc_attr($this->tfa_status_badge_style($state['tfa_status'])) . '">' . esc_html($this->format_tfa_label($state['tfa_status'])) . '</span></td>';
			echo '<td><span style="' . esc_attr($this->tfa_meta_badge_style($state['tfa_source'])) . '">' . esc_html(ucfirst($state['tfa_source'])) . '</span></td>';
			echo '<td><span style="' . esc_attr($this->tfa_meta_badge_style($state['tfa_managed'])) . '">' . esc_html(ucfirst($state['tfa_managed'])) . '</span></td>';
			echo '<td>' . esc_html($state['last_verified_at'] !== '' ? freesiem_sentinel_format_datetime($state['last_verified_at']) : __('Never', 'freesiem-sentinel')) . '</td>';
			echo '<td><a class="button button-secondary" href="' . esc_url($view_url) . '">' . esc_html__('View', 'freesiem-sentinel') . '</a> ';
			if ($service->local_actions_allowed((int) $user->ID)) {
				echo '<a class="button button-secondary" href="' . esc_url($enroll_url) . '">' . esc_html__('Enroll TFA', 'freesiem-sentinel') . '</a> ';
				echo '<a class="button button-secondary" href="' . esc_url($reset_url) . '">' . esc_html__('Reset TFA', 'freesiem-sentinel') . '</a>';
			} else {
				echo '<span style="color:#50575e;">' . esc_html__('Core-managed', 'freesiem-sentinel') . '</span>';
			}
			echo '</td>';
			echo '</tr>';
		}

		echo '</tbody></table>';
		echo '</div>';

		if ($selected_user instanceof WP_User && is_array($selected_state)) {
			echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-top:20px;">';
			echo '<h2 style="margin-top:0;">' . esc_html(sprintf(__('TFA Details: %s', 'freesiem-sentinel'), $selected_user->user_login)) . '</h2>';
			echo '<p><strong>' . esc_html__('Status', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->format_tfa_label($selected_state['tfa_status'])) . '</p>';
			echo '<p><strong>' . esc_html__('Managed By', 'freesiem-sentinel') . ':</strong> ' . esc_html(ucfirst($selected_state['tfa_managed'])) . '</p>';

			if ($selected_state['tfa_managed'] === Freesiem_TFA_Service::MANAGED_CORE) {
				echo '<p style="color:#50575e;">' . esc_html__('This account is Core-managed. Local enroll, reset, and password changes are disabled, but local WordPress login enforcement still applies.', 'freesiem-sentinel') . '</p>';
			} else {
				echo '<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">';
				echo '<div>';
				echo '<h3 style="margin-top:0;">' . esc_html__('Change Password', 'freesiem-sentinel') . '</h3>';
				echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
				wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
				echo '<input type="hidden" name="action" value="freesiem_sentinel_tfa_change_password" />';
				echo '<input type="hidden" name="user_id" value="' . esc_attr((string) $selected_user->ID) . '" />';
				echo '<p><label>' . esc_html__('New Password', 'freesiem-sentinel') . '<br /><input type="text" name="password" class="regular-text" value="" autocomplete="new-password" /></label></p>';
				echo '<p><button type="submit" class="button button-primary">' . esc_html__('Change Password', 'freesiem-sentinel') . '</button></p>';
				echo '</form>';
				echo '</div>';

				echo '<div>';
				echo '<h3 style="margin-top:0;">' . esc_html__('Enrollment', 'freesiem-sentinel') . '</h3>';
				if ($selected_state['tfa_status'] === Freesiem_TFA_Service::STATUS_PENDING_SETUP && is_string($selected_secret) && $selected_secret !== '') {
					echo '<p>' . esc_html__('Scan the setup data with an authenticator app, then submit the first verification code.', 'freesiem-sentinel') . '</p>';
					echo '<p><strong>' . esc_html__('Manual Setup Key', 'freesiem-sentinel') . ':</strong><br /><code>' . esc_html($selected_secret) . '</code></p>';
					echo '<p><strong>' . esc_html__('Authenticator URI', 'freesiem-sentinel') . ':</strong><br /><code style="word-break:break-all;">' . esc_html($selected_otpauth) . '</code></p>';
					echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
					wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
					echo '<input type="hidden" name="action" value="freesiem_sentinel_tfa_complete_setup" />';
					echo '<input type="hidden" name="user_id" value="' . esc_attr((string) $selected_user->ID) . '" />';
					echo '<p><label>' . esc_html__('Verification Code', 'freesiem-sentinel') . '<br /><input type="text" name="tfa_code" class="regular-text" inputmode="numeric" autocomplete="one-time-code" value="" /></label></p>';
					echo '<p><button type="submit" class="button button-primary">' . esc_html__('Complete Pending Setup', 'freesiem-sentinel') . '</button></p>';
					echo '</form>';
				} else {
					echo '<p>' . esc_html__('Start a fresh local enrollment if this user needs a new authenticator binding.', 'freesiem-sentinel') . '</p>';
					echo '<p><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_post_url('freesiem_sentinel_tfa_enroll', ['user_id' => (string) $selected_user->ID])) . '">' . esc_html__('Enroll TFA', 'freesiem-sentinel') . '</a></p>';
				}
				echo '</div>';
				echo '</div>';
			}

			echo '</div>';
		}

		echo '</div>';
	}

	public function render_ssl_page(): void
	{
		$this->assert_manage_permissions();

		$tab = isset($_GET['tab']) ? sanitize_key((string) wp_unslash($_GET['tab'])) : 'overview';
		if (!in_array($tab, ['overview', 'preflight', 'dry-run', 'logs'], true)) {
			$tab = 'overview';
		}

		$ssl_settings = freesiem_sentinel_get_ssl_settings();
		$preflight = freesiem_sentinel_get_ssl_preflight();
		$dry_run = freesiem_sentinel_get_ssl_dry_run();
		$environment = freesiem_sentinel_get_ssl_environment_snapshot($ssl_settings);
		$readiness = freesiem_sentinel_calculate_ssl_readiness($ssl_settings, $environment, $preflight);
		$ssl_state = freesiem_sentinel_get_ssl_state();
		$install_environment = freesiem_sentinel_detect_ssl_install_environment();
		$logs = array_reverse(freesiem_sentinel_get_ssl_logs());

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__('SSL / HTTPS', 'freesiem-sentinel') . '</h1>';
		echo '<div class="notice notice-warning inline"><p>' . esc_html__('Sentinel now supports explicit admin-triggered certbot actions plus nginx SSL apply. Force HTTPS and HSTS are both applied through the nginx workflow when enabled. Apache automation is still not included in this version.', 'freesiem-sentinel') . '</p></div>';
		echo '<nav class="nav-tab-wrapper" style="margin-bottom:20px;">';
		foreach ([
			'overview' => __('Overview', 'freesiem-sentinel'),
			'preflight' => __('Preflight', 'freesiem-sentinel'),
			'dry-run' => __('Dry Run', 'freesiem-sentinel'),
			'logs' => __('Logs', 'freesiem-sentinel'),
		] as $slug => $label) {
			$url = freesiem_sentinel_admin_page_url('freesiem-ssl', ['tab' => $slug]);
			$class = $tab === $slug ? 'nav-tab nav-tab-active' : 'nav-tab';
			echo '<a class="' . esc_attr($class) . '" href="' . esc_url($url) . '">' . esc_html($label) . '</a>';
		}
		echo '</nav>';

		if ($tab === 'overview') {
			$this->render_ssl_overview_tab($ssl_settings, $preflight, $dry_run, $readiness, $environment, $ssl_state, $install_environment);
		} elseif ($tab === 'preflight') {
			$this->render_ssl_preflight_tab($preflight);
		} elseif ($tab === 'dry-run') {
			$this->render_ssl_dry_run_tab($ssl_settings, $dry_run, $readiness, $environment, $ssl_state);
		} else {
			$this->render_ssl_logs_tab($logs, $preflight, $dry_run, $ssl_state);
		}

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

	private function render_pending_task_detail(array $task): void
	{
		$service = $this->plugin->get_pending_tasks();
		$events = $service->get_task_events((int) ($task['id'] ?? 0));
		$back_url = freesiem_sentinel_admin_page_url('freesiem-pending-tasks');
		$approve_url = freesiem_sentinel_admin_post_url('freesiem_sentinel_approve_task', ['task_id' => (string) ($task['id'] ?? 0)]);
		$deny_url = admin_url('admin-post.php');
		$payload = is_array($task['payload'] ?? null) ? $task['payload'] : [];
		$execution_result = is_array($task['execution_result'] ?? null) ? $task['execution_result'] : [];

		echo '<div style="display:flex;gap:10px;flex-wrap:wrap;margin:18px 0;">';
		echo '<a class="button button-secondary" href="' . esc_url($back_url) . '">' . esc_html__('Back to Task Queue', 'freesiem-sentinel') . '</a>';
		if (($task['status'] ?? '') === 'pending') {
			echo '<a class="button button-primary" href="' . esc_url($approve_url) . '">' . esc_html__('Approve Task', 'freesiem-sentinel') . '</a>';
		}
		echo '</div>';

		echo '<div style="display:grid;grid-template-columns:minmax(0,1.4fr) minmax(280px,.8fr);gap:20px;">';
		echo '<div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Task Summary', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('Local Task ID', 'freesiem-sentinel') . ':</strong> #' . esc_html((string) ($task['id'] ?? 0)) . '</p>';
		echo '<p><strong>' . esc_html__('Core Task ID', 'freesiem-sentinel') . ':</strong> <code>' . esc_html((string) ($task['core_task_id'] ?? '')) . '</code></p>';
		echo '<p><strong>' . esc_html__('Action', 'freesiem-sentinel') . ':</strong> ' . esc_html(ucwords(str_replace('_', ' ', (string) ($task['action_type'] ?? '')))) . '</p>';
		echo '<p><strong>' . esc_html__('Target', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->task_target_summary($task)) . '</p>';
		echo '<p><strong>' . esc_html__('Source Core', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($task['source_core_identifier'] ?? 'freeSIEM Core')) . '</p>';
		echo '<p><strong>' . esc_html__('Source URL', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($task['source_core_url'] ?? '')) . '</p>';
		echo '<p><strong>' . esc_html__('Signature Verified', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($task['signature_verified']) ? __('Yes', 'freesiem-sentinel') : __('No', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Status', 'freesiem-sentinel') . ':</strong> <span style="' . esc_attr($this->task_status_badge_style((string) ($task['status'] ?? 'pending'))) . '">' . esc_html(ucwords(str_replace('_', ' ', (string) ($task['status'] ?? 'pending')))) . '</span></p>';
		echo '<p><strong>' . esc_html__('Requested At', 'freesiem-sentinel') . ':</strong> ' . esc_html(freesiem_sentinel_format_datetime((string) ($task['requested_at'] ?? ''))) . '</p>';
		echo '<p><strong>' . esc_html__('Auto Approve At', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($task['auto_approve_at']) ? freesiem_sentinel_format_datetime((string) $task['auto_approve_at']) : __('Manual only', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Approval Mode', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($task['approval_mode'] ?? 'manual')) . '</p>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Payload Snapshot', 'freesiem-sentinel') . '</h2>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html(freesiem_sentinel_safe_json_pretty($payload)) . '</pre>';
		if (($task['action_type'] ?? '') === 'update_user') {
			echo '<h3>' . esc_html__('Requested Field Changes', 'freesiem-sentinel') . '</h3>';
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Field', 'freesiem-sentinel') . '</th><th>' . esc_html__('Requested Value', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
			foreach ((array) ($payload['target'] ?? $payload) as $field => $value) {
				if (in_array((string) $field, ['user_id', 'username', 'user_login', 'email', 'user_email'], true)) {
					continue;
				}
				echo '<tr><td>' . esc_html((string) $field) . '</td><td>' . esc_html(is_scalar($value) ? (string) $value : wp_json_encode($value)) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';

		if ($execution_result !== []) {
			echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
			echo '<h2 style="margin-top:0;">' . esc_html__('Execution Result', 'freesiem-sentinel') . '</h2>';
			echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html(freesiem_sentinel_safe_json_pretty($execution_result)) . '</pre>';
			echo '</div>';
		}

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Audit Trail', 'freesiem-sentinel') . '</h2>';
		if ($events === []) {
			$this->render_empty_state(__('No audit events yet.', 'freesiem-sentinel'), __('Task lifecycle events will appear here as the request moves through review and execution.', 'freesiem-sentinel'));
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('When', 'freesiem-sentinel') . '</th><th>' . esc_html__('Event', 'freesiem-sentinel') . '</th><th>' . esc_html__('Message', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
			foreach ($events as $event) {
				echo '<tr><td>' . esc_html(freesiem_sentinel_format_datetime((string) ($event['created_at'] ?? ''))) . '</td><td>' . esc_html(ucwords(str_replace('_', ' ', (string) ($event['event_type'] ?? '')))) . '</td><td>' . esc_html((string) ($event['message'] ?? '')) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
		echo '</div>';

		echo '<div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Decision Controls', 'freesiem-sentinel') . '</h2>';
		if (($task['status'] ?? '') === 'pending') {
			echo '<p>' . esc_html__('This task is waiting for a local approval decision before WordPress executes it.', 'freesiem-sentinel') . '</p>';
			echo '<p><a class="button button-primary" href="' . esc_url($approve_url) . '">' . esc_html__('Approve Task', 'freesiem-sentinel') . '</a></p>';
			echo '<form method="post" action="' . esc_url($deny_url) . '">';
			wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
			echo '<input type="hidden" name="action" value="freesiem_sentinel_deny_task" />';
			echo '<input type="hidden" name="task_id" value="' . esc_attr((string) ($task['id'] ?? 0)) . '" />';
			echo '<p><label for="freesiem-deny-reason">' . esc_html__('Deny Reason', 'freesiem-sentinel') . '</label><br /><textarea id="freesiem-deny-reason" name="deny_reason" rows="4" class="large-text"></textarea></p>';
			submit_button(__('Deny Task', 'freesiem-sentinel'), 'secondary', '', false);
			echo '</form>';
		} else {
			$this->render_empty_state(__('Task decision already recorded.', 'freesiem-sentinel'), __('This task is no longer pending, so review controls are disabled.', 'freesiem-sentinel'));
		}
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Task Timing', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('Approved At', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($task['approved_at']) ? freesiem_sentinel_format_datetime((string) $task['approved_at']) : __('Not approved yet', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Denied At', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($task['denied_at']) ? freesiem_sentinel_format_datetime((string) $task['denied_at']) : __('Not denied', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Executed At', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($task['executed_at']) ? freesiem_sentinel_format_datetime((string) $task['executed_at']) : __('Not executed yet', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Completed At', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($task['completed_at']) ? freesiem_sentinel_format_datetime((string) $task['completed_at']) : __('Not completed', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Failed At', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($task['failed_at']) ? freesiem_sentinel_format_datetime((string) $task['failed_at']) : __('Not failed', 'freesiem-sentinel')) . '</p>';
		if (!empty($task['deny_reason'])) {
			echo '<p><strong>' . esc_html__('Deny Reason', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) $task['deny_reason']) . '</p>';
		}
		if (!empty($task['error_message'])) {
			echo '<p><strong>' . esc_html__('Error', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) $task['error_message']) . '</p>';
		}
		echo '</div>';
		echo '</div>';
		echo '</div>';
	}

	private function task_status_badge_style(string $status): string
	{
		$palette = match ($status) {
			'completed' => 'background:#ecfdf5;color:#166534;border:1px solid #86efac;',
			'failed', 'denied' => 'background:#fef2f2;color:#991b1b;border:1px solid #fca5a5;',
			'approved', 'auto_approved', 'executing' => 'background:#eff6ff;color:#1d4ed8;border:1px solid #93c5fd;',
			default => 'background:#fffbeb;color:#92400e;border:1px solid #fcd34d;',
		};

		return 'display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;font-weight:700;text-decoration:none;' . $palette;
	}

	private function task_target_summary(array $task): string
	{
		$parts = [];

		if (!empty($task['target_username'])) {
			$parts[] = '@' . (string) $task['target_username'];
		}
		if (!empty($task['target_email'])) {
			$parts[] = (string) $task['target_email'];
		}
		if (!empty($task['target_user_id'])) {
			$parts[] = '#' . (int) $task['target_user_id'];
		}

		return $parts !== [] ? implode(' ', $parts) : __('Site users', 'freesiem-sentinel');
	}

	private function is_cloud_connected(array $settings): bool
	{
		return Freesiem_Cloud_Connect_State::is_connected($settings);
	}

	private function format_tfa_label(string $value): string
	{
		return ucwords(str_replace('_', ' ', sanitize_key($value)));
	}

	private function tfa_status_badge_style(string $status): string
	{
		return match (sanitize_key($status)) {
			Freesiem_TFA_Service::STATUS_ENABLED => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#dcfce7;color:#166534;font-weight:600;',
			Freesiem_TFA_Service::STATUS_PENDING_SETUP => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#fef3c7;color:#92400e;font-weight:600;',
			default => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#e5e7eb;color:#374151;font-weight:600;',
		};
	}

	private function tfa_meta_badge_style(string $value): string
	{
		return sanitize_key($value) === 'core'
			? 'display:inline-block;padding:4px 10px;border-radius:999px;background:#dbeafe;color:#1d4ed8;font-weight:600;'
			: 'display:inline-block;padding:4px 10px;border-radius:999px;background:#ecfccb;color:#3f6212;font-weight:600;';
	}

	private function render_ssl_overview_tab(array $ssl_settings, array $preflight, array $dry_run, array $readiness, array $environment, array $ssl_state, array $install_environment): void
	{
		$certificate = freesiem_sentinel_get_certificate_view_data($ssl_state);
		$endpoint_status = freesiem_sentinel_get_ssl_endpoint_status($environment);
		$integration = freesiem_sentinel_detect_nginx_integration($ssl_settings, $environment, $ssl_state);
		$permission_guidance = freesiem_sentinel_get_nginx_permission_guidance($integration, $environment);
		$user_space = freesiem_sentinel_get_ssl_user_space_paths($ssl_settings);
		$user_space_config = !empty($ssl_state['user_space_config_dir']) ? (string) $ssl_state['user_space_config_dir'] : (string) ($user_space['config_dir'] ?? '');
		$lineage_exists = freesiem_sentinel_ssl_lineage_exists((string) ($environment['configured_host'] ?? ''), ['user_space' => ['config_dir' => $user_space_config]]);
		$issue_gate = freesiem_sentinel_can_run_live_ssl_action('issue', $ssl_settings, $environment, $readiness);
		$renew_gate = freesiem_sentinel_can_run_live_ssl_action('renew', $ssl_settings, $environment, $readiness);

		$this->render_ssl_action_bar($issue_gate, $renew_gate, $integration, $lineage_exists, $ssl_settings);

		echo '<div style="display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-bottom:20px;">';
		$this->render_summary_stat(__('Domain', 'freesiem-sentinel'), $environment['configured_host'] !== '' ? $environment['configured_host'] : __('Unavailable', 'freesiem-sentinel'));
		$this->render_summary_stat(__('HTTPS', 'freesiem-sentinel'), (string) ($endpoint_status['https'] ?? __('Unavailable', 'freesiem-sentinel')), __('WordPress HTTPS', 'freesiem-sentinel'), $environment['is_https_configured'] ? __('Yes', 'freesiem-sentinel') : __('No', 'freesiem-sentinel'));
		$this->render_summary_stat(__('Redirect', 'freesiem-sentinel'), (string) ($endpoint_status['redirect'] ?? __('Unavailable', 'freesiem-sentinel')), __('Force HTTPS', 'freesiem-sentinel'), !empty($ssl_settings['force_https']) ? __('Enabled', 'freesiem-sentinel') : __('Off', 'freesiem-sentinel'));
		$this->render_summary_stat(__('Certbot', 'freesiem-sentinel'), !empty($environment['certbot']['available']) ? __('Installed', 'freesiem-sentinel') : __('Missing', 'freesiem-sentinel'), __('Version', 'freesiem-sentinel'), !empty($environment['certbot']['version']) ? (string) $environment['certbot']['version'] : __('Unavailable', 'freesiem-sentinel'));
		$this->render_summary_stat(__('Certificate', 'freesiem-sentinel'), !empty($certificate['exists']) ? (!empty($certificate['is_staging_certificate']) ? __('Staging cert', 'freesiem-sentinel') : __('Present', 'freesiem-sentinel')) : __('Not found', 'freesiem-sentinel'), __('Nginx', 'freesiem-sentinel'), in_array((string) ($integration['mode'] ?? ''), ['patch', 'pending_root_finalize'], true) ? __('Ready', 'freesiem-sentinel') : __('Needs setup', 'freesiem-sentinel'));
		$this->render_summary_stat(__('HSTS', 'freesiem-sentinel'), (string) ($endpoint_status['hsts'] ?? __('Unavailable', 'freesiem-sentinel')), __('Configured', 'freesiem-sentinel'), !empty($ssl_settings['hsts_enabled']) ? __('Enabled', 'freesiem-sentinel') : __('Off', 'freesiem-sentinel'));
		echo '</div>';

		echo '<div style="display:grid;gap:16px;">';
		echo '<div style="background:#fff;padding:18px;border:1px solid #dcdcde;border-radius:12px;">';
		$this->render_ssl_next_steps_panel($ssl_settings, $environment, $ssl_state, $certificate, $integration, $endpoint_status);
		echo '</div>';

		echo '<div style="background:#fff;padding:18px;border:1px solid #dcdcde;border-radius:12px;">';
		$this->render_ssl_core_settings_panel($ssl_settings, $environment, $ssl_state);
		echo '</div>';

		echo '<div style="background:#fff;padding:18px;border:1px solid #dcdcde;border-radius:12px;">';
		$this->render_ssl_certificate_panel($certificate);
		echo '</div>';

		echo '<div style="background:#fff;padding:18px;border:1px solid #dcdcde;border-radius:12px;">';
		$this->render_ssl_nginx_section($ssl_settings, $environment, $ssl_state, $endpoint_status);
		echo '</div>';
		if (!empty($permission_guidance['blocked'])) {
			echo '<div style="background:#fff;padding:18px;border:1px solid #dcdcde;border-radius:12px;">';
			$this->render_ssl_nginx_permission_guidance($permission_guidance);
			echo '</div>';
		}
		echo '<div style="background:#fff;padding:18px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Logs / Diagnostics', 'freesiem-sentinel') . '</h2>';
		echo '<p style="margin:0 0 12px 0;color:#646970;">' . esc_html__('Preflight detail, dry-run output, nginx parsing detail, and raw command traces now live in the Logs tab to keep Overview clean.', 'freesiem-sentinel') . '</p>';
		echo '<p style="margin:0;"><a class="button button-secondary" href="' . esc_url(freesiem_sentinel_admin_page_url('freesiem-ssl', ['tab' => 'logs'])) . '">' . esc_html__('Open Logs / Diagnostics', 'freesiem-sentinel') . '</a></p>';
		echo '</div>';
		echo '</div>';
	}

	private function render_ssl_action_bar(array $issue_gate, array $renew_gate, array $integration, bool $lineage_exists, array $ssl_settings): void
	{
		echo '<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-start;margin-bottom:20px;background:#fff;padding:16px;border:1px solid #dcdcde;border-radius:12px;">';
		$this->render_ssl_action_form(__('Detect Nginx Config', 'freesiem-sentinel'), 'freesiem_sentinel_detect_nginx_config', true, '', 'secondary');
		$this->render_ssl_action_form(__('Run Preflight', 'freesiem-sentinel'), 'freesiem_sentinel_run_ssl_preflight', true, '', 'secondary', ['redirect_tab' => 'preflight']);
		$this->render_ssl_action_form(__('Run Dry Run', 'freesiem-sentinel'), 'freesiem_sentinel_run_ssl_dry_run', true, '', 'secondary', ['redirect_tab' => 'dry-run']);
		$this->render_ssl_action_form(__('Issue Certificate', 'freesiem-sentinel'), 'freesiem_sentinel_issue_ssl_certificate', !empty($issue_gate['allowed']), (string) ($issue_gate['reason'] ?? ''), 'primary');
		$this->render_ssl_action_form(__('Re-Issue Certificate', 'freesiem-sentinel'), 'freesiem_sentinel_issue_ssl_certificate', !empty($issue_gate['allowed']) && $lineage_exists, $lineage_exists ? __('Re-Issue uses force renewal to replace the current certificate lineage.', 'freesiem-sentinel') : __('No existing certificate lineage is available to replace yet.', 'freesiem-sentinel'), 'secondary', ['force_reissue_existing_certificate' => '1']);
		$this->render_ssl_action_form(__('Renew', 'freesiem-sentinel'), 'freesiem_sentinel_renew_ssl_certificate', !empty($renew_gate['allowed']), (string) ($renew_gate['reason'] ?? ''), 'secondary');
		$this->render_ssl_action_form(__('Apply SSL to Nginx', 'freesiem-sentinel'), 'freesiem_sentinel_apply_ssl_to_nginx', !empty($integration['apply_allowed']), (string) ($integration['apply_reason'] ?? $integration['reason'] ?? ''), 'secondary', ['enable_nginx_https_redirect' => !empty($ssl_settings['force_https']) ? '1' : '0']);
		echo '</div>';
	}

	private function render_ssl_action_form(string $label, string $action, bool $allowed, string $reason = '', string $button_class = 'secondary', array $hidden_fields = []): void
	{
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin:0;">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="' . esc_attr($action) . '" />';
		foreach ($hidden_fields as $name => $value) {
			if ($value === '') {
				continue;
			}
			echo '<input type="hidden" name="' . esc_attr((string) $name) . '" value="' . esc_attr((string) $value) . '" />';
		}
		submit_button($label, $button_class, '', false, $allowed ? [] : ['disabled' => 'disabled', 'title' => $reason !== '' ? $reason : __('Action unavailable.', 'freesiem-sentinel')]);
		echo '</form>';
	}

	private function render_ssl_core_settings_panel(array $ssl_settings, array $environment, array $ssl_state): void
	{
		$webroot = freesiem_sentinel_recommend_ssl_webroot_path($ssl_settings, $environment, $ssl_state);

		echo '<h2 style="margin-top:0;">' . esc_html__('Core SSL Settings', 'freesiem-sentinel') . '</h2>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin:0;">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_save_ssl_settings" />';
		echo '<div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;align-items:end;">';
		echo '<div><label for="freesiem-ssl-email" style="display:block;font-weight:600;margin-bottom:6px;">' . esc_html__('Email', 'freesiem-sentinel') . '</label><input id="freesiem-ssl-email" type="email" name="acme_contact_email" value="' . esc_attr((string) ($ssl_settings['acme_contact_email'] ?? '')) . '" class="regular-text" style="width:100%;max-width:none;" /></div>';
		echo '<div><label for="freesiem-ssl-webroot" style="display:block;font-weight:600;margin-bottom:6px;">' . esc_html__('Webroot', 'freesiem-sentinel') . '</label><input id="freesiem-ssl-webroot" type="text" name="webroot_path" value="' . esc_attr($webroot) . '" class="regular-text" style="width:100%;max-width:none;" /></div>';
		echo '<div><label for="freesiem-ssl-challenge" style="display:block;font-weight:600;margin-bottom:6px;">' . esc_html__('Challenge method', 'freesiem-sentinel') . '</label><select id="freesiem-ssl-challenge" name="challenge_method" style="width:100%;max-width:none;">';
		foreach ([
			'webroot-http-01' => __('webroot-http-01', 'freesiem-sentinel'),
			'standalone-http-01' => __('standalone-http-01', 'freesiem-sentinel'),
			'manual-dns-01' => __('manual-dns-01', 'freesiem-sentinel'),
		] as $value => $label) {
			echo '<option value="' . esc_attr($value) . '" ' . selected((string) ($ssl_settings['challenge_method'] ?? 'webroot-http-01'), $value, false) . '>' . esc_html($label) . '</option>';
		}
		echo '</select></div>';
		echo '</div>';
		echo '<div style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin-top:12px;">';
		echo '<label><input type="checkbox" name="force_https" value="1" ' . checked(!empty($ssl_settings['force_https']), true, false) . ' /> ' . esc_html__('Force HTTPS', 'freesiem-sentinel') . '</label>';
		echo '<label><input type="checkbox" name="hsts_enabled" value="1" ' . checked(!empty($ssl_settings['hsts_enabled']), true, false) . ' /> ' . esc_html__('HSTS', 'freesiem-sentinel') . '</label>';
		echo '<label><input type="checkbox" name="auto_renew" value="1" ' . checked(!empty($ssl_settings['auto_renew']), true, false) . ' /> ' . esc_html__('Auto-renew', 'freesiem-sentinel') . '</label>';
		echo '<label><input type="checkbox" name="use_staging" value="1" ' . checked(!empty($ssl_settings['use_staging']), true, false) . ' /> ' . esc_html__('Use staging', 'freesiem-sentinel') . '</label>';
		echo '<label><input type="checkbox" name="detailed_logs" value="1" ' . checked(!empty($ssl_settings['detailed_logs']), true, false) . ' /> ' . esc_html__('Detailed logs', 'freesiem-sentinel') . '</label>';
		echo '</div>';
		echo '<p style="margin:10px 0 0 0;color:#646970;">' . esc_html__('Webroot is auto-populated from nginx when available and falls back to WordPress paths if needed. HSTS and Auto-renew remain stored-only in this version.', 'freesiem-sentinel') . '</p>';
		echo '<p style="margin:12px 0 0 0;">';
		submit_button(__('Save SSL Settings', 'freesiem-sentinel'), 'secondary', '', false);
		echo '</p>';
		echo '</form>';
	}

	private function render_ssl_certificate_panel(array $certificate): void
	{
		echo '<h2 style="margin-top:0;">' . esc_html__('Certificate', 'freesiem-sentinel') . '</h2>';
		if (!empty($certificate['is_staging_certificate'])) {
			echo '<p style="margin-top:0;padding:12px;border-radius:8px;background:#fee2e2;border:1px solid #fca5a5;"><strong>' . esc_html__('Browser warning expected.', 'freesiem-sentinel') . '</strong> ' . esc_html__('This site is currently serving a Let’s Encrypt staging certificate. Disable staging and issue a production certificate next.', 'freesiem-sentinel') . '</p>';
		}
		echo '<p><strong>' . esc_html__('Issuer', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($certificate['issuer']) ? (string) $certificate['issuer'] : __('Unavailable', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Expiry', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($certificate['expires_at']) ? (string) $certificate['expires_at'] : __('Unavailable', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('SANs', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($certificate['sans']) ? implode(', ', (array) $certificate['sans']) : __('Unavailable', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Environment', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($certificate['staging']) ? __('Staging', 'freesiem-sentinel') : __('Production', 'freesiem-sentinel')) . '</p>';
		echo '<details style="margin-top:12px;"><summary style="cursor:pointer;list-style:none;"><span class="button button-secondary">' . esc_html__('View Certificate', 'freesiem-sentinel') . '</span></summary>';
		if (empty($certificate['exists'])) {
			echo '<p style="margin-top:12px;">' . esc_html__('No certificate files are currently available to inspect.', 'freesiem-sentinel') . '</p>';
		} else {
			echo '<p style="margin-top:12px;"><strong>' . esc_html__('Certificate path', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($certificate['cert_path'] ?? '')) . '</p>';
			echo '<p><strong>' . esc_html__('Key path', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($certificate['key_path'] ?? '')) . '</p>';
			if (!empty($certificate['raw_text'])) {
				echo '<details style="margin-top:8px;"><summary style="cursor:pointer;">' . esc_html__('Show raw details', 'freesiem-sentinel') . '</summary><pre style="white-space:pre-wrap;overflow:auto;margin-top:12px;">' . esc_html((string) $certificate['raw_text']) . '</pre></details>';
			}
		}
		echo '</details>';
	}

	private function render_ssl_nginx_section(array $ssl_settings, array $environment, array $ssl_state, array $endpoint_status): void
	{
		$integration = freesiem_sentinel_detect_nginx_integration($ssl_settings, $environment, $ssl_state);

		echo '<h2 style="margin-top:0;">' . esc_html__('Nginx Integration', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('Integration mode', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($integration['mode'] ?? 'manual_required')) . '</p>';
		echo '<p><strong>' . esc_html__('Detection result', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($integration['reason'] ?? __('Unavailable', 'freesiem-sentinel'))) . '</p>';
		echo '<p><strong>' . esc_html__('Matched file', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($integration['target_path'] ?? __('Unavailable', 'freesiem-sentinel'))) . '</p>';
		echo '<p><strong>' . esc_html__('Matched server_name', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($integration['matched_server_name'] ?? __('Unavailable', 'freesiem-sentinel'))) . '</p>';
		echo '<p><strong>' . esc_html__('Confidence level', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($integration['detection_confidence'] ?? 'ambiguous')) . '</p>';
		echo '<p><strong>' . esc_html__('Redirect on apply', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($ssl_settings['force_https']) ? __('Enabled', 'freesiem-sentinel') : __('Off', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('HSTS on apply', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($ssl_settings['hsts_enabled']) ? __('Enabled', 'freesiem-sentinel') : __('Off', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Last apply attempt', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->summary_value_or_fallback((string) ($ssl_state['nginx_last_apply_at'] ?? ''), true) . ' / ' . (!empty($ssl_state['nginx_last_apply_status']) ? (string) $ssl_state['nginx_last_apply_status'] : __('none', 'freesiem-sentinel'))) . '</p>';
		if (empty($integration['apply_allowed'])) {
			echo '<p><strong>' . esc_html__('Apply gate', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($integration['apply_reason'] ?? $integration['reason'] ?? __('Automatic nginx apply is unavailable.', 'freesiem-sentinel'))) . '</p>';
		}
		echo '<table class="widefat striped" style="margin-bottom:14px;"><thead><tr><th>' . esc_html__('Check', 'freesiem-sentinel') . '</th><th>' . esc_html__('Status', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
		foreach ([
			__('Nginx binary', 'freesiem-sentinel') => !empty($integration['detection_checks']['binary']) ? strtoupper((string) $integration['detection_checks']['binary']) : (!empty($integration['binary_available']) ? 'PASS' : 'FAIL'),
			__('Command execution', 'freesiem-sentinel') => !empty($integration['detection_checks']['execution']) ? strtoupper((string) $integration['detection_checks']['execution']) : (!empty($integration['execution_available']) ? 'PASS' : 'FAIL'),
			__('Hostname', 'freesiem-sentinel') => !empty($integration['detection_checks']['hostname']) ? strtoupper((string) $integration['detection_checks']['hostname']) : (!empty($environment['configured_host']) ? 'PASS' : 'WARN'),
			__('nginx -T', 'freesiem-sentinel') => !empty($integration['detection_checks']['nginx_t']) ? strtoupper((string) $integration['detection_checks']['nginx_t']) : (!empty($integration['nginx_t_ok']) ? 'PASS' : 'WARN'),
			__('Parsing / config path', 'freesiem-sentinel') => !empty($integration['detection_checks']['parsing']) ? strtoupper((string) $integration['detection_checks']['parsing']) : (!empty($integration['target_path']) ? 'PASS' : 'FAIL'),
			__('Config writable', 'freesiem-sentinel') => !empty($integration['config_writable']) ? 'PASS' : 'FAIL',
			__('Snippets writable', 'freesiem-sentinel') => !empty($integration['snippet_dir_writable']) ? 'PASS' : 'FAIL',
			__('Certificate files', 'freesiem-sentinel') => (!empty($integration['fullchain_exists']) && !empty($integration['privkey_exists'])) ? 'PASS' : 'FAIL',
			__('Redirect status', 'freesiem-sentinel') => !empty($endpoint_status['redirect_enabled']) ? 'PASS' : (!empty($ssl_settings['force_https']) ? 'FAIL' : 'WARN'),
			__('HSTS status', 'freesiem-sentinel') => !empty($endpoint_status['hsts_enabled']) ? 'PASS' : (!empty($ssl_settings['hsts_enabled']) ? 'FAIL' : 'WARN'),
		] as $label => $status) {
			echo '<tr><td>' . esc_html($label) . '</td><td><span style="' . esc_attr($this->ssl_preflight_badge_style($status)) . '">' . esc_html($status) . '</span></td></tr>';
		}
		echo '</tbody></table>';
		echo '<p><strong>' . esc_html__('Last live status check', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->summary_value_or_fallback((string) ($ssl_state['live_status_checked_at'] ?? ''), true)) . '</p>';
		echo '<p><strong>' . esc_html__('Last nginx test result', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($ssl_state['nginx_last_test_result']) ? (string) $ssl_state['nginx_last_test_result'] : __('None yet', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Last nginx reload result', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($ssl_state['nginx_last_reload_result']) ? (string) $ssl_state['nginx_last_reload_result'] : __('None yet', 'freesiem-sentinel')) . '</p>';
		echo '<p style="margin-bottom:6px;color:#646970;">' . esc_html__('Deep nginx preview and parser output now live in the Logs tab. Apply SSL to Nginx respects both Force HTTPS and HSTS from Core SSL Settings.', 'freesiem-sentinel') . '</p>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html((string) ($integration['test_command'] ?? 'nginx -t') . "\n" . (string) ($integration['reload_command'] ?? 'nginx -s reload')) . '</pre>';
	}

	private function render_ssl_next_steps_panel(array $ssl_settings, array $environment, array $ssl_state, array $certificate, array $integration, array $endpoint_status): void
	{
		$steps = [];
		$title = __('What To Do Next', 'freesiem-sentinel');

		if (!empty($certificate['is_staging_certificate']) && empty($ssl_settings['use_staging'])) {
			$steps[] = __('Issue a production certificate now.', 'freesiem-sentinel');
			$steps[] = __('If the lineage is reused, use Re-Issue Certificate from the top action bar.', 'freesiem-sentinel');
			$steps[] = __('After issuance, apply the updated cert to nginx.', 'freesiem-sentinel');
		} elseif (!empty($certificate['is_staging_certificate'])) {
			$steps[] = __('Turn off staging in Core SSL Settings.', 'freesiem-sentinel');
			$steps[] = __('Issue a browser-trusted production certificate.', 'freesiem-sentinel');
		} elseif (($ssl_state['nginx_integration_mode'] ?? '') === 'pending_root_finalize') {
			$steps[] = __('Run nginx -t as root, then reload nginx as root.', 'freesiem-sentinel');
			$steps[] = __('Refresh this page and verify HTTPS loads without browser warnings.', 'freesiem-sentinel');
		} elseif (empty($certificate['exists'])) {
			$steps[] = __('Run Preflight if needed, then issue the first certificate.', 'freesiem-sentinel');
		} elseif (!empty($integration['apply_allowed']) && empty($ssl_state['nginx_last_apply_at'])) {
			$steps[] = __('Apply SSL to nginx so the site starts serving the certificate.', 'freesiem-sentinel');
		} elseif (!empty($ssl_settings['force_https']) && empty($endpoint_status['redirect_enabled'])) {
			$steps[] = __('Force HTTPS is enabled, but HTTP is still serving directly.', 'freesiem-sentinel');
			$steps[] = __('Apply SSL to nginx again so the redirect block is written.', 'freesiem-sentinel');
		} elseif (!empty($certificate['exists']) && !empty($endpoint_status['https_ok']) && (empty($ssl_settings['force_https']) || !empty($endpoint_status['redirect_enabled']))) {
			$steps[] = __('SSL fully configured.', 'freesiem-sentinel');
			$steps[] = __('Optional: switch the WordPress Site URL and Home URL to HTTPS if they still use HTTP.', 'freesiem-sentinel');
		} else {
			$steps[] = __('Refresh detection and review the latest SSL status.', 'freesiem-sentinel');
		}

		if (!$environment['is_https_configured'] && !empty($endpoint_status['https_ok']) && empty($certificate['is_staging_certificate'])) {
			$steps[] = __('Update the WordPress Site URL and Home URL to HTTPS when you are ready.', 'freesiem-sentinel');
		}

		echo '<h2 style="margin-top:0;">' . esc_html($title) . '</h2>';
		echo '<ol style="margin:0;padding-left:18px;">';
		foreach ($steps as $step) {
			echo '<li style="margin-bottom:8px;">' . esc_html((string) $step) . '</li>';
		}
		echo '</ol>';
	}

	private function render_ssl_nginx_permission_guidance(array $guidance): void
	{
		echo '<h2 style="margin-top:0;">' . esc_html__('Permissions Required for Auto Apply', 'freesiem-sentinel') . '</h2>';
		echo '<p style="margin-top:0;color:#646970;">' . esc_html__('Auto apply is blocked by filesystem permissions. Sentinel only recommends the minimum write access needed for the detected nginx files.', 'freesiem-sentinel') . '</p>';
		echo '<p><strong>' . esc_html__('Detected web user', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($guidance['web_user']['user'] ?? 'www-data')) . ' (' . esc_html((string) ($guidance['web_user']['confidence'] ?? 'low')) . ')</p>';
		echo '<table class="widefat striped" style="margin-bottom:14px;"><thead><tr><th>' . esc_html__('Path', 'freesiem-sentinel') . '</th><th>' . esc_html__('Writable', 'freesiem-sentinel') . '</th><th>' . esc_html__('Reason needed', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
		foreach ((array) ($guidance['items'] ?? []) as $item) {
			if (!is_array($item)) {
				continue;
			}
			echo '<tr>';
			echo '<td><code>' . esc_html((string) ($item['path'] ?? '')) . '</code></td>';
			echo '<td><span style="' . esc_attr($this->ssl_preflight_badge_style(!empty($item['writable']) ? 'PASS' : 'FAIL')) . '">' . esc_html(!empty($item['writable']) ? 'PASS' : 'FAIL') . '</span></td>';
			echo '<td>' . esc_html((string) ($item['reason'] ?? '')) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '<p><strong>' . esc_html__('Recommended order', 'freesiem-sentinel') . ':</strong></p>';
		echo '<ul style="margin-top:0;">';
		echo '<li><strong>' . esc_html__('ACL', 'freesiem-sentinel') . '</strong> ' . esc_html__('LOW risk. Preferred because it grants path-specific access to the detected web user only.', 'freesiem-sentinel') . '</li>';
		echo '<li><strong>' . esc_html__('Group write', 'freesiem-sentinel') . '</strong> ' . esc_html__('MEDIUM risk. Use only if ACL is unavailable on this server.', 'freesiem-sentinel') . '</li>';
		echo '<li><strong>' . esc_html__('Broad permissions', 'freesiem-sentinel') . '</strong> ' . esc_html__('NOT recommended. Sentinel does not suggest chmod 777 or broad /etc/nginx access.', 'freesiem-sentinel') . '</li>';
		echo '</ul>';
		echo '<p><strong>' . esc_html__('ACL example commands', 'freesiem-sentinel') . ':</strong></p>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html(implode("\n", (array) ($guidance['commands']['acl'] ?? []))) . '</pre>';
		echo '<p><strong>' . esc_html__('Fallback group-write commands', 'freesiem-sentinel') . ':</strong></p>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html(implode("\n", (array) ($guidance['commands']['group_write'] ?? []))) . '</pre>';
		echo '<p><strong>' . esc_html__('Next steps', 'freesiem-sentinel') . ':</strong></p>';
		echo '<ol style="margin-top:0;padding-left:18px;">';
		foreach ((array) ($guidance['steps'] ?? []) as $step) {
			echo '<li>' . esc_html((string) $step) . '</li>';
		}
		echo '</ol>';
	}

	private function render_ssl_preflight_tab(array $preflight): void
	{
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Safe Preflight Checks', 'freesiem-sentinel') . '</h2>';
		echo '<p>' . esc_html__('This preflight only inspects WordPress and server readiness. It does not run certbot, issue certificates, install packages, or change web server configuration.', 'freesiem-sentinel') . '</p>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_run_ssl_preflight" />';
		submit_button(__('Run Preflight', 'freesiem-sentinel'), 'primary', '', false);
		echo '</form>';
		echo '</div>';
		$this->render_ssl_results_table($preflight, __('Latest Results', 'freesiem-sentinel'));
	}

	private function render_ssl_settings_tab(array $ssl_settings, array $readiness, array $environment, array $install_environment): void
	{
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_save_ssl_settings" />';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Future SSL Settings', 'freesiem-sentinel') . '</h2>';
		echo '<p><span style="' . esc_attr($this->ssl_readiness_badge_style((string) ($readiness['state'] ?? 'not_configured'))) . '">' . esc_html(strtoupper((string) ($readiness['state'] ?? 'not_configured'))) . '</span></p>';
		echo '<p style="margin-bottom:0;color:#646970;"><strong>' . esc_html__('Stored only for future implementation; not active in this version.', 'freesiem-sentinel') . '</strong></p>';
		echo '</div>';

		echo '<table class="form-table" role="presentation">';
		$this->render_ssl_checkbox_field('enable_management_ui', __('Enable SSL management UI', 'freesiem-sentinel'), !empty($ssl_settings['enable_management_ui']), __('Keeps this SSL/HTTPS admin area available without turning on live SSL management.', 'freesiem-sentinel'));
		$this->render_ssl_text_field('acme_contact_email', __('ACME contact email', 'freesiem-sentinel'), (string) ($ssl_settings['acme_contact_email'] ?? ''), __('Stored for future certificate registration only.', 'freesiem-sentinel'), 'email');
		$this->render_ssl_text_field('hostname_override', __('Preferred domain / hostname override', 'freesiem-sentinel'), (string) ($ssl_settings['hostname_override'] ?? ''), __('Optional override used by preflight, dry run, and future certificate planning.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('allow_local_override', __('Allow localhost / IP override', 'freesiem-sentinel'), !empty($ssl_settings['allow_local_override']), __('Use only if you intentionally want validation to accept a local or IP-based hostname.', 'freesiem-sentinel'));
		echo '<tr><th scope="row"><label for="freesiem-challenge-method">' . esc_html__('Preferred challenge method', 'freesiem-sentinel') . '</label></th><td>';
		echo '<select id="freesiem-challenge-method" name="challenge_method">';
		foreach ([
			'webroot-http-01' => __('webroot-http-01', 'freesiem-sentinel'),
			'standalone-http-01' => __('standalone-http-01', 'freesiem-sentinel'),
			'manual-dns-01' => __('manual-dns-01', 'freesiem-sentinel'),
		] as $value => $label) {
			echo '<option value="' . esc_attr($value) . '" ' . selected((string) ($ssl_settings['challenge_method'] ?? ''), $value, false) . '>' . esc_html($label) . '</option>';
		}
		echo '</select>';
		echo '<p class="description">' . esc_html__('Selection is stored now for future implementation only.', 'freesiem-sentinel') . '</p>';
		echo '</td></tr>';
		$this->render_ssl_text_field('webroot_path', __('Webroot path', 'freesiem-sentinel'), (string) ($ssl_settings['webroot_path'] ?? ''), __('Required for webroot HTTP-01 dry-run validation and future planning.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('check_port_80', __('Intent to use port 80', 'freesiem-sentinel'), !empty($ssl_settings['check_port_80']), __('Used for readiness reporting only right now.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('check_port_443', __('Intent to use port 443', 'freesiem-sentinel'), !empty($ssl_settings['check_port_443']), __('Used for readiness reporting only right now.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('force_https', __('Force HTTPS', 'freesiem-sentinel'), !empty($ssl_settings['force_https']), __('Stored only for future implementation; no redirects are added in this version.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('hsts_enabled', __('HSTS', 'freesiem-sentinel'), !empty($ssl_settings['hsts_enabled']), __('Applied through nginx SSL config when you run Apply SSL to Nginx.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('auto_renew', __('Auto-renew', 'freesiem-sentinel'), !empty($ssl_settings['auto_renew']), __('Stored only for future implementation; no renewal jobs are scheduled in this version.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('use_staging', __('Use Let’s Encrypt staging', 'freesiem-sentinel'), !empty($ssl_settings['use_staging']), __('Recommended for safe simulated execution planning.', 'freesiem-sentinel'));
		$this->render_ssl_checkbox_field('detailed_logs', __('Enable detailed SSL logs', 'freesiem-sentinel'), !empty($ssl_settings['detailed_logs']), __('Adds category and context details to the lightweight SSL log store.', 'freesiem-sentinel'));
		echo '</table>';
		submit_button(__('Save SSL Settings', 'freesiem-sentinel'));
		echo '</form>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-top:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Certbot Installation', 'freesiem-sentinel') . '</h2>';
		$this->render_ssl_install_section($environment, $install_environment, freesiem_sentinel_can_install_certbot($install_environment, $environment));
		echo '</div>';
	}

	private function render_ssl_dry_run_tab(array $ssl_settings, array $dry_run, array $readiness, array $environment, array $ssl_state): void
	{
		$preview = freesiem_sentinel_get_ssl_command_preview($ssl_settings, $environment);
		$issue_gate = freesiem_sentinel_can_run_live_ssl_action('issue', $ssl_settings, $environment, $readiness);
		$renew_gate = freesiem_sentinel_can_run_live_ssl_action('renew', $ssl_settings, $environment, $readiness);

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Dry Run Validation', 'freesiem-sentinel') . '</h2>';
		echo '<p>' . esc_html__('This dry run re-checks configuration completeness, re-runs safe preflight, builds a simulated command preview, and records whether the site would be ready for an explicit admin-triggered issuance attempt. No certificate will be issued by this dry-run action.', 'freesiem-sentinel') . '</p>';
		echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
		wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
		echo '<input type="hidden" name="action" value="freesiem_sentinel_run_ssl_dry_run" />';
		submit_button(__('Run Dry Run Validation', 'freesiem-sentinel'), 'primary', '', false);
		echo '</form>';
		echo '</div>';

		echo '<div style="display:grid;grid-template-columns:minmax(0,1fr) minmax(280px,.9fr);gap:20px;margin-bottom:20px;">';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Simulated Command Preview', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html((string) ($preview['label'] ?? __('Preview only', 'freesiem-sentinel'))) . '</strong></p>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html((string) ($preview['command'] ?? '')) . '</pre>';
		if (!empty($preview['user_space']) && is_array($preview['user_space'])) {
			echo '<p><strong>' . esc_html__('User-space config dir', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($preview['user_space']['config_dir'] ?? '')) . '</p>';
			echo '<p><strong>' . esc_html__('User-space work dir', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($preview['user_space']['work_dir'] ?? '')) . '</p>';
			echo '<p><strong>' . esc_html__('User-space logs dir', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($preview['user_space']['logs_dir'] ?? '')) . '</p>';
		}
		echo '<p style="margin-bottom:0;color:#646970;">' . esc_html__('Preview only. No shell execution occurs in this version.', 'freesiem-sentinel') . '</p>';
		echo '</div>';
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Readiness Snapshot', 'freesiem-sentinel') . '</h2>';
		echo '<p><span style="' . esc_attr($this->ssl_readiness_badge_style((string) ($readiness['state'] ?? 'not_configured'))) . '">' . esc_html(strtoupper((string) ($readiness['state'] ?? 'not_configured'))) . '</span></p>';
		echo '<p><strong>' . esc_html((string) ($readiness['label'] ?? '')) . '</strong></p>';
		echo '<p><strong>' . esc_html__('Current certbot state', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($environment['certbot']['available']) ? sprintf(__('Available (%s)', 'freesiem-sentinel'), (string) ($environment['certbot']['version'] ?? '')) : __('Unavailable', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Last verification', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($ssl_state['last_verification_result']) ? (string) $ssl_state['last_verification_result'] : __('No verification recorded yet.', 'freesiem-sentinel')) . '</p>';
		echo '<p style="margin-bottom:0;color:#646970;">' . esc_html((string) ($readiness['description'] ?? '')) . '</p>';
		echo '</div>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Live Action Gates', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('Issue Certificate', 'freesiem-sentinel') . ':</strong> ' . esc_html($issue_gate['allowed'] ? __('Enabled', 'freesiem-sentinel') : (string) $issue_gate['reason']) . '</p>';
		echo '<p style="margin-bottom:0;"><strong>' . esc_html__('Renew Now', 'freesiem-sentinel') . ':</strong> ' . esc_html($renew_gate['allowed'] ? __('Enabled', 'freesiem-sentinel') : (string) $renew_gate['reason']) . '</p>';
		echo '</div>';

		$this->render_ssl_results_table($dry_run, __('Latest Dry Run', 'freesiem-sentinel'));

		if (!empty($dry_run['plan'])) {
			echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-top:20px;">';
			echo '<h2 style="margin-top:0;">' . esc_html__('Execution Plan Summary', 'freesiem-sentinel') . '</h2>';
			echo '<ol style="margin:0;padding-left:18px;">';
			foreach ((array) $dry_run['plan'] as $step) {
				echo '<li style="margin-bottom:8px;">' . esc_html((string) $step) . '</li>';
			}
			echo '</ol>';
			echo '</div>';
		}
	}

	private function render_ssl_logs_tab(array $logs, array $preflight, array $dry_run, array $ssl_state): void
	{
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Latest Summary', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('Last preflight', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->summary_value_or_fallback((string) ($preflight['ran_at'] ?? ''), true)) . '</p>';
		echo '<p><strong>' . esc_html__('Preflight summary', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($preflight['summary'] ?? __('No preflight run yet.', 'freesiem-sentinel'))) . '</p>';
		echo '<p><strong>' . esc_html__('Last dry run', 'freesiem-sentinel') . ':</strong> ' . esc_html($this->summary_value_or_fallback((string) ($dry_run['ran_at'] ?? ''), true)) . '</p>';
		echo '<p style="margin-bottom:0;"><strong>' . esc_html__('Dry-run summary', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) ($dry_run['summary'] ?? __('No dry run yet.', 'freesiem-sentinel'))) . '</p>';
		echo '</div>';

		echo '<div style="display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:20px;margin-bottom:20px;">';
		$this->render_ssl_results_table($preflight, __('Preflight Details', 'freesiem-sentinel'));
		$this->render_ssl_results_table($dry_run, __('Dry Run Details', 'freesiem-sentinel'));
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;margin-bottom:20px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Nginx Detection Details', 'freesiem-sentinel') . '</h2>';
		echo '<p><strong>' . esc_html__('Detection source', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($ssl_state['nginx_detection_source']) ? (string) $ssl_state['nginx_detection_source'] : __('Unavailable', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Matched file', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($ssl_state['nginx_config_path']) ? (string) $ssl_state['nginx_config_path'] : __('Unavailable', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Matched server_name', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($ssl_state['nginx_matched_server_name']) ? (string) $ssl_state['nginx_matched_server_name'] : __('Unavailable', 'freesiem-sentinel')) . '</p>';
		echo '<p><strong>' . esc_html__('Confidence', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($ssl_state['nginx_detection_confidence']) ? (string) $ssl_state['nginx_detection_confidence'] : __('Unavailable', 'freesiem-sentinel')) . '</p>';
		echo '<p style="margin-bottom:0;"><strong>' . esc_html__('Last detect result', 'freesiem-sentinel') . ':</strong> ' . esc_html(!empty($ssl_state['nginx_last_detect_result']) ? (string) $ssl_state['nginx_last_detect_result'] : __('None yet', 'freesiem-sentinel')) . '</p>';
		echo '</div>';

		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<h2 style="margin-top:0;">' . esc_html__('Event Log', 'freesiem-sentinel') . '</h2>';
		if ($logs === []) {
			$this->render_empty_state(__('No SSL events logged yet.', 'freesiem-sentinel'), __('Saving SSL settings, running preflight, or running a dry run will add lightweight event entries here.', 'freesiem-sentinel'));
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Timestamp', 'freesiem-sentinel') . '</th><th>' . esc_html__('Category', 'freesiem-sentinel') . '</th><th>' . esc_html__('Level', 'freesiem-sentinel') . '</th><th>' . esc_html__('Message', 'freesiem-sentinel') . '</th><th>' . esc_html__('Context', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
			foreach ($logs as $entry) {
				if (!is_array($entry)) {
					continue;
				}
				echo '<tr>';
				echo '<td>' . esc_html($this->summary_value_or_fallback((string) ($entry['timestamp'] ?? ''), true)) . '</td>';
				echo '<td>' . esc_html(ucwords(str_replace('_', ' ', (string) ($entry['category'] ?? 'general')))) . '</td>';
				echo '<td><span style="' . esc_attr($this->ssl_log_badge_style((string) ($entry['level'] ?? 'info'))) . '">' . esc_html(strtoupper((string) ($entry['level'] ?? 'info'))) . '</span></td>';
				echo '<td>' . esc_html((string) ($entry['message'] ?? '')) . '</td>';
				echo '<td><code>' . esc_html(wp_json_encode((array) ($entry['context'] ?? []))) . '</code></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
	}

	private function render_ssl_results_table(array $result, string $title): void
	{
		echo '<div style="background:#fff;padding:20px;border:1px solid #dcdcde;border-radius:12px;">';
		echo '<div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap;">';
		echo '<div>';
		echo '<h2 style="margin:0 0 6px 0;">' . esc_html($title) . '</h2>';
		echo '<p style="margin:0;color:#646970;">' . esc_html($this->summary_value_or_fallback((string) ($result['ran_at'] ?? ''), true)) . '</p>';
		echo '</div>';
		echo '<p style="margin:0;"><strong>' . esc_html((string) ($result['summary'] ?? __('No results yet.', 'freesiem-sentinel'))) . '</strong></p>';
		echo '</div>';

		if (empty($result['items'])) {
			echo '<div style="margin-top:20px;">';
			$this->render_empty_state(__('No results yet.', 'freesiem-sentinel'), __('Run the relevant SSL validation action to populate results here.', 'freesiem-sentinel'));
			echo '</div>';
		} else {
			echo '<table class="widefat striped" style="margin-top:20px;"><thead><tr><th>' . esc_html__('Check', 'freesiem-sentinel') . '</th><th>' . esc_html__('Status', 'freesiem-sentinel') . '</th><th>' . esc_html__('Details', 'freesiem-sentinel') . '</th></tr></thead><tbody>';
			foreach ((array) $result['items'] as $item) {
				if (!is_array($item)) {
					continue;
				}
				echo '<tr>';
				echo '<td><strong>' . esc_html((string) ($item['label'] ?? '')) . '</strong></td>';
				echo '<td><span style="' . esc_attr($this->ssl_preflight_badge_style((string) ($item['status'] ?? 'WARN'))) . '">' . esc_html((string) ($item['status'] ?? 'WARN')) . '</span></td>';
				echo '<td>' . esc_html((string) ($item['message'] ?? '')) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
	}

	private function render_ssl_install_section(array $environment, array $install_environment, array $install_gate): void
	{
		$preview = freesiem_sentinel_get_certbot_install_preview($install_environment);
		$manual = freesiem_sentinel_get_certbot_manual_install_instructions();
		$show_button = empty($environment['certbot']['available']) && !empty($environment['execution_support']);

		if ($show_button) {
			if (!$install_gate['allowed']) {
				echo '<p><strong>' . esc_html__('Install gate', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) $install_gate['reason']) . '</p>';
			}

			if (!empty($preview['preview'])) {
				echo '<p><strong>' . esc_html__('Install preview', 'freesiem-sentinel') . ':</strong></p>';
				echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html((string) $preview['preview']) . '</pre>';
			}

			echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
			wp_nonce_field(FREESIEM_SENTINEL_NONCE_ACTION);
			echo '<input type="hidden" name="action" value="freesiem_sentinel_install_certbot" />';
			echo '<p><label><input type="checkbox" name="confirm_certbot_install" value="1" /> ' . esc_html__('I understand this requires server-level permissions', 'freesiem-sentinel') . '</label></p>';
			submit_button(__('Install Certbot', 'freesiem-sentinel'), 'secondary', '', false, $install_gate['allowed'] ? [] : ['disabled' => 'disabled']);
			echo '</form>';
		}

		echo '<p><strong>' . esc_html__('Manual fallback', 'freesiem-sentinel') . ':</strong></p>';
		echo '<p style="margin-bottom:6px;"><strong>' . esc_html__('Ubuntu / Debian', 'freesiem-sentinel') . '</strong></p>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html((string) $manual['ubuntu']) . '</pre>';
		echo '<p style="margin-bottom:6px;"><strong>' . esc_html__('CentOS / RHEL', 'freesiem-sentinel') . '</strong></p>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;">' . esc_html((string) $manual['centos']) . '</pre>';
		echo '<p style="margin-bottom:6px;"><strong>' . esc_html__('Snap', 'freesiem-sentinel') . '</strong></p>';
		echo '<pre style="white-space:pre-wrap;overflow:auto;margin-bottom:0;">' . esc_html((string) $manual['snap']) . '</pre>';
	}

	private function render_ssl_readiness_details(array $ssl_settings, array $environment, array $readiness): void
	{
		$details = [
			['status' => is_email((string) ($ssl_settings['acme_contact_email'] ?? '')) ? 'PASS' : 'FAIL', 'message' => __('ACME contact email is configured.', 'freesiem-sentinel')],
			['status' => $environment['configured_host'] !== '' ? 'PASS' : 'FAIL', 'message' => __('Hostname/domain is configured.', 'freesiem-sentinel')],
			['status' => !empty($environment['certbot']['available']) ? 'PASS' : 'FAIL', 'message' => !empty($environment['certbot']['available']) ? __('Certbot is installed and detectable.', 'freesiem-sentinel') : __('Certbot is not installed or not detectable on this server.', 'freesiem-sentinel')],
			['status' => $environment['execution_support'] ? 'PASS' : 'FAIL', 'message' => $environment['execution_support'] ? __('Command execution capability is available.', 'freesiem-sentinel') : __('Command execution capability is not available.', 'freesiem-sentinel')],
			['status' => empty($readiness['warning_messages']) ? 'PASS' : 'WARN', 'message' => empty($readiness['warning_messages']) ? __('No readiness warnings remain.', 'freesiem-sentinel') : __('One or more readiness warnings still need review.', 'freesiem-sentinel')],
		];

		echo '<p><strong>' . esc_html__('Readiness Details', 'freesiem-sentinel') . '</strong></p>';
		echo '<ul style="margin-top:0;margin-bottom:0;">';
		foreach ($details as $detail) {
			echo '<li><span style="' . esc_attr($this->ssl_preflight_badge_style((string) $detail['status'])) . '">' . esc_html((string) $detail['status']) . '</span> ' . esc_html((string) $detail['message']) . '</li>';
		}
		echo '</ul>';
	}

	private function format_ssl_install_environment(array $install_environment): string
	{
		$parts = [];
		if (!empty($install_environment['os_family'])) {
			$parts[] = str_replace('_', '/', (string) $install_environment['os_family']);
		}
		if (!empty($install_environment['root_status'])) {
			$parts[] = 'privileges: ' . (string) $install_environment['root_status'];
		}
		if (!empty($install_environment['install_method'])) {
			$parts[] = 'installer: ' . (string) $install_environment['install_method'];
		}

		return $parts !== [] ? implode(' | ', $parts) : __('Unknown', 'freesiem-sentinel');
	}

	private function render_ssl_checkbox_field(string $name, string $label, bool $checked, string $description): void
	{
		echo '<tr><th scope="row">' . esc_html($label) . '</th><td>';
		echo '<label><input type="checkbox" name="' . esc_attr($name) . '" value="1" ' . checked($checked, true, false) . ' /> ' . esc_html__('Enabled', 'freesiem-sentinel') . '</label>';
		echo '<p class="description">' . esc_html($description) . '</p>';
		echo '</td></tr>';
	}

	private function render_ssl_text_field(string $name, string $label, string $value, string $description, string $type = 'text'): void
	{
		echo '<tr><th scope="row"><label for="freesiem-' . esc_attr($name) . '">' . esc_html($label) . '</label></th><td>';
		echo '<input id="freesiem-' . esc_attr($name) . '" type="' . esc_attr($type) . '" class="regular-text" name="' . esc_attr($name) . '" value="' . esc_attr($value) . '" />';
		echo '<p class="description">' . esc_html($description) . '</p>';
		echo '</td></tr>';
	}

	private function format_ssl_challenge_method(string $method): string
	{
		return match ($method) {
			'webroot-http-01' => 'webroot-http-01',
			'standalone-http-01' => 'standalone-http-01',
			'manual-dns-01' => 'manual-dns-01',
			default => 'webroot-http-01',
		};
	}

	private function ssl_preflight_badge_style(string $status): string
	{
		return match (strtoupper($status)) {
			'PASS' => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#dcfce7;color:#166534;font-weight:700;',
			'FAIL' => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#fee2e2;color:#991b1b;font-weight:700;',
			default => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#fef3c7;color:#92400e;font-weight:700;',
		};
	}

	private function ssl_readiness_badge_style(string $state): string
	{
		return match (sanitize_key($state)) {
			'future_ready' => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#dcfce7;color:#166534;font-weight:700;',
			'ready_for_dry_run' => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#dbeafe;color:#1d4ed8;font-weight:700;',
			'blocked' => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#fee2e2;color:#991b1b;font-weight:700;',
			'partially_configured' => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#fef3c7;color:#92400e;font-weight:700;',
			default => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#e5e7eb;color:#374151;font-weight:700;',
		};
	}

	private function ssl_log_badge_style(string $level): string
	{
		return match (sanitize_key($level)) {
			'error' => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#fee2e2;color:#991b1b;font-weight:700;',
			'warning' => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#fef3c7;color:#92400e;font-weight:700;',
			'success' => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#dcfce7;color:#166534;font-weight:700;',
			default => 'display:inline-block;padding:4px 10px;border-radius:999px;background:#dbeafe;color:#1d4ed8;font-weight:700;',
		};
	}

	private function ssl_result_log_level(string $status): string
	{
		return match (sanitize_key($status)) {
			'success', 'applied' => 'success',
			'warning', 'warn', 'blocked', 'no_action_needed', 'manual_required' => 'warning',
			default => 'error',
		};
	}

	public function maybe_enforce_login_lockout($user, string $username, string $password)
	{
		$settings = freesiem_sentinel_get_login_protection_settings();
		if (empty($settings['enabled']) || $username === '' || $user instanceof WP_User) {
			return $user;
		}

		$state = freesiem_sentinel_get_login_lockout_state($username);
		if (!empty($state['locked_until']) && (int) ($state['locked_until'] ?? 0) > time()) {
			freesiem_sentinel_log_event('lockout_active', __('Login attempt blocked because the username/IP is currently locked out.', 'freesiem-sentinel'), $username, '', [
				'locked_until' => (int) $state['locked_until'],
			]);

			return new WP_Error('freesiem_login_locked', __('Too many failed login attempts. Please try again later.', 'freesiem-sentinel'));
		}

		return $user;
	}

	public function handle_login_failed_event(string $username): void
	{
		$settings = freesiem_sentinel_get_login_protection_settings();
		if (empty($settings['enabled'])) {
			if (!empty($settings['log_failed_logins'])) {
				freesiem_sentinel_log_event('login_failed', __('WordPress login failed.', 'freesiem-sentinel'), $username);
			}

			return;
		}

		$state = freesiem_sentinel_get_login_lockout_state($username);
		$state['count'] = (int) ($state['count'] ?? 0) + 1;

		if ((int) $state['count'] >= (int) ($settings['max_failed_attempts'] ?? 5)) {
			$state['locked_until'] = time() + ((int) ($settings['lockout_duration_minutes'] ?? 15) * MINUTE_IN_SECONDS);
			freesiem_sentinel_log_event('lockout_triggered', __('Login lockout triggered after repeated failed attempts.', 'freesiem-sentinel'), $username, '', [
				'count' => (int) $state['count'],
				'locked_until' => (int) $state['locked_until'],
			]);
		}

		freesiem_sentinel_update_login_lockout_state($username, $state, (int) ($settings['lockout_duration_minutes'] ?? 15));
		if (!empty($settings['log_failed_logins'])) {
			freesiem_sentinel_log_event('login_failed', __('WordPress login failed.', 'freesiem-sentinel'), $username, '', [
				'count' => !empty($settings['track_failed_login_count']) ? (int) $state['count'] : 0,
			]);
		}
	}

	public function handle_login_success_event(string $user_login, WP_User $user): void
	{
		$settings = freesiem_sentinel_get_login_protection_settings();
		freesiem_sentinel_clear_login_lockout_state($user_login);

		if (!empty($settings['log_successful_logins'])) {
			freesiem_sentinel_log_event('login_success', __('WordPress login succeeded.', 'freesiem-sentinel'), $user_login, '', [
				'user_id' => (int) $user->ID,
			]);
		}
	}

	public function handle_tfa_success_event(int $user_id, array $context = []): void
	{
		$user = get_user_by('id', $user_id);
		freesiem_sentinel_log_event('tfa_success', __('TFA verification succeeded.', 'freesiem-sentinel'), $user instanceof WP_User ? (string) $user->user_login : '', '', $context);
	}

	public function handle_tfa_failure_event(int $user_id, array $context = []): void
	{
		$user = get_user_by('id', $user_id);
		freesiem_sentinel_log_event('tfa_failure', __('TFA verification failed.', 'freesiem-sentinel'), $user instanceof WP_User ? (string) $user->user_login : '', '', $context);
	}

	public function maybe_handle_stealth_mode(): void
	{
		$settings = freesiem_sentinel_get_stealth_mode_settings();
		if (empty($settings['enabled'])) {
			return;
		}

		$script_name = isset($_SERVER['SCRIPT_NAME']) ? (string) $_SERVER['SCRIPT_NAME'] : '';
		$is_login_request = str_ends_with($script_name, 'wp-login.php');
		$is_admin_request = is_admin() && !wp_doing_ajax();
		$token = isset($_GET['freesiem_login']) ? sanitize_title((string) wp_unslash($_GET['freesiem_login'])) : '';
		$expected = (string) ($settings['custom_login_slug'] ?? 'sentinel-login');
		$login_action = isset($_REQUEST['action']) ? sanitize_key((string) wp_unslash($_REQUEST['action'])) : '';
		$allowed_login_actions = ['logout', 'lostpassword', 'retrievepassword', 'rp', 'resetpass', 'postpass'];

		if ($is_login_request && !is_user_logged_in() && !empty($settings['block_direct_wp_login']) && $token !== $expected && !in_array($login_action, $allowed_login_actions, true)) {
			freesiem_sentinel_log_event('stealth_block', __('Direct wp-login.php access was blocked by Stealth Mode.', 'freesiem-sentinel'));
			wp_safe_redirect(home_url('/'));
			exit;
		}

		if ($is_admin_request && !is_user_logged_in() && !empty($settings['redirect_wp_admin_guests'])) {
			freesiem_sentinel_log_event('stealth_redirect', __('Unauthenticated wp-admin access was redirected to the Sentinel login URL.', 'freesiem-sentinel'));
			wp_safe_redirect(freesiem_sentinel_get_stealth_login_url($settings));
			exit;
		}
	}

	public function filter_login_url(string $login_url, string $redirect, bool $force_reauth): string
	{
		$settings = freesiem_sentinel_get_stealth_mode_settings();
		if (empty($settings['enabled'])) {
			return $login_url;
		}

		$url = add_query_arg(['freesiem_login' => (string) ($settings['custom_login_slug'] ?? 'sentinel-login')], $login_url);
		if ($redirect !== '') {
			$url = add_query_arg(['redirect_to' => $redirect], $url);
		}
		if ($force_reauth) {
			$url = add_query_arg(['reauth' => '1'], $url);
		}

		return $url;
	}

	private function assert_manage_permissions(): void
	{
		if (!freesiem_sentinel_current_user_can_manage()) {
			wp_die(esc_html__('You are not allowed to manage freeSIEM Sentinel.', 'freesiem-sentinel'));
		}
	}

	private function assert_task_permissions(): void
	{
		if (!$this->plugin->get_pending_tasks()->current_user_can_approve_tasks()) {
			wp_die(esc_html__('You are not allowed to review freeSIEM Pending Tasks.', 'freesiem-sentinel'));
		}
	}

	private function redirect_to_page(string $page, array $args = []): void
	{
		wp_safe_redirect(freesiem_sentinel_admin_page_url($page, $args));
		exit;
	}
}
