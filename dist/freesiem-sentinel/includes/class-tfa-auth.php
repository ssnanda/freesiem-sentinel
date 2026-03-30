<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_TFA_Auth
{
	private const CHALLENGE_TRANSIENT_PREFIX = 'freesiem_tfa_challenge_';
	private const ATTEMPT_TRANSIENT_PREFIX = 'freesiem_tfa_attempts_';
	private Freesiem_Plugin $plugin;
	private Freesiem_TFA_Service $service;

	public function __construct(Freesiem_Plugin $plugin, Freesiem_TFA_Service $service)
	{
		$this->plugin = $plugin;
		$this->service = $service;
	}

	public function register(): void
	{
		add_action('login_form_login', [$this, 'handle_login_flow']);
	}

	public function get_login_requirement(WP_User $user): string
	{
		return $this->service->get_user_tfa_state((int) $user->ID)['tfa_status'];
	}

	public function handle_login_flow(): void
	{
		if (!$this->is_login_request()) {
			return;
		}

		if (isset($_POST['freesiem_tfa_verify'])) {
			$this->handle_tfa_verification();
			return;
		}

		$token = isset($_REQUEST['freesiem_tfa_token']) ? sanitize_text_field(wp_unslash((string) $_REQUEST['freesiem_tfa_token'])) : '';

		if ($token !== '') {
			$this->render_challenge_page($token);
			exit;
		}

		if (strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
			return;
		}

		$username = isset($_POST['log']) ? wp_unslash((string) $_POST['log']) : '';
		$password = isset($_POST['pwd']) ? wp_unslash((string) $_POST['pwd']) : '';

		if ($username === '' || $password === '') {
			return;
		}

		$user = wp_authenticate($username, $password);

		if (!$user instanceof WP_User) {
			return;
		}

		$requirement = $this->get_login_requirement($user);

		if ($requirement === Freesiem_TFA_Service::STATUS_NOT_ENABLED) {
			return;
		}

		$redirect_to = isset($_POST['redirect_to']) ? esc_url_raw(wp_unslash((string) $_POST['redirect_to'])) : '';
		$remember = !empty($_POST['rememberme']);
		$token = wp_generate_password(32, false, false);
		$challenge = [
			'user_id' => (int) $user->ID,
			'remember' => $remember ? 1 : 0,
			'redirect_to' => $redirect_to,
			'status' => $requirement,
			'created_at' => time(),
		];
		set_transient(self::CHALLENGE_TRANSIENT_PREFIX . $token, $challenge, 10 * MINUTE_IN_SECONDS);
		wp_safe_redirect(wp_login_url() . '?freesiem_tfa_token=' . rawurlencode($token));
		exit;
	}

	private function handle_tfa_verification(): void
	{
		$token = isset($_POST['freesiem_tfa_token']) ? sanitize_text_field(wp_unslash((string) $_POST['freesiem_tfa_token'])) : '';
		$code = isset($_POST['freesiem_tfa_code']) ? wp_unslash((string) $_POST['freesiem_tfa_code']) : '';
		$nonce = isset($_POST['_wpnonce']) ? wp_unslash((string) $_POST['_wpnonce']) : '';

		if ($token === '' || !wp_verify_nonce($nonce, 'freesiem_tfa_verify_' . $token)) {
			$this->render_challenge_page($token, __('The TFA session is no longer valid. Please sign in again.', 'freesiem-sentinel'));
			exit;
		}

		$challenge = get_transient(self::CHALLENGE_TRANSIENT_PREFIX . $token);

		if (!is_array($challenge) || empty($challenge['user_id'])) {
			$this->render_challenge_page($token, __('The TFA session expired. Please sign in again.', 'freesiem-sentinel'));
			exit;
		}

		$user_id = (int) $challenge['user_id'];
		$lockout = $this->get_attempt_state($user_id);

		if (!empty($lockout['locked_until']) && $lockout['locked_until'] > time()) {
			$this->render_challenge_page($token, __('Too many invalid codes were submitted. Please wait a few minutes and try again.', 'freesiem-sentinel'));
			exit;
		}

		$state = $this->service->get_user_tfa_state($user_id);

		if (!$this->service->verify_user_code($user_id, $code)) {
			$this->record_failed_attempt($user_id);
			$this->render_challenge_page($token, __('The verification code was not accepted.', 'freesiem-sentinel'));
			exit;
		}

		if ($state['tfa_status'] === Freesiem_TFA_Service::STATUS_PENDING_SETUP) {
			$result = $this->service->complete_pending_setup($user_id, $code);

			if (is_wp_error($result)) {
				$this->render_challenge_page($token, $result->get_error_message());
				exit;
			}
		} else {
			$this->service->mark_verified($user_id);
		}

		delete_transient(self::CHALLENGE_TRANSIENT_PREFIX . $token);
		delete_transient(self::ATTEMPT_TRANSIENT_PREFIX . $user_id);

		$user = get_user_by('id', $user_id);
		$remember = !empty($challenge['remember']);
		$redirect_to = !empty($challenge['redirect_to']) ? (string) $challenge['redirect_to'] : admin_url();

		if (!$user instanceof WP_User) {
			wp_safe_redirect(wp_login_url());
			exit;
		}

		wp_set_current_user($user_id, (string) $user->user_login);
		wp_set_auth_cookie($user_id, $remember);
		do_action('wp_login', (string) $user->user_login, $user);
		wp_safe_redirect($redirect_to);
		exit;
	}

	private function render_challenge_page(string $token, string $error = ''): void
	{
		$challenge = $token !== '' ? get_transient(self::CHALLENGE_TRANSIENT_PREFIX . $token) : null;
		$user = is_array($challenge) && !empty($challenge['user_id']) ? get_user_by('id', (int) $challenge['user_id']) : null;

		if (!$user instanceof WP_User) {
			login_header(__('Two-Factor Authentication', 'freesiem-sentinel'));
			echo '<p class="message message-error">' . esc_html__('The TFA session expired. Please sign in again.', 'freesiem-sentinel') . '</p>';
			echo '<p><a href="' . esc_url(wp_login_url()) . '">' . esc_html__('Back to login', 'freesiem-sentinel') . '</a></p>';
			login_footer();
			return;
		}

		$state = $this->service->get_user_tfa_state((int) $user->ID);
		$secret = $state['tfa_status'] === Freesiem_TFA_Service::STATUS_PENDING_SETUP ? $this->service->get_secret((int) $user->ID) : '';
		$otpauth = !is_wp_error($secret) && $secret !== '' ? $this->service->build_otpauth_uri($user, $secret) : '';
		login_header(__('Two-Factor Authentication', 'freesiem-sentinel'), '', null);

		if ($error !== '') {
			echo '<div id="login_error"><strong>' . esc_html__('Error:', 'freesiem-sentinel') . '</strong> ' . esc_html($error) . '</div>';
		}

		echo '<form method="post" action="' . esc_url(wp_login_url()) . '">';
		wp_nonce_field('freesiem_tfa_verify_' . $token);
		echo '<input type="hidden" name="freesiem_tfa_verify" value="1" />';
		echo '<input type="hidden" name="freesiem_tfa_token" value="' . esc_attr($token) . '" />';
		echo '<p><strong>' . esc_html__('Account', 'freesiem-sentinel') . ':</strong> ' . esc_html((string) $user->user_login) . '</p>';

		if ($state['tfa_status'] === Freesiem_TFA_Service::STATUS_PENDING_SETUP) {
			echo '<p>' . esc_html__('Finish setting up your authenticator app before access is granted.', 'freesiem-sentinel') . '</p>';
			if ($secret === '' || is_wp_error($secret)) {
				echo '<p>' . esc_html__('A TFA secret has not been prepared for this user yet. Contact your site administrator.', 'freesiem-sentinel') . '</p>';
			} else {
				echo '<p><strong>' . esc_html__('Manual Setup Key', 'freesiem-sentinel') . ':</strong><br /><code>' . esc_html($secret) . '</code></p>';
				echo '<p><strong>' . esc_html__('Authenticator URI', 'freesiem-sentinel') . ':</strong><br /><code style="word-break:break-all;">' . esc_html($otpauth) . '</code></p>';
			}
		} else {
			echo '<p>' . esc_html__('Enter the 6-digit verification code from your authenticator app to continue.', 'freesiem-sentinel') . '</p>';
		}

		echo '<p><label for="freesiem_tfa_code">' . esc_html__('Verification Code', 'freesiem-sentinel') . '<br /><input type="text" name="freesiem_tfa_code" id="freesiem_tfa_code" inputmode="numeric" autocomplete="one-time-code" class="input" value="" /></label></p>';
		echo '<p><button type="submit" class="button button-primary button-large">' . esc_html__('Verify & Sign In', 'freesiem-sentinel') . '</button></p>';
		echo '</form>';
		echo '<p><a href="' . esc_url(wp_login_url()) . '">' . esc_html__('Back to login', 'freesiem-sentinel') . '</a></p>';
		login_footer();
	}

	private function get_attempt_state(int $user_id): array
	{
		$state = get_transient(self::ATTEMPT_TRANSIENT_PREFIX . $user_id);

		return is_array($state) ? $state : ['attempts' => 0, 'locked_until' => 0];
	}

	private function record_failed_attempt(int $user_id): void
	{
		$state = $this->get_attempt_state($user_id);
		$state['attempts'] = (int) ($state['attempts'] ?? 0) + 1;

		if ($state['attempts'] >= 5) {
			$state['locked_until'] = time() + (5 * MINUTE_IN_SECONDS);
		}

		set_transient(self::ATTEMPT_TRANSIENT_PREFIX . $user_id, $state, 10 * MINUTE_IN_SECONDS);
	}

	private function is_login_request(): bool
	{
		$script = isset($_SERVER['SCRIPT_NAME']) ? wp_basename((string) $_SERVER['SCRIPT_NAME']) : '';

		return $script === 'wp-login.php';
	}
}
