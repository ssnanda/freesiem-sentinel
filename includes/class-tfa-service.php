<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_TFA_Service
{
	public const STATUS_NOT_ENABLED = 'not_enabled';
	public const STATUS_PENDING_SETUP = 'pending_setup';
	public const STATUS_ENABLED = 'enabled';
	public const SOURCE_CORE = 'core';
	public const SOURCE_LOCAL = 'local';
	public const MANAGED_CORE = 'core';
	public const MANAGED_LOCAL = 'local';
	public const META_STATUS = 'freesiem_tfa_status';
	public const META_SOURCE = 'freesiem_tfa_source';
	public const META_MANAGED = 'freesiem_tfa_managed';
	public const META_SECRET_ENCRYPTED = 'freesiem_tfa_secret_encrypted';
	public const META_SECRET_VERSION = 'freesiem_tfa_secret_version';
	public const META_LAST_VERIFIED_AT = 'freesiem_tfa_last_verified_at';
	public const SECRET_VERSION = 'v1';
	private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	public function generate_secret(int $length = 32): string
	{
		$alphabet = self::BASE32_ALPHABET;
		$secret = '';

		for ($index = 0; $index < $length; $index++) {
			$secret .= $alphabet[random_int(0, strlen($alphabet) - 1)];
		}

		return $secret;
	}

	public function generate_totp_code(string $secret, ?int $timestamp = null): string
	{
		$timestamp = $timestamp ?? time();
		$counter = (int) floor($timestamp / 30);
		$secret_key = $this->base32_decode($secret);

		if ($secret_key === '') {
			return '000000';
		}

		$binary_counter = pack('N*', 0) . pack('N*', $counter);
		$hash = hash_hmac('sha1', $binary_counter, $secret_key, true);
		$offset = ord(substr($hash, -1)) & 0x0F;
		$truncated = substr($hash, $offset, 4);
		$value = unpack('N', $truncated);
		$value = is_array($value) ? (int) ($value[1] ?? 0) : 0;
		$value = $value & 0x7FFFFFFF;

		return str_pad((string) ($value % 1000000), 6, '0', STR_PAD_LEFT);
	}

	public function verify_totp_code(string $secret, string $code, int $window = 1): bool
	{
		$normalized = preg_replace('/\D+/', '', $code);
		$normalized = is_string($normalized) ? $normalized : '';

		if (strlen($normalized) !== 6) {
			return false;
		}

		$timestamp = time();

		for ($offset = -$window; $offset <= $window; $offset++) {
			if (hash_equals($this->generate_totp_code($secret, $timestamp + ($offset * 30)), $normalized)) {
				return true;
			}
		}

		return false;
	}

	public function build_otpauth_uri(WP_User $user, string $secret): string
	{
		$issuer = rawurlencode(get_bloginfo('name') ?: 'freeSIEM Sentinel');
		$label = rawurlencode((string) $user->user_login . '@' . wp_parse_url(home_url('/'), PHP_URL_HOST));

		return sprintf(
			'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
			$label,
			rawurlencode($secret),
			$issuer
		);
	}

	public function get_user_tfa_state(int $user_id): array
	{
		$user_id = max(0, $user_id);

		return [
			'tfa_status' => $this->normalize_status((string) get_user_meta($user_id, self::META_STATUS, true)),
			'tfa_source' => $this->normalize_source((string) get_user_meta($user_id, self::META_SOURCE, true)),
			'tfa_managed' => $this->normalize_managed((string) get_user_meta($user_id, self::META_MANAGED, true)),
			'last_verified_at' => freesiem_sentinel_sanitize_datetime((string) get_user_meta($user_id, self::META_LAST_VERIFIED_AT, true)),
			'has_secret' => (string) get_user_meta($user_id, self::META_SECRET_ENCRYPTED, true) !== '',
		];
	}

	public function set_not_enabled(int $user_id, string $source = self::SOURCE_LOCAL, string $managed = self::MANAGED_LOCAL): void
	{
		update_user_meta($user_id, self::META_STATUS, self::STATUS_NOT_ENABLED);
		update_user_meta($user_id, self::META_SOURCE, $this->normalize_source($source));
		update_user_meta($user_id, self::META_MANAGED, $this->normalize_managed($managed));
		delete_user_meta($user_id, self::META_LAST_VERIFIED_AT);
	}

	public function set_pending_setup(int $user_id, string $source = self::SOURCE_LOCAL, string $managed = self::MANAGED_LOCAL, string $secret = ''): bool|WP_Error
	{
		if ($secret !== '') {
			$result = $this->set_secret($user_id, $secret);

			if (is_wp_error($result)) {
				return $result;
			}
		}

		update_user_meta($user_id, self::META_STATUS, self::STATUS_PENDING_SETUP);
		update_user_meta($user_id, self::META_SOURCE, $this->normalize_source($source));
		update_user_meta($user_id, self::META_MANAGED, $this->normalize_managed($managed));

		return true;
	}

	public function set_enabled(int $user_id, string $source = self::SOURCE_LOCAL, string $managed = self::MANAGED_LOCAL, string $secret = ''): bool|WP_Error
	{
		if ($secret !== '') {
			$result = $this->set_secret($user_id, $secret);

			if (is_wp_error($result)) {
				return $result;
			}
		}

		update_user_meta($user_id, self::META_STATUS, self::STATUS_ENABLED);
		update_user_meta($user_id, self::META_SOURCE, $this->normalize_source($source));
		update_user_meta($user_id, self::META_MANAGED, $this->normalize_managed($managed));
		update_user_meta($user_id, self::META_LAST_VERIFIED_AT, freesiem_sentinel_get_iso8601_time());

		return true;
	}

	public function clear_tfa(int $user_id, string $source = self::SOURCE_LOCAL, string $managed = self::MANAGED_LOCAL): void
	{
		$this->clear_secret($user_id);
		update_user_meta($user_id, self::META_STATUS, self::STATUS_NOT_ENABLED);
		update_user_meta($user_id, self::META_SOURCE, $this->normalize_source($source));
		update_user_meta($user_id, self::META_MANAGED, $this->normalize_managed($managed));
		delete_user_meta($user_id, self::META_LAST_VERIFIED_AT);
	}

	public function is_core_managed(int $user_id): bool
	{
		return $this->get_user_tfa_state($user_id)['tfa_managed'] === self::MANAGED_CORE;
	}

	public function local_actions_allowed(int $user_id): bool
	{
		return !$this->is_core_managed($user_id);
	}

	public function start_local_enrollment(int $user_id): array|WP_Error
	{
		if (!$this->local_actions_allowed($user_id)) {
			return new WP_Error('freesiem_tfa_core_managed', __('This user is managed by freeSIEM Core for TFA.', 'freesiem-sentinel'));
		}

		$user = get_user_by('id', $user_id);

		if (!$user instanceof WP_User) {
			return new WP_Error('freesiem_tfa_user_missing', __('The selected user could not be found.', 'freesiem-sentinel'));
		}

		$secret = $this->generate_secret();
		$result = $this->set_pending_setup($user_id, self::SOURCE_LOCAL, self::MANAGED_LOCAL, $secret);

		if (is_wp_error($result)) {
			return $result;
		}

		return [
			'user_id' => (int) $user_id,
			'secret' => $secret,
			'otpauth_uri' => $this->build_otpauth_uri($user, $secret),
			'tfa_status' => self::STATUS_PENDING_SETUP,
			'tfa_source' => self::SOURCE_LOCAL,
			'tfa_managed' => self::MANAGED_LOCAL,
		];
	}

	public function complete_pending_setup(int $user_id, string $code): bool|WP_Error
	{
		$secret = $this->get_secret($user_id);

		if (is_wp_error($secret)) {
			return $secret;
		}

		if ($secret === '') {
			return new WP_Error('freesiem_tfa_secret_missing', __('A TFA secret is required before setup can be completed.', 'freesiem-sentinel'));
		}

		if (!$this->verify_totp_code($secret, $code)) {
			return new WP_Error('freesiem_tfa_code_invalid', __('The verification code was not accepted.', 'freesiem-sentinel'));
		}

		$state = $this->get_user_tfa_state($user_id);
		$this->set_enabled($user_id, $state['tfa_source'], $state['tfa_managed']);

		return true;
	}

	public function verify_user_code(int $user_id, string $code): bool
	{
		$secret = $this->get_secret($user_id);

		return !is_wp_error($secret) && $secret !== '' && $this->verify_totp_code($secret, $code);
	}

	public function mark_verified(int $user_id): void
	{
		update_user_meta($user_id, self::META_LAST_VERIFIED_AT, freesiem_sentinel_get_iso8601_time());

		if ($this->get_user_tfa_state($user_id)['tfa_status'] === self::STATUS_PENDING_SETUP) {
			$state = $this->get_user_tfa_state($user_id);
			$this->set_enabled($user_id, $state['tfa_source'], $state['tfa_managed']);
		}
	}

	public function reset_local_tfa(int $user_id): bool|WP_Error
	{
		if (!$this->local_actions_allowed($user_id)) {
			return new WP_Error('freesiem_tfa_core_managed', __('This user is managed by freeSIEM Core for TFA.', 'freesiem-sentinel'));
		}

		$this->clear_tfa($user_id, self::SOURCE_LOCAL, self::MANAGED_LOCAL);

		return true;
	}

	public function change_local_password(int $user_id, string $password): bool|WP_Error
	{
		if (!$this->local_actions_allowed($user_id)) {
			return new WP_Error('freesiem_password_core_managed', __('This user is managed by freeSIEM Core for password changes.', 'freesiem-sentinel'));
		}

		if ($password === '') {
			return new WP_Error('freesiem_password_required', __('Enter a non-empty password to continue.', 'freesiem-sentinel'));
		}

		wp_set_password($password, $user_id);

		return true;
	}

	public function set_secret(int $user_id, string $secret): bool|WP_Error
	{
		if ($secret === '') {
			return new WP_Error('freesiem_tfa_secret_empty', __('A non-empty TFA secret is required.', 'freesiem-sentinel'));
		}

		$protected = $this->protect_secret($secret);

		if (is_wp_error($protected)) {
			return $protected;
		}

		update_user_meta($user_id, self::META_SECRET_ENCRYPTED, $protected);
		update_user_meta($user_id, self::META_SECRET_VERSION, self::SECRET_VERSION);

		return true;
	}

	public function get_secret(int $user_id): string|WP_Error
	{
		$protected = (string) get_user_meta($user_id, self::META_SECRET_ENCRYPTED, true);

		if ($protected === '') {
			return '';
		}

		return $this->reveal_secret($protected);
	}

	public function clear_secret(int $user_id): void
	{
		delete_user_meta($user_id, self::META_SECRET_ENCRYPTED);
		delete_user_meta($user_id, self::META_SECRET_VERSION);
	}

	public function get_safe_user_list(): array
	{
		$users = get_users(['orderby' => 'login', 'order' => 'ASC']);
		$items = [];

		foreach ($users as $user) {
			if (!$user instanceof WP_User) {
				continue;
			}

			$state = $this->get_user_tfa_state((int) $user->ID);
			$items[] = [
				'id' => (int) $user->ID,
				'username' => (string) $user->user_login,
				'email' => $user->user_email !== '' ? (string) $user->user_email : null,
				'tfa_status' => $state['tfa_status'],
				'tfa_source' => $state['tfa_source'],
				'tfa_managed' => $state['tfa_managed'],
				'last_verified_at' => $state['last_verified_at'] !== '' ? $state['last_verified_at'] : null,
			];
		}

		return $items;
	}

	public function provision_user(array $payload): array|WP_Error
	{
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : $payload;
		$user = $this->find_target_user($target);
		$user_login = sanitize_user((string) ($target['username'] ?? $target['user_login'] ?? ''), true);
		$user_email = sanitize_email((string) ($target['email'] ?? $target['user_email'] ?? ''));
		$role = sanitize_key((string) ($target['role'] ?? get_option('default_role', 'subscriber')));
		$password = '';

		foreach (['password', 'user_pass', 'pass'] as $key) {
			if (isset($target[$key]) && is_string($target[$key])) {
				$password = $target[$key];
				break;
			}
			if (isset($payload[$key]) && is_string($payload[$key])) {
				$password = $payload[$key];
				break;
			}
		}

		if (!$user instanceof WP_User && ($user_login === '' || $user_email === '')) {
			return new WP_Error('freesiem_tfa_provision_invalid', __('Provisioning requires a username and email for new users.', 'freesiem-sentinel'));
		}

		if ($user instanceof WP_User) {
			$update_args = [
				'ID' => (int) $user->ID,
				'first_name' => sanitize_text_field((string) ($target['first_name'] ?? $user->first_name)),
				'last_name' => sanitize_text_field((string) ($target['last_name'] ?? $user->last_name)),
				'display_name' => sanitize_text_field((string) ($target['display_name'] ?? $user->display_name)),
				'user_email' => $user_email !== '' ? $user_email : (string) $user->user_email,
			];
			$updated = wp_update_user($update_args);

			if (is_wp_error($updated)) {
				return $updated;
			}

			if ($role !== '') {
				$user->set_role($role);
			}
			$user_id = (int) $user->ID;
		} else {
			$user_id = wp_insert_user([
				'user_login' => $user_login,
				'user_email' => $user_email,
				'first_name' => sanitize_text_field((string) ($target['first_name'] ?? '')),
				'last_name' => sanitize_text_field((string) ($target['last_name'] ?? '')),
				'display_name' => sanitize_text_field((string) ($target['display_name'] ?? $user_login)),
				'role' => $role !== '' ? $role : get_option('default_role', 'subscriber'),
				'user_pass' => $password !== '' ? $password : wp_generate_password(24, true, true),
			]);

			if (is_wp_error($user_id)) {
				return $user_id;
			}
		}

		if ($password !== '') {
			wp_set_password($password, (int) $user_id);
		}

		$tfa_payload = is_array($payload['tfa'] ?? null) ? $payload['tfa'] : (is_array($target['tfa'] ?? null) ? $target['tfa'] : $payload);
		$tfa_result = $this->apply_remote_tfa_update((int) $user_id, $tfa_payload);

		if (is_wp_error($tfa_result)) {
			return $tfa_result;
		}

		$state = $this->get_user_tfa_state((int) $user_id);
		$stored_user = get_user_by('id', (int) $user_id);

		return [
			'user_id' => (int) $user_id,
			'username' => $stored_user instanceof WP_User ? (string) $stored_user->user_login : $user_login,
			'email' => $stored_user instanceof WP_User ? (string) $stored_user->user_email : $user_email,
			'tfa_status' => $state['tfa_status'],
			'tfa_source' => $state['tfa_source'],
			'tfa_managed' => $state['tfa_managed'],
			'password_updated' => $password !== '',
		];
	}

	public function apply_remote_tfa_update(int $user_id, array $payload): bool|WP_Error
	{
		$status = $this->normalize_status((string) ($payload['tfa_status'] ?? self::STATUS_NOT_ENABLED));
		$source = $this->normalize_source((string) ($payload['tfa_source'] ?? self::SOURCE_CORE));
		$managed = $this->normalize_managed((string) ($payload['tfa_managed'] ?? self::MANAGED_CORE));
		$secret = isset($payload['tfa_secret']) && is_string($payload['tfa_secret']) ? $payload['tfa_secret'] : '';

		if ($status === self::STATUS_NOT_ENABLED) {
			$this->clear_tfa($user_id, $source, $managed);
			return true;
		}

		if ($secret !== '') {
			$result = $this->set_secret($user_id, $secret);

			if (is_wp_error($result)) {
				return $result;
			}
		}

		if ($status === self::STATUS_PENDING_SETUP) {
			update_user_meta($user_id, self::META_STATUS, self::STATUS_PENDING_SETUP);
		} else {
			update_user_meta($user_id, self::META_STATUS, self::STATUS_ENABLED);
			if (!empty($payload['last_verified_at'])) {
				update_user_meta($user_id, self::META_LAST_VERIFIED_AT, freesiem_sentinel_sanitize_datetime((string) $payload['last_verified_at']));
			}
		}

		update_user_meta($user_id, self::META_SOURCE, $source);
		update_user_meta($user_id, self::META_MANAGED, $managed);

		return true;
	}

	public function reset_remote_tfa(array $payload): array|WP_Error
	{
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : $payload;
		$user = $this->find_target_user($target);

		if (!$user instanceof WP_User) {
			return new WP_Error('freesiem_tfa_user_missing', __('The selected user could not be found.', 'freesiem-sentinel'));
		}

		$replace_secret = isset($payload['tfa_secret']) && is_string($payload['tfa_secret']) ? $payload['tfa_secret'] : '';
		$status = $this->normalize_status((string) ($payload['tfa_status'] ?? self::STATUS_PENDING_SETUP));
		$source = $this->normalize_source((string) ($payload['tfa_source'] ?? self::SOURCE_CORE));
		$managed = $this->normalize_managed((string) ($payload['tfa_managed'] ?? self::MANAGED_CORE));

		$this->clear_secret((int) $user->ID);

		if ($replace_secret !== '') {
			$result = $this->set_secret((int) $user->ID, $replace_secret);

			if (is_wp_error($result)) {
				return $result;
			}
		}

		if ($status === self::STATUS_NOT_ENABLED) {
			$this->set_not_enabled((int) $user->ID, $source, $managed);
		} else {
			$this->set_pending_setup((int) $user->ID, $source, $managed);
		}

		return $this->get_user_tfa_state((int) $user->ID);
	}

	public function set_remote_password(array $payload): array|WP_Error
	{
		$target = is_array($payload['target'] ?? null) ? $payload['target'] : $payload;
		$user = $this->find_target_user($target);

		if (!$user instanceof WP_User) {
			return new WP_Error('freesiem_tfa_user_missing', __('The selected user could not be found.', 'freesiem-sentinel'));
		}

		$password = '';
		foreach (['password', 'user_pass', 'pass'] as $key) {
			if (isset($payload[$key]) && is_string($payload[$key])) {
				$password = $payload[$key];
				break;
			}
			if (isset($target[$key]) && is_string($target[$key])) {
				$password = $target[$key];
				break;
			}
		}

		if ($password === '') {
			return new WP_Error('freesiem_password_required', __('A non-empty password is required.', 'freesiem-sentinel'));
		}

		wp_set_password($password, (int) $user->ID);

		return [
			'user_id' => (int) $user->ID,
			'username' => (string) $user->user_login,
			'password_updated' => true,
		];
	}

	public function find_target_user(array $target): ?WP_User
	{
		$user_id = !empty($target['user_id']) ? (int) $target['user_id'] : 0;

		if ($user_id > 0) {
			$user = get_user_by('id', $user_id);
			if ($user instanceof WP_User) {
				return $user;
			}
		}

		$username = sanitize_user((string) ($target['username'] ?? $target['user_login'] ?? ''));
		if ($username !== '') {
			$user = get_user_by('login', $username);
			if ($user instanceof WP_User) {
				return $user;
			}
		}

		$email = sanitize_email((string) ($target['email'] ?? $target['user_email'] ?? ''));
		if ($email !== '') {
			$user = get_user_by('email', $email);
			if ($user instanceof WP_User) {
				return $user;
			}
		}

		return null;
	}

	private function protect_secret(string $secret): string|WP_Error
	{
		if (!function_exists('openssl_encrypt') || !function_exists('openssl_decrypt')) {
			return new WP_Error('freesiem_tfa_openssl_missing', __('OpenSSL is required for encrypted TFA secret storage.', 'freesiem-sentinel'));
		}

		$key = $this->get_secret_protection_key();
		$iv = random_bytes(16);
		$ciphertext = openssl_encrypt($secret, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

		if (!is_string($ciphertext) || $ciphertext === '') {
			return new WP_Error('freesiem_tfa_encrypt_failed', __('The TFA secret could not be encrypted.', 'freesiem-sentinel'));
		}

		$mac = hash_hmac('sha256', $iv . $ciphertext, $key);

		return self::SECRET_VERSION . ':' . base64_encode($iv) . ':' . base64_encode($ciphertext) . ':' . $mac;
	}

	private function reveal_secret(string $protected): string|WP_Error
	{
		$parts = explode(':', $protected, 4);

		if (count($parts) !== 4 || $parts[0] !== self::SECRET_VERSION) {
			return new WP_Error('freesiem_tfa_payload_invalid', __('The stored TFA secret payload is invalid.', 'freesiem-sentinel'));
		}

		$key = $this->get_secret_protection_key();
		$iv = base64_decode($parts[1], true);
		$ciphertext = base64_decode($parts[2], true);
		$mac = (string) $parts[3];

		if (!is_string($iv) || !is_string($ciphertext) || $iv === '' || $ciphertext === '') {
			return new WP_Error('freesiem_tfa_payload_invalid', __('The stored TFA secret payload is invalid.', 'freesiem-sentinel'));
		}

		$expected_mac = hash_hmac('sha256', $iv . $ciphertext, $key);

		if (!hash_equals($expected_mac, $mac)) {
			return new WP_Error('freesiem_tfa_payload_invalid', __('The stored TFA secret payload failed verification.', 'freesiem-sentinel'));
		}

		$secret = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

		if (!is_string($secret) || $secret === '') {
			return new WP_Error('freesiem_tfa_payload_invalid', __('The stored TFA secret could not be decrypted.', 'freesiem-sentinel'));
		}

		return $secret;
	}

	private function get_secret_protection_key(): string
	{
		return hash('sha256', wp_salt('secure_auth') . '|' . site_url('/') . '|freesiem-tfa', true);
	}

	private function normalize_status(string $status): string
	{
		$status = sanitize_key($status);

		return in_array($status, [self::STATUS_NOT_ENABLED, self::STATUS_PENDING_SETUP, self::STATUS_ENABLED], true)
			? $status
			: self::STATUS_NOT_ENABLED;
	}

	private function normalize_source(string $source): string
	{
		$source = sanitize_key($source);

		return in_array($source, [self::SOURCE_CORE, self::SOURCE_LOCAL], true) ? $source : self::SOURCE_LOCAL;
	}

	private function normalize_managed(string $managed): string
	{
		$managed = sanitize_key($managed);

		return in_array($managed, [self::MANAGED_CORE, self::MANAGED_LOCAL], true) ? $managed : self::MANAGED_LOCAL;
	}

	private function base32_decode(string $value): string
	{
		$value = strtoupper(preg_replace('/[^A-Z2-7]/', '', $value) ?: '');
		$alphabet = array_flip(str_split(self::BASE32_ALPHABET));
		$buffer = 0;
		$bits_left = 0;
		$output = '';

		for ($index = 0, $length = strlen($value); $index < $length; $index++) {
			$char = $value[$index];

			if (!isset($alphabet[$char])) {
				continue;
			}

			$buffer = ($buffer << 5) | $alphabet[$char];
			$bits_left += 5;

			if ($bits_left >= 8) {
				$bits_left -= 8;
				$output .= chr(($buffer >> $bits_left) & 0xFF);
			}
		}

		return $output;
	}
}
