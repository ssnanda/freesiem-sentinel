<?php

if (!defined('ABSPATH')) {
	exit;
}

class Freesiem_Features
{
	public static function get_plan(): string
	{
		$settings = freesiem_sentinel_get_settings();
		$plan = freesiem_sentinel_safe_string($settings['plan'] ?? 'free');

		return in_array($plan, ['free', 'pro'], true) ? $plan : 'free';
	}

	public static function is_enabled(string $feature): bool
	{
		$plan = self::get_plan();

		$map = [
			'free' => [
				'basic_scan' => true,
				'filesystem_basic' => true,
			],
			'pro' => [
				'basic_scan' => true,
				'filesystem_basic' => true,
				'filesystem_advanced' => true,
				'fim' => true,
				'high_frequency' => true,
			],
		];

		return !empty($map[$plan][$feature]);
	}
}
