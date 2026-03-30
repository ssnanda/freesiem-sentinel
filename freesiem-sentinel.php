<?php
/**
 * Plugin Name: freeSIEM Sentinel
 * Plugin URI: https://github.com/ssnanda/freesiem-sentinel
 * Description: Connects a WordPress site to freeSIEM Core for verification, local scanning, secure result uploads, command handling, and summary reporting.
 * Version: 0.2.6
 * Update URI: https://github.com/ssnanda/freesiem-sentinel
 * Author: freesiem.com
 * Text Domain: freesiem-sentinel
 */

if (!defined('ABSPATH')) {
	exit;
}

define('FREESIEM_SENTINEL_VERSION', '0.2.6');
define('FREESIEM_SENTINEL_SLUG', 'freesiem-sentinel');
define('FREESIEM_SENTINEL_OPTION', 'freesiem_sentinel_settings');
define('FREESIEM_SENTINEL_NONCE_ACTION', 'freesiem_sentinel_admin_action');
define('FREESIEM_SENTINEL_BACKEND_URL', 'https://core.freesiem.com');
define('FREESIEM_SENTINEL_PLUGIN_FILE', __FILE__);
define('FREESIEM_SENTINEL_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('FREESIEM_SENTINEL_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('FREESIEM_SENTINEL_PLUGIN_URL', plugin_dir_url(__FILE__));

if (!defined('FREESIEM_SENTINEL_GITHUB_REPOSITORY')) {
	define('FREESIEM_SENTINEL_GITHUB_REPOSITORY', 'https://github.com/ssnanda/freesiem-sentinel');
}

if (!defined('FREESIEM_SENTINEL_GITHUB_BRANCH')) {
	define('FREESIEM_SENTINEL_GITHUB_BRANCH', 'main');
}

if (!defined('FREESIEM_SENTINEL_GITHUB_RELEASE_ASSET')) {
	define('FREESIEM_SENTINEL_GITHUB_RELEASE_ASSET', 'freesiem-sentinel.zip');
}

require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/helpers.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-features.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-api-client.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-cloud-connect-state.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-cloud-connect-signer.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-cloud-connect-client.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-pending-tasks.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-tfa-service.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-tfa-auth.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-tfa-remote.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-scanner.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-results.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-commands.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-cron.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-updater.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-admin.php';
require_once FREESIEM_SENTINEL_PLUGIN_DIR . 'includes/class-plugin.php';

register_activation_hook(__FILE__, ['Freesiem_Plugin', 'activate']);
register_deactivation_hook(__FILE__, ['Freesiem_Plugin', 'deactivate']);

Freesiem_Plugin::instance();
