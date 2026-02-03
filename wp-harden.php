<?php
/**
 * Plugin Name: WP Harden
 * Plugin URI: https://github.com/mgrandusky/wp-harden
 * Description: A comprehensive WordPress security plugin providing firewall protection, malware scanning, login security, and real-time threat monitoring.
 * Version: 1.0.0
 * Author: WP Harden Team
 * Author URI: https://github.com/mgrandusky/wp-harden
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-harden
 * Domain Path: /languages
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

// Define plugin constants
define( 'WPH_VERSION', '1.0.0' );
define( 'WPH_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPH_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WPH_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

/**
 * Plugin activation hook
 */
function activate_wp_harden() {
	require_once WPH_PLUGIN_DIR . 'includes/class-wph-activator.php';
	WPH_Activator::activate();
}

/**
 * Plugin deactivation hook
 */
function deactivate_wp_harden() {
	require_once WPH_PLUGIN_DIR . 'includes/class-wph-deactivator.php';
	WPH_Deactivator::deactivate();
}

register_activation_hook( __FILE__, 'activate_wp_harden' );
register_deactivation_hook( __FILE__, 'deactivate_wp_harden' );

/**
 * The core plugin class
 */
require_once WPH_PLUGIN_DIR . 'includes/class-wph-core.php';

/**
 * Begin plugin execution
 */
function run_wp_harden() {
	$plugin = new WPH_Core();
	$plugin->run();
}

run_wp_harden();
