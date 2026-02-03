<?php
/**
 * Core Plugin Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Core
 *
 * Main plugin orchestration class
 */
class WPH_Core {

	/**
	 * Plugin loader
	 *
	 * @var WPH_Loader
	 */
	protected $loader;

	/**
	 * Plugin version
	 *
	 * @var string
	 */
	protected $version;

	/**
	 * Constructor
	 *
	 * @since 1.0.0
	 */
	public function __construct() {
		$this->version = WPH_VERSION;
		$this->load_dependencies();
		$this->define_hooks();
	}

	/**
	 * Load required dependencies
	 *
	 * @since 1.0.0
	 */
	private function load_dependencies() {
		// Core classes
		require_once WPH_PLUGIN_DIR . 'includes/class-wph-settings.php';
		require_once WPH_PLUGIN_DIR . 'includes/class-wph-logger.php';
		require_once WPH_PLUGIN_DIR . 'includes/class-wph-ip-manager.php';
		require_once WPH_PLUGIN_DIR . 'includes/class-wph-firewall.php';
		require_once WPH_PLUGIN_DIR . 'includes/class-wph-login-security.php';
		require_once WPH_PLUGIN_DIR . 'includes/class-wph-scanner.php';
		require_once WPH_PLUGIN_DIR . 'includes/class-wph-notifications.php';
		require_once WPH_PLUGIN_DIR . 'includes/class-wph-advanced-auth.php';
		require_once WPH_PLUGIN_DIR . 'includes/class-wph-hardening.php';

		// Admin classes
		if ( is_admin() ) {
			require_once WPH_PLUGIN_DIR . 'admin/class-wph-admin.php';
		}
	}

	/**
	 * Define plugin hooks
	 *
	 * @since 1.0.0
	 */
	private function define_hooks() {
		// Initialize settings
		$settings = WPH_Settings::get_instance();

		// Initialize firewall (runs early)
		$firewall = WPH_Firewall::get_instance();

		// Initialize login security
		$login_security = WPH_Login_Security::get_instance();

		// Initialize scanner
		$scanner = WPH_Scanner::get_instance();

		// Initialize advanced authentication
		$advanced_auth = WPH_Advanced_Auth::get_instance();

		// Initialize security hardening
		$hardening = WPH_Hardening::get_instance();

		// Initialize admin interface
		if ( is_admin() ) {
			$admin = WPH_Admin::get_instance();
		}

		// Schedule cron jobs
		add_action( 'wp', array( $this, 'schedule_events' ) );
	}

	/**
	 * Schedule plugin cron events
	 *
	 * @since 1.0.0
	 */
	public function schedule_events() {
		if ( ! wp_next_scheduled( 'wph_daily_scan' ) ) {
			wp_schedule_event( time(), 'daily', 'wph_daily_scan' );
		}

		if ( ! wp_next_scheduled( 'wph_cleanup_logs' ) ) {
			wp_schedule_event( time(), 'daily', 'wph_cleanup_logs' );
		}

		if ( ! wp_next_scheduled( 'wph_cleanup_expired_blocks' ) ) {
			wp_schedule_event( time(), 'hourly', 'wph_cleanup_expired_blocks' );
		}
	}

	/**
	 * Run the plugin
	 *
	 * @since 1.0.0
	 */
	public function run() {
		// Plugin is now running
		do_action( 'wph_loaded' );
	}

	/**
	 * Get plugin version
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function get_version() {
		return $this->version;
	}
}
