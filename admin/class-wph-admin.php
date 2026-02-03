<?php
/**
 * Admin Interface Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Admin
 *
 * Handles admin interface and functionality
 */
class WPH_Admin {

	/**
	 * Singleton instance
	 *
	 * @var WPH_Admin
	 */
	private static $instance = null;

	/**
	 * Get singleton instance
	 *
	 * @return WPH_Admin
	 * @since 1.0.0
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor
	 *
	 * @since 1.0.0
	 */
	private function __construct() {
		$this->init_hooks();
	}

	/**
	 * Initialize hooks
	 *
	 * @since 1.0.0
	 */
	private function init_hooks() {
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		add_action( 'wp_ajax_wph_run_scan', array( $this, 'ajax_run_scan' ) );
		add_action( 'wp_ajax_wph_block_ip', array( $this, 'ajax_block_ip' ) );
		add_action( 'wp_ajax_wph_unblock_ip', array( $this, 'ajax_unblock_ip' ) );
		add_action( 'wp_ajax_wph_export_logs', array( $this, 'ajax_export_logs' ) );
	}

	/**
	 * Add admin menu pages
	 *
	 * @since 1.0.0
	 */
	public function add_admin_menu() {
		// Main dashboard page
		add_menu_page(
			__( 'WP Harden', 'wp-harden' ),
			__( 'WP Harden', 'wp-harden' ),
			'manage_options',
			'wp-harden',
			array( $this, 'render_dashboard' ),
			'dashicons-shield',
			30
		);

		// Scanner page
		add_submenu_page(
			'wp-harden',
			__( 'Security Scanner', 'wp-harden' ),
			__( 'Scanner', 'wp-harden' ),
			'manage_options',
			'wp-harden-scanner',
			array( $this, 'render_scanner' )
		);

		// Logs page
		add_submenu_page(
			'wp-harden',
			__( 'Activity Logs', 'wp-harden' ),
			__( 'Logs', 'wp-harden' ),
			'manage_options',
			'wp-harden-logs',
			array( $this, 'render_logs' )
		);

		// IP Management page
		add_submenu_page(
			'wp-harden',
			__( 'IP Management', 'wp-harden' ),
			__( 'IP Management', 'wp-harden' ),
			'manage_options',
			'wp-harden-ip-management',
			array( $this, 'render_ip_management' )
		);

		// Settings page
		add_submenu_page(
			'wp-harden',
			__( 'Settings', 'wp-harden' ),
			__( 'Settings', 'wp-harden' ),
			'manage_options',
			'wp-harden-settings',
			array( $this, 'render_settings' )
		);
	}

	/**
	 * Enqueue admin assets
	 *
	 * @param string $hook Current admin page hook.
	 * @since 1.0.0
	 */
	public function enqueue_admin_assets( $hook ) {
		// Only load on WP Harden pages
		if ( strpos( $hook, 'wp-harden' ) === false ) {
			return;
		}

		wp_enqueue_style(
			'wph-admin-styles',
			WPH_PLUGIN_URL . 'admin/css/admin-styles.css',
			array(),
			WPH_VERSION
		);

		wp_enqueue_script(
			'wph-admin-scripts',
			WPH_PLUGIN_URL . 'admin/js/admin-scripts.js',
			array( 'jquery' ),
			WPH_VERSION,
			true
		);

		wp_localize_script(
			'wph-admin-scripts',
			'wphAjax',
			array(
				'ajaxurl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'wph_ajax_nonce' ),
			)
		);
	}

	/**
	 * Render dashboard page
	 *
	 * @since 1.0.0
	 */
	public function render_dashboard() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-harden' ) );
		}

		require_once WPH_PLUGIN_DIR . 'admin/views/dashboard.php';
	}

	/**
	 * Render scanner page
	 *
	 * @since 1.0.0
	 */
	public function render_scanner() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-harden' ) );
		}

		require_once WPH_PLUGIN_DIR . 'admin/views/scanner.php';
	}

	/**
	 * Render logs page
	 *
	 * @since 1.0.0
	 */
	public function render_logs() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-harden' ) );
		}

		require_once WPH_PLUGIN_DIR . 'admin/views/logs.php';
	}

	/**
	 * Render IP management page
	 *
	 * @since 1.0.0
	 */
	public function render_ip_management() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-harden' ) );
		}

		require_once WPH_PLUGIN_DIR . 'admin/views/ip-management.php';
	}

	/**
	 * Render settings page
	 *
	 * @since 1.0.0
	 */
	public function render_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-harden' ) );
		}

		require_once WPH_PLUGIN_DIR . 'admin/views/settings.php';
	}

	/**
	 * AJAX handler for running security scan
	 *
	 * @since 1.0.0
	 */
	public function ajax_run_scan() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized', 'wp-harden' ) ) );
		}

		$scanner = WPH_Scanner::get_instance();
		$results = $scanner->run_scan();

		wp_send_json_success( array( 'results' => $results ) );
	}

	/**
	 * AJAX handler for blocking IP
	 *
	 * @since 1.0.0
	 */
	public function ajax_block_ip() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized', 'wp-harden' ) ) );
		}

		$ip_address = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$reason     = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : 'Manual block';
		$block_type = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : 'permanent';

		if ( empty( $ip_address ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required', 'wp-harden' ) ) );
		}

		$ip_manager = WPH_IP_Manager::get_instance();
		$result     = $ip_manager->block_ip( $ip_address, $reason, $block_type );

		if ( $result ) {
			wp_send_json_success( array( 'message' => __( 'IP blocked successfully', 'wp-harden' ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'Failed to block IP', 'wp-harden' ) ) );
		}
	}

	/**
	 * AJAX handler for unblocking IP
	 *
	 * @since 1.0.0
	 */
	public function ajax_unblock_ip() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized', 'wp-harden' ) ) );
		}

		$ip_address = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';

		if ( empty( $ip_address ) ) {
			wp_send_json_error( array( 'message' => __( 'IP address is required', 'wp-harden' ) ) );
		}

		$ip_manager = WPH_IP_Manager::get_instance();
		$result     = $ip_manager->unblock_ip( $ip_address );

		if ( $result ) {
			wp_send_json_success( array( 'message' => __( 'IP unblocked successfully', 'wp-harden' ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'Failed to unblock IP', 'wp-harden' ) ) );
		}
	}

	/**
	 * AJAX handler for exporting logs
	 *
	 * @since 1.0.0
	 */
	public function ajax_export_logs() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'wp-harden' ) );
		}

		$logger = WPH_Logger::get_instance();
		$csv    = $logger->export_logs_csv( array( 'limit' => 10000 ) );

		header( 'Content-Type: text/csv' );
		header( 'Content-Disposition: attachment; filename="wph-logs-' . gmdate( 'Y-m-d' ) . '.csv"' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		echo $csv;
		exit;
	}
}
