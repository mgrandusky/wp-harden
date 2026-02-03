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
		add_action( 'wp_ajax_wph_test_api_key', array( $this, 'ajax_test_api_key' ) );
		add_action( 'wp_ajax_wph_download_geoip', array( $this, 'ajax_download_geoip' ) );
		add_action( 'wp_ajax_wph_clear_logs', array( $this, 'ajax_clear_logs' ) );
		add_action( 'wp_ajax_wph_export_report', array( $this, 'ajax_export_report' ) );
		add_action( 'wp_ajax_wph_fix_issue', array( $this, 'ajax_fix_issue' ) );
		add_action( 'wp_ajax_wph_ignore_issue', array( $this, 'ajax_ignore_issue' ) );
		add_action( 'wp_ajax_wph_bulk_fix', array( $this, 'ajax_bulk_fix' ) );
		add_action( 'wp_ajax_wph_bulk_ignore', array( $this, 'ajax_bulk_ignore' ) );
		add_action( 'wp_ajax_wph_get_log_details', array( $this, 'ajax_get_log_details' ) );
		add_action( 'wp_ajax_wph_delete_logs', array( $this, 'ajax_delete_logs' ) );
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

	/**
	 * AJAX handler for testing API keys
	 *
	 * @since 1.0.0
	 */
	public function ajax_test_api_key() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized', 'wp-harden' ) ) );
		}

		$api_type = isset( $_POST['api_type'] ) ? sanitize_text_field( wp_unslash( $_POST['api_type'] ) ) : '';
		$api_key  = isset( $_POST['api_key'] ) ? sanitize_text_field( wp_unslash( $_POST['api_key'] ) ) : '';

		if ( empty( $api_type ) || empty( $api_key ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid parameters', 'wp-harden' ) ) );
		}

		$result = $this->test_api_connection( $api_type, $api_key );

		if ( $result['success'] ) {
			wp_send_json_success( $result );
		} else {
			wp_send_json_error( $result );
		}
	}

	/**
	 * AJAX handler for downloading GeoIP database
	 *
	 * @since 1.0.0
	 */
	public function ajax_download_geoip() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized', 'wp-harden' ) ) );
		}

		$license_key = isset( $_POST['license_key'] ) ? sanitize_text_field( wp_unslash( $_POST['license_key'] ) ) : '';

		if ( empty( $license_key ) ) {
			wp_send_json_error( array( 'message' => __( 'License key is required', 'wp-harden' ) ) );
		}

		// Placeholder for actual GeoIP download logic
		// In a real implementation, this would download the MaxMind database
		wp_send_json_success( array( 'message' => __( 'GeoIP database download functionality will be implemented', 'wp-harden' ) ) );
	}

	/**
	 * AJAX handler for clearing old logs
	 *
	 * @since 1.0.0
	 */
	public function ajax_clear_logs() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized', 'wp-harden' ) ) );
		}

		$logger   = WPH_Logger::get_instance();
		$settings = WPH_Settings::get_instance();
		
		$retention_days = $settings->get( 'log_retention_days', 30 );
		$deleted        = $logger->clean_old_logs( $retention_days );

		wp_send_json_success(
			array(
				'message' => sprintf(
					/* translators: %d: number of deleted logs */
					__( '%d old logs deleted successfully', 'wp-harden' ),
					$deleted
				),
			)
		);
	}

	/**
	 * AJAX handler for exporting security report
	 *
	 * @since 1.0.0
	 */
	public function ajax_export_report() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized', 'wp-harden' ) );
		}

		$logger     = WPH_Logger::get_instance();
		$ip_manager = WPH_IP_Manager::get_instance();
		$settings   = WPH_Settings::get_instance();

		global $wpdb;
		
		// Gather report data
		$report_data = array();
		
		// Summary statistics
		$report_data['summary'] = array(
			'total_logs'      => $logger->get_log_count(),
			'critical_events' => $logger->get_log_count( array( 'severity' => 'critical' ) ),
			'blocked_ips'     => count( $ip_manager->get_blocked_ips() ),
			'generated_at'    => current_time( 'mysql' ),
		);

		// Latest scan
		$latest_scan = $wpdb->get_row(
			"SELECT * FROM {$wpdb->prefix}wph_scan_results 
			WHERE status = 'completed' 
			ORDER BY completed_at DESC 
			LIMIT 1"
		);
		
		if ( $latest_scan ) {
			$report_data['latest_scan'] = array(
				'completed_at'  => $latest_scan->completed_at,
				'issues_found'  => $latest_scan->issues_found,
				'status'        => $latest_scan->status,
			);
		}

		// Recent critical logs
		$critical_logs = $logger->get_logs(
			array(
				'severity' => 'critical',
				'limit'    => 50,
			)
		);
		
		$report_data['critical_events'] = $critical_logs;

		// Blocked IPs
		$blocked_ips = $ip_manager->get_blocked_ips( array( 'limit' => 100 ) );
		$report_data['blocked_ips'] = $blocked_ips;

		// Generate report
		$report = $this->generate_report_html( $report_data );

		// Output as HTML
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="wph-security-report-' . gmdate( 'Y-m-d' ) . '.html"' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		echo $report;
		exit;
	}

	/**
	 * Generate HTML security report
	 *
	 * @param array $data Report data.
	 * @return string HTML report
	 * @since 1.0.0
	 */
	private function generate_report_html( $data ) {
		ob_start();
		?>
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<title>WP Harden Security Report - <?php echo esc_html( gmdate( 'Y-m-d' ) ); ?></title>
			<style>
				body { font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5; }
				.container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
				h1 { color: #2271b1; border-bottom: 3px solid #2271b1; padding-bottom: 10px; }
				h2 { color: #333; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 8px; }
				.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
				.summary-card { background: #f9f9f9; padding: 15px; border-left: 4px solid #2271b1; }
				.summary-card strong { display: block; color: #666; font-size: 12px; margin-bottom: 5px; }
				.summary-card .value { font-size: 24px; font-weight: bold; color: #2271b1; }
				table { width: 100%; border-collapse: collapse; margin: 20px 0; }
				th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
				th { background: #f5f5f5; font-weight: bold; }
				.severity-critical { color: #d63638; font-weight: bold; }
				.severity-high { color: #d63638; }
				.severity-medium { color: #dba617; }
				.severity-low { color: #2271b1; }
				.footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px; }
			</style>
		</head>
		<body>
			<div class="container">
				<h1>🛡️ WP Harden Security Report</h1>
				<p>Generated on <?php echo esc_html( gmdate( 'F j, Y - H:i:s' ) ); ?> UTC</p>

				<h2>Summary</h2>
				<div class="summary-grid">
					<div class="summary-card">
						<strong>Total Security Events</strong>
						<div class="value"><?php echo absint( $data['summary']['total_logs'] ); ?></div>
					</div>
					<div class="summary-card">
						<strong>Critical Events</strong>
						<div class="value"><?php echo absint( $data['summary']['critical_events'] ); ?></div>
					</div>
					<div class="summary-card">
						<strong>Blocked IP Addresses</strong>
						<div class="value"><?php echo absint( $data['summary']['blocked_ips'] ); ?></div>
					</div>
				</div>

				<?php if ( isset( $data['latest_scan'] ) ) : ?>
				<h2>Latest Security Scan</h2>
				<table>
					<tr>
						<th>Completed</th>
						<td><?php echo esc_html( $data['latest_scan']['completed_at'] ); ?></td>
					</tr>
					<tr>
						<th>Issues Found</th>
						<td><?php echo absint( $data['latest_scan']['issues_found'] ); ?></td>
					</tr>
					<tr>
						<th>Status</th>
						<td><?php echo esc_html( ucfirst( $data['latest_scan']['status'] ) ); ?></td>
					</tr>
				</table>
				<?php endif; ?>

				<h2>Recent Critical Events</h2>
				<?php if ( ! empty( $data['critical_events'] ) ) : ?>
				<table>
					<thead>
						<tr>
							<th>Date/Time</th>
							<th>Type</th>
							<th>Severity</th>
							<th>Message</th>
							<th>IP Address</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $data['critical_events'] as $event ) : ?>
						<tr>
							<td><?php echo esc_html( $event->created_at ); ?></td>
							<td><?php echo esc_html( ucfirst( $event->log_type ) ); ?></td>
							<td class="severity-<?php echo esc_attr( $event->severity ); ?>">
								<?php echo esc_html( ucfirst( $event->severity ) ); ?>
							</td>
							<td><?php echo esc_html( $event->message ); ?></td>
							<td><?php echo esc_html( $event->ip_address ); ?></td>
						</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php else : ?>
				<p>No critical events recorded.</p>
				<?php endif; ?>

				<h2>Blocked IP Addresses</h2>
				<?php if ( ! empty( $data['blocked_ips'] ) ) : ?>
				<table>
					<thead>
						<tr>
							<th>IP Address</th>
							<th>Block Type</th>
							<th>Reason</th>
							<th>Blocked At</th>
							<th>Expires At</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $data['blocked_ips'] as $ip ) : ?>
						<tr>
							<td><?php echo esc_html( $ip->ip_address ); ?></td>
							<td><?php echo esc_html( ucfirst( $ip->block_type ) ); ?></td>
							<td><?php echo esc_html( $ip->reason ); ?></td>
							<td><?php echo esc_html( $ip->blocked_at ); ?></td>
							<td><?php echo esc_html( $ip->expires_at ?? 'Never' ); ?></td>
						</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<?php else : ?>
				<p>No IP addresses are currently blocked.</p>
				<?php endif; ?>

				<div class="footer">
					<p>Generated by WP Harden v<?php echo esc_html( WPH_VERSION ); ?></p>
				</div>
			</div>
		</body>
		</html>
		<?php
		return ob_get_clean();
	}

	/**
	 * Test API connection
	 *
	 * @param string $api_type API type (abuseipdb, wpscan, virustotal).
	 * @param string $api_key  API key to test.
	 * @return array Result of the test
	 * @since 1.0.0
	 */
	private function test_api_connection( $api_type, $api_key ) {
		$result = array(
			'success' => false,
			'message' => '',
		);

		switch ( $api_type ) {
			case 'abuseipdb':
				// Test AbuseIPDB API
				$response = wp_remote_get(
					'https://api.abuseipdb.com/api/v2/check?ipAddress=127.0.0.1',
					array(
						'headers' => array(
							'Key'    => $api_key,
							'Accept' => 'application/json',
						),
						'timeout' => 10,
					)
				);

				if ( is_wp_error( $response ) ) {
					$result['message'] = $response->get_error_message();
				} else {
					$code = wp_remote_retrieve_response_code( $response );
					if ( 200 === $code ) {
						$result['success'] = true;
						$result['message'] = __( 'AbuseIPDB API key is valid', 'wp-harden' );
					} else {
						$result['message'] = __( 'Invalid API key or API error', 'wp-harden' );
					}
				}
				break;

			case 'wpscan':
				// Test WPScan API
				$response = wp_remote_get(
					'https://wpscan.com/api/v3/wordpress/versions',
					array(
						'headers' => array(
							'Authorization' => 'Token token=' . $api_key,
						),
						'timeout' => 10,
					)
				);

				if ( is_wp_error( $response ) ) {
					$result['message'] = $response->get_error_message();
				} else {
					$code = wp_remote_retrieve_response_code( $response );
					if ( 200 === $code ) {
						$result['success'] = true;
						$result['message'] = __( 'WPScan API key is valid', 'wp-harden' );
					} else {
						$result['message'] = __( 'Invalid API key or API error', 'wp-harden' );
					}
				}
				break;

			case 'virustotal':
				// Test VirusTotal API
				$response = wp_remote_get(
					'https://www.virustotal.com/api/v3/ip_addresses/127.0.0.1',
					array(
						'headers' => array(
							'x-apikey' => $api_key,
						),
						'timeout' => 10,
					)
				);

				if ( is_wp_error( $response ) ) {
					$result['message'] = $response->get_error_message();
				} else {
					$code = wp_remote_retrieve_response_code( $response );
					if ( 200 === $code ) {
						$result['success'] = true;
						$result['message'] = __( 'VirusTotal API key is valid', 'wp-harden' );
					} else {
						$result['message'] = __( 'Invalid API key or API error', 'wp-harden' );
					}
				}
				break;

			default:
				$result['message'] = __( 'Unknown API type', 'wp-harden' );
				break;
		}

		return $result;
	}

	/**
	 * AJAX handler for fixing a single security issue
	 *
	 * @since 1.0.0
	 */
	public function ajax_fix_issue() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );
		
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'wp-harden' ) ) );
		}
		
		$issue_type = isset( $_POST['issue_type'] ) ? sanitize_text_field( wp_unslash( $_POST['issue_type'] ) ) : '';
		$issue_data = isset( $_POST['issue_data'] ) ? json_decode( stripslashes( $_POST['issue_data'] ), true ) : array();
		
		if ( empty( $issue_type ) || empty( $issue_data ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid issue data.', 'wp-harden' ) ) );
		}
		
		$scanner = WPH_Scanner::get_instance();
		$result = $scanner->fix_issue( $issue_type, $issue_data );
		
		if ( $result['success'] ) {
			wp_send_json_success( array(
				'message' => $result['message'],
				'fixed' => true
			) );
		} else {
			wp_send_json_error( array( 'message' => $result['message'] ) );
		}
	}

	/**
	 * AJAX handler for ignoring a single security issue
	 *
	 * @since 1.0.0
	 */
	public function ajax_ignore_issue() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );
		
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'wp-harden' ) ) );
		}
		
		$issue_type = isset( $_POST['issue_type'] ) ? sanitize_text_field( wp_unslash( $_POST['issue_type'] ) ) : '';
		$issue_data = isset( $_POST['issue_data'] ) ? json_decode( stripslashes( $_POST['issue_data'] ), true ) : array();
		$reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';
		
		if ( empty( $issue_type ) || empty( $issue_data ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid issue data.', 'wp-harden' ) ) );
		}
		
		$scanner = WPH_Scanner::get_instance();
		$success = $scanner->ignore_issue( $issue_type, $issue_data, $reason );
		
		if ( $success ) {
			wp_send_json_success( array(
				'message' => __( 'Issue ignored successfully.', 'wp-harden' ),
				'ignored' => true
			) );
		} else {
			wp_send_json_error( array( 'message' => __( 'Failed to ignore issue.', 'wp-harden' ) ) );
		}
	}

	/**
	 * AJAX handler for bulk fix
	 *
	 * @since 1.0.0
	 */
	public function ajax_bulk_fix() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );
		
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'wp-harden' ) ) );
		}
		
		$issues = isset( $_POST['issues'] ) ? json_decode( stripslashes( $_POST['issues'] ), true ) : array();
		
		if ( empty( $issues ) ) {
			wp_send_json_error( array( 'message' => __( 'No issues selected.', 'wp-harden' ) ) );
		}
		
		$scanner = WPH_Scanner::get_instance();
		$fixed_count = 0;
		$failed_count = 0;
		$messages = array();
		
		foreach ( $issues as $issue ) {
			$result = $scanner->fix_issue( $issue['type'], $issue['data'] );
			if ( $result['success'] ) {
				$fixed_count++;
			} else {
				$failed_count++;
				$messages[] = $result['message'];
			}
		}
		
		wp_send_json_success( array(
			'message' => sprintf( __( 'Fixed %d of %d issues.', 'wp-harden' ), $fixed_count, count( $issues ) ),
			'fixed' => $fixed_count,
			'failed' => $failed_count,
			'details' => $messages
		) );
	}

	/**
	 * AJAX handler for bulk ignore
	 *
	 * @since 1.0.0
	 */
	public function ajax_bulk_ignore() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );
		
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'wp-harden' ) ) );
		}
		
		$issues = isset( $_POST['issues'] ) ? json_decode( stripslashes( $_POST['issues'] ), true ) : array();
		$reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';
		
		if ( empty( $issues ) ) {
			wp_send_json_error( array( 'message' => __( 'No issues selected.', 'wp-harden' ) ) );
		}
		
		$scanner = WPH_Scanner::get_instance();
		$ignored_count = 0;
		
		foreach ( $issues as $issue ) {
			if ( $scanner->ignore_issue( $issue['type'], $issue['data'], $reason ) ) {
				$ignored_count++;
			}
		}
		
		wp_send_json_success( array(
			'message' => sprintf( __( 'Ignored %d issues.', 'wp-harden' ), $ignored_count ),
			'ignored' => $ignored_count
		) );
	}

	/**
	 * AJAX handler to get log details
	 *
	 * @since 1.0.0
	 */
	public function ajax_get_log_details() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );
		
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'wp-harden' ) ) );
		}
		
		$log_id = isset( $_POST['log_id'] ) ? absint( $_POST['log_id'] ) : 0;
		
		if ( empty( $log_id ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid log ID.', 'wp-harden' ) ) );
		}
		
		global $wpdb;
		$table = $wpdb->prefix . 'wph_logs';
		
		$log = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM $table WHERE id = %d",
				$log_id
			)
		);
		
		if ( ! $log ) {
			wp_send_json_error( array( 'message' => __( 'Log not found.', 'wp-harden' ) ) );
		}
		
		// Parse context JSON if it exists
		if ( ! empty( $log->metadata ) ) {
			$log->context = json_decode( $log->metadata, true );
		}
		
		// Get user info if user_id exists
		if ( ! empty( $log->user_id ) ) {
			$user = get_userdata( $log->user_id );
			$log->user_login = $user ? $user->user_login : __( 'Unknown', 'wp-harden' );
			$log->user_email = $user ? $user->user_email : '';
		}
		
		wp_send_json_success( array( 'log' => $log ) );
	}

	/**
	 * AJAX handler to delete logs
	 *
	 * @since 1.0.0
	 */
	public function ajax_delete_logs() {
		check_ajax_referer( 'wph_ajax_nonce', 'nonce' );
		
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'wp-harden' ) ) );
		}
		
		$log_ids = isset( $_POST['log_ids'] ) ? array_map( 'absint', $_POST['log_ids'] ) : array();
		
		if ( empty( $log_ids ) ) {
			wp_send_json_error( array( 'message' => __( 'No logs selected.', 'wp-harden' ) ) );
		}
		
		global $wpdb;
		$table = $wpdb->prefix . 'wph_logs';
		
		// Sanitize IDs
		$ids_placeholder = implode( ',', array_fill( 0, count( $log_ids ), '%d' ) );
		
		// Delete logs
		$deleted = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM $table WHERE id IN ($ids_placeholder)",
				...$log_ids
			)
		);
		
		if ( false === $deleted ) {
			wp_send_json_error( array( 'message' => __( 'Failed to delete logs.', 'wp-harden' ) ) );
		}
		
		// Log the deletion action
		$logger = WPH_Logger::get_instance();
		$logger->log(
			'admin',
			'low',
			sprintf( __( 'Deleted %d log entries', 'wp-harden' ), $deleted ),
			array(
				'deleted_count' => $deleted,
				'log_ids' => $log_ids,
				'user_id' => get_current_user_id()
			)
		);
		
		wp_send_json_success( array(
			'message' => sprintf( __( 'Successfully deleted %d log(s).', 'wp-harden' ), $deleted ),
			'deleted' => $deleted
		) );
	}
}
