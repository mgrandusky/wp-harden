<?php
/**
 * Activity Logger Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Logger
 *
 * Handles security event logging
 */
class WPH_Logger {

	/**
	 * Singleton instance
	 *
	 * @var WPH_Logger
	 */
	private static $instance = null;

	/**
	 * Get singleton instance
	 *
	 * @return WPH_Logger
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
		add_action( 'wph_cleanup_logs', array( $this, 'cleanup_old_logs' ) );
	}

	/**
	 * Log a security event
	 *
	 * @param string $log_type Event type (login, firewall, scan, etc).
	 * @param string $severity Severity level (low, medium, high, critical).
	 * @param string $message  Event message.
	 * @param array  $metadata Additional event data.
	 * @return int|false Log ID or false on failure
	 * @since 1.0.0
	 */
	public function log( $log_type, $severity, $message, $metadata = array() ) {
		global $wpdb;

		$table = $wpdb->prefix . 'wph_logs';

		$data = array(
			'log_type'   => sanitize_text_field( $log_type ),
			'severity'   => sanitize_text_field( $severity ),
			'message'    => sanitize_text_field( $message ),
			'ip_address' => $this->get_client_ip(),
			'user_id'    => get_current_user_id(),
			'metadata'   => wp_json_encode( $metadata ),
			'created_at' => current_time( 'mysql' ),
		);

		$result = $wpdb->insert( $table, $data );

		if ( $result ) {
			// Trigger notification for critical events
			if ( 'critical' === $severity || 'high' === $severity ) {
				do_action( 'wph_critical_event', $log_type, $message, $metadata );
			}

			return $wpdb->insert_id;
		}

		return false;
	}

	/**
	 * Get logs with filtering
	 *
	 * @param array $args Query arguments.
	 * @return array
	 * @since 1.0.0
	 */
	public function get_logs( $args = array() ) {
		global $wpdb;

		$defaults = array(
			'log_type'   => '',
			'severity'   => '',
			'ip_address' => '',
			'limit'      => 100,
			'offset'     => 0,
			'orderby'    => 'created_at',
			'order'      => 'DESC',
		);

		$args = wp_parse_args( $args, $defaults );

		$table = $wpdb->prefix . 'wph_logs';
		$where = array( '1=1' );

		if ( ! empty( $args['log_type'] ) ) {
			$where[] = $wpdb->prepare( 'log_type = %s', $args['log_type'] );
		}

		if ( ! empty( $args['severity'] ) ) {
			$where[] = $wpdb->prepare( 'severity = %s', $args['severity'] );
		}

		if ( ! empty( $args['ip_address'] ) ) {
			$where[] = $wpdb->prepare( 'ip_address = %s', $args['ip_address'] );
		}

		$where_clause = implode( ' AND ', $where );
		$orderby      = sanitize_sql_orderby( $args['orderby'] . ' ' . $args['order'] );
		$limit        = absint( $args['limit'] );
		$offset       = absint( $args['offset'] );

		// Use prepare for the complete query
		$query = $wpdb->prepare(
			"SELECT * FROM $table WHERE $where_clause ORDER BY $orderby LIMIT %d OFFSET %d",
			$limit,
			$offset
		);

		return $wpdb->get_results( $query );
	}

	/**
	 * Get log count
	 *
	 * @param array $args Query arguments.
	 * @return int
	 * @since 1.0.0
	 */
	public function get_log_count( $args = array() ) {
		global $wpdb;

		$table = $wpdb->prefix . 'wph_logs';
		$where = array( '1=1' );

		if ( ! empty( $args['log_type'] ) ) {
			$where[] = $wpdb->prepare( 'log_type = %s', $args['log_type'] );
		}

		if ( ! empty( $args['severity'] ) ) {
			$where[] = $wpdb->prepare( 'severity = %s', $args['severity'] );
		}

		$where_clause = implode( ' AND ', $where );

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table WHERE $where_clause" );
	}

	/**
	 * Export logs to CSV
	 *
	 * @param array $args Query arguments.
	 * @return string CSV content
	 * @since 1.0.0
	 */
	public function export_logs_csv( $args = array() ) {
		$logs = $this->get_logs( $args );

		$csv = "ID,Type,Severity,Message,IP Address,User ID,Created At\n";

		foreach ( $logs as $log ) {
			$csv .= sprintf(
				"%d,%s,%s,%s,%s,%d,%s\n",
				$log->id,
				$log->log_type,
				$log->severity,
				str_replace( ',', ';', $log->message ),
				$log->ip_address,
				$log->user_id,
				$log->created_at
			);
		}

		return $csv;
	}

	/**
	 * Clean up old logs based on retention policy
	 *
	 * @since 1.0.0
	 */
	public function cleanup_old_logs() {
		global $wpdb;

		$settings       = WPH_Settings::get_instance();
		$retention_days = $settings->get( 'log_retention_days', 30 );

		$table = $wpdb->prefix . 'wph_logs';

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM $table WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
				$retention_days
			)
		);
	}

	/**
	 * Get client IP address
	 *
	 * @return string
	 * @since 1.0.0
	 */
	private function get_client_ip() {
		$ip = '';

		if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) );
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
		} elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		// Validate IP address
		$ip = filter_var( $ip, FILTER_VALIDATE_IP );

		return $ip ? $ip : '0.0.0.0';
	}
}
