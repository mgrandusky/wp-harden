<?php
/**
 * Plugin Activator
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Activator
 *
 * Handles plugin activation tasks
 */
class WPH_Activator {

	/**
	 * Activate the plugin
	 *
	 * Creates necessary database tables and sets default options
	 *
	 * @since 1.0.0
	 */
	public static function activate() {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		// Table for security logs
		$table_logs = $wpdb->prefix . 'wph_logs';
		$sql_logs   = "CREATE TABLE IF NOT EXISTS $table_logs (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			log_type varchar(50) NOT NULL,
			severity varchar(20) NOT NULL,
			message text NOT NULL,
			ip_address varchar(45) NOT NULL,
			user_id bigint(20) DEFAULT NULL,
			metadata longtext DEFAULT NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY log_type (log_type),
			KEY severity (severity),
			KEY ip_address (ip_address),
			KEY created_at (created_at)
		) $charset_collate;";

		// Table for blocked IPs
		$table_blocked_ips = $wpdb->prefix . 'wph_blocked_ips';
		$sql_blocked_ips   = "CREATE TABLE IF NOT EXISTS $table_blocked_ips (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL,
			block_type varchar(20) NOT NULL DEFAULT 'temporary',
			reason text NOT NULL,
			blocked_at datetime NOT NULL,
			expires_at datetime DEFAULT NULL,
			unblocked_at datetime DEFAULT NULL,
			is_active tinyint(1) NOT NULL DEFAULT 1,
			PRIMARY KEY  (id),
			UNIQUE KEY ip_address (ip_address),
			KEY block_type (block_type),
			KEY is_active (is_active),
			KEY expires_at (expires_at)
		) $charset_collate;";

		// Table for login attempts
		$table_login_attempts = $wpdb->prefix . 'wph_login_attempts';
		$sql_login_attempts   = "CREATE TABLE IF NOT EXISTS $table_login_attempts (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL,
			username varchar(255) NOT NULL,
			success tinyint(1) NOT NULL DEFAULT 0,
			attempted_at datetime NOT NULL,
			user_agent text DEFAULT NULL,
			PRIMARY KEY  (id),
			KEY ip_address (ip_address),
			KEY username (username(191)),
			KEY attempted_at (attempted_at),
			KEY success (success)
		) $charset_collate;";

		// Table for scan results
		$table_scan_results = $wpdb->prefix . 'wph_scan_results';
		$sql_scan_results   = "CREATE TABLE IF NOT EXISTS $table_scan_results (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			scan_type varchar(50) NOT NULL,
			status varchar(20) NOT NULL,
			issues_found int(11) NOT NULL DEFAULT 0,
			scan_data longtext DEFAULT NULL,
			started_at datetime NOT NULL,
			completed_at datetime DEFAULT NULL,
			PRIMARY KEY  (id),
			KEY scan_type (scan_type),
			KEY status (status),
			KEY started_at (started_at)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql_logs );
		dbDelta( $sql_blocked_ips );
		dbDelta( $sql_login_attempts );
		dbDelta( $sql_scan_results );

		// Set default options
		$default_settings = array(
			'firewall_enabled'           => true,
			'firewall_sensitivity'       => 'medium',
			'login_security_enabled'     => true,
			'max_login_attempts'         => 5,
			'login_lockout_duration'     => 900, // 15 minutes
			'scanner_enabled'            => true,
			'scan_schedule'              => 'daily',
			'email_notifications'        => true,
			'notification_email'         => get_option( 'admin_email' ),
			'log_retention_days'         => 30,
			'ip_whitelist'               => array(),
			'ip_blacklist'               => array(),
			'rate_limit_enabled'         => true,
			'rate_limit_requests'        => 60,
			'rate_limit_period'          => 60, // per minute
			'strong_password_enforcement' => true,
			'prevent_username_enumeration' => true,
			// Advanced WAF settings
			'advanced_rate_limiting'     => true,
			'ddos_protection'            => true,
			'ddos_spike_threshold'       => 3,
			'http_method_filtering'      => true,
			'file_upload_security'       => true,
			'max_upload_size'            => 10485760, // 10MB
			'header_anomaly_detection'   => true,
			'header_anomaly_threshold'   => 20,
			'cookie_security'            => true,
			'cookie_samesite'            => 'Lax',
		);

		add_option( 'wph_settings', $default_settings );
		add_option( 'wph_version', WPH_VERSION );
		add_option( 'wph_activated_at', current_time( 'mysql' ) );

		// Clear any cached data
		wp_cache_flush();
	}
}
