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

		// Table for 2FA tokens
		$table_2fa_tokens = $wpdb->prefix . 'wph_2fa_tokens';
		$sql_2fa_tokens   = "CREATE TABLE IF NOT EXISTS $table_2fa_tokens (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			user_id bigint(20) NOT NULL,
			secret_key varchar(255) NOT NULL,
			is_enabled tinyint(1) NOT NULL DEFAULT 0,
			backup_codes longtext DEFAULT NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY user_id (user_id)
		) $charset_collate;";

		// Table for sessions
		$table_sessions = $wpdb->prefix . 'wph_sessions';
		$sql_sessions   = "CREATE TABLE IF NOT EXISTS $table_sessions (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			user_id bigint(20) NOT NULL,
			session_token varchar(255) NOT NULL,
			ip_address varchar(45) NOT NULL,
			user_agent text DEFAULT NULL,
			device_fingerprint varchar(255) DEFAULT NULL,
			created_at datetime NOT NULL,
			last_activity datetime NOT NULL,
			expires_at datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY session_token (session_token),
			KEY user_id (user_id),
			KEY expires_at (expires_at)
		) $charset_collate;";

		// Table for threat intelligence
		$table_threat_intel = $wpdb->prefix . 'wph_threat_intelligence';
		$sql_threat_intel   = "CREATE TABLE IF NOT EXISTS $table_threat_intel (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL,
			threat_type varchar(50) NOT NULL,
			threat_score int(11) NOT NULL DEFAULT 0,
			threat_data longtext DEFAULT NULL,
			checked_at datetime NOT NULL,
			expires_at datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY ip_threat_type (ip_address(45), threat_type(50)),
			KEY expires_at (expires_at)
		) $charset_collate;";

		// Table for file changes
		$table_file_changes = $wpdb->prefix . 'wph_file_changes';
		$sql_file_changes   = "CREATE TABLE IF NOT EXISTS $table_file_changes (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			file_path varchar(500) NOT NULL,
			change_type varchar(20) NOT NULL,
			old_hash varchar(32) DEFAULT NULL,
			new_hash varchar(32) DEFAULT NULL,
			file_size bigint(20) DEFAULT NULL,
			detected_at datetime NOT NULL,
			is_reviewed tinyint(1) DEFAULT 0,
			PRIMARY KEY  (id),
			KEY file_path (file_path(191)),
			KEY change_type (change_type),
			KEY detected_at (detected_at)
		) $charset_collate;";

		// Table for database backups
		$table_backups = $wpdb->prefix . 'wph_backups';
		$sql_backups   = "CREATE TABLE IF NOT EXISTS $table_backups (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			backup_file varchar(255) NOT NULL,
			backup_size bigint(20) NOT NULL,
			is_encrypted tinyint(1) DEFAULT 0,
			created_at datetime NOT NULL,
			expires_at datetime DEFAULT NULL,
			PRIMARY KEY  (id),
			KEY created_at (created_at)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql_logs );
		dbDelta( $sql_blocked_ips );
		dbDelta( $sql_login_attempts );
		dbDelta( $sql_scan_results );
		dbDelta( $sql_2fa_tokens );
		dbDelta( $sql_sessions );
		dbDelta( $sql_threat_intel );
		dbDelta( $sql_file_changes );
		dbDelta( $sql_backups );

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
			// Advanced Authentication settings
			'2fa_enabled'                => false,
			'2fa_required_roles'         => array( 'administrator' ),
			'2fa_grace_period'           => 7, // days
			'passwordless_login'         => false,
			'session_ip_binding'         => true,
			'session_timeout'            => 43200, // 12 hours
			'max_concurrent_sessions'    => 3,
			'password_expiry_days'       => 90,
			'password_history_count'     => 5,
			// Security Hardening settings
			'hardening_disable_xmlrpc'   => true,
			'hardening_disable_file_edit' => true,
			'hardening_disable_file_mods' => false,
			'hardening_hide_wp_version'  => true,
			'hardening_security_headers' => true,
			'hardening_csp_policy'       => "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
			'hardening_xframe_options'   => 'SAMEORIGIN',
			'hardening_referrer_policy'  => 'strict-origin-when-cross-origin',
			'hardening_disable_rest_api' => false,
			'hardening_rest_whitelist'   => array(),
			'hardening_remove_meta_tags' => true,
			'hardening_disable_user_enum' => true,
			'hardening_hide_login_errors' => true,
			'hardening_disable_pingbacks' => true,
			'hardening_force_ssl_admin'  => false,
			'hardening_disable_app_passwords' => true,
			// Threat Intelligence settings
			'threat_intel_enabled'       => true,
			'threat_intel_abuseipdb_key' => '',
			'threat_intel_proxycheck_key' => '',
			'threat_intel_cache_ttl'     => 24, // hours
			'threat_intel_auto_block'    => true,
			'threat_intel_block_threshold' => 75,
			'threat_intel_check_proxies' => true,
			'threat_intel_check_tor'     => true,
			// File Protection settings
			'file_protection_enabled'    => true,
			'file_monitoring_enabled'    => true,
			'file_monitoring_scan_interval' => 'daily',
			'block_executable_uploads'   => true,
			'directory_listing_protection' => true,
			'htaccess_hardening'         => true,
			'wpconfig_protection'        => true,
			'file_quarantine_enabled'    => true,
			'monitored_directories'      => array( 'wp-includes', 'wp-admin', 'wp-content/themes', 'wp-content/plugins' ),
			// Database Security settings
			'db_security_enabled'        => true,
			'db_backup_enabled'          => true,
			'db_backup_schedule'         => 'weekly',
			'db_backup_retention'        => 30, // days
			'db_backup_encryption'       => true,
			'db_backup_encryption_key'   => wp_generate_password( 32, true, true ),
			'db_optimization_enabled'    => true,
			'db_query_monitoring'        => false,
			'db_slow_query_threshold'    => 2.0, // seconds
			'db_cleanup_revisions'       => true,
			'db_max_revisions'           => 5,
		);

		add_option( 'wph_settings', $default_settings );
		add_option( 'wph_version', WPH_VERSION );
		add_option( 'wph_activated_at', current_time( 'mysql' ) );

		// Clear any cached data
		wp_cache_flush();
	}
}
