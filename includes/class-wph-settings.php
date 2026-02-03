<?php
/**
 * Settings Management Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Settings
 *
 * Manages plugin settings and configuration
 */
class WPH_Settings {

	/**
	 * Singleton instance
	 *
	 * @var WPH_Settings
	 */
	private static $instance = null;

	/**
	 * Settings array
	 *
	 * @var array
	 */
	private $settings = array();

	/**
	 * Get singleton instance
	 *
	 * @return WPH_Settings
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
		$this->load_settings();
		$this->init_hooks();
	}

	/**
	 * Load settings from database
	 *
	 * @since 1.0.0
	 */
	private function load_settings() {
		$this->settings = get_option( 'wph_settings', array() );
	}

	/**
	 * Initialize hooks
	 *
	 * @since 1.0.0
	 */
	private function init_hooks() {
		add_action( 'admin_init', array( $this, 'register_settings' ) );
	}

	/**
	 * Register settings with WordPress
	 *
	 * @since 1.0.0
	 */
	public function register_settings() {
		register_setting( 'wph_settings_group', 'wph_settings', array( $this, 'sanitize_settings' ) );
	}

	/**
	 * Sanitize settings before saving
	 *
	 * @param array $input Raw input data.
	 * @return array Sanitized settings
	 * @since 1.0.0
	 */
	public function sanitize_settings( $input ) {
		$sanitized = array();

		// Boolean settings
		$boolean_fields = array(
			'firewall_enabled',
			'login_security_enabled',
			'scanner_enabled',
			'email_notifications',
			'rate_limit_enabled',
			'strong_password_enforcement',
			'prevent_username_enumeration',
			'sql_injection_protection',
			'xss_protection',
			'file_inclusion_protection',
			'enable_captcha',
			'twofa_enabled',
			'twofa_force_admins',
			'twofa_force_editors',
			'twofa_backup_codes',
			'database_backups_enabled',
			'database_encryption',
			'query_monitoring',
			'auto_optimize_database',
			'disable_xmlrpc',
			'disable_file_editing',
			'remove_wp_version',
			'enable_security_headers',
			'disable_rest_api_unauth',
			'force_ssl_admin',
			'disable_pingbacks',
			'debug_mode',
		);

		foreach ( $boolean_fields as $field ) {
			$sanitized[ $field ] = isset( $input[ $field ] ) ? (bool) $input[ $field ] : false;
		}

		// String settings
		$string_fields = array(
			'firewall_sensitivity',
			'scan_schedule',
			'security_level',
			'captcha_type',
			'backup_frequency',
		);

		foreach ( $string_fields as $field ) {
			if ( isset( $input[ $field ] ) ) {
				$sanitized[ $field ] = sanitize_text_field( $input[ $field ] );
			}
		}

		// Email field
		if ( isset( $input['notification_email'] ) ) {
			$sanitized['notification_email'] = sanitize_email( $input['notification_email'] );
		}

		// API Keys (sensitive data)
		$api_key_fields = array(
			'abuseipdb_api_key',
			'wpscan_api_key',
			'maxmind_license_key',
			'virustotal_api_key',
			'recaptcha_site_key',
			'recaptcha_secret_key',
		);

		foreach ( $api_key_fields as $field ) {
			if ( isset( $input[ $field ] ) ) {
				$sanitized[ $field ] = sanitize_text_field( $input[ $field ] );
			}
		}

		// Textarea fields
		if ( isset( $input['custom_firewall_rules'] ) ) {
			$sanitized['custom_firewall_rules'] = sanitize_textarea_field( $input['custom_firewall_rules'] );
		}

		if ( isset( $input['excluded_urls'] ) ) {
			$sanitized['excluded_urls'] = sanitize_textarea_field( $input['excluded_urls'] );
		}

		// Integer settings
		$integer_fields = array(
			'max_login_attempts',
			'login_lockout_duration',
			'log_retention_days',
			'rate_limit_requests',
			'rate_limit_period',
			'rate_limit_lockout',
			'twofa_backup_codes_count',
			'twofa_grace_period',
			'twofa_qr_size',
			'backup_retention_days',
		);

		foreach ( $integer_fields as $field ) {
			if ( isset( $input[ $field ] ) ) {
				$sanitized[ $field ] = absint( $input[ $field ] );
			}
		}

		// Array settings
		if ( isset( $input['ip_whitelist'] ) && is_array( $input['ip_whitelist'] ) ) {
			$sanitized['ip_whitelist'] = array_map( 'sanitize_text_field', $input['ip_whitelist'] );
		}

		if ( isset( $input['ip_blacklist'] ) && is_array( $input['ip_blacklist'] ) ) {
			$sanitized['ip_blacklist'] = array_map( 'sanitize_text_field', $input['ip_blacklist'] );
		}

		return $sanitized;
	}

	/**
	 * Get a setting value
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $default Default value if setting doesn't exist.
	 * @return mixed Setting value
	 * @since 1.0.0
	 */
	public function get( $key, $default = null ) {
		return isset( $this->settings[ $key ] ) ? $this->settings[ $key ] : $default;
	}

	/**
	 * Update a setting value
	 *
	 * @param string $key   Setting key.
	 * @param mixed  $value Setting value.
	 * @return bool
	 * @since 1.0.0
	 */
	public function set( $key, $value ) {
		$this->settings[ $key ] = $value;
		return update_option( 'wph_settings', $this->settings );
	}

	/**
	 * Get all settings
	 *
	 * @return array
	 * @since 1.0.0
	 */
	public function get_all() {
		return $this->settings;
	}

	/**
	 * Export settings to JSON
	 *
	 * @return string JSON encoded settings
	 * @since 1.0.0
	 */
	public function export_settings() {
		return wp_json_encode( $this->settings, JSON_PRETTY_PRINT );
	}

	/**
	 * Import settings from JSON
	 *
	 * @param string $json JSON encoded settings.
	 * @return bool
	 * @since 1.0.0
	 */
	public function import_settings( $json ) {
		$imported = json_decode( $json, true );

		if ( json_last_error() !== JSON_ERROR_NONE ) {
			return false;
		}

		$sanitized = $this->sanitize_settings( $imported );
		return update_option( 'wph_settings', $sanitized );
	}
}
