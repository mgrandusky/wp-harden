<?php
/**
 * Login Security Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Login_Security
 *
 * Provides login security features
 */
class WPH_Login_Security {

	/**
	 * Singleton instance
	 *
	 * @var WPH_Login_Security
	 */
	private static $instance = null;

	/**
	 * Get singleton instance
	 *
	 * @return WPH_Login_Security
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
		add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ) );
		add_filter( 'authenticate', array( $this, 'check_login_attempts' ), 30, 3 );
		add_action( 'wp_login', array( $this, 'handle_successful_login' ), 10, 2 );
		
		$settings = WPH_Settings::get_instance();
		
		// Prevent username enumeration
		if ( $settings->get( 'prevent_username_enumeration', true ) ) {
			add_filter( 'redirect_canonical', array( $this, 'prevent_username_enumeration' ), 10, 2 );
		}

		// Strong password enforcement
		if ( $settings->get( 'strong_password_enforcement', true ) ) {
			add_action( 'user_profile_update_errors', array( $this, 'enforce_strong_password' ), 10, 3 );
		}
	}

	/**
	 * Handle failed login attempt
	 *
	 * @param string $username Username used in login attempt.
	 * @since 1.0.0
	 */
	public function handle_failed_login( $username ) {
		$ip_manager = WPH_IP_Manager::get_instance();
		$ip_address = $ip_manager->get_client_ip();

		// Log the failed attempt
		$this->log_login_attempt( $ip_address, $username, false );

		// Check if we should block this IP
		$attempts = $this->get_failed_attempts( $ip_address );
		$settings = WPH_Settings::get_instance();
		$max_attempts = $settings->get( 'max_login_attempts', 5 );

		if ( $attempts >= $max_attempts ) {
			$lockout_duration = $settings->get( 'login_lockout_duration', 900 );
			
			$ip_manager->block_ip(
				$ip_address,
				sprintf( 'Too many failed login attempts (%d)', $attempts ),
				'temporary',
				$lockout_duration
			);

			// Log the block
			$logger = WPH_Logger::get_instance();
			$logger->log(
				'login',
				'high',
				sprintf( 'IP blocked after %d failed login attempts', $attempts ),
				array(
					'ip'       => $ip_address,
					'username' => $username,
					'attempts' => $attempts,
				)
			);
		}
	}

	/**
	 * Handle successful login
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User object.
	 * @since 1.0.0
	 */
	public function handle_successful_login( $user_login, $user ) {
		$ip_manager = WPH_IP_Manager::get_instance();
		$ip_address = $ip_manager->get_client_ip();

		// Log successful login
		$this->log_login_attempt( $ip_address, $user_login, true );

		// Clear failed attempts for this IP
		$this->clear_failed_attempts( $ip_address );

		// Log the event
		$logger = WPH_Logger::get_instance();
		$logger->log(
			'login',
			'low',
			sprintf( 'Successful login for user: %s', $user_login ),
			array(
				'ip'      => $ip_address,
				'user_id' => $user->ID,
			)
		);
	}

	/**
	 * Check login attempts before authentication
	 *
	 * @param WP_User|WP_Error|null $user     User object or error.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error
	 * @since 1.0.0
	 */
	public function check_login_attempts( $user, $username, $password ) {
		if ( empty( $username ) ) {
			return $user;
		}

		$ip_manager = WPH_IP_Manager::get_instance();
		$ip_address = $ip_manager->get_client_ip();

		// Check if IP is blocked
		if ( $ip_manager->is_blocked( $ip_address ) ) {
			return new WP_Error(
				'login_blocked',
				__( 'Too many failed login attempts. Please try again later.', 'wp-harden' )
			);
		}

		return $user;
	}

	/**
	 * Log login attempt to database
	 *
	 * @param string $ip_address IP address.
	 * @param string $username   Username.
	 * @param bool   $success    Whether login was successful.
	 * @since 1.0.0
	 */
	private function log_login_attempt( $ip_address, $username, $success ) {
		global $wpdb;

		$table = $wpdb->prefix . 'wph_login_attempts';

		$wpdb->insert(
			$table,
			array(
				'ip_address'   => $ip_address,
				'username'     => $username,
				'success'      => $success ? 1 : 0,
				'attempted_at' => current_time( 'mysql' ),
				'user_agent'   => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
			)
		);
	}

	/**
	 * Get failed login attempts for an IP
	 *
	 * @param string $ip_address IP address.
	 * @param int    $timeframe  Timeframe in seconds (default 1 hour).
	 * @return int Number of failed attempts
	 * @since 1.0.0
	 */
	private function get_failed_attempts( $ip_address, $timeframe = 3600 ) {
		global $wpdb;

		$table = $wpdb->prefix . 'wph_login_attempts';

		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $table 
				WHERE ip_address = %s 
				AND success = 0 
				AND attempted_at > DATE_SUB(NOW(), INTERVAL %d SECOND)",
				$ip_address,
				$timeframe
			)
		);

		return (int) $count;
	}

	/**
	 * Clear failed attempts for an IP
	 *
	 * @param string $ip_address IP address.
	 * @since 1.0.0
	 */
	private function clear_failed_attempts( $ip_address ) {
		global $wpdb;

		$table = $wpdb->prefix . 'wph_login_attempts';

		$wpdb->delete(
			$table,
			array(
				'ip_address' => $ip_address,
				'success'    => 0,
			)
		);
	}

	/**
	 * Prevent username enumeration
	 *
	 * @param string $redirect_url  Redirect URL.
	 * @param string $requested_url Requested URL.
	 * @return string|false
	 * @since 1.0.0
	 */
	public function prevent_username_enumeration( $redirect_url, $requested_url ) {
		if ( is_admin() || ! isset( $_GET['author'] ) ) {
			return $redirect_url;
		}

		if ( ! is_user_logged_in() ) {
			wp_die(
				esc_html__( 'Access Denied', 'wp-harden' ),
				esc_html__( 'Security Check', 'wp-harden' ),
				array( 'response' => 403 )
			);
		}

		return $redirect_url;
	}

	/**
	 * Enforce strong password requirements
	 *
	 * @param WP_Error $errors Errors object.
	 * @param bool     $update Whether this is a user update.
	 * @param WP_User  $user   User object.
	 * @since 1.0.0
	 */
	public function enforce_strong_password( $errors, $update, $user ) {
		if ( empty( $_POST['pass1'] ) ) {
			return;
		}

		$password = wp_unslash( $_POST['pass1'] );

		// Check password strength
		if ( ! $this->is_strong_password( $password ) ) {
			$errors->add(
				'weak_password',
				__( 'Password must be at least 12 characters long and contain uppercase, lowercase, numbers, and special characters.', 'wp-harden' )
			);
		}
	}

	/**
	 * Check if password is strong
	 *
	 * @param string $password Password to check.
	 * @return bool
	 * @since 1.0.0
	 */
	private function is_strong_password( $password ) {
		// At least 12 characters
		if ( strlen( $password ) < 12 ) {
			return false;
		}

		// Contains uppercase
		if ( ! preg_match( '/[A-Z]/', $password ) ) {
			return false;
		}

		// Contains lowercase
		if ( ! preg_match( '/[a-z]/', $password ) ) {
			return false;
		}

		// Contains numbers
		if ( ! preg_match( '/[0-9]/', $password ) ) {
			return false;
		}

		// Contains special characters
		if ( ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
			return false;
		}

		return true;
	}
}
