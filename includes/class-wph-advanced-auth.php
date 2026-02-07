<?php
/**
 * WP Harden Advanced Authentication Module
 *
 * Enterprise-grade authentication features including Two-Factor Authentication (TOTP),
 * Passwordless Login, Session Management, and Force Password Reset.
 *
 * @package    WP_Harden
 * @subpackage WP_Harden/includes
 * @since      1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Advanced Authentication Class
 *
 * Handles Two-Factor Authentication (TOTP), Passwordless Login,
 * Session Management, and Password Policies.
 *
 * @since 1.0.0
 */
class WPH_Advanced_Auth {

	/**
	 * Single instance of the class
	 *
	 * @since 1.0.0
	 * @var WPH_Advanced_Auth
	 */
	private static $instance = null;

	/**
	 * TOTP time step in seconds
	 *
	 * @since 1.0.0
	 * @var int
	 */
	const TOTP_TIME_STEP = 30;

	/**
	 * TOTP code length
	 *
	 * @since 1.0.0
	 * @var int
	 */
	const TOTP_CODE_LENGTH = 6;

	/**
	 * TOTP time drift tolerance (number of time windows)
	 *
	 * @since 1.0.0
	 * @var int
	 */
	const TOTP_TIME_DRIFT = 1;

	/**
	 * Magic link token expiry in seconds (15 minutes)
	 *
	 * @since 1.0.0
	 * @var int
	 */
	const MAGIC_LINK_EXPIRY = 900;

	/**
	 * Number of backup codes to generate
	 *
	 * @since 1.0.0
	 * @var int
	 */
	const BACKUP_CODES_COUNT = 10;

	/**
	 * Backup code length
	 *
	 * @since 1.0.0
	 * @var int
	 */
	const BACKUP_CODE_LENGTH = 8;

	/**
	 * Password history count
	 *
	 * @since 1.0.0
	 * @var int
	 */
	const PASSWORD_HISTORY_COUNT = 5;

	/**
	 * Get singleton instance
	 *
	 * @since 1.0.0
	 * @return WPH_Advanced_Auth
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
	 * Initialize WordPress hooks
	 *
	 * @since 1.0.0
	 */
	private function init_hooks() {
		add_filter( 'authenticate', array( $this, 'authenticate_2fa' ), 30, 3 );
		add_action( 'wp_login', array( $this, 'handle_login' ), 10, 2 );
		add_action( 'wp_logout', array( $this, 'handle_logout' ) );
		add_action( 'init', array( $this, 'check_session_validity' ) );
		add_action( 'init', array( $this, 'handle_magic_link' ) );
	}

	// =====================================================================
	// Two-Factor Authentication (TOTP)
	// =====================================================================

	/**
	 * Generate TOTP secret key
	 *
	 * @since 1.0.0
	 * @return string Base32 encoded secret
	 */
	public function generate_totp_secret() {
		$secret = '';
		$bytes  = random_bytes( 20 );
		$secret = $this->base32_encode( $bytes );
		return $secret;
	}

	/**
	 * Enable 2FA for user
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return array|WP_Error Secret and backup codes or error.
	 */
	public function enable_2fa( $user_id ) {
		global $wpdb;

		$user_id = absint( $user_id );
		if ( ! $user_id ) {
			return new WP_Error( 'invalid_user', __( 'Invalid user ID.', 'wp-harden' ) );
		}

		// Generate secret and backup codes
		$secret       = $this->generate_totp_secret();
		$backup_codes = $this->generate_backup_codes();

		// Store in database
		$table_name = $wpdb->prefix . 'wph_2fa_tokens';
		$result     = $wpdb->replace(
			$table_name,
			array(
				'user_id'      => $user_id,
				'secret_key'   => $secret,
				'is_enabled'   => 0, // Not enabled until verified
				'backup_codes' => wp_json_encode( $backup_codes ),
				'created_at'   => current_time( 'mysql' ),
			),
			array( '%d', '%s', '%d', '%s', '%s' )
		);

		if ( false === $result ) {
			return new WP_Error( 'db_error', __( 'Failed to store 2FA data.', 'wp-harden' ) );
		}

		// Log event
		if ( class_exists( 'WPH_Logger' ) ) {
			WPH_Logger::log( 'info', "2FA setup initiated for user {$user_id}" );
		}

		do_action( 'wph_2fa_enabled', $user_id );

		return array(
			'secret'       => $secret,
			'backup_codes' => $backup_codes,
		);
	}

	/**
	 * Verify TOTP code and enable 2FA
	 *
	 * @since 1.0.0
	 * @param int    $user_id User ID.
	 * @param string $code    TOTP code.
	 * @return bool|WP_Error True on success, error on failure.
	 */
	public function verify_and_enable_2fa( $user_id, $code ) {
		global $wpdb;

		$user_id = absint( $user_id );
		$code    = sanitize_text_field( $code );

		if ( ! $user_id || empty( $code ) ) {
			return new WP_Error( 'invalid_params', __( 'Invalid parameters.', 'wp-harden' ) );
		}

		// Get secret from database
		$table_name = $wpdb->prefix . 'wph_2fa_tokens';
		$row        = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table_name} WHERE user_id = %d", $user_id )
		);

		if ( ! $row ) {
			return new WP_Error( 'no_secret', __( '2FA not initialized.', 'wp-harden' ) );
		}

		// Verify code
		if ( ! $this->verify_totp_code( $row->secret_key, $code ) ) {
			return new WP_Error( 'invalid_code', __( 'Invalid verification code.', 'wp-harden' ) );
		}

		// Enable 2FA
		$wpdb->update(
			$table_name,
			array( 'is_enabled' => 1 ),
			array( 'user_id' => $user_id ),
			array( '%d' ),
			array( '%d' )
		);

		// Log event
		if ( class_exists( 'WPH_Logger' ) ) {
			WPH_Logger::log( 'info', "2FA enabled for user {$user_id}" );
		}

		do_action( 'wph_2fa_verified', $user_id );

		return true;
	}

	/**
	 * Disable 2FA for user
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return bool True on success, false on failure.
	 */
	public function disable_2fa( $user_id ) {
		global $wpdb;

		$user_id = absint( $user_id );
		if ( ! $user_id ) {
			return false;
		}

		$table_name = $wpdb->prefix . 'wph_2fa_tokens';
		$result     = $wpdb->delete( $table_name, array( 'user_id' => $user_id ), array( '%d' ) );

		if ( false !== $result ) {
			// Log event
			if ( class_exists( 'WPH_Logger' ) ) {
				WPH_Logger::log( 'info', "2FA disabled for user {$user_id}" );
			}
			return true;
		}

		return false;
	}

	/**
	 * Check if 2FA is enabled for user
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return bool True if enabled, false otherwise.
	 */
	public function is_2fa_enabled( $user_id ) {
		global $wpdb;

		$user_id = absint( $user_id );
		if ( ! $user_id ) {
			return false;
		}

		$table_name = $wpdb->prefix . 'wph_2fa_tokens';
		$is_enabled = $wpdb->get_var(
			$wpdb->prepare( "SELECT is_enabled FROM {$table_name} WHERE user_id = %d", $user_id )
		);

		return (bool) $is_enabled;
	}

	/**
	 * Verify TOTP code
	 *
	 * @since 1.0.0
	 * @param string $secret Base32 encoded secret.
	 * @param string $code   User-provided code.
	 * @return bool True if valid, false otherwise.
	 */
	public function verify_totp_code( $secret, $code ) {
		$code = sanitize_text_field( $code );

		if ( strlen( $code ) !== self::TOTP_CODE_LENGTH ) {
			return false;
		}

		$current_time = time();

		// Check current time window and drift tolerance
		for ( $i = -self::TOTP_TIME_DRIFT; $i <= self::TOTP_TIME_DRIFT; $i++ ) {
			$time_counter = floor( $current_time / self::TOTP_TIME_STEP ) + $i;
			$generated    = $this->generate_totp_code( $secret, $time_counter );

			if ( hash_equals( $generated, $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Generate TOTP code for given time counter
	 *
	 * @since 1.0.0
	 * @param string $secret        Base32 encoded secret.
	 * @param int    $time_counter  Time counter.
	 * @return string TOTP code.
	 */
	private function generate_totp_code( $secret, $time_counter ) {
		$secret_key = $this->base32_decode( $secret );

		// Pack time counter as 8 bytes
		$time_bytes = pack( 'N*', 0 ) . pack( 'N*', $time_counter );

		// HMAC-SHA1
		$hash = hash_hmac( 'sha1', $time_bytes, $secret_key, true );

		// Dynamic truncation
		$offset = ord( $hash[19] ) & 0xf;
		$code   = (
			( ( ord( $hash[ $offset + 0 ] ) & 0x7f ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xff )
		) % pow( 10, self::TOTP_CODE_LENGTH );

		return str_pad( $code, self::TOTP_CODE_LENGTH, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify backup code
	 *
	 * @since 1.0.0
	 * @param int    $user_id User ID.
	 * @param string $code    Backup code.
	 * @return bool|WP_Error True on success, error on failure.
	 */
	public function verify_backup_code( $user_id, $code ) {
		global $wpdb;

		$user_id = absint( $user_id );
		$code    = sanitize_text_field( $code );

		if ( ! $user_id || empty( $code ) ) {
			return new WP_Error( 'invalid_params', __( 'Invalid parameters.', 'wp-harden' ) );
		}

		$table_name = $wpdb->prefix . 'wph_2fa_tokens';
		$row        = $wpdb->get_row(
			$wpdb->prepare( "SELECT backup_codes FROM {$table_name} WHERE user_id = %d AND is_enabled = 1", $user_id )
		);

		if ( ! $row ) {
			return new WP_Error( 'no_2fa', __( '2FA not enabled.', 'wp-harden' ) );
		}

		$backup_codes = json_decode( $row->backup_codes, true );
		if ( ! is_array( $backup_codes ) ) {
			return new WP_Error( 'invalid_codes', __( 'Invalid backup codes.', 'wp-harden' ) );
		}

		// Check if code exists and is not used
		$code_key = array_search( $code, array_column( $backup_codes, 'code' ), true );
		if ( false === $code_key ) {
			return new WP_Error( 'invalid_code', __( 'Invalid backup code.', 'wp-harden' ) );
		}

		if ( ! empty( $backup_codes[ $code_key ]['used'] ) ) {
			return new WP_Error( 'code_used', __( 'Backup code already used.', 'wp-harden' ) );
		}

		// Mark code as used
		$backup_codes[ $code_key ]['used'] = current_time( 'mysql' );

		$wpdb->update(
			$table_name,
			array( 'backup_codes' => wp_json_encode( $backup_codes ) ),
			array( 'user_id' => $user_id ),
			array( '%s' ),
			array( '%d' )
		);

		// Log event
		if ( class_exists( 'WPH_Logger' ) ) {
			WPH_Logger::log( 'info', "Backup code used for user {$user_id}" );
		}

		return true;
	}

	/**
	 * Generate backup codes
	 *
	 * @since 1.0.0
	 * @return array Array of backup codes.
	 */
	private function generate_backup_codes() {
		$codes = array();

		for ( $i = 0; $i < self::BACKUP_CODES_COUNT; $i++ ) {
			$codes[] = array(
				'code' => $this->generate_random_code( self::BACKUP_CODE_LENGTH ),
				'used' => null,
			);
		}

		return $codes;
	}

	/**
	 * Generate random code
	 *
	 * @since 1.0.0
	 * @param int $length Code length.
	 * @return string Random code.
	 */
	private function generate_random_code( $length ) {
		$characters = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // Removed ambiguous characters
		$code       = '';

		for ( $i = 0; $i < $length; $i++ ) {
			$code .= $characters[ random_int( 0, strlen( $characters ) - 1 ) ];
		}

		return $code;
	}

	/**
	 * Generate QR code for TOTP secret
	 *
	 * @since 1.0.0
	 * @param int    $user_id User ID.
	 * @param string $secret  Base32 encoded secret.
	 * @return string QR code data URI.
	 */
	public function generate_qr_code( $user_id, $secret ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return '';
		}

		$site_name = get_bloginfo( 'name' );
		$label     = rawurlencode( $site_name . ':' . $user->user_email );
		$issuer    = rawurlencode( $site_name );

		// TOTP URI format
		$otpauth_uri = sprintf(
			'otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d',
			$label,
			$secret,
			$issuer,
			self::TOTP_CODE_LENGTH,
			self::TOTP_TIME_STEP
		);

		// Generate QR code using Google Charts API (simple method)
		$qr_url = sprintf(
			'https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=%s',
			rawurlencode( $otpauth_uri )
		);

		return $qr_url;
	}

	/**
	 * Authenticate with 2FA
	 *
	 * @since 1.0.0
	 * @param WP_User|WP_Error|null $user     User object or error.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error User object or error.
	 */
	public function authenticate_2fa( $user, $username, $password ) {
		// Only proceed if user is valid
		if ( ! $user instanceof WP_User ) {
			return $user;
		}

		// Check if 2FA is required for user's role
		$required_roles = apply_filters( 'wph_2fa_required_roles', array( 'administrator' ) );
		$user_roles     = $user->roles;

		if ( ! array_intersect( $user_roles, $required_roles ) ) {
			return $user;
		}

		// Check if 2FA is enabled
		if ( ! $this->is_2fa_enabled( $user->ID ) ) {
			return $user;
		}

		// Store user ID in session for 2FA verification
		if ( ! session_id() ) {
			session_start();
		}
		$_SESSION['wph_2fa_user_id'] = $user->ID;

		// Return error to prevent login until 2FA is verified
		return new WP_Error(
			'2fa_required',
			__( 'Two-Factor Authentication required. Please enter your verification code.', 'wp-harden' )
		);
	}

	/**
	 * Complete 2FA verification
	 *
	 * @since 1.0.0
	 * @param string $code    Verification code.
	 * @param int    $user_id User ID (optional, uses session if not provided).
	 * @return bool|WP_Error True on success, error on failure.
	 */
	public function complete_2fa_verification( $code, $user_id = 0 ) {
		if ( ! $user_id ) {
			if ( ! session_id() ) {
				session_start();
			}
			$user_id = isset( $_SESSION['wph_2fa_user_id'] ) ? absint( $_SESSION['wph_2fa_user_id'] ) : 0;
		}

		if ( ! $user_id ) {
			return new WP_Error( 'no_user', __( 'No user ID provided.', 'wp-harden' ) );
		}

		global $wpdb;
		$table_name = $wpdb->prefix . 'wph_2fa_tokens';
		$row        = $wpdb->get_row(
			$wpdb->prepare( "SELECT secret_key FROM {$table_name} WHERE user_id = %d AND is_enabled = 1", $user_id )
		);

		if ( ! $row ) {
			return new WP_Error( 'no_2fa', __( '2FA not enabled.', 'wp-harden' ) );
		}

		// Try TOTP code first
		if ( $this->verify_totp_code( $row->secret_key, $code ) ) {
			// Clear session
			if ( isset( $_SESSION['wph_2fa_user_id'] ) ) {
				unset( $_SESSION['wph_2fa_user_id'] );
			}

			// Log successful verification
			if ( class_exists( 'WPH_Logger' ) ) {
				WPH_Logger::log( 'info', "2FA verified for user {$user_id}" );
			}

			return true;
		}

		// Try backup code
		$backup_result = $this->verify_backup_code( $user_id, $code );
		if ( true === $backup_result ) {
			// Clear session
			if ( isset( $_SESSION['wph_2fa_user_id'] ) ) {
				unset( $_SESSION['wph_2fa_user_id'] );
			}

			return true;
		}

		return new WP_Error( 'invalid_code', __( 'Invalid verification code.', 'wp-harden' ) );
	}

	// =====================================================================
	// Passwordless Login (Magic Links)
	// =====================================================================

	/**
	 * Generate magic link token
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return string|WP_Error Magic link URL or error.
	 */
	public function generate_magic_link( $user_id ) {
		$user_id = absint( $user_id );
		if ( ! $user_id ) {
			return new WP_Error( 'invalid_user', __( 'Invalid user ID.', 'wp-harden' ) );
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return new WP_Error( 'user_not_found', __( 'User not found.', 'wp-harden' ) );
		}

		// Generate random token
		$token = bin2hex( random_bytes( 32 ) );

		// Store token in user meta with expiry
		$token_data = array(
			'token'      => wp_hash( $token ),
			'expires_at' => time() + self::MAGIC_LINK_EXPIRY,
			'ip_address' => $this->get_client_ip(),
		);

		update_user_meta( $user_id, '_wph_magic_link_token', $token_data );

		// Generate magic link URL
		$magic_link = add_query_arg(
			array(
				'wph_action' => 'magic_login',
				'token'      => $token,
				'user_id'    => $user_id,
			),
			wp_login_url()
		);

		// Log event
		if ( class_exists( 'WPH_Logger' ) ) {
			WPH_Logger::log( 'info', "Magic link generated for user {$user_id}" );
		}

		return $magic_link;
	}

	/**
	 * Send magic link via email
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return bool|WP_Error True on success, error on failure.
	 */
	public function send_magic_link( $user_id ) {
		$user_id = absint( $user_id );
		$user    = get_userdata( $user_id );

		if ( ! $user ) {
			return new WP_Error( 'user_not_found', __( 'User not found.', 'wp-harden' ) );
		}

		$magic_link = $this->generate_magic_link( $user_id );

		if ( is_wp_error( $magic_link ) ) {
			return $magic_link;
		}

		$subject = sprintf(
			/* translators: %s: Site name */
			__( 'Your login link for %s', 'wp-harden' ),
			get_bloginfo( 'name' )
		);

		$message = sprintf(
			/* translators: 1: User display name, 2: Magic link URL, 3: Expiry minutes */
			__(
				"Hello %1\$s,\n\n" .
				"Click the link below to log in to your account:\n\n" .
				"%2\$s\n\n" .
				"This link will expire in %3\$d minutes.\n\n" .
				"If you didn't request this link, please ignore this email.",
				'wp-harden'
			),
			$user->display_name,
			$magic_link,
			self::MAGIC_LINK_EXPIRY / 60
		);

		$sent = wp_mail( $user->user_email, $subject, $message );

		if ( $sent ) {
			// Log event
			if ( class_exists( 'WPH_Logger' ) ) {
				WPH_Logger::log( 'info', "Magic link sent to user {$user_id}" );
			}
			return true;
		}

		return new WP_Error( 'email_failed', __( 'Failed to send magic link email.', 'wp-harden' ) );
	}

	/**
	 * Handle magic link login
	 *
	 * @since 1.0.0
	 */
	public function handle_magic_link() {
		if ( ! isset( $_GET['wph_action'] ) || 'magic_login' !== $_GET['wph_action'] ) {
			return;
		}

		if ( ! isset( $_GET['token'] ) || ! isset( $_GET['user_id'] ) ) {
			wp_die( esc_html__( 'Invalid magic link.', 'wp-harden' ) );
		}

		$token   = sanitize_text_field( wp_unslash( $_GET['token'] ) );
		$user_id = absint( $_GET['user_id'] );

		// Verify token
		$result = $this->verify_magic_link_token( $user_id, $token );

		if ( is_wp_error( $result ) ) {
			wp_die( esc_html( $result->get_error_message() ) );
		}

		// Delete token after use (single-use)
		delete_user_meta( $user_id, '_wph_magic_link_token' );

		// Log in user
		wp_set_current_user( $user_id );
		wp_set_auth_cookie( $user_id );

		// Log event
		if ( class_exists( 'WPH_Logger' ) ) {
			WPH_Logger::log( 'info', "User {$user_id} logged in via magic link" );
		}

		// Redirect to admin
		wp_safe_redirect( admin_url() );
		exit;
	}

	/**
	 * Verify magic link token
	 *
	 * @since 1.0.0
	 * @param int    $user_id User ID.
	 * @param string $token   Token to verify.
	 * @return bool|WP_Error True on success, error on failure.
	 */
	private function verify_magic_link_token( $user_id, $token ) {
		$user_id = absint( $user_id );
		$token   = sanitize_text_field( $token );

		if ( ! $user_id || empty( $token ) ) {
			return new WP_Error( 'invalid_params', __( 'Invalid parameters.', 'wp-harden' ) );
		}

		$token_data = get_user_meta( $user_id, '_wph_magic_link_token', true );

		if ( ! $token_data || ! is_array( $token_data ) ) {
			return new WP_Error( 'no_token', __( 'No magic link token found.', 'wp-harden' ) );
		}

		// Check expiry
		if ( time() > $token_data['expires_at'] ) {
			delete_user_meta( $user_id, '_wph_magic_link_token' );
			return new WP_Error( 'token_expired', __( 'Magic link has expired.', 'wp-harden' ) );
		}

		// Verify token
		if ( ! hash_equals( $token_data['token'], wp_hash( $token ) ) ) {
			return new WP_Error( 'invalid_token', __( 'Invalid magic link token.', 'wp-harden' ) );
		}

		// Verify IP address (optional, can be configured)
		if ( class_exists( 'WPH_Settings' ) ) {
			$verify_ip = WPH_Settings::get_instance()->get( 'magic_link_verify_ip', true );
			if ( $verify_ip && $token_data['ip_address'] !== $this->get_client_ip() ) {
				return new WP_Error( 'ip_mismatch', __( 'IP address mismatch.', 'wp-harden' ) );
			}
		}

		return true;
	}

	// =====================================================================
	// Session Management
	// =====================================================================

	/**
	 * Handle login - Create session record
	 *
	 * @since 1.0.0
	 * @param string  $user_login Username.
	 * @param WP_User $user       User object.
	 */
	public function handle_login( $user_login, $user ) {
		$this->create_session( $user->ID );
	}

	/**
	 * Handle logout - Delete session record
	 *
	 * @since 1.0.0
	 */
	public function handle_logout() {
		$user_id = get_current_user_id();
		if ( $user_id ) {
			$this->delete_current_session( $user_id );
		}
	}

	/**
	 * Create session record
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return bool True on success, false on failure.
	 */
	private function create_session( $user_id ) {
		global $wpdb;

		$user_id = absint( $user_id );
		if ( ! $user_id ) {
			return false;
		}

		// Check concurrent session limit
		$max_sessions = 5;
		if ( class_exists( 'WPH_Settings' ) ) {
			$max_sessions = WPH_Settings::get_instance()->get( 'max_concurrent_sessions', 5 );
		}

		// Delete oldest sessions if limit exceeded
		$this->enforce_session_limit( $user_id, $max_sessions );

		$session_token      = $this->generate_session_token();
		$ip_address         = $this->get_client_ip();
		$user_agent         = $this->get_user_agent();
		$device_fingerprint = $this->generate_device_fingerprint();
		$session_timeout    = $this->get_session_timeout();

		$table_name = $wpdb->prefix . 'wph_sessions';
		$result     = $wpdb->insert(
			$table_name,
			array(
				'user_id'            => $user_id,
				'session_token'      => wp_hash( $session_token ),
				'ip_address'         => $ip_address,
				'user_agent'         => $user_agent,
				'device_fingerprint' => $device_fingerprint,
				'created_at'         => current_time( 'mysql' ),
				'last_activity'      => current_time( 'mysql' ),
				'expires_at'         => gmdate( 'Y-m-d H:i:s', time() + $session_timeout ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);

		if ( $result ) {
			// Store session token in cookie for validation
			setcookie( 'wph_session_token', $session_token, time() + $session_timeout, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );

			// Log event
			if ( class_exists( 'WPH_Logger' ) ) {
				WPH_Logger::log( 'info', "Session created for user {$user_id} from IP {$ip_address}" );
			}

			return true;
		}

		return false;
	}

	/**
	 * Check session validity
	 *
	 * @since 1.0.0
	 */
	public function check_session_validity() {
		if ( ! is_user_logged_in() ) {
			return;
		}

		$user_id = get_current_user_id();

		if ( ! isset( $_COOKIE['wph_session_token'] ) ) {
			return;
		}

		$session_token = sanitize_text_field( wp_unslash( $_COOKIE['wph_session_token'] ) );

		if ( ! $this->verify_session( $user_id, $session_token ) ) {
			// Invalid session - force logout
			wp_logout();
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// Update last activity
		$this->update_session_activity( $user_id, $session_token );
	}

	/**
	 * Verify session
	 *
	 * @since 1.0.0
	 * @param int    $user_id       User ID.
	 * @param string $session_token Session token.
	 * @return bool True if valid, false otherwise.
	 */
	private function verify_session( $user_id, $session_token ) {
		global $wpdb;

		$user_id = absint( $user_id );
		$token   = sanitize_text_field( $session_token );

		if ( ! $user_id || empty( $token ) ) {
			return false;
		}

		$table_name = $wpdb->prefix . 'wph_sessions';
		$session    = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table_name} WHERE user_id = %d AND session_token = %s AND expires_at > NOW()",
				$user_id,
				wp_hash( $token )
			)
		);

		if ( ! $session ) {
			return false;
		}

		// Verify IP binding
		if ( class_exists( 'WPH_Settings' ) ) {
			$bind_ip = WPH_Settings::get_instance()->get( 'session_bind_ip', true );
			if ( $bind_ip && $session->ip_address !== $this->get_client_ip() ) {
				// Log event
				if ( class_exists( 'WPH_Logger' ) ) {
					WPH_Logger::log( 'warning', "Session IP mismatch for user {$user_id}" );
				}
				return false;
			}
		}

		// Verify device fingerprint
		$verify_fingerprint = apply_filters( 'wph_verify_device_fingerprint', true );
		if ( $verify_fingerprint && $session->device_fingerprint !== $this->generate_device_fingerprint() ) {
			// Log event
			if ( class_exists( 'WPH_Logger' ) ) {
				WPH_Logger::log( 'warning', "Session fingerprint mismatch for user {$user_id}" );
			}
			return false;
		}

		return true;
	}

	/**
	 * Update session activity
	 *
	 * @since 1.0.0
	 * @param int    $user_id       User ID.
	 * @param string $session_token Session token.
	 */
	private function update_session_activity( $user_id, $session_token ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'wph_sessions';
		$wpdb->update(
			$table_name,
			array( 'last_activity' => current_time( 'mysql' ) ),
			array(
				'user_id'       => $user_id,
				'session_token' => wp_hash( $session_token ),
			),
			array( '%s' ),
			array( '%d', '%s' )
		);
	}

	/**
	 * Delete current session
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 */
	private function delete_current_session( $user_id ) {
		global $wpdb;

		if ( ! isset( $_COOKIE['wph_session_token'] ) ) {
			return;
		}

		$session_token = sanitize_text_field( wp_unslash( $_COOKIE['wph_session_token'] ) );

		$table_name = $wpdb->prefix . 'wph_sessions';
		$wpdb->delete(
			$table_name,
			array(
				'user_id'       => $user_id,
				'session_token' => wp_hash( $session_token ),
			),
			array( '%d', '%s' )
		);

		// Clear cookie
		setcookie( 'wph_session_token', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );

		// Log event
		if ( class_exists( 'WPH_Logger' ) ) {
			WPH_Logger::log( 'info', "Session deleted for user {$user_id}" );
		}
	}

	/**
	 * Force logout all sessions for user
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return bool True on success, false on failure.
	 */
	public function force_logout_all_sessions( $user_id ) {
		global $wpdb;

		$user_id = absint( $user_id );
		if ( ! $user_id ) {
			return false;
		}

		$table_name = $wpdb->prefix . 'wph_sessions';
		$result     = $wpdb->delete( $table_name, array( 'user_id' => $user_id ), array( '%d' ) );

		if ( false !== $result ) {
			// Log event
			if ( class_exists( 'WPH_Logger' ) ) {
				WPH_Logger::log( 'info', "All sessions force logged out for user {$user_id}" );
			}
			return true;
		}

		return false;
	}

	/**
	 * Get active sessions for user
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return array Array of active sessions.
	 */
	public function get_active_sessions( $user_id ) {
		global $wpdb;

		$user_id = absint( $user_id );
		if ( ! $user_id ) {
			return array();
		}

		$table_name = $wpdb->prefix . 'wph_sessions';
		$sessions   = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table_name} WHERE user_id = %d AND expires_at > NOW() ORDER BY last_activity DESC",
				$user_id
			)
		);

		return $sessions ? $sessions : array();
	}

	/**
	 * Enforce session limit
	 *
	 * @since 1.0.0
	 * @param int $user_id      User ID.
	 * @param int $max_sessions Maximum allowed sessions.
	 */
	private function enforce_session_limit( $user_id, $max_sessions ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'wph_sessions';
		$count      = $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table_name} WHERE user_id = %d", $user_id )
		);

		if ( $count >= $max_sessions ) {
			// Delete oldest sessions
			$to_delete = $count - $max_sessions + 1;
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$table_name} WHERE user_id = %d ORDER BY last_activity ASC LIMIT %d",
					$user_id,
					$to_delete
				)
			);
		}
	}

	/**
	 * Generate session token
	 *
	 * @since 1.0.0
	 * @return string Session token.
	 */
	private function generate_session_token() {
		return bin2hex( random_bytes( 32 ) );
	}

	/**
	 * Generate device fingerprint
	 *
	 * @since 1.0.0
	 * @return string Device fingerprint.
	 */
	private function generate_device_fingerprint() {
		$user_agent = $this->get_user_agent();
		$ip_address = $this->get_client_ip();
		$accept_language = isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ) : '';

		$fingerprint_data = $user_agent . $ip_address . $accept_language;
		return hash( 'sha256', $fingerprint_data );
	}

	/**
	 * Get session timeout in seconds
	 *
	 * @since 1.0.0
	 * @return int Timeout in seconds.
	 */
	private function get_session_timeout() {
		$default_timeout = 24 * 60 * 60; // 24 hours

		if ( class_exists( 'WPH_Settings' ) ) {
			return WPH_Settings::get_instance()->get( 'session_timeout', $default_timeout );
		}

		return $default_timeout;
	}

	// =====================================================================
	// Force Password Reset
	// =====================================================================

	/**
	 * Check if password reset is required
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return bool True if reset required, false otherwise.
	 */
	public function is_password_reset_required( $user_id ) {
		$user_id = absint( $user_id );
		if ( ! $user_id ) {
			return false;
		}

		// Check if admin forced password reset
		$force_reset = get_user_meta( $user_id, '_wph_force_password_reset', true );
		if ( $force_reset ) {
			return true;
		}

		// Check password expiry
		$expiry_days = 90;
		if ( class_exists( 'WPH_Settings' ) ) {
			$expiry_days = WPH_Settings::get_instance()->get( 'password_expiry_days', 90 );
		}

		if ( $expiry_days <= 0 ) {
			return false;
		}

		$last_changed = get_user_meta( $user_id, '_wph_password_last_changed', true );
		if ( ! $last_changed ) {
			// Set current time as last changed if not set
			update_user_meta( $user_id, '_wph_password_last_changed', time() );
			return false;
		}

		$days_since_change = ( time() - $last_changed ) / DAY_IN_SECONDS;

		return $days_since_change >= $expiry_days;
	}

	/**
	 * Force password reset for user
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return bool True on success, false on failure.
	 */
	public function force_password_reset( $user_id ) {
		$user_id = absint( $user_id );
		if ( ! $user_id ) {
			return false;
		}

		update_user_meta( $user_id, '_wph_force_password_reset', 1 );

		// Log event
		if ( class_exists( 'WPH_Logger' ) ) {
			WPH_Logger::log( 'info', "Password reset forced for user {$user_id}" );
		}

		return true;
	}

	/**
	 * Force password reset for all users
	 *
	 * @since 1.0.0
	 * @return int Number of users affected.
	 */
	public function force_password_reset_all_users() {
		$users = get_users( array( 'fields' => array( 'ID' ) ) );
		$count = 0;

		foreach ( $users as $user ) {
			if ( $this->force_password_reset( $user->ID ) ) {
				$count++;
			}
		}

		// Log event
		if ( class_exists( 'WPH_Logger' ) ) {
			WPH_Logger::log( 'info', "Password reset forced for {$count} users" );
		}

		return $count;
	}

	/**
	 * Validate strong password
	 *
	 * @since 1.0.0
	 * @param string $password Password to validate.
	 * @return bool|WP_Error True if valid, error otherwise.
	 */
	public function validate_strong_password( $password ) {
		$password = sanitize_text_field( $password );

		if ( strlen( $password ) < 12 ) {
			return new WP_Error( 'password_too_short', __( 'Password must be at least 12 characters long.', 'wp-harden' ) );
		}

		// Check for uppercase
		if ( ! preg_match( '/[A-Z]/', $password ) ) {
			return new WP_Error( 'password_no_uppercase', __( 'Password must contain at least one uppercase letter.', 'wp-harden' ) );
		}

		// Check for lowercase
		if ( ! preg_match( '/[a-z]/', $password ) ) {
			return new WP_Error( 'password_no_lowercase', __( 'Password must contain at least one lowercase letter.', 'wp-harden' ) );
		}

		// Check for number
		if ( ! preg_match( '/[0-9]/', $password ) ) {
			return new WP_Error( 'password_no_number', __( 'Password must contain at least one number.', 'wp-harden' ) );
		}

		// Check for special character
		if ( ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
			return new WP_Error( 'password_no_special', __( 'Password must contain at least one special character.', 'wp-harden' ) );
		}

		return true;
	}

	/**
	 * Check password history
	 *
	 * @since 1.0.0
	 * @param int    $user_id  User ID.
	 * @param string $password New password.
	 * @return bool|WP_Error True if valid, error if password was used recently.
	 */
	public function check_password_history( $user_id, $password ) {
		$user_id  = absint( $user_id );
		$password = sanitize_text_field( $password );

		if ( ! $user_id || empty( $password ) ) {
			return new WP_Error( 'invalid_params', __( 'Invalid parameters.', 'wp-harden' ) );
		}

		$history = get_user_meta( $user_id, '_wph_password_history', true );
		if ( ! is_array( $history ) ) {
			$history = array();
		}

		// Check if password matches any in history
		foreach ( $history as $old_hash ) {
			if ( wp_check_password( $password, $old_hash ) ) {
				return new WP_Error(
					'password_reused',
					sprintf(
						/* translators: %d: Number of passwords to remember */
						__( 'Password cannot be one of your last %d passwords.', 'wp-harden' ),
						self::PASSWORD_HISTORY_COUNT
					)
				);
			}
		}

		return true;
	}

	/**
	 * Update password history
	 *
	 * @since 1.0.0
	 * @param int    $user_id  User ID.
	 * @param string $password New password (plain text).
	 */
	public function update_password_history( $user_id, $password ) {
		$user_id  = absint( $user_id );
		$password = sanitize_text_field( $password );

		if ( ! $user_id || empty( $password ) ) {
			return;
		}

		$history = get_user_meta( $user_id, '_wph_password_history', true );
		if ( ! is_array( $history ) ) {
			$history = array();
		}

		// Add new password hash to history
		array_unshift( $history, wp_hash_password( $password ) );

		// Keep only last N passwords
		$history = array_slice( $history, 0, self::PASSWORD_HISTORY_COUNT );

		update_user_meta( $user_id, '_wph_password_history', $history );
		update_user_meta( $user_id, '_wph_password_last_changed', time() );

		// Clear force reset flag
		delete_user_meta( $user_id, '_wph_force_password_reset' );

		// Log event
		if ( class_exists( 'WPH_Logger' ) ) {
			WPH_Logger::log( 'info', "Password changed for user {$user_id}" );
		}
	}

	// =====================================================================
	// Utility Methods
	// =====================================================================

	/**
	 * Get client IP address
	 *
	 * @since 1.0.0
	 * @return string IP address.
	 */
	private function get_client_ip() {
		$ip_keys = array(
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		);

		foreach ( $ip_keys as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
				// Handle comma-separated IPs (take first one)
				if ( strpos( $ip, ',' ) !== false ) {
					$ip = trim( explode( ',', $ip )[0] );
				}
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		return '0.0.0.0';
	}

	/**
	 * Get user agent
	 *
	 * @since 1.0.0
	 * @return string User agent.
	 */
	private function get_user_agent() {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
	}

	/**
	 * Base32 encode
	 *
	 * @since 1.0.0
	 * @param string $data Data to encode.
	 * @return string Base32 encoded string.
	 */
	private function base32_encode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$output   = '';
		$v        = 0;
		$vbits    = 0;

		for ( $i = 0, $j = strlen( $data ); $i < $j; $i++ ) {
			$v     = ( $v << 8 ) | ord( $data[ $i ] );
			$vbits += 8;

			while ( $vbits >= 5 ) {
				$vbits  -= 5;
				$output .= $alphabet[ ( $v >> $vbits ) & 0x1f ];
			}
		}

		if ( $vbits > 0 ) {
			$output .= $alphabet[ ( $v << ( 5 - $vbits ) ) & 0x1f ];
		}

		return $output;
	}

	/**
	 * Base32 decode
	 *
	 * @since 1.0.0
	 * @param string $data Base32 encoded string.
	 * @return string Decoded data.
	 */
	private function base32_decode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$output   = '';
		$v        = 0;
		$vbits    = 0;
		$data     = strtoupper( $data );

		for ( $i = 0, $j = strlen( $data ); $i < $j; $i++ ) {
			$c = $data[ $i ];
			if ( '=' === $c ) {
				break;
			}

			$pos = strpos( $alphabet, $c );
			if ( false === $pos ) {
				continue;
			}

			$v      = ( $v << 5 ) | $pos;
			$vbits += 5;

			if ( $vbits >= 8 ) {
				$vbits  -= 8;
				$output .= chr( ( $v >> $vbits ) & 0xff );
			}
		}

		return $output;
	}

	/**
	 * Clean up expired sessions
	 *
	 * @since 1.0.0
	 * @return int Number of sessions deleted.
	 */
	public function cleanup_expired_sessions() {
		global $wpdb;

		$table_name = $wpdb->prefix . 'wph_sessions';
		$deleted    = $wpdb->query( "DELETE FROM {$table_name} WHERE expires_at < NOW()" );

		if ( $deleted && class_exists( 'WPH_Logger' ) ) {
			WPH_Logger::log( 'info', "Cleaned up {$deleted} expired sessions" );
		}

		return $deleted ? $deleted : 0;
	}
}
