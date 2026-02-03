<?php
/**
 * WP Harden Security Hardening Module
 *
 * Provides comprehensive WordPress security hardening features including XML-RPC control,
 * file editing restrictions, version hiding, security headers, REST API control, and more.
 *
 * @package    WP_Harden
 * @subpackage WP_Harden/includes
 * @since      1.0.0
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Security Hardening Class
 *
 * Implements various WordPress security hardening measures including:
 * - XML-RPC control and method filtering
 * - File editing restrictions via wp-config constants
 * - WordPress version hiding across all surfaces
 * - Security headers (CSP, X-Frame-Options, HSTS, etc.)
 * - REST API access control and rate limiting
 * - Removal of sensitive meta tags
 * - User enumeration prevention
 * - Login error message obfuscation
 * - Pingback/trackback disabling
 * - SSL enforcement for admin area
 * - Application password control
 *
 * @since 1.0.0
 */
class WPH_Hardening {

	/**
	 * Singleton instance
	 *
	 * @since  1.0.0
	 * @access private
	 * @var    WPH_Hardening
	 */
	private static $instance = null;

	/**
	 * Settings handler instance
	 *
	 * @since  1.0.0
	 * @access private
	 * @var    WPH_Settings
	 */
	private $settings;

	/**
	 * Logger instance
	 *
	 * @since  1.0.0
	 * @access private
	 * @var    WPH_Logger
	 */
	private $logger;

	/**
	 * REST API rate limit cache
	 *
	 * @since  1.0.0
	 * @access private
	 * @var    array
	 */
	private $rest_rate_limits = array();

	/**
	 * Get singleton instance
	 *
	 * @since  1.0.0
	 * @return WPH_Hardening
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor to prevent direct instantiation
	 *
	 * @since 1.0.0
	 */
	private function __construct() {
		// Initialize dependencies
		if ( class_exists( 'WPH_Settings' ) ) {
			$this->settings = WPH_Settings::get_instance();
		}
		if ( class_exists( 'WPH_Logger' ) ) {
			$this->logger = WPH_Logger::get_instance();
		}

		// Initialize hooks
		$this->init_hooks();
	}

	/**
	 * Initialize WordPress hooks based on active settings
	 *
	 * @since 1.0.0
	 */
	public function init_hooks() {
		// XML-RPC Control
		if ( $this->get_setting( 'hardening_disable_xmlrpc', false ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false', 999 );
			add_filter( 'xmlrpc_methods', array( $this, 'filter_xmlrpc_methods' ), 999 );
		}

		// File Editing Disable
		if ( $this->get_setting( 'hardening_disable_file_edit', false ) ) {
			add_action( 'init', array( $this, 'disable_file_editing' ), 1 );
		}

		// WordPress Version Hiding
		if ( $this->get_setting( 'hardening_hide_wp_version', false ) ) {
			add_action( 'init', array( $this, 'hide_wp_version' ), 1 );
		}

		// Security Headers
		if ( $this->get_setting( 'hardening_security_headers', false ) ) {
			add_action( 'send_headers', array( $this, 'set_security_headers' ), 999 );
			add_filter( 'wp_headers', array( $this, 'filter_wp_headers' ), 999 );
		}

		// REST API Control
		if ( $this->get_setting( 'hardening_disable_rest_api', false ) ) {
			add_filter( 'rest_authentication_errors', array( $this, 'control_rest_api' ), 999 );
		}

		// Remove Sensitive Meta Tags
		if ( $this->get_setting( 'hardening_remove_meta_tags', false ) ) {
			add_action( 'init', array( $this, 'remove_meta_tags' ), 1 );
		}

		// Disable User Enumeration
		if ( $this->get_setting( 'hardening_disable_user_enum', false ) ) {
			add_action( 'init', array( $this, 'disable_user_enumeration' ), 1 );
		}

		// Hide Login Errors
		if ( $this->get_setting( 'hardening_hide_login_errors', false ) ) {
			add_filter( 'login_errors', array( $this, 'hide_login_errors' ), 999 );
		}

		// Disable Pingbacks
		if ( $this->get_setting( 'hardening_disable_pingbacks', false ) ) {
			add_action( 'init', array( $this, 'disable_pingbacks' ), 1 );
		}

		// Force SSL Admin
		if ( $this->get_setting( 'hardening_force_ssl_admin', false ) ) {
			add_action( 'init', array( $this, 'force_ssl_admin' ), 1 );
		}

		// Disable Application Passwords
		if ( $this->get_setting( 'hardening_disable_app_passwords', false ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false', 999 );
		}
	}

	/**
	 * Disable XML-RPC completely or filter dangerous methods
	 *
	 * @since  1.0.0
	 * @param  array $methods Available XML-RPC methods
	 * @return array Modified methods array
	 */
	public function filter_xmlrpc_methods( $methods ) {
		// Get whitelist configuration
		$whitelist = $this->get_setting( 'hardening_xmlrpc_whitelist', array() );

		// Dangerous methods to block
		$dangerous_methods = array(
			'pingback.ping',
			'pingback.extensions.getPingbacks',
			'wp.getUsersBlogs',
			'system.multicall',
			'system.listMethods',
			'wp.getCategories',
			'wp.getTags',
			'wp.getUsers',
		);

		// Apply filter for extensibility
		$dangerous_methods = apply_filters( 'wph_xmlrpc_dangerous_methods', $dangerous_methods );

		// Check if Jetpack is active and whitelist its methods
		if ( class_exists( 'Jetpack' ) && in_array( 'jetpack', $whitelist, true ) ) {
			$jetpack_methods = array(
				'jetpack.jsonAPI',
				'jetpack.testConnection',
			);
			$dangerous_methods = array_diff( $dangerous_methods, $jetpack_methods );
		}

		// Remove dangerous methods
		foreach ( $dangerous_methods as $method ) {
			unset( $methods[ $method ] );
		}

		$this->log( 'XML-RPC methods filtered. Blocked: ' . count( $dangerous_methods ) . ' methods.' );

		return $methods;
	}

	/**
	 * Disable file editing in WordPress admin
	 *
	 * Sets DISALLOW_FILE_EDIT and optionally DISALLOW_FILE_MODS constants.
	 * Note: Constants can only be set if not already defined.
	 *
	 * @since 1.0.0
	 */
	public function disable_file_editing() {
		// Define DISALLOW_FILE_EDIT if not already set
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
			$this->log( 'DISALLOW_FILE_EDIT constant defined.' );
		}

		// Optionally disable file modifications (installs/updates)
		if ( $this->get_setting( 'hardening_disable_file_mods', false ) ) {
			if ( ! defined( 'DISALLOW_FILE_MODS' ) ) {
				define( 'DISALLOW_FILE_MODS', true );
				$this->log( 'DISALLOW_FILE_MODS constant defined.' );
			}
		}
	}

	/**
	 * Hide WordPress version information
	 *
	 * Removes version from meta tags, scripts, styles, RSS feeds, and admin footer.
	 *
	 * @since 1.0.0
	 */
	public function hide_wp_version() {
		// Remove generator meta tag
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string', 999 );

		// Remove version from scripts and styles
		add_filter( 'script_loader_src', array( $this, 'remove_version_from_src' ), 999, 2 );
		add_filter( 'style_loader_src', array( $this, 'remove_version_from_src' ), 999, 2 );

		// Remove version from RSS feeds
		add_filter( 'the_generator', '__return_empty_string', 999 );

		// Remove version from admin footer
		add_filter( 'update_footer', '__return_empty_string', 999 );

		$this->log( 'WordPress version information hidden.' );
	}

	/**
	 * Remove version parameter from script and style URLs
	 *
	 * @since  1.0.0
	 * @param  string $src    Script/style URL
	 * @param  string $handle Script/style handle
	 * @return string Modified URL without version parameter
	 */
	public function remove_version_from_src( $src, $handle ) {
		if ( strpos( $src, 'ver=' ) ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	/**
	 * Set security headers via send_headers action
	 *
	 * Adds various security headers including CSP, X-Frame-Options, HSTS, etc.
	 *
	 * @since 1.0.0
	 */
	public function set_security_headers() {
		// Don't set headers for admin area unless specifically configured
		if ( is_admin() && ! $this->get_setting( 'hardening_headers_in_admin', false ) ) {
			return;
		}

		$headers = array();

		// X-Content-Type-Options
		$headers['X-Content-Type-Options'] = 'nosniff';

		// X-Frame-Options
		$xframe_option = $this->get_setting( 'hardening_xframe_options', 'SAMEORIGIN' );
		$headers['X-Frame-Options'] = sanitize_text_field( $xframe_option );

		// X-XSS-Protection (legacy but still useful)
		$headers['X-XSS-Protection'] = '1; mode=block';

		// Referrer-Policy
		$referrer_policy = $this->get_setting( 'hardening_referrer_policy', 'strict-origin-when-cross-origin' );
		$headers['Referrer-Policy'] = sanitize_text_field( $referrer_policy );

		// Content-Security-Policy
		$csp_policy = $this->get_setting( 'hardening_csp_policy', '' );
		if ( ! empty( $csp_policy ) ) {
			$headers['Content-Security-Policy'] = $csp_policy;
		}

		// Permissions-Policy (formerly Feature-Policy)
		$permissions_policy = $this->get_setting( 'hardening_permissions_policy', '' );
		if ( empty( $permissions_policy ) ) {
			// Default restrictive policy
			$permissions_policy = 'geolocation=(), microphone=(), camera=()';
		}
		$headers['Permissions-Policy'] = $permissions_policy;

		// Strict-Transport-Security (HSTS) - only for HTTPS
		if ( is_ssl() ) {
			$hsts_max_age = $this->get_setting( 'hardening_hsts_max_age', 31536000 ); // 1 year default
			$hsts_include_subdomains = $this->get_setting( 'hardening_hsts_subdomains', true );
			$hsts_preload = $this->get_setting( 'hardening_hsts_preload', false );

			$hsts_value = 'max-age=' . absint( $hsts_max_age );
			if ( $hsts_include_subdomains ) {
				$hsts_value .= '; includeSubDomains';
			}
			if ( $hsts_preload ) {
				$hsts_value .= '; preload';
			}
			$headers['Strict-Transport-Security'] = $hsts_value;
		}

		// Apply filter for extensibility
		$headers = apply_filters( 'wph_security_headers', $headers );

		// Send headers
		foreach ( $headers as $header => $value ) {
			if ( ! headers_sent() ) {
				header( sprintf( '%s: %s', $header, $value ), true );
			}
		}

		$this->log( 'Security headers set: ' . implode( ', ', array_keys( $headers ) ) );
	}

	/**
	 * Filter WordPress headers
	 *
	 * Alternative method to add security headers using wp_headers filter.
	 *
	 * @since  1.0.0
	 * @param  array $headers Existing headers
	 * @return array Modified headers
	 */
	public function filter_wp_headers( $headers ) {
		// Add security headers that aren't already set
		if ( ! isset( $headers['X-Content-Type-Options'] ) ) {
			$headers['X-Content-Type-Options'] = 'nosniff';
		}

		if ( ! isset( $headers['X-Frame-Options'] ) ) {
			$xframe_option = $this->get_setting( 'hardening_xframe_options', 'SAMEORIGIN' );
			$headers['X-Frame-Options'] = sanitize_text_field( $xframe_option );
		}

		return $headers;
	}

	/**
	 * Control REST API access
	 *
	 * Restricts REST API access to authenticated users with optional endpoint whitelist.
	 * Implements rate limiting using WordPress transients.
	 *
	 * @since  1.0.0
	 * @param  WP_Error|null|true $result Error if authentication failed
	 * @return WP_Error|null|true Modified result
	 */
	public function control_rest_api( $result ) {
		// If already an error, return it
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		// Allow authenticated users
		if ( is_user_logged_in() ) {
			return $result;
		}

		// Get whitelisted endpoints
		$whitelist = $this->get_setting( 'hardening_rest_whitelist', array() );

		// Default endpoints to whitelist
		$default_whitelist = array(
			'/wp/v2/posts',
			'/wp/v2/pages',
			'/wp/v2/categories',
			'/wp/v2/tags',
		);

		$whitelist = array_merge( $default_whitelist, $whitelist );
		$whitelist = apply_filters( 'wph_rest_api_whitelist', $whitelist );

		// Get current route
		$current_route = $GLOBALS['wp']->query_vars['rest_route'] ?? '';

		// Check if current route is whitelisted
		foreach ( $whitelist as $allowed_route ) {
			if ( strpos( $current_route, $allowed_route ) === 0 ) {
				// Apply rate limiting
				if ( ! $this->check_rest_rate_limit() ) {
					$this->log( 'REST API rate limit exceeded for IP: ' . $this->get_client_ip() );
					return new WP_Error(
						'rest_rate_limit',
						__( 'Too many requests. Please try again later.', 'wp-harden' ),
						array( 'status' => 429 )
					);
				}
				return $result;
			}
		}

		// Block access to non-whitelisted endpoints
		$this->log( 'REST API access blocked for unauthenticated user: ' . $current_route );

		return new WP_Error(
			'rest_authentication_required',
			__( 'Authentication required to access this endpoint.', 'wp-harden' ),
			array( 'status' => 401 )
		);
	}

	/**
	 * Check REST API rate limit
	 *
	 * Implements simple rate limiting using WordPress transients.
	 *
	 * @since  1.0.0
	 * @return bool True if within rate limit, false if exceeded
	 */
	private function check_rest_rate_limit() {
		$rate_limit_enabled = $this->get_setting( 'hardening_rest_rate_limit', true );
		if ( ! $rate_limit_enabled ) {
			return true;
		}

		$ip = $this->get_client_ip();
		$transient_key = 'wph_rest_rate_' . md5( $ip );

		// Get current request count
		$request_count = get_transient( $transient_key );

		// Rate limit: 60 requests per minute
		$max_requests = apply_filters( 'wph_rest_rate_limit_max', 60 );
		$time_window = apply_filters( 'wph_rest_rate_limit_window', 60 ); // seconds

		if ( false === $request_count ) {
			// First request in this time window
			set_transient( $transient_key, 1, $time_window );
			return true;
		}

		if ( $request_count >= $max_requests ) {
			return false;
		}

		// Increment request count
		set_transient( $transient_key, $request_count + 1, $time_window );
		return true;
	}

	/**
	 * Remove sensitive meta tags from wp_head
	 *
	 * Removes RSD link, wlwmanifest, shortlink, and adjacent post links.
	 *
	 * @since 1.0.0
	 */
	public function remove_meta_tags() {
		// Remove RSD (Really Simple Discovery) link
		remove_action( 'wp_head', 'rsd_link' );

		// Remove wlwmanifest (Windows Live Writer) link
		remove_action( 'wp_head', 'wlwmanifest_link' );

		// Remove shortlink
		remove_action( 'wp_head', 'wp_shortlink_wp_head', 10 );
		remove_action( 'template_redirect', 'wp_shortlink_header', 11 );

		// Remove adjacent posts links
		remove_action( 'wp_head', 'adjacent_posts_rel_link_wp_head', 10 );
		remove_action( 'wp_head', 'parent_post_rel_link', 10 );
		remove_action( 'wp_head', 'start_post_rel_link', 10 );
		remove_action( 'wp_head', 'index_rel_link' );

		// Remove REST API link from header
		remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
		remove_action( 'template_redirect', 'rest_output_link_header', 11 );

		// Remove oEmbed discovery links
		remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 10 );

		$this->log( 'Sensitive meta tags removed from wp_head.' );
	}

	/**
	 * Disable user enumeration
	 *
	 * Blocks ?author=N queries and redirects author archives to homepage.
	 *
	 * @since 1.0.0
	 */
	public function disable_user_enumeration() {
		// Block author queries via REST API
		add_filter( 'rest_endpoints', array( $this, 'filter_rest_user_endpoints' ) );

		// Block author scan via ?author=N
		if ( ! is_admin() ) {
			if ( isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
				$this->log( 'User enumeration attempt blocked: ?author=' . intval( $_GET['author'] ) );
				wp_safe_redirect( home_url(), 301 );
				exit;
			}
		}

		// Optionally disable author archives
		if ( $this->get_setting( 'hardening_disable_author_archives', false ) ) {
			add_action( 'template_redirect', array( $this, 'redirect_author_archives' ) );
		}

		// Modify author link in posts
		add_filter( 'author_link', array( $this, 'modify_author_link' ), 999, 3 );
	}

	/**
	 * Filter REST API user endpoints
	 *
	 * @since  1.0.0
	 * @param  array $endpoints Available endpoints
	 * @return array Modified endpoints
	 */
	public function filter_rest_user_endpoints( $endpoints ) {
		if ( ! is_user_logged_in() ) {
			if ( isset( $endpoints['/wp/v2/users'] ) ) {
				unset( $endpoints['/wp/v2/users'] );
			}
			if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
				unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
			}
		}
		return $endpoints;
	}

	/**
	 * Redirect author archives to homepage
	 *
	 * @since 1.0.0
	 */
	public function redirect_author_archives() {
		if ( is_author() ) {
			$this->log( 'Author archive access blocked, redirecting to homepage.' );
			wp_safe_redirect( home_url(), 301 );
			exit;
		}
	}

	/**
	 * Modify author link to prevent enumeration
	 *
	 * @since  1.0.0
	 * @param  string $link   Author link
	 * @param  int    $author_id Author ID
	 * @param  string $author_nicename Author nicename
	 * @return string Modified link
	 */
	public function modify_author_link( $link, $author_id, $author_nicename ) {
		if ( $this->get_setting( 'hardening_disable_author_archives', false ) ) {
			return home_url();
		}
		return $link;
	}

	/**
	 * Hide login error messages
	 *
	 * Returns generic error message instead of specific username/password errors.
	 *
	 * @since  1.0.0
	 * @param  string $error Error message
	 * @return string Generic error message
	 */
	public function hide_login_errors( $error ) {
		// Don't modify errors on admin side
		if ( is_admin() && current_user_can( 'manage_options' ) ) {
			return $error;
		}

		$generic_message = apply_filters(
			'wph_login_error_message',
			__( '<strong>Error:</strong> Invalid username or password.', 'wp-harden' )
		);

		return $generic_message;
	}

	/**
	 * Disable pingback functionality
	 *
	 * Removes pingback methods from XML-RPC and disables pingback header.
	 *
	 * @since 1.0.0
	 */
	public function disable_pingbacks() {
		// Remove X-Pingback header
		add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ), 999 );

		// Disable XML-RPC pingback
		add_filter( 'xmlrpc_methods', array( $this, 'remove_pingback_method' ), 999 );

		// Disable pingbacks on old posts
		$close_days = $this->get_setting( 'hardening_close_pingbacks_days', 30 );
		if ( $close_days > 0 ) {
			add_filter( 'pings_open', array( $this, 'disable_old_post_pingbacks' ), 999, 2 );
		}

		$this->log( 'Pingback functionality disabled.' );
	}

	/**
	 * Remove X-Pingback header
	 *
	 * @since  1.0.0
	 * @param  array $headers HTTP headers
	 * @return array Modified headers
	 */
	public function remove_pingback_header( $headers ) {
		if ( isset( $headers['X-Pingback'] ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	/**
	 * Remove pingback.ping method from XML-RPC
	 *
	 * @since  1.0.0
	 * @param  array $methods XML-RPC methods
	 * @return array Modified methods
	 */
	public function remove_pingback_method( $methods ) {
		unset( $methods['pingback.ping'] );
		unset( $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	/**
	 * Disable pingbacks on old posts
	 *
	 * @since  1.0.0
	 * @param  bool $open    Whether pings are open
	 * @param  int  $post_id Post ID
	 * @return bool Modified pings open status
	 */
	public function disable_old_post_pingbacks( $open, $post_id ) {
		if ( ! $open ) {
			return $open;
		}

		$close_days = $this->get_setting( 'hardening_close_pingbacks_days', 30 );
		$post_date = get_post_field( 'post_date', $post_id );
		$post_age_days = ( time() - strtotime( $post_date ) ) / DAY_IN_SECONDS;

		if ( $post_age_days > $close_days ) {
			return false;
		}

		return $open;
	}

	/**
	 * Force SSL for admin area
	 *
	 * Sets FORCE_SSL_ADMIN constant and redirects HTTP admin requests to HTTPS.
	 *
	 * @since 1.0.0
	 */
	public function force_ssl_admin() {
		// Only proceed if site supports HTTPS
		if ( ! is_ssl() && ! $this->site_supports_https() ) {
			$this->log( 'SSL admin enforcement skipped: Site does not support HTTPS.' );
			return;
		}

		// Define FORCE_SSL_ADMIN if not already set
		if ( ! defined( 'FORCE_SSL_ADMIN' ) ) {
			define( 'FORCE_SSL_ADMIN', true );
			$this->log( 'FORCE_SSL_ADMIN constant defined.' );
		}

		// Redirect admin requests to HTTPS
		if ( is_admin() && ! is_ssl() ) {
			$redirect_url = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
			wp_safe_redirect( $redirect_url, 301 );
			exit;
		}
	}

	/**
	 * Check if site supports HTTPS
	 *
	 * @since  1.0.0
	 * @return bool True if HTTPS is supported
	 */
	private function site_supports_https() {
		$home_url = get_home_url();
		return strpos( $home_url, 'https://' ) === 0;
	}

	/**
	 * Apply all hardening measures at once
	 *
	 * Enables all security hardening features with safe defaults.
	 * Useful for one-click hardening during plugin setup.
	 *
	 * @since 1.0.0
	 */
	public function apply_all_hardening() {
		$settings = array(
			'hardening_disable_xmlrpc'        => true,
			'hardening_disable_file_edit'     => true,
			'hardening_hide_wp_version'       => true,
			'hardening_security_headers'      => true,
			'hardening_xframe_options'        => 'SAMEORIGIN',
			'hardening_referrer_policy'       => 'strict-origin-when-cross-origin',
			'hardening_disable_rest_api'      => false, // Keep disabled to avoid breaking sites
			'hardening_remove_meta_tags'      => true,
			'hardening_disable_user_enum'     => true,
			'hardening_hide_login_errors'     => true,
			'hardening_disable_pingbacks'     => true,
			'hardening_force_ssl_admin'       => $this->site_supports_https(),
			'hardening_disable_app_passwords' => true,
		);

		// Apply filter for extensibility
		$settings = apply_filters( 'wph_apply_all_hardening_settings', $settings );

		// Save all settings
		foreach ( $settings as $key => $value ) {
			$this->set_setting( $key, $value );
		}

		// Re-initialize hooks with new settings
		$this->init_hooks();

		$this->log( 'All hardening measures applied successfully.' );

		return true;
	}

	/**
	 * Get client IP address
	 *
	 * @since  1.0.0
	 * @return string Client IP address
	 */
	private function get_client_ip() {
		$ip = '';

		if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			$ip = $_SERVER['HTTP_CLIENT_IP'];
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		} elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = $_SERVER['REMOTE_ADDR'];
		}

		// Validate IP
		$ip = filter_var( $ip, FILTER_VALIDATE_IP );

		return $ip ? $ip : '0.0.0.0';
	}

	/**
	 * Get setting value
	 *
	 * @since  1.0.0
	 * @param  string $key     Setting key
	 * @param  mixed  $default Default value
	 * @return mixed Setting value
	 */
	private function get_setting( $key, $default = false ) {
		if ( $this->settings && method_exists( $this->settings, 'get' ) ) {
			return $this->settings->get( $key, $default );
		}
		return get_option( 'wph_' . $key, $default );
	}

	/**
	 * Set setting value
	 *
	 * @since  1.0.0
	 * @param  string $key   Setting key
	 * @param  mixed  $value Setting value
	 * @return bool True on success
	 */
	private function set_setting( $key, $value ) {
		if ( $this->settings && method_exists( $this->settings, 'set' ) ) {
			return $this->settings->set( $key, $value );
		}
		return update_option( 'wph_' . $key, $value );
	}

	/**
	 * Log a message
	 *
	 * @since 1.0.0
	 * @param string $message Log message
	 * @param string $level   Log level (info, warning, error)
	 */
	private function log( $message, $level = 'info' ) {
		if ( $this->logger && method_exists( $this->logger, 'log' ) ) {
			$this->logger->log( $message, $level );
		}
	}

	/**
	 * Prevent cloning of the instance
	 *
	 * @since 1.0.0
	 */
	private function __clone() {}

	/**
	 * Prevent unserializing of the instance
	 *
	 * @since 1.0.0
	 */
	public function __wakeup() {
		throw new Exception( 'Cannot unserialize singleton' );
	}
}
