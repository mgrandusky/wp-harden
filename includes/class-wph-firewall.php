<?php
/**
 * Web Application Firewall Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Firewall
 *
 * Provides Web Application Firewall functionality
 */
class WPH_Firewall {

	/**
	 * Singleton instance
	 *
	 * @var WPH_Firewall
	 */
	private static $instance = null;

	/**
	 * Rate limit tracking
	 *
	 * @var array
	 */
	private $rate_limits = array();

	/**
	 * Traffic baseline for DDoS detection
	 *
	 * @var array
	 */
	private $traffic_baseline = array();

	/**
	 * Allowed HTTP methods per endpoint
	 *
	 * @var array
	 */
	private $allowed_methods = array();

	/**
	 * Dangerous file extensions
	 *
	 * @var array
	 */
	private $dangerous_extensions = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'pht', 'phar', 'exe', 'com', 'bat', 'cmd', 'sh' );

	/**
	 * Get singleton instance
	 *
	 * @return WPH_Firewall
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
		// Run firewall checks early
		add_action( 'plugins_loaded', array( $this, 'run_firewall' ), 1 );
		
		// Cookie security hardening
		add_action( 'init', array( $this, 'harden_cookies' ), 1 );
		add_filter( 'wp_headers', array( $this, 'set_security_headers' ) );
		
		// File upload security
		add_filter( 'wp_handle_upload_prefilter', array( $this, 'validate_file_upload' ), 10, 1 );
	}

	/**
	 * Run firewall checks
	 *
	 * @since 1.0.0
	 */
	public function run_firewall() {
		$settings = WPH_Settings::get_instance();

		if ( ! $settings->get( 'firewall_enabled', true ) ) {
			return;
		}

		$ip_manager = WPH_IP_Manager::get_instance();
		$client_ip  = $ip_manager->get_client_ip();

		// Check if IP is blocked
		if ( $ip_manager->is_blocked( $client_ip ) ) {
			$this->block_request( 'IP address is blocked' );
		}

		// HTTP Method Filtering
		if ( $settings->get( 'http_method_filtering_enabled', true ) ) {
			if ( ! $this->validate_http_method() ) {
				$this->block_request( 'HTTP method not allowed' );
			}
		}

		// Request Header Anomaly Detection
		if ( $settings->get( 'header_anomaly_detection_enabled', true ) ) {
			if ( $this->detect_header_anomalies() ) {
				$this->block_request( 'Request header anomaly detected' );
			}
		}

		// DDoS Protection - Check for traffic spikes
		if ( $settings->get( 'ddos_protection_enabled', false ) ) {
			if ( $this->detect_traffic_spike( $client_ip ) ) {
				// Issue JS challenge instead of immediate block
				$this->issue_js_challenge();
			}
		}

		// Advanced Rate Limiting with sliding window
		if ( $settings->get( 'rate_limit_enabled', true ) ) {
			if ( $this->is_rate_limited_advanced( $client_ip ) ) {
				$this->block_request( 'Rate limit exceeded' );
			}
		}

		// Check for malicious patterns
		$threat_score = $this->calculate_threat_score();

		if ( $threat_score >= 70 ) {
			$this->handle_threat( $client_ip, $threat_score );
		}
	}

	/**
	 * Calculate threat score for current request
	 *
	 * @return int Threat score (0-100)
	 * @since 1.0.0
	 */
	private function calculate_threat_score() {
		$score = 0;

		// Check for SQL injection patterns
		if ( $this->detect_sql_injection() ) {
			$score += 50;
		}

		// Check for XSS patterns
		if ( $this->detect_xss() ) {
			$score += 40;
		}

		// Check for file inclusion attempts
		if ( $this->detect_file_inclusion() ) {
			$score += 60;
		}

		// Check for suspicious user agents
		if ( $this->detect_suspicious_user_agent() ) {
			$score += 20;
		}

		// Check for path traversal
		if ( $this->detect_path_traversal() ) {
			$score += 50;
		}

		return min( $score, 100 );
	}

	/**
	 * Detect SQL injection attempts
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	private function detect_sql_injection() {
		$patterns = array(
			'/(\bunion\b.*\bselect\b)/i',
			'/(\bselect\b.*\bfrom\b)/i',
			'/(;\s*drop\s+table)/i',
			'/(\bor\b\s+\d+\s*=\s*\d+)/i',
			'/(\band\b\s+\d+\s*=\s*\d+)/i',
			'/(\'|\")(\s*)(or|and)(\s*)(\'|\")/i',
			'/\b(exec|execute|sp_executesql)\b/i',
		);

		return $this->check_patterns_in_request( $patterns );
	}

	/**
	 * Detect XSS attempts
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	private function detect_xss() {
		$patterns = array(
			'/<script[^>]*>.*?<\/script>/is',
			'/<iframe[^>]*>.*?<\/iframe>/is',
			'/javascript:/i',
			'/on\w+\s*=/i',
			'/<embed[^>]*>/i',
			'/<object[^>]*>/i',
		);

		return $this->check_patterns_in_request( $patterns );
	}

	/**
	 * Detect file inclusion attempts
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	private function detect_file_inclusion() {
		$patterns = array(
			'/(\.\.\/|\.\.\\\\)/i',
			'/\b(php|data|file|glob|phar):\/\//i',
			'/\b(etc\/passwd|boot\.ini|win\.ini)/i',
		);

		return $this->check_patterns_in_request( $patterns );
	}

	/**
	 * Detect path traversal attempts
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	private function detect_path_traversal() {
		$patterns = array(
			'/\.\.[\/\\\\]/',
			'/%2e%2e[\/\\\\]/',
			'/\.\.[%2f%5c]/',
		);

		return $this->check_patterns_in_request( $patterns );
	}

	/**
	 * Detect suspicious user agents
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	private function detect_suspicious_user_agent() {
		if ( empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			return false;
		}

		$user_agent = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );

		$suspicious_agents = array(
			'sqlmap',
			'nikto',
			'nmap',
			'masscan',
			'metasploit',
			'havij',
			'acunetix',
		);

		foreach ( $suspicious_agents as $agent ) {
			if ( stripos( $user_agent, $agent ) !== false ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check patterns in request data
	 *
	 * @param array $patterns Regular expression patterns.
	 * @return bool
	 * @since 1.0.0
	 */
	private function check_patterns_in_request( $patterns ) {
		// Safely handle request data with wp_unslash
		$get_data  = isset( $_GET ) ? wp_unslash( $_GET ) : array();
		$post_data = isset( $_POST ) ? wp_unslash( $_POST ) : array();
		$request_data = array_merge( $get_data, $post_data );

		foreach ( $request_data as $value ) {
			if ( is_array( $value ) ) {
				$value = wp_json_encode( $value );
			}

			foreach ( $patterns as $pattern ) {
				if ( preg_match( $pattern, $value ) ) {
					return true;
				}
			}
		}

		// Check request URI
		if ( ! empty( $_SERVER['REQUEST_URI'] ) ) {
			$request_uri = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) );
			foreach ( $patterns as $pattern ) {
				if ( preg_match( $pattern, $request_uri ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Check if IP is rate limited
	 *
	 * @param string $ip_address IP address to check.
	 * @return bool
	 * @since 1.0.0
	 */
	private function is_rate_limited( $ip_address ) {
		$settings = WPH_Settings::get_instance();
		$max_requests = $settings->get( 'rate_limit_requests', 60 );
		$period = $settings->get( 'rate_limit_period', 60 );

		$transient_key = 'wph_rate_limit_' . md5( $ip_address );
		$requests = get_transient( $transient_key );

		if ( false === $requests ) {
			set_transient( $transient_key, 1, $period );
			return false;
		}

		if ( $requests >= $max_requests ) {
			return true;
		}

		set_transient( $transient_key, $requests + 1, $period );
		return false;
	}

	/**
	 * Handle detected threat
	 *
	 * @param string $ip_address   IP address.
	 * @param int    $threat_score Threat score.
	 * @since 1.0.0
	 */
	private function handle_threat( $ip_address, $threat_score ) {
		$logger = WPH_Logger::get_instance();
		$logger->log(
			'firewall',
			'high',
			sprintf( 'Threat detected with score %d', $threat_score ),
			array(
				'ip'           => $ip_address,
				'threat_score' => $threat_score,
				'request_uri'  => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
			)
		);

		// Auto-block if threat score is very high
		if ( $threat_score >= 80 ) {
			$ip_manager = WPH_IP_Manager::get_instance();
			$ip_manager->block_ip(
				$ip_address,
				sprintf( 'Automatic block - threat score: %d', $threat_score ),
				'temporary',
				3600 // 1 hour
			);

			$this->block_request( 'Suspicious activity detected' );
		}
	}

	/**
	 * Block the current request
	 *
	 * @param string $reason Reason for blocking.
	 * @since 1.0.0
	 */
	private function block_request( $reason ) {
		$logger = WPH_Logger::get_instance();
		$ip_manager = WPH_IP_Manager::get_instance();

		$logger->log(
			'firewall',
			'medium',
			'Request blocked: ' . $reason,
			array(
				'ip'          => $ip_manager->get_client_ip(),
				'request_uri' => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
			)
		);

		wp_die(
			esc_html__( 'Access Denied', 'wp-harden' ),
			esc_html__( 'Security Check', 'wp-harden' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Advanced rate limiting with sliding window algorithm
	 *
	 * @param string $ip_address IP address to check.
	 * @return bool True if rate limited.
	 * @since 1.0.0
	 */
	private function is_rate_limited_advanced( $ip_address ) {
		$settings = WPH_Settings::get_instance();
		$endpoint = $this->get_current_endpoint();
		
		// Get endpoint-specific limits or use defaults
		$endpoint_limits = $settings->get( 'rate_limit_endpoints', array() );
		
		if ( isset( $endpoint_limits[ $endpoint ] ) ) {
			$max_requests = $endpoint_limits[ $endpoint ]['requests'];
			$period       = $endpoint_limits[ $endpoint ]['period'];
		} else {
			$max_requests = $settings->get( 'rate_limit_requests', 60 );
			$period       = $settings->get( 'rate_limit_period', 60 );
		}

		// Sliding window implementation
		$transient_key = 'wph_rate_limit_sw_' . md5( $ip_address . $endpoint );
		$requests = get_transient( $transient_key );
		
		if ( false === $requests ) {
			$requests = array();
		}

		$current_time = time();
		$window_start = $current_time - $period;

		// Remove old requests outside the window
		$requests = array_filter( $requests, function( $timestamp ) use ( $window_start ) {
			return $timestamp > $window_start;
		});

		// Check burst detection
		if ( $this->detect_burst( $requests, $current_time ) ) {
			$this->temporary_block_ip( $ip_address, 'Burst traffic detected' );
			return true;
		}

		// Check if limit exceeded
		if ( count( $requests ) >= $max_requests ) {
			return true;
		}

		// Add current request
		$requests[] = $current_time;
		set_transient( $transient_key, $requests, $period * 2 );

		return false;
	}

	/**
	 * Get current endpoint from request
	 *
	 * @return string Current endpoint identifier.
	 * @since 1.0.0
	 */
	private function get_current_endpoint() {
		if ( empty( $_SERVER['REQUEST_URI'] ) ) {
			return 'unknown';
		}

		$request_uri = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		$parsed = wp_parse_url( $request_uri );
		$path = isset( $parsed['path'] ) ? $parsed['path'] : '';

		// Match specific endpoints
		if ( strpos( $path, 'wp-login.php' ) !== false ) {
			return 'wp-login';
		} elseif ( strpos( $path, 'xmlrpc.php' ) !== false ) {
			return 'xmlrpc';
		} elseif ( strpos( $path, 'wp-admin' ) !== false ) {
			return 'wp-admin';
		} elseif ( strpos( $path, 'wp-json' ) !== false ) {
			return 'wp-json';
		}

		return 'default';
	}

	/**
	 * Detect burst traffic (too many requests in short time)
	 *
	 * @param array $requests Array of request timestamps.
	 * @param int   $current_time Current timestamp.
	 * @return bool True if burst detected.
	 * @since 1.0.0
	 */
	private function detect_burst( $requests, $current_time ) {
		$settings = WPH_Settings::get_instance();
		$burst_threshold = $settings->get( 'rate_limit_burst_threshold', 10 );
		$burst_window = $settings->get( 'rate_limit_burst_window', 5 ); // 5 seconds

		$burst_start = $current_time - $burst_window;
		$burst_count = 0;

		foreach ( $requests as $timestamp ) {
			if ( $timestamp > $burst_start ) {
				$burst_count++;
			}
		}

		return $burst_count >= $burst_threshold;
	}

	/**
	 * Detect traffic spike for DDoS protection
	 *
	 * @param string $ip_address IP address.
	 * @return bool True if spike detected.
	 * @since 1.0.0
	 */
	private function detect_traffic_spike( $ip_address ) {
		$settings = WPH_Settings::get_instance();
		$spike_threshold = $settings->get( 'ddos_spike_threshold', 3.0 ); // 3x baseline
		
		// Track global request rate
		$current_minute = floor( time() / 60 );
		$traffic_key = 'wph_traffic_' . $current_minute;
		$current_traffic = get_transient( $traffic_key );
		
		if ( false === $current_traffic ) {
			$current_traffic = 0;
		}
		
		$current_traffic++;
		set_transient( $traffic_key, $current_traffic, 120 );

		// Get baseline (average from previous 5 minutes)
		$baseline = $this->calculate_traffic_baseline( $current_minute );
		
		if ( $baseline > 0 && $current_traffic > ( $baseline * $spike_threshold ) ) {
			$logger = WPH_Logger::get_instance();
			$logger->log(
				'firewall',
				'high',
				'Traffic spike detected',
				array(
					'current_traffic' => $current_traffic,
					'baseline'        => $baseline,
					'threshold'       => $spike_threshold,
				)
			);
			return true;
		}

		return false;
	}

	/**
	 * Calculate traffic baseline
	 *
	 * @param int $current_minute Current minute timestamp.
	 * @return float Average traffic baseline.
	 * @since 1.0.0
	 */
	private function calculate_traffic_baseline( $current_minute ) {
		$total = 0;
		$count = 0;

		// Check previous 5 minutes
		for ( $i = 1; $i <= 5; $i++ ) {
			$traffic_key = 'wph_traffic_' . ( $current_minute - $i );
			$traffic = get_transient( $traffic_key );
			
			if ( false !== $traffic ) {
				$total += $traffic;
				$count++;
			}
		}

		return $count > 0 ? ( $total / $count ) : 0;
	}

	/**
	 * Issue JavaScript challenge for suspected bots
	 *
	 * @since 1.0.0
	 */
	private function issue_js_challenge() {
		$settings = WPH_Settings::get_instance();
		
		$ip_manager = WPH_IP_Manager::get_instance();
		$client_ip = $ip_manager->get_client_ip();
		
		// Check if challenge cookie exists
		if ( isset( $_COOKIE['wph_js_challenge'] ) ) {
			$challenge_value = sanitize_text_field( wp_unslash( $_COOKIE['wph_js_challenge'] ) );
			$expected_value = get_transient( 'wph_challenge_' . md5( $client_ip ) );
			
			if ( $challenge_value === $expected_value ) {
				// Challenge passed
				return;
			}
		}

		// Generate challenge
		$challenge_code = wp_generate_password( 32, false );
		set_transient( 'wph_challenge_' . md5( $client_ip ), $challenge_code, 300 );

		// Output challenge page
		status_header( 429 );
		nocache_headers();
		
		$secure_flag = is_ssl() ? '; Secure' : '';
		?>
		<!DOCTYPE html>
		<html>
		<head>
			<title><?php echo esc_html__( 'Security Check', 'wp-harden' ); ?></title>
			<meta name="robots" content="noindex, nofollow">
		</head>
		<body>
			<h1><?php echo esc_html__( 'Checking your browser...', 'wp-harden' ); ?></h1>
			<p><?php echo esc_html__( 'This process is automatic. Your browser will redirect shortly.', 'wp-harden' ); ?></p>
			<script>
				document.cookie = "wph_js_challenge=<?php echo esc_js( $challenge_code ); ?>; path=/; max-age=300; SameSite=Lax<?php echo esc_js( $secure_flag ); ?>";
				setTimeout(function() {
					window.location.reload();
				}, 2000);
			</script>
			<noscript>
				<p><?php echo esc_html__( 'Please enable JavaScript and refresh the page.', 'wp-harden' ); ?></p>
			</noscript>
		</body>
		</html>
		<?php
		exit;
	}

	/**
	 * Temporarily block IP address
	 *
	 * @param string $ip_address IP address to block.
	 * @param string $reason Reason for blocking.
	 * @since 1.0.0
	 */
	private function temporary_block_ip( $ip_address, $reason ) {
		$settings = WPH_Settings::get_instance();
		$block_duration = $settings->get( 'ddos_block_duration', 300 ); // 5 minutes default

		$ip_manager = WPH_IP_Manager::get_instance();
		$ip_manager->block_ip( $ip_address, $reason, 'temporary', $block_duration );

		$logger = WPH_Logger::get_instance();
		$logger->log(
			'firewall',
			'medium',
			'Temporary IP block: ' . $reason,
			array(
				'ip'       => $ip_address,
				'duration' => $block_duration,
			)
		);
	}

	/**
	 * Validate HTTP method
	 *
	 * @return bool True if method is allowed.
	 * @since 1.0.0
	 */
	private function validate_http_method() {
		if ( empty( $_SERVER['REQUEST_METHOD'] ) ) {
			return false;
		}

		$method = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) );
		$settings = WPH_Settings::get_instance();

		// Block dangerous methods globally
		$blocked_methods = $settings->get( 'http_blocked_methods', array( 'TRACE', 'TRACK', 'DEBUG' ) );
		if ( in_array( $method, $blocked_methods, true ) ) {
			$logger = WPH_Logger::get_instance();
			$logger->log(
				'firewall',
				'medium',
				'Blocked HTTP method: ' . $method,
				array( 'ip' => WPH_IP_Manager::get_instance()->get_client_ip() )
			);
			return false;
		}

		// Check endpoint-specific restrictions
		$endpoint = $this->get_current_endpoint();
		$endpoint_methods = $settings->get( 'http_allowed_methods', array() );

		if ( isset( $endpoint_methods[ $endpoint ] ) ) {
			$allowed = $endpoint_methods[ $endpoint ];
			return in_array( $method, $allowed, true );
		}

		// Default allowed methods
		$default_allowed = array( 'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH' );
		return in_array( $method, $default_allowed, true );
	}

	/**
	 * Detect request header anomalies
	 *
	 * @return bool True if anomaly detected.
	 * @since 1.0.0
	 */
	private function detect_header_anomalies() {
		$settings = WPH_Settings::get_instance();
		$score = 0;

		// Check for missing User-Agent
		if ( $settings->get( 'header_check_user_agent', true ) ) {
			if ( empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
				$score += 30;
			}
		}

		// Check for missing Accept header
		if ( $settings->get( 'header_check_accept', true ) ) {
			if ( empty( $_SERVER['HTTP_ACCEPT'] ) ) {
				$score += 20;
			}
		}

		// Check for header injection attempts
		if ( $this->detect_header_injection() ) {
			$score += 50;
		}

		// Check for spoofed headers
		if ( $this->detect_spoofed_headers() ) {
			$score += 40;
		}

		// Check for malformed headers
		if ( $this->detect_malformed_headers() ) {
			$score += 30;
		}

		$threshold = $settings->get( 'header_anomaly_threshold', 50 );
		
		if ( $score >= $threshold ) {
			$logger = WPH_Logger::get_instance();
			$logger->log(
				'firewall',
				'medium',
				'Header anomaly detected',
				array(
					'score' => $score,
					'ip'    => WPH_IP_Manager::get_instance()->get_client_ip(),
				)
			);
			return true;
		}

		return false;
	}

	/**
	 * Detect header injection attempts
	 *
	 * @return bool True if injection detected.
	 * @since 1.0.0
	 */
	private function detect_header_injection() {
		$patterns = array( '/\r/', '/\n/', '/%0d/', '/%0a/' );
		
		foreach ( $_SERVER as $key => $value ) {
			if ( strpos( $key, 'HTTP_' ) === 0 ) {
				$header_value = is_string( $value ) ? $value : '';
				foreach ( $patterns as $pattern ) {
					if ( preg_match( $pattern, $header_value ) ) {
						return true;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Detect spoofed headers
	 *
	 * @return bool True if spoofing detected.
	 * @since 1.0.0
	 */
	private function detect_spoofed_headers() {
		// Check for conflicting X-Forwarded-For headers
		if ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$xff = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			// Check for suspicious patterns
			if ( preg_match( '/[^\d\.,\s:]/', $xff ) ) {
				return true;
			}
		}

		// Check for mismatched Host headers
		if ( isset( $_SERVER['HTTP_HOST'] ) && isset( $_SERVER['SERVER_NAME'] ) ) {
			$http_host = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) );
			$server_name = sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) );
			
			// Remove port from HTTP_HOST for comparison
			$http_host_clean = preg_replace( '/:\d+$/', '', $http_host );
			
			if ( $http_host_clean !== $server_name && $http_host !== $server_name ) {
				// Check if it's a valid configured domain
				$site_url = wp_parse_url( get_site_url() );
				if ( isset( $site_url['host'] ) && $http_host_clean !== $site_url['host'] ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Detect malformed headers
	 *
	 * @return bool True if malformed headers detected.
	 * @since 1.0.0
	 */
	private function detect_malformed_headers() {
		$settings = WPH_Settings::get_instance();
		
		// Check Content-Length header format
		if ( isset( $_SERVER['HTTP_CONTENT_LENGTH'] ) ) {
			$content_length = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CONTENT_LENGTH'] ) );
			if ( ! is_numeric( $content_length ) || intval( $content_length ) < 0 ) {
				return true;
			}
		}

		// Check for extremely long headers
		$max_header_size = $settings->get( 'max_header_size', 8192 ); // 8KB default
		foreach ( $_SERVER as $key => $value ) {
			if ( strpos( $key, 'HTTP_' ) === 0 && is_string( $value ) ) {
				if ( strlen( $value ) > $max_header_size ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Validate file upload
	 *
	 * @param array $file File data array.
	 * @return array Modified file data or error.
	 * @since 1.0.0
	 */
	public function validate_file_upload( $file ) {
		$settings = WPH_Settings::get_instance();

		if ( ! $settings->get( 'file_upload_security_enabled', true ) ) {
			return $file;
		}

		// Check file size limit
		$max_size = $settings->get( 'file_upload_max_size', 10485760 ); // 10MB default
		if ( $file['size'] > $max_size ) {
			$file['error'] = sprintf(
				/* translators: %s: Maximum file size */
				__( 'File size exceeds the maximum limit of %s.', 'wp-harden' ),
				size_format( $max_size )
			);
			return $file;
		}

		// Validate MIME type
		if ( ! $this->validate_mime_type( $file ) ) {
			$file['error'] = __( 'File type is not allowed.', 'wp-harden' );
			return $file;
		}

		// Check file extension
		if ( ! $this->validate_file_extension( $file['name'] ) ) {
			$file['error'] = __( 'File extension is not allowed.', 'wp-harden' );
			return $file;
		}

		// Detect double extensions
		if ( $this->detect_double_extension( $file['name'] ) ) {
			$file['error'] = __( 'Double file extensions are not allowed.', 'wp-harden' );
			return $file;
		}

		// Detect null byte injection
		if ( $this->detect_null_byte_injection( $file['name'] ) ) {
			$file['error'] = __( 'Invalid file name detected.', 'wp-harden' );
			return $file;
		}

		// Hook for virus scanning
		$scan_result = apply_filters( 'wph_file_upload_virus_scan', true, $file );
		if ( ! $scan_result ) {
			$file['error'] = __( 'File failed security scan.', 'wp-harden' );
			return $file;
		}

		return $file;
	}

	/**
	 * Validate MIME type
	 *
	 * @param array $file File data.
	 * @return bool True if valid.
	 * @since 1.0.0
	 */
	private function validate_mime_type( $file ) {
		$settings = WPH_Settings::get_instance();
		$allowed_mimes = $settings->get( 'file_upload_allowed_mimes', array() );

		// Use WordPress allowed mime types if none configured
		if ( empty( $allowed_mimes ) ) {
			$allowed_mimes = get_allowed_mime_types();
		}

		// Check file type
		$file_type = wp_check_filetype( $file['name'], $allowed_mimes );
		
		if ( ! $file_type['type'] ) {
			return false;
		}

		// Verify MIME type matches
		if ( $file['type'] !== $file_type['type'] ) {
			// Some browsers send different MIME types, do additional check
			$finfo = finfo_open( FILEINFO_MIME_TYPE );
			if ( false === $finfo ) {
				$logger = WPH_Logger::get_instance();
				$logger->log(
					'firewall',
					'low',
					'File information extension (finfo) unavailable for MIME type validation',
					array( 'file' => $file['name'] )
				);
				return false;
			}
			$detected_type = finfo_file( $finfo, $file['tmp_name'] );
			finfo_close( $finfo );

			if ( $detected_type !== $file_type['type'] && $detected_type !== $file['type'] ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Validate file extension
	 *
	 * @param string $filename File name.
	 * @return bool True if valid.
	 * @since 1.0.0
	 */
	private function validate_file_extension( $filename ) {
		$settings = WPH_Settings::get_instance();
		
		// Get file extension
		$ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );

		// Check blacklist first
		$blacklist = $settings->get( 'file_upload_extension_blacklist', $this->dangerous_extensions );
		if ( in_array( $ext, $blacklist, true ) ) {
			return false;
		}

		// Check whitelist if configured
		$whitelist = $settings->get( 'file_upload_extension_whitelist', array() );
		if ( ! empty( $whitelist ) && ! in_array( $ext, $whitelist, true ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Detect double extension (.php.jpg)
	 *
	 * @param string $filename File name.
	 * @return bool True if double extension detected.
	 * @since 1.0.0
	 */
	private function detect_double_extension( $filename ) {
		// Remove the last extension
		$name_without_ext = pathinfo( $filename, PATHINFO_FILENAME );
		
		// Check if there's another extension
		$secondary_ext = strtolower( pathinfo( $name_without_ext, PATHINFO_EXTENSION ) );
		
		if ( ! empty( $secondary_ext ) && in_array( $secondary_ext, $this->dangerous_extensions, true ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Detect null byte injection in filename
	 *
	 * @param string $filename File name.
	 * @return bool True if null byte detected.
	 * @since 1.0.0
	 */
	private function detect_null_byte_injection( $filename ) {
		// Check for null bytes
		if ( strpos( $filename, "\0" ) !== false ) {
			return true;
		}

		// Check for URL encoded null bytes
		if ( strpos( $filename, '%00' ) !== false ) {
			return true;
		}

		return false;
	}

	/**
	 * Harden WordPress cookies with security flags
	 *
	 * @since 1.0.0
	 */
	public function harden_cookies() {
		$settings = WPH_Settings::get_instance();

		if ( ! $settings->get( 'cookie_security_enabled', true ) ) {
			return;
		}

		// Set cookie parameters
		$secure = is_ssl();
		$httponly = true;
		$samesite = $settings->get( 'cookie_samesite', 'Lax' );

		// Apply to PHP session cookies
		if ( version_compare( PHP_VERSION, '7.3.0', '>=' ) ) {
			session_set_cookie_params( array(
				'lifetime' => 0,
				'path'     => COOKIEPATH,
				'domain'   => COOKIE_DOMAIN,
				'secure'   => $secure,
				'httponly' => $httponly,
				'samesite' => $samesite,
			));
		} else {
			session_set_cookie_params( 0, COOKIEPATH, COOKIE_DOMAIN, $secure, $httponly );
		}

		// Filter WordPress auth cookies
		add_filter( 'auth_cookie', array( $this, 'secure_auth_cookie' ), 10, 5 );
		add_filter( 'secure_auth_cookie', array( $this, 'secure_auth_cookie' ), 10, 5 );
		add_filter( 'logged_in_cookie', array( $this, 'secure_auth_cookie' ), 10, 5 );
	}

	/**
	 * Secure WordPress authentication cookies
	 *
	 * @param string $cookie_value Cookie value.
	 * @param int    $expire Expiration time.
	 * @param int    $expiration Expiration duration.
	 * @param int    $user_id User ID.
	 * @param string $scheme Authentication scheme.
	 * @return string Cookie value.
	 * @since 1.0.0
	 */
	public function secure_auth_cookie( $cookie_value, $expire, $expiration, $user_id, $scheme ) {
		// The cookie value is returned unchanged
		// Security settings are applied via session_set_cookie_params in harden_cookies()
		return $cookie_value;
	}

	/**
	 * Set security headers
	 *
	 * @param array $headers HTTP headers.
	 * @return array Modified headers.
	 * @since 1.0.0
	 */
	public function set_security_headers( $headers ) {
		$settings = WPH_Settings::get_instance();

		if ( ! $settings->get( 'cookie_security_enabled', true ) ) {
			return $headers;
		}

		// Note: SameSite attribute is primarily set via session_set_cookie_params()
		// in the harden_cookies() method. This filter is available for additional
		// security header customization via apply_filters('wph_security_headers', $headers)
		return apply_filters( 'wph_security_headers', $headers );
	}

	/**
	 * Get default rate limit endpoint configuration
	 *
	 * @return array Default endpoint limits.
	 * @since 1.0.0
	 */
	public function get_default_endpoint_limits() {
		return array(
			'wp-login' => array(
				'requests' => 5,
				'period'   => 60,
			),
			'xmlrpc'   => array(
				'requests' => 10,
				'period'   => 60,
			),
			'wp-admin' => array(
				'requests' => 30,
				'period'   => 60,
			),
			'wp-json'  => array(
				'requests' => 60,
				'period'   => 60,
			),
			'default'  => array(
				'requests' => 60,
				'period'   => 60,
			),
		);
	}

	/**
	 * Get default HTTP method restrictions
	 *
	 * @return array Default method restrictions per endpoint.
	 * @since 1.0.0
	 */
	public function get_default_method_restrictions() {
		return array(
			'wp-login' => array( 'GET', 'POST' ),
			'xmlrpc'   => array( 'POST' ),
			'wp-admin' => array( 'GET', 'POST' ),
			'wp-json'  => array( 'GET', 'POST', 'PUT', 'DELETE', 'PATCH' ),
		);
	}
}
