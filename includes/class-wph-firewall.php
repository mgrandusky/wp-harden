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

		// Check rate limiting
		if ( $settings->get( 'rate_limit_enabled', true ) ) {
			if ( $this->is_rate_limited( $client_ip ) ) {
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
		$request_data = array_merge( $_GET, $_POST );

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
}
