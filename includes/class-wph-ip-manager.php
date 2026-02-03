<?php
/**
 * IP Management Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_IP_Manager
 *
 * Manages IP blocking, whitelisting, and blacklisting
 */
class WPH_IP_Manager {

	/**
	 * Singleton instance
	 *
	 * @var WPH_IP_Manager
	 */
	private static $instance = null;

	/**
	 * Get singleton instance
	 *
	 * @return WPH_IP_Manager
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
		add_action( 'wph_cleanup_expired_blocks', array( $this, 'cleanup_expired_blocks' ) );
	}

	/**
	 * Check if an IP is blocked
	 *
	 * @param string $ip_address IP address to check.
	 * @return bool
	 * @since 1.0.0
	 */
	public function is_blocked( $ip_address ) {
		// Check if IP is in whitelist
		if ( $this->is_whitelisted( $ip_address ) ) {
			return false;
		}

		// Check if IP is in permanent blacklist
		if ( $this->is_blacklisted( $ip_address ) ) {
			return true;
		}

		// Check database for active blocks
		global $wpdb;
		$table = $wpdb->prefix . 'wph_blocked_ips';

		$result = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM $table 
				WHERE ip_address = %s 
				AND is_active = 1 
				AND (expires_at IS NULL OR expires_at > NOW())",
				$ip_address
			)
		);

		return ! empty( $result );
	}

	/**
	 * Check if an IP is whitelisted
	 *
	 * @param string $ip_address IP address to check.
	 * @return bool
	 * @since 1.0.0
	 */
	public function is_whitelisted( $ip_address ) {
		$settings  = WPH_Settings::get_instance();
		$whitelist = $settings->get( 'ip_whitelist', array() );

		foreach ( $whitelist as $whitelisted_ip ) {
			if ( $this->ip_matches( $ip_address, $whitelisted_ip ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if an IP is blacklisted
	 *
	 * @param string $ip_address IP address to check.
	 * @return bool
	 * @since 1.0.0
	 */
	public function is_blacklisted( $ip_address ) {
		$settings  = WPH_Settings::get_instance();
		$blacklist = $settings->get( 'ip_blacklist', array() );

		foreach ( $blacklist as $blacklisted_ip ) {
			if ( $this->ip_matches( $ip_address, $blacklisted_ip ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Block an IP address
	 *
	 * @param string $ip_address IP address to block.
	 * @param string $reason     Reason for blocking.
	 * @param string $block_type Block type (temporary or permanent).
	 * @param int    $duration   Duration in seconds (for temporary blocks).
	 * @return bool
	 * @since 1.0.0
	 */
	public function block_ip( $ip_address, $reason, $block_type = 'temporary', $duration = 3600 ) {
		global $wpdb;

		$table = $wpdb->prefix . 'wph_blocked_ips';

		// Check if IP already blocked
		$existing = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM $table WHERE ip_address = %s AND is_active = 1",
				$ip_address
			)
		);

		$expires_at = null;
		if ( 'temporary' === $block_type && $duration > 0 ) {
			$expires_at = gmdate( 'Y-m-d H:i:s', time() + $duration );
		}

		if ( $existing ) {
			// Update existing block
			return $wpdb->update(
				$table,
				array(
					'block_type' => $block_type,
					'reason'     => $reason,
					'expires_at' => $expires_at,
					'is_active'  => 1,
				),
				array( 'id' => $existing->id )
			);
		}

		// Insert new block
		return $wpdb->insert(
			$table,
			array(
				'ip_address' => $ip_address,
				'block_type' => $block_type,
				'reason'     => $reason,
				'blocked_at' => current_time( 'mysql' ),
				'expires_at' => $expires_at,
				'is_active'  => 1,
			)
		);
	}

	/**
	 * Unblock an IP address
	 *
	 * @param string $ip_address IP address to unblock.
	 * @return bool
	 * @since 1.0.0
	 */
	public function unblock_ip( $ip_address ) {
		global $wpdb;

		$table = $wpdb->prefix . 'wph_blocked_ips';

		return $wpdb->update(
			$table,
			array(
				'is_active'    => 0,
				'unblocked_at' => current_time( 'mysql' ),
			),
			array(
				'ip_address' => $ip_address,
				'is_active'  => 1,
			)
		);
	}

	/**
	 * Get blocked IPs
	 *
	 * @param array $args Query arguments.
	 * @return array
	 * @since 1.0.0
	 */
	public function get_blocked_ips( $args = array() ) {
		global $wpdb;

		$defaults = array(
			'is_active' => 1,
			'limit'     => 100,
			'offset'    => 0,
		);

		$args = wp_parse_args( $args, $defaults );

		$table = $wpdb->prefix . 'wph_blocked_ips';
		$where = array();

		if ( isset( $args['is_active'] ) ) {
			$where[] = $wpdb->prepare( 'is_active = %d', $args['is_active'] );
		}

		$where_clause = ! empty( $where ) ? 'WHERE ' . implode( ' AND ', $where ) : '';
		$limit        = absint( $args['limit'] );
		$offset       = absint( $args['offset'] );

		$query = "SELECT * FROM $table $where_clause ORDER BY blocked_at DESC LIMIT $limit OFFSET $offset";

		return $wpdb->get_results( $query );
	}

	/**
	 * Clean up expired blocks
	 *
	 * @since 1.0.0
	 */
	public function cleanup_expired_blocks() {
		global $wpdb;

		$table = $wpdb->prefix . 'wph_blocked_ips';

		$wpdb->query(
			"UPDATE $table 
			SET is_active = 0, unblocked_at = NOW() 
			WHERE is_active = 1 
			AND expires_at IS NOT NULL 
			AND expires_at < NOW()"
		);
	}

	/**
	 * Check if IP matches a pattern (supports CIDR notation)
	 *
	 * @param string $ip      IP address to check.
	 * @param string $pattern Pattern to match against.
	 * @return bool
	 * @since 1.0.0
	 */
	private function ip_matches( $ip, $pattern ) {
		// Exact match
		if ( $ip === $pattern ) {
			return true;
		}

		// CIDR notation support
		if ( strpos( $pattern, '/' ) !== false ) {
			list( $subnet, $mask ) = explode( '/', $pattern );

			$ip_long     = ip2long( $ip );
			$subnet_long = ip2long( $subnet );

			if ( false === $ip_long || false === $subnet_long ) {
				return false;
			}

			$mask_long = -1 << ( 32 - (int) $mask );
			$subnet_long &= $mask_long;

			return ( $ip_long & $mask_long ) === $subnet_long;
		}

		return false;
	}

	/**
	 * Get client IP address
	 *
	 * @return string
	 * @since 1.0.0
	 */
	public function get_client_ip() {
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
