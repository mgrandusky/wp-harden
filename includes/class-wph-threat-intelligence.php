<?php
/**
 * Threat Intelligence Module
 *
 * Provides enterprise-grade threat intelligence features including IP reputation checking,
 * bot detection, proxy/VPN detection, and threat scoring.
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class WPH_Threat_Intelligence
 *
 * Handles threat intelligence operations including IP reputation checks,
 * bot detection, and threat scoring with caching.
 */
class WPH_Threat_Intelligence {

    /**
     * Singleton instance
     *
     * @var WPH_Threat_Intelligence|null
     */
    private static $instance = null;

    /**
     * Settings instance
     *
     * @var WPH_Settings
     */
    private $settings;

    /**
     * Logger instance
     *
     * @var WPH_Logger
     */
    private $logger;

    /**
     * IP Manager instance
     *
     * @var WPH_IP_Manager
     */
    private $ip_manager;

    /**
     * Database table name
     *
     * @var string
     */
    private $table_name;

    /**
     * Known malicious user agent patterns
     *
     * @var array
     */
    private $malicious_patterns = array(
        'sqlmap',
        'nikto',
        'nmap',
        'masscan',
        'nessus',
        'openvas',
        'acunetix',
        'netsparker',
        'metasploit',
        'burpsuite',
        'w3af',
        'dirbuster',
        'havij',
        'pangolin',
        'zmeu',
        'morfeus',
        'toata',
        'scanner',
        'exploit',
        'grabber',
        'libwww-perl',
        'python-requests',
        'curl/7',
        'wget',
    );

    /**
     * Known good bot patterns (whitelist)
     *
     * @var array
     */
    private $whitelisted_bots = array(
        'googlebot',
        'bingbot',
        'slurp',
        'duckduckbot',
        'baiduspider',
        'yandexbot',
        'facebookexternalhit',
        'twitterbot',
        'linkedinbot',
        'applebot',
    );

    /**
     * Tor exit nodes cache key
     *
     * @var string
     */
    private $tor_cache_key = 'wph_tor_exit_nodes';

    /**
     * Get singleton instance
     *
     * @return WPH_Threat_Intelligence
     */
    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'wph_threat_intelligence';

        // Initialize dependencies
        if ( class_exists( 'WPH_Settings' ) ) {
            $this->settings = WPH_Settings::get_instance();
        }
        if ( class_exists( 'WPH_Logger' ) ) {
            $this->logger = WPH_Logger::get_instance();
        }
        if ( class_exists( 'WPH_IP_Manager' ) ) {
            $this->ip_manager = WPH_IP_Manager::get_instance();
        }

        $this->init_hooks();
    }

    /**
     * Initialize WordPress hooks
     */
    private function init_hooks() {
        // Schedule cache cleanup
        if ( ! wp_next_scheduled( 'wph_threat_intel_cleanup' ) ) {
            wp_schedule_event( time(), 'daily', 'wph_threat_intel_cleanup' );
        }
        add_action( 'wph_threat_intel_cleanup', array( $this, 'cleanup_expired_cache' ) );
    }

    /**
     * Create database table
     *
     * @return bool True on success, false on failure
     */
    public function create_table() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            threat_type varchar(50) NOT NULL,
            threat_score int(11) NOT NULL DEFAULT 0,
            threat_data longtext DEFAULT NULL,
            checked_at datetime NOT NULL,
            expires_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY ip_threat_type (ip_address, threat_type),
            KEY expires_at (expires_at)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );

        return true;
    }

    /**
     * Check if threat intelligence is enabled
     *
     * @return bool
     */
    private function is_enabled() {
        if ( ! $this->settings ) {
            return false;
        }
        return (bool) $this->settings->get_setting( 'threat_intel_enabled', false );
    }

    /**
     * Check if IP is whitelisted
     *
     * @param string $ip_address IP address to check
     * @return bool True if whitelisted, false otherwise
     */
    public function is_whitelisted( $ip_address ) {
        // Check if it's an admin IP
        if ( is_user_logged_in() && current_user_can( 'manage_options' ) ) {
            $current_ip = $this->get_client_ip();
            if ( $current_ip === $ip_address ) {
                return true;
            }
        }

        // Check whitelist via IP Manager
        if ( $this->ip_manager ) {
            return $this->ip_manager->is_whitelisted( $ip_address );
        }

        return false;
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    private function get_client_ip() {
        $ip = '';
        if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        } elseif ( isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
            $ip = explode( ',', $ip )[0];
        } elseif ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }
        return trim( $ip );
    }

    /**
     * Check IP reputation against AbuseIPDB
     *
     * @param string $ip_address IP address to check
     * @return int Reputation score 0-100 (0 = clean, 100 = malicious)
     */
    public function check_ip_reputation( $ip_address ) {
        if ( ! $this->is_enabled() ) {
            return 0;
        }

        // Validate IP address
        if ( ! filter_var( $ip_address, FILTER_VALIDATE_IP ) ) {
            return 0;
        }

        // Check whitelist
        if ( $this->is_whitelisted( $ip_address ) ) {
            return 0;
        }

        // Check cache first
        $cached = $this->get_cached_threat_data( $ip_address, 'ip_reputation' );
        if ( false !== $cached ) {
            return (int) $cached['threat_score'];
        }

        // Get API key
        $api_key = $this->settings ? $this->settings->get_setting( 'threat_intel_abuseipdb_key', '' ) : '';
        if ( empty( $api_key ) ) {
            return 0;
        }

        // Call AbuseIPDB API
        $score = 0;
        $url   = add_query_arg(
            array(
                'ipAddress'    => $ip_address,
                'maxAgeInDays' => 90,
            ),
            'https://api.abuseipdb.com/api/v2/check'
        );

        $response = wp_remote_get(
            $url,
            array(
                'headers' => array(
                    'Key'    => $api_key,
                    'Accept' => 'application/json',
                ),
                'timeout' => 10,
            )
        );

        if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
            $body = wp_remote_retrieve_body( $response );
            $data = json_decode( $body, true );

            if ( isset( $data['data']['abuseConfidenceScore'] ) ) {
                $score = (int) $data['data']['abuseConfidenceScore'];
                // Cache the result
                $this->cache_threat_data( $ip_address, 'ip_reputation', $score, $data );
            }
        } else {
            // Log error
            if ( $this->logger ) {
                $error = is_wp_error( $response ) ? $response->get_error_message() : 'API request failed';
                $this->logger->log( 'threat_intel', "AbuseIPDB API error: {$error}", 'warning' );
            }
        }

        return $score;
    }

    /**
     * Detect if request is from a malicious bot
     *
     * @param string $user_agent   User agent string
     * @param array  $behavior_data Behavioral data (request rate, patterns, etc.)
     * @return bool True if malicious bot detected, false otherwise
     */
    public function detect_bot( $user_agent, $behavior_data = array() ) {
        if ( ! $this->is_enabled() ) {
            return false;
        }

        $user_agent = strtolower( $user_agent );

        // Check if it's a whitelisted bot
        foreach ( $this->whitelisted_bots as $bot ) {
            if ( false !== strpos( $user_agent, $bot ) ) {
                return false;
            }
        }

        // Check malicious patterns
        if ( $this->is_suspicious_user_agent( $user_agent ) ) {
            return true;
        }

        // Behavioral analysis
        if ( ! empty( $behavior_data ) ) {
            // Check request rate
            if ( isset( $behavior_data['request_rate'] ) && $behavior_data['request_rate'] > 10 ) {
                return true;
            }

            // Check for suspicious patterns
            if ( isset( $behavior_data['suspicious_paths'] ) && $behavior_data['suspicious_paths'] > 5 ) {
                return true;
            }

            // No referrer and empty user agent
            if ( empty( $user_agent ) && isset( $behavior_data['no_referrer'] ) && $behavior_data['no_referrer'] ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user agent is suspicious
     *
     * @param string $user_agent User agent string
     * @return bool True if suspicious, false otherwise
     */
    public function is_suspicious_user_agent( $user_agent ) {
        if ( empty( $user_agent ) ) {
            return true;
        }

        $user_agent = strtolower( $user_agent );

        // Check against known malicious patterns
        foreach ( $this->malicious_patterns as $pattern ) {
            if ( false !== strpos( $user_agent, $pattern ) ) {
                return true;
            }
        }

        // Check for common attack tool patterns
        if ( preg_match( '/^(python|ruby|perl|java)\//i', $user_agent ) ) {
            return true;
        }

        return false;
    }

    /**
     * Check if IP is a Tor exit node, VPN, or proxy
     *
     * @param string $ip_address IP address to check
     * @return array Details about proxy/VPN status
     */
    public function is_proxy_or_vpn( $ip_address ) {
        if ( ! $this->is_enabled() ) {
            return array(
                'is_proxy' => false,
                'type'     => '',
                'details'  => array(),
            );
        }

        // Validate IP address
        if ( ! filter_var( $ip_address, FILTER_VALIDATE_IP ) ) {
            return array(
                'is_proxy' => false,
                'type'     => '',
                'details'  => array(),
            );
        }

        // Check whitelist
        if ( $this->is_whitelisted( $ip_address ) ) {
            return array(
                'is_proxy' => false,
                'type'     => '',
                'details'  => array(),
            );
        }

        // Check cache first
        $cached = $this->get_cached_threat_data( $ip_address, 'proxy_vpn' );
        if ( false !== $cached ) {
            return json_decode( $cached['threat_data'], true );
        }

        $result = array(
            'is_proxy' => false,
            'type'     => '',
            'details'  => array(),
        );

        // Check Tor exit nodes
        if ( $this->settings && $this->settings->get_setting( 'threat_intel_check_tor', true ) ) {
            if ( $this->is_tor_exit_node( $ip_address ) ) {
                $result['is_proxy'] = true;
                $result['type']     = 'tor';
                $result['details']  = array( 'source' => 'tor_exit_list' );
                $this->cache_threat_data( $ip_address, 'proxy_vpn', 100, $result );
                return $result;
            }
        }

        // Check ProxyCheck.io API
        if ( $this->settings && $this->settings->get_setting( 'threat_intel_check_proxies', true ) ) {
            $api_key = $this->settings->get_setting( 'threat_intel_proxycheck_key', '' );
            if ( ! empty( $api_key ) ) {
                $url      = "http://proxycheck.io/v2/{$ip_address}?key={$api_key}&vpn=1&asn=1";
                $response = wp_remote_get( $url, array( 'timeout' => 10 ) );

                if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
                    $body = wp_remote_retrieve_body( $response );
                    $data = json_decode( $body, true );

                    if ( isset( $data[ $ip_address ] ) ) {
                        $ip_data = $data[ $ip_address ];
                        if ( isset( $ip_data['proxy'] ) && 'yes' === $ip_data['proxy'] ) {
                            $result['is_proxy'] = true;
                            $result['type']     = isset( $ip_data['type'] ) ? $ip_data['type'] : 'unknown';
                            $result['details']  = $ip_data;
                        }
                    }
                }
            }
        }

        // Cache the result
        $score = $result['is_proxy'] ? 100 : 0;
        $this->cache_threat_data( $ip_address, 'proxy_vpn', $score, $result );

        return $result;
    }

    /**
     * Check if IP is a Tor exit node
     *
     * @param string $ip_address IP address to check
     * @return bool True if Tor exit node, false otherwise
     */
    private function is_tor_exit_node( $ip_address ) {
        $tor_nodes = $this->get_tor_exit_nodes();
        return in_array( $ip_address, $tor_nodes, true );
    }

    /**
     * Get list of Tor exit nodes
     *
     * @return array Array of Tor exit node IP addresses
     */
    public function get_tor_exit_nodes() {
        // Check cache
        $cached = get_transient( $this->tor_cache_key );
        if ( false !== $cached && is_array( $cached ) ) {
            return $cached;
        }

        // Fetch Tor exit node list
        $tor_nodes = array();
        $url       = 'https://check.torproject.org/torbulkexitlist';
        $response  = wp_remote_get( $url, array( 'timeout' => 15 ) );

        if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
            $body      = wp_remote_retrieve_body( $response );
            $tor_nodes = array_filter( explode( "\n", $body ) );
            $tor_nodes = array_map( 'trim', $tor_nodes );

            // Cache for 6 hours
            set_transient( $this->tor_cache_key, $tor_nodes, 6 * HOUR_IN_SECONDS );
        }

        return $tor_nodes;
    }

    /**
     * Calculate overall threat score
     *
     * @param string $ip_address IP address to check
     * @param string $user_agent User agent string
     * @return int Threat score 0-100
     */
    public function calculate_threat_score( $ip_address, $user_agent ) {
        if ( ! $this->is_enabled() ) {
            return 0;
        }

        // Check whitelist
        if ( $this->is_whitelisted( $ip_address ) ) {
            return 0;
        }

        $scores = array();

        // IP reputation (40% weight)
        $ip_score       = $this->check_ip_reputation( $ip_address );
        $scores['ip']   = $ip_score * 0.4;

        // Bot detection (30% weight)
        $is_bot         = $this->detect_bot( $user_agent );
        $scores['bot']  = $is_bot ? 30 : 0;

        // Proxy/VPN detection (30% weight)
        $proxy_data      = $this->is_proxy_or_vpn( $ip_address );
        $scores['proxy'] = $proxy_data['is_proxy'] ? 30 : 0;

        // Calculate total score
        $total_score = array_sum( $scores );

        // Log if score is high
        if ( $this->logger && $total_score >= 50 ) {
            $this->logger->log(
                'threat_intel',
                sprintf(
                    'High threat score detected: %d for IP: %s (IP: %d, Bot: %s, Proxy: %s)',
                    $total_score,
                    $ip_address,
                    $ip_score,
                    $is_bot ? 'yes' : 'no',
                    $proxy_data['is_proxy'] ? 'yes' : 'no'
                ),
                'warning'
            );
        }

        // Handle threat if auto-blocking is enabled
        $this->handle_threat( $ip_address, $total_score );

        return (int) $total_score;
    }

    /**
     * Handle detected threat
     *
     * @param string $ip_address   IP address
     * @param int    $threat_score Threat score
     */
    public function handle_threat( $ip_address, $threat_score ) {
        if ( ! $this->is_enabled() || ! $this->settings ) {
            return;
        }

        // Check if auto-blocking is enabled
        $auto_block = $this->settings->get_setting( 'threat_intel_auto_block', false );
        if ( ! $auto_block ) {
            return;
        }

        // Get blocking threshold
        $threshold = (int) $this->settings->get_setting( 'threat_intel_block_threshold', 70 );

        // Block if score exceeds threshold
        if ( $threat_score >= $threshold && $this->ip_manager ) {
            $this->ip_manager->block_ip( $ip_address, 'Threat intelligence auto-block (score: ' . $threat_score . ')' );

            // Log the action
            if ( $this->logger ) {
                $this->logger->log(
                    'threat_intel',
                    sprintf( 'Auto-blocked IP %s with threat score %d', $ip_address, $threat_score ),
                    'critical'
                );
            }

            // Send email notification if configured
            $this->send_threat_notification( $ip_address, $threat_score );
        }
    }

    /**
     * Send email notification for critical threat
     *
     * @param string $ip_address   IP address
     * @param int    $threat_score Threat score
     */
    private function send_threat_notification( $ip_address, $threat_score ) {
        $admin_email = get_option( 'admin_email' );
        $subject     = sprintf( '[%s] Critical Threat Detected', get_bloginfo( 'name' ) );
        $message     = sprintf(
            "A critical threat has been detected and blocked:\n\nIP Address: %s\nThreat Score: %d\nTime: %s\n\nThe IP has been automatically blocked.",
            $ip_address,
            $threat_score,
            current_time( 'mysql' )
        );

        wp_mail( $admin_email, $subject, $message );
    }

    /**
     * Cache threat data
     *
     * @param string $ip_address   IP address
     * @param string $threat_type  Type of threat data
     * @param int    $threat_score Threat score
     * @param mixed  $threat_data  Additional threat data
     * @return bool True on success, false on failure
     */
    public function cache_threat_data( $ip_address, $threat_type, $threat_score, $threat_data ) {
        global $wpdb;

        // Get cache TTL
        $ttl_hours = $this->settings ? (int) $this->settings->get_setting( 'threat_intel_cache_ttl', 24 ) : 24;
        $ttl       = $ttl_hours * HOUR_IN_SECONDS;

        $data = array(
            'ip_address'   => $ip_address,
            'threat_type'  => $threat_type,
            'threat_score' => $threat_score,
            'threat_data'  => is_array( $threat_data ) ? wp_json_encode( $threat_data ) : $threat_data,
            'checked_at'   => current_time( 'mysql' ),
            'expires_at'   => gmdate( 'Y-m-d H:i:s', time() + $ttl ),
        );

        // Insert or update
        $existing = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT id FROM {$this->table_name} WHERE ip_address = %s AND threat_type = %s",
                $ip_address,
                $threat_type
            )
        );

        if ( $existing ) {
            return (bool) $wpdb->update(
                $this->table_name,
                $data,
                array(
                    'ip_address'  => $ip_address,
                    'threat_type' => $threat_type,
                ),
                array( '%s', '%s', '%d', '%s', '%s', '%s' ),
                array( '%s', '%s' )
            );
        } else {
            return (bool) $wpdb->insert(
                $this->table_name,
                $data,
                array( '%s', '%s', '%d', '%s', '%s', '%s' )
            );
        }
    }

    /**
     * Get cached threat data
     *
     * @param string $ip_address  IP address
     * @param string $threat_type Type of threat data
     * @return array|false Cached data or false if not found/expired
     */
    public function get_cached_threat_data( $ip_address, $threat_type ) {
        global $wpdb;

        $result = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table_name} 
                WHERE ip_address = %s 
                AND threat_type = %s 
                AND expires_at > %s",
                $ip_address,
                $threat_type,
                current_time( 'mysql' )
            ),
            ARRAY_A
        );

        return $result ? $result : false;
    }

    /**
     * Clean up expired cache entries
     *
     * @return int Number of deleted entries
     */
    public function cleanup_expired_cache() {
        global $wpdb;

        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$this->table_name} WHERE expires_at < %s",
                current_time( 'mysql' )
            )
        );

        // Log cleanup
        if ( $this->logger && $deleted > 0 ) {
            $this->logger->log(
                'threat_intel',
                sprintf( 'Cleaned up %d expired threat intelligence cache entries', $deleted ),
                'info'
            );
        }

        return (int) $deleted;
    }

    /**
     * Get threat statistics
     *
     * @return array Statistics data
     */
    public function get_statistics() {
        global $wpdb;

        $stats = array();

        // Total cached entries
        $stats['total_entries'] = $wpdb->get_var( "SELECT COUNT(*) FROM {$this->table_name}" );

        // High threat IPs (score >= 70)
        $stats['high_threat_ips'] = $wpdb->get_var(
            "SELECT COUNT(DISTINCT ip_address) FROM {$this->table_name} WHERE threat_score >= 70"
        );

        // Entries by type
        $by_type = $wpdb->get_results(
            "SELECT threat_type, COUNT(*) as count FROM {$this->table_name} GROUP BY threat_type",
            ARRAY_A
        );
        $stats['by_type'] = $by_type;

        // Recent threats (last 24 hours)
        $stats['recent_threats'] = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table_name} 
                WHERE checked_at > %s AND threat_score >= 50",
                gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS )
            )
        );

        return $stats;
    }

    /**
     * Clear all cached threat data
     *
     * @return bool True on success, false on failure
     */
    public function clear_cache() {
        global $wpdb;
        return (bool) $wpdb->query( "TRUNCATE TABLE {$this->table_name}" );
    }
}
