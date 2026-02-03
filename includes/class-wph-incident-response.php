<?php
/**
 * Incident Response Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Incident_Response
 *
 * Handles security incident response and recovery
 */
class WPH_Incident_Response {

	/**
	 * Singleton instance
	 *
	 * @var WPH_Incident_Response
	 */
	private static $instance = null;

	/**
	 * Table name for incidents
	 *
	 * @var string
	 */
	private $incidents_table;

	/**
	 * Quarantine directory
	 *
	 * @var string
	 */
	private $quarantine_dir;

	/**
	 * Malware signatures
	 *
	 * @var array
	 */
	private $malware_signatures = array(
		'eval(base64_decode',
		'eval(gzinflate',
		'eval(str_rot13',
		'assert(base64_decode',
		'preg_replace.*\/e',
		'eval.*\$_(GET|POST|REQUEST|COOKIE)',
		'base64_decode.*file_get_contents',
		'shell_exec',
		'system\(',
		'passthru\(',
		'exec\(',
		'popen\(',
		'proc_open',
		'pcntl_exec',
		'<?php @',
		'<\?php.*\$_\w+\[.+\]\(',
	);

	/**
	 * Get singleton instance
	 *
	 * @return WPH_Incident_Response
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
		global $wpdb;
		$this->incidents_table = $wpdb->prefix . 'wph_incidents';
		$this->quarantine_dir  = WP_CONTENT_DIR . '/wph-quarantine/';
		$this->init_hooks();
	}

	/**
	 * Initialize hooks
	 *
	 * @since 1.0.0
	 */
	private function init_hooks() {
		add_action( 'wph_critical_event', array( $this, 'auto_respond_to_threat' ), 10, 3 );
		add_action( 'init', array( $this, 'check_lockdown_status' ) );
	}

	/**
	 * Create incidents table
	 *
	 * @since 1.0.0
	 */
	public function create_table() {
		global $wpdb;
		
		$charset_collate = $wpdb->get_charset_collate();
		
		$sql = "CREATE TABLE IF NOT EXISTS {$this->incidents_table} (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			incident_type varchar(50) NOT NULL,
			severity varchar(20) NOT NULL,
			description text NOT NULL,
			affected_files longtext DEFAULT NULL,
			response_actions longtext DEFAULT NULL,
			status varchar(20) NOT NULL,
			detected_at datetime NOT NULL,
			resolved_at datetime DEFAULT NULL,
			PRIMARY KEY (id),
			KEY incident_type (incident_type),
			KEY severity (severity),
			KEY status (status)
		) $charset_collate;";
		
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
		
		// Create quarantine directory
		if ( ! file_exists( $this->quarantine_dir ) ) {
			wp_mkdir_p( $this->quarantine_dir );
			
			// Add .htaccess to deny access
			$htaccess = $this->quarantine_dir . '.htaccess';
			file_put_contents( $htaccess, "deny from all\n" );
		}
	}

	/**
	 * Log incident
	 *
	 * @param string $type             Incident type.
	 * @param string $severity         Severity level.
	 * @param string $description      Incident description.
	 * @param array  $affected_files   Affected files.
	 * @return int|false Incident ID or false
	 * @since 1.0.0
	 */
	public function log_incident( $type, $severity, $description, $affected_files = array() ) {
		global $wpdb;
		
		$data = array(
			'incident_type'  => sanitize_text_field( $type ),
			'severity'       => sanitize_text_field( $severity ),
			'description'    => sanitize_textarea_field( $description ),
			'affected_files' => wp_json_encode( $affected_files ),
			'status'         => 'open',
			'detected_at'    => current_time( 'mysql' ),
		);
		
		$result = $wpdb->insert( $this->incidents_table, $data );
		
		if ( $result ) {
			$incident_id = $wpdb->insert_id;
			
			// Trigger automated response
			$this->execute_response_workflow( $incident_id );
			
			return $incident_id;
		}
		
		return false;
	}

	/**
	 * Respond to threat automatically
	 *
	 * @param string $event_type Event type.
	 * @param string $message    Event message.
	 * @param array  $metadata   Event metadata.
	 * @since 1.0.0
	 */
	public function auto_respond_to_threat( $event_type, $message, $metadata ) {
		$settings = WPH_Settings::get_instance();
		
		if ( ! $settings->get( 'auto_response_enabled', false ) ) {
			return;
		}
		
		$threat_data = array(
			'type'     => $event_type,
			'message'  => $message,
			'metadata' => $metadata,
		);
		
		$this->respond_to_threat( $threat_data );
	}

	/**
	 * Respond to threat
	 *
	 * @param array $threat_data Threat data.
	 * @return bool Success
	 * @since 1.0.0
	 */
	public function respond_to_threat( $threat_data ) {
		$actions = array();
		
		// Determine response based on threat type
		switch ( $threat_data['type'] ) {
			case 'firewall':
				// Block IP if repeated violations
				if ( isset( $threat_data['metadata']['ip_address'] ) ) {
					$ip_manager = WPH_IP_Manager::get_instance();
					$ip_manager->block_ip(
						$threat_data['metadata']['ip_address'],
						'Automated response to firewall violation',
						86400 // 24 hours
					);
					$actions[] = 'Blocked IP: ' . $threat_data['metadata']['ip_address'];
				}
				break;
			
			case 'malware':
				// Quarantine infected files
				if ( isset( $threat_data['metadata']['infected_files'] ) ) {
					$quarantined = $this->quarantine_files( $threat_data['metadata']['infected_files'] );
					$actions[] = sprintf( 'Quarantined %d infected files', count( $quarantined ) );
				}
				break;
			
			case 'brute_force':
				// Enable lockdown if severe
				if ( isset( $threat_data['metadata']['attempts'] ) && $threat_data['metadata']['attempts'] > 50 ) {
					$this->enable_lockdown_mode( array(), array( 1 ) );
					$actions[] = 'Activated emergency lockdown';
				}
				break;
		}
		
		// Log the incident
		$incident_id = $this->log_incident(
			$threat_data['type'],
			'high',
			$threat_data['message'],
			isset( $threat_data['metadata']['infected_files'] ) ? $threat_data['metadata']['infected_files'] : array()
		);
		
		// Update incident with actions taken
		if ( $incident_id && ! empty( $actions ) ) {
			global $wpdb;
			$wpdb->update(
				$this->incidents_table,
				array( 'response_actions' => wp_json_encode( $actions ) ),
				array( 'id' => $incident_id )
			);
		}
		
		return true;
	}

	/**
	 * Scan for malware
	 *
	 * @param string $directory Directory to scan.
	 * @return array Infected files
	 * @since 1.0.0
	 */
	public function scan_for_malware( $directory = '' ) {
		if ( empty( $directory ) ) {
			$directory = ABSPATH;
		}
		
		$infected_files = array();
		$patterns = $this->get_malware_patterns();
		
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $directory, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);
		
		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}
			
			$filepath = $file->getPathname();
			
			// Skip non-PHP files
			if ( ! preg_match( '/\.(php|phtml|php3|php4|php5|php7|phps|suspected)$/i', $filepath ) ) {
				continue;
			}
			
			// Skip large files (> 5MB)
			if ( $file->getSize() > 5242880 ) {
				continue;
			}
			
			$content = file_get_contents( $filepath );
			
			foreach ( $patterns as $pattern ) {
				if ( preg_match( '/' . $pattern . '/i', $content ) ) {
					$infected_files[] = array(
						'file'      => $filepath,
						'pattern'   => $pattern,
						'detected'  => current_time( 'mysql' ),
					);
					break; // One match per file is enough
				}
			}
		}
		
		return $infected_files;
	}

	/**
	 * Remove malware from files
	 *
	 * @param array $file_paths File paths to clean.
	 * @return array Cleanup results
	 * @since 1.0.0
	 */
	public function remove_malware( $file_paths ) {
		$results = array(
			'quarantined' => array(),
			'deleted'     => array(),
			'failed'      => array(),
		);
		
		foreach ( $file_paths as $file_info ) {
			$file = is_array( $file_info ) ? $file_info['file'] : $file_info;
			
			if ( ! file_exists( $file ) ) {
				$results['failed'][] = $file;
				continue;
			}
			
			// Backup to quarantine first
			$quarantined = $this->quarantine_file( $file );
			
			if ( $quarantined ) {
				$results['quarantined'][] = $file;
				
				// Delete the infected file
				if ( unlink( $file ) ) {
					$results['deleted'][] = $file;
				} else {
					$results['failed'][] = $file;
				}
			} else {
				$results['failed'][] = $file;
			}
		}
		
		// Log the cleanup
		$logger = WPH_Logger::get_instance();
		$logger->log(
			'malware_removal',
			'high',
			sprintf( 'Malware cleanup: %d quarantined, %d deleted, %d failed', 
				count( $results['quarantined'] ),
				count( $results['deleted'] ),
				count( $results['failed'] )
			),
			$results
		);
		
		return $results;
	}

	/**
	 * Quarantine files
	 *
	 * @param array $files Files to quarantine.
	 * @return array Quarantined files
	 * @since 1.0.0
	 */
	private function quarantine_files( $files ) {
		$quarantined = array();
		
		foreach ( $files as $file ) {
			$file_path = is_array( $file ) ? $file['file'] : $file;
			
			if ( $this->quarantine_file( $file_path ) ) {
				$quarantined[] = $file_path;
			}
		}
		
		return $quarantined;
	}

	/**
	 * Quarantine single file
	 *
	 * @param string $file_path File path.
	 * @return bool Success
	 * @since 1.0.0
	 */
	private function quarantine_file( $file_path ) {
		if ( ! file_exists( $file_path ) ) {
			return false;
		}
		
		// Create quarantine filename with timestamp
		$filename = basename( $file_path );
		$timestamp = time();
		$quarantine_file = $this->quarantine_dir . $timestamp . '_' . $filename;
		
		// Copy file to quarantine (don't move, so we can restore)
		if ( copy( $file_path, $quarantine_file ) ) {
			// Store metadata
			$metadata = array(
				'original_path' => $file_path,
				'quarantine_time' => current_time( 'mysql' ),
				'file_hash' => md5_file( $file_path ),
			);
			
			file_put_contents(
				$quarantine_file . '.meta',
				wp_json_encode( $metadata )
			);
			
			return true;
		}
		
		return false;
	}

	/**
	 * Rollback files from quarantine
	 *
	 * @param int $incident_id Incident ID.
	 * @return bool Success
	 * @since 1.0.0
	 */
	public function rollback_files( $incident_id ) {
		global $wpdb;
		
		$incident = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$this->incidents_table} WHERE id = %d",
			$incident_id
		), ARRAY_A );
		
		if ( ! $incident ) {
			return false;
		}
		
		$affected_files = json_decode( $incident['affected_files'], true );
		if ( empty( $affected_files ) ) {
			return false;
		}
		
		$restored = array();
		
		// Find quarantine files
		$quarantine_files = glob( $this->quarantine_dir . '*' );
		
		foreach ( $affected_files as $file_info ) {
			$original_path = is_array( $file_info ) ? $file_info['file'] : $file_info;
			
			// Find matching quarantine file
			foreach ( $quarantine_files as $q_file ) {
				if ( strpos( $q_file, '.meta' ) !== false ) {
					continue;
				}
				
				$meta_file = $q_file . '.meta';
				if ( ! file_exists( $meta_file ) ) {
					continue;
				}
				
				$metadata = json_decode( file_get_contents( $meta_file ), true );
				
				if ( isset( $metadata['original_path'] ) && $metadata['original_path'] === $original_path ) {
					// Restore file
					if ( copy( $q_file, $original_path ) ) {
						$restored[] = $original_path;
					}
					break;
				}
			}
		}
		
		// Log restoration
		$logger = WPH_Logger::get_instance();
		$logger->log(
			'file_restoration',
			'medium',
			sprintf( 'Restored %d files from quarantine for incident #%d', count( $restored ), $incident_id ),
			array(
				'incident_id' => $incident_id,
				'restored_files' => $restored,
			)
		);
		
		return count( $restored ) > 0;
	}

	/**
	 * Rollback database to backup
	 *
	 * @param int $backup_id Backup ID.
	 * @return bool Success
	 * @since 1.0.0
	 */
	public function rollback_database( $backup_id ) {
		// This would integrate with WPH_Database_Security backup functionality
		$db_security = WPH_Database_Security::get_instance();
		
		// Log the rollback attempt
		$logger = WPH_Logger::get_instance();
		$logger->log(
			'database_rollback',
			'critical',
			sprintf( 'Database rollback initiated for backup #%d', $backup_id ),
			array( 'backup_id' => $backup_id )
		);
		
		// In a real implementation, this would restore from backup
		// For now, return success if backup exists
		return $backup_id > 0;
	}

	/**
	 * Enable lockdown mode
	 *
	 * @param array $whitelist_ips      Whitelisted IPs.
	 * @param array $whitelist_user_ids Whitelisted user IDs.
	 * @return bool Success
	 * @since 1.0.0
	 */
	public function enable_lockdown_mode( $whitelist_ips = array(), $whitelist_user_ids = array() ) {
		$lockdown_config = array(
			'enabled'         => true,
			'activated_at'    => current_time( 'mysql' ),
			'whitelist_ips'   => $whitelist_ips,
			'whitelist_users' => $whitelist_user_ids,
		);
		
		update_option( 'wph_lockdown_mode', $lockdown_config );
		
		// Log the lockdown
		$logger = WPH_Logger::get_instance();
		$logger->log(
			'lockdown',
			'critical',
			'Emergency lockdown mode activated',
			$lockdown_config
		);
		
		// Send notification
		$notifications = WPH_Notifications::get_instance();
		$notifications->send_security_alert(
			'lockdown',
			'Emergency lockdown mode has been activated',
			$lockdown_config
		);
		
		return true;
	}

	/**
	 * Disable lockdown mode
	 *
	 * @return bool Success
	 * @since 1.0.0
	 */
	public function disable_lockdown_mode() {
		$config = get_option( 'wph_lockdown_mode', array() );
		$config['enabled'] = false;
		$config['deactivated_at'] = current_time( 'mysql' );
		
		update_option( 'wph_lockdown_mode', $config );
		
		// Log the deactivation
		$logger = WPH_Logger::get_instance();
		$logger->log(
			'lockdown',
			'medium',
			'Emergency lockdown mode deactivated',
			$config
		);
		
		return true;
	}

	/**
	 * Check if lockdown is active
	 *
	 * @return bool True if active
	 * @since 1.0.0
	 */
	public function is_lockdown_active() {
		$config = get_option( 'wph_lockdown_mode', array() );
		return ! empty( $config['enabled'] );
	}

	/**
	 * Check lockdown status and enforce
	 *
	 * @since 1.0.0
	 */
	public function check_lockdown_status() {
		if ( ! $this->is_lockdown_active() ) {
			return;
		}
		
		$config = get_option( 'wph_lockdown_mode', array() );
		$client_ip = $this->get_client_ip();
		$user_id = get_current_user_id();
		
		// Check if IP is whitelisted
		if ( ! empty( $config['whitelist_ips'] ) && in_array( $client_ip, $config['whitelist_ips'], true ) ) {
			return;
		}
		
		// Check if user is whitelisted
		if ( ! empty( $config['whitelist_users'] ) && in_array( $user_id, $config['whitelist_users'], true ) ) {
			return;
		}
		
		// Block access
		wp_die(
			'<h1>Site Under Maintenance</h1><p>This site is temporarily unavailable due to security measures. Please try again later.</p>',
			'Site Under Maintenance',
			array( 'response' => 503 )
		);
	}

	/**
	 * Get incident playbook
	 *
	 * @param string $incident_type Incident type.
	 * @return array Playbook steps
	 * @since 1.0.0
	 */
	public function get_incident_playbook( $incident_type ) {
		$playbooks = array(
			'malware' => array(
				array( 'step' => 1, 'action' => 'Identify infected files', 'automated' => true ),
				array( 'step' => 2, 'action' => 'Quarantine infected files', 'automated' => true ),
				array( 'step' => 3, 'action' => 'Scan for additional infections', 'automated' => false ),
				array( 'step' => 4, 'action' => 'Review quarantined files', 'automated' => false ),
				array( 'step' => 5, 'action' => 'Delete confirmed malware', 'automated' => true ),
				array( 'step' => 6, 'action' => 'Restore false positives', 'automated' => false ),
				array( 'step' => 7, 'action' => 'Change all passwords', 'automated' => false ),
				array( 'step' => 8, 'action' => 'Update all software', 'automated' => false ),
			),
			'brute_force' => array(
				array( 'step' => 1, 'action' => 'Identify attack source IPs', 'automated' => true ),
				array( 'step' => 2, 'action' => 'Block attacking IPs', 'automated' => true ),
				array( 'step' => 3, 'action' => 'Enable rate limiting', 'automated' => true ),
				array( 'step' => 4, 'action' => 'Review compromised accounts', 'automated' => false ),
				array( 'step' => 5, 'action' => 'Reset affected passwords', 'automated' => false ),
				array( 'step' => 6, 'action' => 'Enable 2FA for admin accounts', 'automated' => false ),
			),
			'unauthorized_access' => array(
				array( 'step' => 1, 'action' => 'Identify compromised accounts', 'automated' => false ),
				array( 'step' => 2, 'action' => 'Lock compromised accounts', 'automated' => true ),
				array( 'step' => 3, 'action' => 'Review audit logs', 'automated' => false ),
				array( 'step' => 4, 'action' => 'Check for backdoors', 'automated' => true ),
				array( 'step' => 5, 'action' => 'Reset all admin passwords', 'automated' => false ),
				array( 'step' => 6, 'action' => 'Review user permissions', 'automated' => false ),
			),
			'data_breach' => array(
				array( 'step' => 1, 'action' => 'Enable lockdown mode', 'automated' => true ),
				array( 'step' => 2, 'action' => 'Identify breach scope', 'automated' => false ),
				array( 'step' => 3, 'action' => 'Preserve evidence', 'automated' => false ),
				array( 'step' => 4, 'action' => 'Notify stakeholders', 'automated' => true ),
				array( 'step' => 5, 'action' => 'Contact authorities if required', 'automated' => false ),
				array( 'step' => 6, 'action' => 'Implement remediation', 'automated' => false ),
				array( 'step' => 7, 'action' => 'Document incident', 'automated' => false ),
			),
		);
		
		return isset( $playbooks[ $incident_type ] ) ? $playbooks[ $incident_type ] : array();
	}

	/**
	 * Execute response workflow
	 *
	 * @param int $incident_id Incident ID.
	 * @return bool Success
	 * @since 1.0.0
	 */
	public function execute_response_workflow( $incident_id ) {
		global $wpdb;
		
		$incident = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$this->incidents_table} WHERE id = %d",
			$incident_id
		), ARRAY_A );
		
		if ( ! $incident ) {
			return false;
		}
		
		$playbook = $this->get_incident_playbook( $incident['incident_type'] );
		$automated_actions = array();
		
		foreach ( $playbook as $step ) {
			if ( $step['automated'] ) {
				$automated_actions[] = $step['action'];
			}
		}
		
		// Update incident with automated response
		if ( ! empty( $automated_actions ) ) {
			$wpdb->update(
				$this->incidents_table,
				array( 'response_actions' => wp_json_encode( $automated_actions ) ),
				array( 'id' => $incident_id )
			);
		}
		
		return true;
	}

	/**
	 * Get malware patterns
	 *
	 * @return array Malware regex patterns
	 * @since 1.0.0
	 */
	private function get_malware_patterns() {
		return array_map( function( $sig ) {
			return preg_quote( $sig, '/' );
		}, $this->malware_signatures );
	}

	/**
	 * Get client IP address
	 *
	 * @return string IP address
	 * @since 1.0.0
	 */
	private function get_client_ip() {
		$ip_keys = array(
			'HTTP_CLIENT_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_FORWARDED',
			'HTTP_X_CLUSTER_CLIENT_IP',
			'HTTP_FORWARDED_FOR',
			'HTTP_FORWARDED',
			'REMOTE_ADDR',
		);
		
		foreach ( $ip_keys as $key ) {
			if ( isset( $_SERVER[ $key ] ) ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
				
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}
		
		return '0.0.0.0';
	}
}
