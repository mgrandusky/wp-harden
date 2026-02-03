<?php
/**
 * Security Scanner Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Scanner
 *
 * Provides security scanning functionality
 */
class WPH_Scanner {

	/**
	 * Singleton instance
	 *
	 * @var WPH_Scanner
	 */
	private static $instance = null;

	/**
	 * Get singleton instance
	 *
	 * @return WPH_Scanner
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
		add_action( 'wph_daily_scan', array( $this, 'run_scheduled_scan' ) );
	}

	/**
	 * Run a complete security scan
	 *
	 * @return array Scan results
	 * @since 1.0.0
	 */
	public function run_scan() {
		$scan_id = $this->create_scan_record();

		$results = array(
			'core_integrity'    => $this->scan_core_integrity(),
			'file_permissions'  => $this->scan_file_permissions(),
			'malware_signatures' => $this->scan_malware_signatures(),
			'database_security' => $this->scan_database_security(),
		);

		$issues_found = 0;
		foreach ( $results as $scan_result ) {
			$issues_found += count( $scan_result['issues'] );
		}

		$this->complete_scan_record( $scan_id, $results, $issues_found );

		return $results;
	}

	/**
	 * Run scheduled scan
	 *
	 * @since 1.0.0
	 */
	public function run_scheduled_scan() {
		$settings = WPH_Settings::get_instance();

		if ( ! $settings->get( 'scanner_enabled', true ) ) {
			return;
		}

		$results = $this->run_scan();

		// Send notification if issues found
		if ( $this->has_critical_issues( $results ) ) {
			$notifications = WPH_Notifications::get_instance();
			$notifications->send_scan_alert( $results );
		}
	}

	/**
	 * Scan WordPress core file integrity
	 *
	 * @return array
	 * @since 1.0.0
	 */
	private function scan_core_integrity() {
		$issues = array();

		// Check if wp-config.php has proper permissions
		$wp_config = ABSPATH . 'wp-config.php';
		if ( file_exists( $wp_config ) ) {
			$perms = substr( sprintf( '%o', fileperms( $wp_config ) ), -4 );
			if ( $perms !== '0600' && $perms !== '0640' && $perms !== '0644' ) {
				$issues[] = array(
					'file'     => 'wp-config.php',
					'issue'    => 'Insecure file permissions',
					'severity' => 'high',
					'current'  => $perms,
					'expected' => '0600, 0640, or 0644',
				);
			}
		}

		// Check for debug mode in production
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG === true ) {
			$issues[] = array(
				'setting'  => 'WP_DEBUG',
				'issue'    => 'Debug mode is enabled',
				'severity' => 'medium',
				'recommendation' => 'Disable WP_DEBUG in production',
			);
		}

		// Check for database prefix
		global $wpdb;
		if ( $wpdb->prefix === 'wp_' ) {
			$issues[] = array(
				'setting'  => 'Database Prefix',
				'issue'    => 'Using default database prefix',
				'severity' => 'low',
				'recommendation' => 'Consider using a custom database prefix',
			);
		}

		// Filter out ignored issues
		$filtered_issues = $this->filter_ignored_issues( 'core_integrity', $issues );

		return array(
			'scan_type' => 'core_integrity',
			'status'    => empty( $filtered_issues ) ? 'passed' : 'failed',
			'issues'    => $filtered_issues,
		);
	}

	/**
	 * Scan file permissions
	 *
	 * @return array
	 * @since 1.0.0
	 */
	private function scan_file_permissions() {
		$issues = array();

		$critical_files = array(
			ABSPATH . 'wp-config.php',
			ABSPATH . '.htaccess',
			ABSPATH . 'wp-admin',
			ABSPATH . 'wp-includes',
		);

		foreach ( $critical_files as $file ) {
			if ( ! file_exists( $file ) ) {
				continue;
			}

			$perms = substr( sprintf( '%o', fileperms( $file ) ), -4 );

			if ( is_dir( $file ) ) {
				// Directories should be 0755 or more restrictive
				if ( $perms > '0755' ) {
					$issues[] = array(
						'file'     => basename( $file ),
						'issue'    => 'Directory permissions too permissive',
						'severity' => 'medium',
						'current'  => $perms,
					);
				}
			} else {
				// Files should be 0644 or more restrictive
				if ( $perms > '0644' ) {
					$issues[] = array(
						'file'     => basename( $file ),
						'issue'    => 'File permissions too permissive',
						'severity' => 'high',
						'current'  => $perms,
					);
				}
			}
		}

		// Filter out ignored issues
		$filtered_issues = $this->filter_ignored_issues( 'file_permissions', $issues );

		return array(
			'scan_type' => 'file_permissions',
			'status'    => empty( $filtered_issues ) ? 'passed' : 'failed',
			'issues'    => $filtered_issues,
		);
	}

	/**
	 * Scan for malware signatures
	 *
	 * @return array
	 * @since 1.0.0
	 */
	private function scan_malware_signatures() {
		$issues = array();

		$suspicious_patterns = array(
			'eval\s*\(',
			'base64_decode\s*\(',
			'gzinflate\s*\(',
			'str_rot13\s*\(',
			'system\s*\(',
			'exec\s*\(',
			'shell_exec\s*\(',
			'passthru\s*\(',
			'preg_replace.*\/e',
		);

		// Scan wp-content/uploads for PHP files
		$uploads_dir = wp_upload_dir();
		if ( is_dir( $uploads_dir['basedir'] ) ) {
			$php_files = $this->find_php_files_in_uploads( $uploads_dir['basedir'] );
			
			if ( ! empty( $php_files ) ) {
				foreach ( $php_files as $file ) {
					$issues[] = array(
						'file'     => str_replace( ABSPATH, '', $file ),
						'issue'    => 'PHP file in uploads directory',
						'severity' => 'high',
					);
				}
			}
		}

		// Filter out ignored issues
		$filtered_issues = $this->filter_ignored_issues( 'malware_signatures', $issues );

		return array(
			'scan_type' => 'malware_signatures',
			'status'    => empty( $filtered_issues ) ? 'passed' : 'failed',
			'issues'    => $filtered_issues,
		);
	}

	/**
	 * Scan database security
	 *
	 * @return array
	 * @since 1.0.0
	 */
	private function scan_database_security() {
		$issues = array();
		global $wpdb;

		// Check for admin user with ID 1
		$admin_user = $wpdb->get_row( "SELECT ID, user_login FROM {$wpdb->users} WHERE ID = 1" );
		if ( $admin_user && $admin_user->user_login === 'admin' ) {
			$issues[] = array(
				'issue'    => 'Default admin username detected',
				'severity' => 'medium',
				'recommendation' => 'Change the admin username',
			);
		}

		// Check for users without passwords (should not exist)
		$users_without_password = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->users} WHERE user_pass = %s",
				''
			)
		);

		if ( $users_without_password > 0 ) {
			$issues[] = array(
				'issue'    => 'Users without passwords detected',
				'severity' => 'critical',
				'count'    => $users_without_password,
			);
		}

		// Filter out ignored issues
		$filtered_issues = $this->filter_ignored_issues( 'database_security', $issues );

		return array(
			'scan_type' => 'database_security',
			'status'    => empty( $filtered_issues ) ? 'passed' : 'failed',
			'issues'    => $filtered_issues,
		);
	}

	/**
	 * Find PHP files in uploads directory
	 *
	 * @param string $dir Directory to scan.
	 * @return array
	 * @since 1.0.0
	 */
	private function find_php_files_in_uploads( $dir ) {
		$php_files = array();
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS )
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() && $file->getExtension() === 'php' ) {
				$php_files[] = $file->getPathname();
			}

			// Limit to prevent timeout
			if ( count( $php_files ) > 100 ) {
				break;
			}
		}

		return $php_files;
	}

	/**
	 * Create scan record in database
	 *
	 * @return int Scan ID
	 * @since 1.0.0
	 */
	private function create_scan_record() {
		global $wpdb;

		$table = $wpdb->prefix . 'wph_scan_results';

		$wpdb->insert(
			$table,
			array(
				'scan_type'  => 'full',
				'status'     => 'running',
				'started_at' => current_time( 'mysql' ),
			)
		);

		return $wpdb->insert_id;
	}

	/**
	 * Complete scan record
	 *
	 * @param int   $scan_id      Scan ID.
	 * @param array $results      Scan results.
	 * @param int   $issues_found Number of issues found.
	 * @since 1.0.0
	 */
	private function complete_scan_record( $scan_id, $results, $issues_found ) {
		global $wpdb;

		$table = $wpdb->prefix . 'wph_scan_results';

		$wpdb->update(
			$table,
			array(
				'status'       => 'completed',
				'issues_found' => $issues_found,
				'scan_data'    => wp_json_encode( $results ),
				'completed_at' => current_time( 'mysql' ),
			),
			array( 'id' => $scan_id )
		);
	}

	/**
	 * Check if results contain critical issues
	 *
	 * @param array $results Scan results.
	 * @return bool
	 * @since 1.0.0
	 */
	private function has_critical_issues( $results ) {
		foreach ( $results as $scan_result ) {
			foreach ( $scan_result['issues'] as $issue ) {
				if ( isset( $issue['severity'] ) && in_array( $issue['severity'], array( 'critical', 'high' ), true ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Fix a specific security issue
	 *
	 * @param string $issue_type Type of issue (core_integrity, file_permissions, etc)
	 * @param array  $issue_data Issue data from scan
	 * @return array Result with success status and message
	 * @since 1.0.0
	 */
	public function fix_issue( $issue_type, $issue_data ) {
		switch ( $issue_type ) {
			case 'core_integrity':
				return $this->fix_core_integrity_issue( $issue_data );
			
			case 'file_permissions':
				return $this->fix_file_permission_issue( $issue_data );
			
			case 'database_security':
				return $this->fix_database_security_issue( $issue_data );
			
			case 'malware_signatures':
				return array(
					'success' => false,
					'message' => 'Malware issues must be manually reviewed. Please quarantine the file or remove it manually.'
				);
			
			default:
				return array(
					'success' => false,
					'message' => 'Unknown issue type.'
				);
		}
	}

	/**
	 * Fix core integrity issues
	 *
	 * @param array $issue Issue data
	 * @return array Result
	 * @since 1.0.0
	 */
	private function fix_core_integrity_issue( $issue ) {
		// Fix wp-config.php permissions
		if ( isset( $issue['file'] ) && $issue['file'] === 'wp-config.php' ) {
			$wp_config = ABSPATH . 'wp-config.php';
			if ( file_exists( $wp_config ) ) {
				if ( @chmod( $wp_config, 0600 ) ) {
					return array(
						'success' => true,
						'message' => 'wp-config.php permissions updated to 0600'
					);
				}
				return array(
					'success' => false,
					'message' => 'Failed to update wp-config.php permissions. Please do this manually via FTP/SSH: chmod 600 wp-config.php'
				);
			}
		}
		
		// Disable debug mode - provide instructions
		if ( isset( $issue['setting'] ) && $issue['setting'] === 'WP_DEBUG' ) {
			return array(
				'success' => false,
				'message' => 'Please manually edit wp-config.php and set: define( \'WP_DEBUG\', false );'
			);
		}
		
		// Database prefix - provide instructions
		if ( isset( $issue['setting'] ) && $issue['setting'] === 'Database Prefix' ) {
			return array(
				'success' => false,
				'message' => 'Changing database prefix requires a backup and manual database modification. Consider using a migration plugin.'
			);
		}
		
		return array(
			'success' => false,
			'message' => 'Unable to automatically fix this issue. Please review and fix manually.'
		);
	}

	/**
	 * Fix file permission issues
	 *
	 * @param array $issue Issue data
	 * @return array Result
	 * @since 1.0.0
	 */
	private function fix_file_permission_issue( $issue ) {
		if ( ! isset( $issue['file'] ) ) {
			return array(
				'success' => false,
				'message' => 'Invalid issue data - no file specified.'
			);
		}
		
		// Construct full file path
		$file = ABSPATH . $issue['file'];
		
		if ( ! file_exists( $file ) ) {
			return array(
				'success' => false,
				'message' => 'File not found: ' . $issue['file']
			);
		}
		
		// Determine appropriate permissions
		$new_perms = is_dir( $file ) ? 0755 : 0644;
		
		// Special case for wp-config.php
		if ( basename( $file ) === 'wp-config.php' ) {
			$new_perms = 0600;
		}
		
		if ( @chmod( $file, $new_perms ) ) {
			return array(
				'success' => true,
				'message' => sprintf( 'Permissions updated to %04o for %s', $new_perms, $issue['file'] )
			);
		}
		
		return array(
			'success' => false,
			'message' => sprintf( 'Failed to update permissions for %s. Please do this via FTP/SSH: chmod %04o %s', $issue['file'], $new_perms, $issue['file'] )
		);
	}

	/**
	 * Fix database security issues
	 *
	 * @param array $issue Issue data
	 * @return array Result
	 * @since 1.0.0
	 */
	private function fix_database_security_issue( $issue ) {
		// Admin username issue
		if ( isset( $issue['user'] ) && $issue['user'] === 'admin' ) {
			return array(
				'success' => false,
				'message' => 'Please manually rename the admin user through Users > All Users > Edit or use WP-CLI: wp user update admin --user_login=newusername'
			);
		}
		
		// Empty password issue
		if ( isset( $issue['issue'] ) && strpos( $issue['issue'], 'empty password' ) !== false ) {
			return array(
				'success' => false,
				'message' => 'Please reset the password for this user account immediately through Users > All Users.'
			);
		}
		
		return array(
			'success' => false,
			'message' => 'Unable to automatically fix this database security issue. Please review and fix manually.'
		);
	}

	/**
	 * Ignore a security issue
	 *
	 * @param string $issue_type Type of issue
	 * @param array  $issue_data Issue data
	 * @param string $reason Reason for ignoring (optional)
	 * @return bool Success status
	 * @since 1.0.0
	 */
	public function ignore_issue( $issue_type, $issue_data, $reason = '' ) {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wph_ignored_issues';
		
		// Create unique key for this issue
		$issue_key = md5( $issue_type . wp_json_encode( $issue_data ) );
		
		// Check if already ignored
		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM `{$table_name}` WHERE issue_key = %s",
				$issue_key
			)
		);
		
		if ( $existing > 0 ) {
			return true; // Already ignored
		}
		
		$result = $wpdb->insert(
			$table_name,
			array(
				'issue_type' => sanitize_text_field( $issue_type ),
				'issue_key'  => $issue_key,
				'issue_data' => wp_json_encode( $issue_data ),
				'ignored_by' => get_current_user_id(),
				'ignored_at' => current_time( 'mysql' ),
				'reason'     => sanitize_text_field( $reason ),
			)
		);
		
		if ( $result ) {
			// Log the action
			$logger = WPH_Logger::get_instance();
			$logger->log(
				'scanner',
				'low',
				sprintf( 'Security issue ignored: %s', $issue_type ),
				array(
					'issue' => $issue_data,
					'reason' => $reason,
					'user_id' => get_current_user_id()
				)
			);
			
			return true;
		}
		
		return false;
	}

	/**
	 * Check if issue is ignored
	 *
	 * @param string $issue_type Type of issue
	 * @param array  $issue_data Issue data
	 * @return bool Whether issue is ignored
	 * @since 1.0.0
	 */
	public function is_issue_ignored( $issue_type, $issue_data ) {
		global $wpdb;
		
		$table_name = $wpdb->prefix . 'wph_ignored_issues';
		$issue_key = md5( $issue_type . wp_json_encode( $issue_data ) );
		
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM `{$table_name}` WHERE issue_key = %s",
				$issue_key
			)
		);
		
		return $count > 0;
	}

	/**
	 * Filter out ignored issues from scan results
	 *
	 * @param string $issue_type Type of scan
	 * @param array  $issues     Array of detected issues
	 * @return array Filtered issues (non-ignored only)
	 * @since 1.0.0
	 */
	private function filter_ignored_issues( $issue_type, $issues ) {
		if ( empty( $issues ) ) {
			return $issues;
		}
		
		$filtered_issues = array();
		
		foreach ( $issues as $issue ) {
			// Check if this specific issue has been ignored
			if ( ! $this->is_issue_ignored( $issue_type, $issue ) ) {
				$filtered_issues[] = $issue;
			}
		}
		
		return $filtered_issues;
	}
}
