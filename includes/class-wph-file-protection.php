<?php
/**
 * File Protection Module
 *
 * Provides comprehensive file system protection including real-time monitoring,
 * upload restrictions, directory protection, and file quarantine system.
 *
 * @package WP_Harden
 * @since 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPH_File_Protection
 *
 * Handles file system security and monitoring for WordPress installations.
 */
class WPH_File_Protection {

	/**
	 * Singleton instance
	 *
	 * @var WPH_File_Protection
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
	 * Notifications instance
	 *
	 * @var WPH_Notifications
	 */
	private $notifications;

	/**
	 * Database table name for file changes
	 *
	 * @var string
	 */
	private $table_name;

	/**
	 * Quarantine directory path
	 *
	 * @var string
	 */
	private $quarantine_dir;

	/**
	 * Blocked file extensions
	 *
	 * @var array
	 */
	private $blocked_extensions = array(
		'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar',
		'exe', 'sh', 'bat', 'cmd', 'com', 'scr', 'vbs', 'js',
		'jar', 'app', 'deb', 'rpm', 'dmg', 'cgi', 'pl', 'py',
	);

	/**
	 * Critical files that require immediate alerts
	 *
	 * @var array
	 */
	private $critical_files = array(
		'wp-config.php',
		'.htaccess',
		'index.php',
	);

	/**
	 * Get singleton instance
	 *
	 * @return WPH_File_Protection
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
		$this->table_name     = $wpdb->prefix . 'wph_file_changes';
		$this->quarantine_dir = wp_normalize_path( WP_CONTENT_DIR . '/wph-quarantine/' );

		$this->init_dependencies();
		$this->init_hooks();
	}

	/**
	 * Initialize dependencies
	 */
	private function init_dependencies() {
		if ( class_exists( 'WPH_Settings' ) ) {
			$this->settings = WPH_Settings::get_instance();
		}
		if ( class_exists( 'WPH_Logger' ) ) {
			$this->logger = WPH_Logger::get_instance();
		}
		if ( class_exists( 'WPH_Notifications' ) ) {
			$this->notifications = WPH_Notifications::get_instance();
		}
	}

	/**
	 * Initialize WordPress hooks
	 */
	public function init_hooks() {
		if ( ! $this->is_enabled() ) {
			return;
		}

		// File upload restrictions
		if ( $this->get_setting( 'block_executable_uploads', true ) ) {
			add_filter( 'wp_handle_upload_prefilter', array( $this, 'restrict_file_uploads' ) );
			add_filter( 'wp_check_filetype_and_ext', array( $this, 'check_file_type' ), 10, 4 );
		}

		// File monitoring
		if ( $this->get_setting( 'file_monitoring_enabled', true ) ) {
			$interval = $this->get_setting( 'file_monitoring_scan_interval', 'daily' );
			add_action( 'wph_file_scan_' . $interval, array( $this, 'scan_files' ) );
		}

		// Directory protection
		if ( $this->get_setting( 'directory_listing_protection', true ) ) {
			add_action( 'admin_init', array( $this, 'protect_directories' ) );
		}

		// .htaccess hardening
		if ( $this->get_setting( 'htaccess_hardening', true ) ) {
			add_action( 'admin_init', array( $this, 'harden_htaccess' ) );
		}

		// wp-config.php protection
		if ( $this->get_setting( 'wpconfig_protection', true ) ) {
			add_action( 'admin_init', array( $this, 'protect_wpconfig' ) );
		}

		// Prevent PHP execution in uploads
		add_action( 'admin_init', array( $this, 'prevent_php_execution' ) );

		// Cleanup old changes
		add_action( 'wph_cleanup_file_changes', array( $this, 'cleanup_old_changes' ) );

		// Initialize quarantine directory
		$this->init_quarantine_directory();
	}

	/**
	 * Check if file protection is enabled
	 *
	 * @return bool
	 */
	private function is_enabled() {
		return (bool) $this->get_setting( 'file_protection_enabled', true );
	}

	/**
	 * Get setting value
	 *
	 * @param string $key Setting key.
	 * @param mixed  $default Default value.
	 * @return mixed
	 */
	private function get_setting( $key, $default = null ) {
		if ( $this->settings ) {
			return $this->settings->get( $key, $default );
		}
		return get_option( 'wph_' . $key, $default );
	}

	/**
	 * Scan files for changes
	 */
	public function scan_files() {
		$monitored_dirs = $this->get_setting(
			'monitored_directories',
			array( 'wp-includes', 'wp-admin', 'wp-content/themes', 'wp-content/plugins' )
		);

		foreach ( $monitored_dirs as $dir ) {
			$full_path = wp_normalize_path( ABSPATH . $dir );
			if ( is_dir( $full_path ) ) {
				$this->scan_directory( $full_path );
			}
		}

		// Scan critical files in root
		foreach ( $this->critical_files as $file ) {
			$file_path = wp_normalize_path( ABSPATH . $file );
			if ( file_exists( $file_path ) ) {
				$this->scan_file( $file_path );
			}
		}

		$this->log( 'File scan completed', 'info' );
	}

	/**
	 * Scan a directory recursively
	 *
	 * @param string $directory Directory path.
	 */
	private function scan_directory( $directory ) {
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $directory, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$this->scan_file( $file->getPathname() );
			}
		}
	}

	/**
	 * Scan a single file
	 *
	 * @param string $file_path File path.
	 */
	private function scan_file( $file_path ) {
		$file_path = wp_normalize_path( $file_path );
		
		if ( ! is_readable( $file_path ) ) {
			return;
		}

		$current_hash = $this->get_file_hash( $file_path );
		if ( ! $current_hash ) {
			return;
		}

		$stored_hash = $this->get_stored_hash( $file_path );

		if ( false === $stored_hash ) {
			// First time scan - store baseline
			$this->store_baseline( $file_path, $current_hash );
		} elseif ( $stored_hash !== $current_hash ) {
			// File has changed
			$this->handle_file_change( $file_path, $stored_hash, $current_hash );
		}
	}

	/**
	 * Calculate MD5 hash of a file
	 *
	 * @param string $file_path File path.
	 * @return string|false MD5 hash or false on failure.
	 */
	public function get_file_hash( $file_path ) {
		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
			return false;
		}
		return md5_file( $file_path );
	}

	/**
	 * Get stored hash from database
	 *
	 * @param string $file_path File path.
	 * @return string|false Stored hash or false if not found.
	 */
	private function get_stored_hash( $file_path ) {
		global $wpdb;
		
		$hash = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT new_hash FROM {$this->table_name} WHERE file_path = %s ORDER BY detected_at DESC LIMIT 1",
				$file_path
			)
		);

		return $hash ? $hash : false;
	}

	/**
	 * Store baseline hash in database
	 *
	 * @param string $file_path File path.
	 * @param string $hash File hash.
	 */
	public function store_baseline( $file_path, $hash ) {
		global $wpdb;

		$file_size = file_exists( $file_path ) ? filesize( $file_path ) : 0;

		$wpdb->insert(
			$this->table_name,
			array(
				'file_path'   => $file_path,
				'change_type' => 'baseline',
				'old_hash'    => null,
				'new_hash'    => $hash,
				'file_size'   => $file_size,
				'detected_at' => current_time( 'mysql' ),
				'is_reviewed' => 0,
			),
			array( '%s', '%s', '%s', '%s', '%d', '%s', '%d' )
		);
	}

	/**
	 * Handle detected file change
	 *
	 * @param string $file_path File path.
	 * @param string $old_hash Old hash.
	 * @param string $new_hash New hash.
	 */
	private function handle_file_change( $file_path, $old_hash, $new_hash ) {
		$this->log_file_change( $file_path, 'modified', $old_hash, $new_hash );

		// Check if it's a critical file
		$filename = basename( $file_path );
		if ( in_array( $filename, $this->critical_files, true ) ) {
			$this->send_alert( $file_path, 'modified' );
			
			// Consider quarantining suspicious changes
			if ( $this->is_change_suspicious( $file_path ) ) {
				$this->quarantine_file( $file_path, 'Suspicious modification detected' );
			}
		}
	}

	/**
	 * Detect file changes by comparing with baseline
	 *
	 * @return array Array of detected changes.
	 */
	public function detect_changes() {
		$changes = array();
		
		$monitored_dirs = $this->get_setting(
			'monitored_directories',
			array( 'wp-includes', 'wp-admin', 'wp-content/themes', 'wp-content/plugins' )
		);

		foreach ( $monitored_dirs as $dir ) {
			$full_path = wp_normalize_path( ABSPATH . $dir );
			if ( is_dir( $full_path ) ) {
				$changes = array_merge( $changes, $this->detect_directory_changes( $full_path ) );
			}
		}

		return $changes;
	}

	/**
	 * Detect changes in a directory
	 *
	 * @param string $directory Directory path.
	 * @return array Array of changes.
	 */
	private function detect_directory_changes( $directory ) {
		$changes  = array();
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $directory, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() ) {
				$file_path    = wp_normalize_path( $file->getPathname() );
				$current_hash = $this->get_file_hash( $file_path );
				$stored_hash  = $this->get_stored_hash( $file_path );

				if ( false === $stored_hash ) {
					$changes[] = array(
						'file'   => $file_path,
						'type'   => 'added',
						'hash'   => $current_hash,
					);
				} elseif ( $stored_hash !== $current_hash ) {
					$changes[] = array(
						'file'     => $file_path,
						'type'     => 'modified',
						'old_hash' => $stored_hash,
						'new_hash' => $current_hash,
					);
				}
			}
		}

		return $changes;
	}

	/**
	 * Log file change to database
	 *
	 * @param string $file_path File path.
	 * @param string $type Change type (modified, added, deleted).
	 * @param string $old_hash Old hash.
	 * @param string $new_hash New hash.
	 * @return int|false Insert ID or false on failure.
	 */
	public function log_file_change( $file_path, $type, $old_hash = null, $new_hash = null ) {
		global $wpdb;

		$file_size = file_exists( $file_path ) ? filesize( $file_path ) : 0;

		$result = $wpdb->insert(
			$this->table_name,
			array(
				'file_path'   => $file_path,
				'change_type' => $type,
				'old_hash'    => $old_hash,
				'new_hash'    => $new_hash,
				'file_size'   => $file_size,
				'detected_at' => current_time( 'mysql' ),
				'is_reviewed' => 0,
			),
			array( '%s', '%s', '%s', '%s', '%d', '%s', '%d' )
		);

		if ( $result ) {
			$this->log( "File change detected: {$file_path} ({$type})", 'warning' );
			return $wpdb->insert_id;
		}

		return false;
	}

	/**
	 * Restrict file uploads
	 *
	 * @param array $file Uploaded file data.
	 * @return array Modified file data or error.
	 */
	public function restrict_file_uploads( $file ) {
		$filename  = isset( $file['name'] ) ? $file['name'] : '';
		$file_ext  = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
		
		// Check for double extensions
		if ( $this->has_double_extension( $filename ) ) {
			$file['error'] = __( 'File upload blocked: Double file extension detected.', 'wp-harden' );
			$this->log( "Blocked upload with double extension: {$filename}", 'warning' );
			return $file;
		}

		// Check for null bytes
		if ( $this->has_null_byte( $filename ) ) {
			$file['error'] = __( 'File upload blocked: Null byte detected in filename.', 'wp-harden' );
			$this->log( "Blocked upload with null byte: {$filename}", 'warning' );
			return $file;
		}

		// Check blocked extensions
		if ( in_array( $file_ext, $this->blocked_extensions, true ) ) {
			$file['error'] = sprintf(
				__( 'File upload blocked: .%s files are not allowed for security reasons.', 'wp-harden' ),
				$file_ext
			);
			$this->log( "Blocked executable file upload: {$filename}", 'warning' );
			return $file;
		}

		return $file;
	}

	/**
	 * Check file type and extension
	 *
	 * @param array  $file_data File data.
	 * @param string $file File path.
	 * @param string $filename File name.
	 * @param array  $mimes Allowed mime types.
	 * @return array Modified file data.
	 */
	public function check_file_type( $file_data, $file, $filename, $mimes ) {
		// Additional validation for suspicious files
		$file_ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );
		
		if ( in_array( $file_ext, $this->blocked_extensions, true ) ) {
			$file_data['ext']             = false;
			$file_data['type']            = false;
			$file_data['proper_filename'] = false;
		}

		return $file_data;
	}

	/**
	 * Check for double file extensions
	 *
	 * @param string $filename Filename.
	 * @return bool True if double extension detected.
	 */
	private function has_double_extension( $filename ) {
		$parts = explode( '.', $filename );
		if ( count( $parts ) > 2 ) {
			$second_ext = strtolower( $parts[ count( $parts ) - 2 ] );
			if ( in_array( $second_ext, $this->blocked_extensions, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check for null byte injection
	 *
	 * @param string $filename Filename.
	 * @return bool True if null byte detected.
	 */
	private function has_null_byte( $filename ) {
		return strpos( $filename, "\0" ) !== false;
	}

	/**
	 * Protect directories from listing
	 */
	public function protect_directories() {
		$dirs = array(
			WP_CONTENT_DIR . '/themes',
			WP_CONTENT_DIR . '/plugins',
			WP_CONTENT_DIR . '/uploads',
		);

		foreach ( $dirs as $dir ) {
			if ( is_dir( $dir ) && is_writable( $dir ) ) {
				$this->add_index_file( $dir );
			}
		}
	}

	/**
	 * Add index.php file to directory
	 *
	 * @param string $directory Directory path.
	 */
	private function add_index_file( $directory ) {
		$index_file = wp_normalize_path( $directory . '/index.php' );
		
		if ( ! file_exists( $index_file ) ) {
			$content = "<?php\n// Silence is golden.\n";
			
			if ( file_put_contents( $index_file, $content ) ) {
				$this->log( "Added index.php to {$directory}", 'info' );
			}
		}
	}

	/**
	 * Harden .htaccess file
	 */
	public function harden_htaccess() {
		$htaccess_file = wp_normalize_path( ABSPATH . '.htaccess' );
		
		if ( ! $this->is_apache_server() ) {
			return;
		}

		$rules = $this->get_security_rules();
		
		// Check if rules already exist
		if ( file_exists( $htaccess_file ) ) {
			$current_content = file_get_contents( $htaccess_file );
			if ( strpos( $current_content, '# BEGIN WP Harden File Protection' ) !== false ) {
				return; // Rules already added
			}
		}

		$this->insert_htaccess_rules( $htaccess_file, $rules );
	}

	/**
	 * Check if server is Apache
	 *
	 * @return bool True if Apache server.
	 */
	private function is_apache_server() {
		$server_software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? $_SERVER['SERVER_SOFTWARE'] : '';
		return strpos( $server_software, 'Apache' ) !== false || function_exists( 'apache_get_version' );
	}

	/**
	 * Get security rules for .htaccess
	 *
	 * @return string Security rules.
	 */
	private function get_security_rules() {
		$rules = "\n# BEGIN WP Harden File Protection\n";
		$rules .= "<IfModule mod_rewrite.c>\n";
		$rules .= "RewriteEngine On\n\n";
		
		// Block access to sensitive files
		$rules .= "# Block access to sensitive files\n";
		$rules .= "<FilesMatch \"\\.(sql|zip|tar|tar\\.gz|tgz|gz|bak|backup|log|txt|md|json|xml|yml|yaml|ini|conf|config)$\">\n";
		$rules .= "    Order allow,deny\n";
		$rules .= "    Deny from all\n";
		$rules .= "</FilesMatch>\n\n";
		
		// Block access to wp-config.php
		$rules .= "# Protect wp-config.php\n";
		$rules .= "<Files wp-config.php>\n";
		$rules .= "    Order allow,deny\n";
		$rules .= "    Deny from all\n";
		$rules .= "</Files>\n\n";
		
		// Disable directory browsing
		$rules .= "# Disable directory browsing\n";
		$rules .= "Options -Indexes\n\n";
		
		// Protect .htaccess and .htpasswd
		$rules .= "# Protect .htaccess and .htpasswd\n";
		$rules .= "<Files ~ \"^\\.ht\">\n";
		$rules .= "    Order allow,deny\n";
		$rules .= "    Deny from all\n";
		$rules .= "</Files>\n\n";
		
		$rules .= "</IfModule>\n";
		$rules .= "# END WP Harden File Protection\n\n";
		
		return $rules;
	}

	/**
	 * Insert rules into .htaccess file
	 *
	 * @param string $file .htaccess file path.
	 * @param string $rules Rules to insert.
	 */
	private function insert_htaccess_rules( $file, $rules ) {
		$content = file_exists( $file ) ? file_get_contents( $file ) : '';
		
		// Add rules at the beginning
		$new_content = $rules . $content;
		
		if ( file_put_contents( $file, $new_content ) ) {
			$this->log( 'Added security rules to .htaccess', 'info' );
		}
	}

	/**
	 * Protect wp-config.php file
	 */
	public function protect_wpconfig() {
		$wpconfig_file = wp_normalize_path( ABSPATH . 'wp-config.php' );
		
		if ( ! file_exists( $wpconfig_file ) ) {
			return;
		}

		// Check file permissions
		$perms = fileperms( $wpconfig_file );
		$octal_perms = substr( sprintf( '%o', $perms ), -4 );
		
		// Recommended permissions: 0400 or 0440
		if ( $octal_perms !== '0400' && $octal_perms !== '0440' && $octal_perms !== '0600' ) {
			if ( chmod( $wpconfig_file, 0400 ) ) {
				$this->log( 'Updated wp-config.php permissions to 0400', 'info' );
			}
		}

		// Check for required security constants
		$this->verify_security_constants();
	}

	/**
	 * Verify security constants in wp-config.php
	 */
	private function verify_security_constants() {
		$required_constants = array(
			'DISALLOW_FILE_EDIT',
			'DISALLOW_FILE_MODS',
		);

		$missing = array();
		foreach ( $required_constants as $constant ) {
			if ( ! defined( $constant ) ) {
				$missing[] = $constant;
			}
		}

		if ( ! empty( $missing ) ) {
			$this->log(
				'Missing security constants in wp-config.php: ' . implode( ', ', $missing ),
				'warning'
			);
		}
	}

	/**
	 * Prevent PHP execution in uploads directory
	 */
	public function prevent_php_execution() {
		$uploads_dir = wp_upload_dir();
		$htaccess_file = wp_normalize_path( $uploads_dir['basedir'] . '/.htaccess' );

		$rules = "# BEGIN WP Harden PHP Execution Prevention\n";
		$rules .= "<FilesMatch \"\\.(?i:php|php3|php4|php5|phtml|phar)$\">\n";
		$rules .= "    Order allow,deny\n";
		$rules .= "    Deny from all\n";
		$rules .= "</FilesMatch>\n";
		$rules .= "# END WP Harden PHP Execution Prevention\n";

		if ( file_exists( $htaccess_file ) ) {
			$content = file_get_contents( $htaccess_file );
			if ( strpos( $content, '# BEGIN WP Harden PHP Execution Prevention' ) !== false ) {
				return; // Rules already exist
			}
			$rules = $content . "\n" . $rules;
		}

		if ( file_put_contents( $htaccess_file, $rules ) ) {
			$this->log( 'Added PHP execution prevention to uploads directory', 'info' );
		}
	}

	/**
	 * Initialize quarantine directory
	 */
	private function init_quarantine_directory() {
		if ( ! is_dir( $this->quarantine_dir ) ) {
			wp_mkdir_p( $this->quarantine_dir );
			
			// Add index.php
			$index_file = $this->quarantine_dir . 'index.php';
			file_put_contents( $index_file, "<?php\n// Silence is golden.\n" );
			
			// Add .htaccess to deny all access
			$htaccess_file = $this->quarantine_dir . '.htaccess';
			$rules = "Order deny,allow\nDeny from all\n";
			file_put_contents( $htaccess_file, $rules );
		}
	}

	/**
	 * Quarantine a suspicious file
	 *
	 * @param string $file_path File path to quarantine.
	 * @param string $reason Reason for quarantine.
	 * @return bool|int Quarantine ID or false on failure.
	 */
	public function quarantine_file( $file_path, $reason ) {
		if ( ! $this->get_setting( 'file_quarantine_enabled', true ) ) {
			return false;
		}

		$file_path = wp_normalize_path( $file_path );
		
		if ( ! file_exists( $file_path ) ) {
			return false;
		}

		// Generate unique quarantine filename
		$quarantine_filename = time() . '_' . md5( $file_path ) . '_' . basename( $file_path );
		$quarantine_path = $this->quarantine_dir . $quarantine_filename;

		// Read file content and encode it
		$content = file_get_contents( $file_path );
		$encoded_content = base64_encode( $content );

		// Save to quarantine
		if ( ! file_put_contents( $quarantine_path, $encoded_content ) ) {
			return false;
		}

		// Store metadata in database
		global $wpdb;
		$table_name = $wpdb->prefix . 'wph_quarantine';
		
		$result = $wpdb->insert(
			$table_name,
			array(
				'original_path'     => $file_path,
				'quarantine_path'   => $quarantine_path,
				'reason'            => $reason,
				'file_size'         => filesize( $file_path ),
				'file_hash'         => md5_file( $file_path ),
				'quarantined_at'    => current_time( 'mysql' ),
				'is_restored'       => 0,
			),
			array( '%s', '%s', '%s', '%d', '%s', '%s', '%d' )
		);

		if ( $result ) {
			// Delete original file
			unlink( $file_path );
			
			$this->log( "File quarantined: {$file_path} - Reason: {$reason}", 'warning' );
			$this->send_alert( $file_path, 'quarantined' );
			
			return $wpdb->insert_id;
		}

		return false;
	}

	/**
	 * Restore a quarantined file
	 *
	 * @param int $quarantine_id Quarantine record ID.
	 * @return bool True on success, false on failure.
	 */
	public function restore_quarantined_file( $quarantine_id ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'wph_quarantine';

		$record = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table_name} WHERE id = %d",
				$quarantine_id
			)
		);

		if ( ! $record || $record->is_restored ) {
			return false;
		}

		if ( ! file_exists( $record->quarantine_path ) ) {
			return false;
		}

		// Decode and restore file
		$encoded_content = file_get_contents( $record->quarantine_path );
		$content = base64_decode( $encoded_content );

		// Ensure directory exists
		$dir = dirname( $record->original_path );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		if ( file_put_contents( $record->original_path, $content ) ) {
			// Update database
			$wpdb->update(
				$table_name,
				array(
					'is_restored' => 1,
					'restored_at' => current_time( 'mysql' ),
				),
				array( 'id' => $quarantine_id ),
				array( '%d', '%s' ),
				array( '%d' )
			);

			$this->log( "File restored from quarantine: {$record->original_path}", 'info' );
			return true;
		}

		return false;
	}

	/**
	 * Delete a quarantined file permanently
	 *
	 * @param int $quarantine_id Quarantine record ID.
	 * @return bool True on success, false on failure.
	 */
	public function delete_quarantined_file( $quarantine_id ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'wph_quarantine';

		$record = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table_name} WHERE id = %d",
				$quarantine_id
			)
		);

		if ( ! $record ) {
			return false;
		}

		// Delete quarantined file
		if ( file_exists( $record->quarantine_path ) ) {
			unlink( $record->quarantine_path );
		}

		// Delete database record
		$result = $wpdb->delete(
			$table_name,
			array( 'id' => $quarantine_id ),
			array( '%d' )
		);

		if ( $result ) {
			$this->log( "Quarantined file deleted permanently: {$record->original_path}", 'info' );
			return true;
		}

		return false;
	}

	/**
	 * Get list of quarantined files
	 *
	 * @param array $args Query arguments.
	 * @return array Array of quarantined files.
	 */
	public function get_quarantined_files( $args = array() ) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'wph_quarantine';

		$defaults = array(
			'limit'  => 50,
			'offset' => 0,
			'orderby' => 'quarantined_at',
			'order'   => 'DESC',
		);

		$args = wp_parse_args( $args, $defaults );

		$query = $wpdb->prepare(
			"SELECT * FROM {$table_name} ORDER BY {$args['orderby']} {$args['order']} LIMIT %d OFFSET %d",
			$args['limit'],
			$args['offset']
		);

		return $wpdb->get_results( $query );
	}

	/**
	 * Check if a file change is suspicious
	 *
	 * @param string $file_path File path.
	 * @return bool True if suspicious.
	 */
	private function is_change_suspicious( $file_path ) {
		// Basic heuristic: check if file contains common malware patterns
		if ( ! is_readable( $file_path ) ) {
			return false;
		}

		$content = file_get_contents( $file_path );
		
		$suspicious_patterns = array(
			'eval\s*\(',
			'base64_decode\s*\(',
			'gzinflate\s*\(',
			'str_rot13\s*\(',
			'system\s*\(',
			'exec\s*\(',
			'shell_exec\s*\(',
			'passthru\s*\(',
			'assert\s*\(',
			'\$_GET\[',
			'\$_POST\[',
			'\$_REQUEST\[',
		);

		foreach ( $suspicious_patterns as $pattern ) {
			if ( preg_match( '/' . $pattern . '/i', $content ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Send alert for critical file changes
	 *
	 * @param string $file_path File path.
	 * @param string $type Alert type.
	 */
	private function send_alert( $file_path, $type ) {
		if ( ! $this->notifications ) {
			return;
		}

		$message = sprintf(
			__( 'Critical file %s detected: %s', 'wp-harden' ),
			$type,
			$file_path
		);

		$this->notifications->send(
			'file_change_alert',
			array(
				'title'   => __( 'Critical File Change Alert', 'wp-harden' ),
				'message' => $message,
				'file'    => $file_path,
				'type'    => $type,
			)
		);
	}

	/**
	 * Cleanup old file change records
	 *
	 * @param int $days Number of days to keep records (default: 90).
	 */
	public function cleanup_old_changes( $days = 90 ) {
		global $wpdb;

		$date = date( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

		$result = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$this->table_name} WHERE detected_at < %s AND is_reviewed = 1",
				$date
			)
		);

		if ( $result ) {
			$this->log( "Cleaned up {$result} old file change records", 'info' );
		}
	}

	/**
	 * Log message
	 *
	 * @param string $message Log message.
	 * @param string $level Log level.
	 */
	private function log( $message, $level = 'info' ) {
		if ( $this->logger ) {
			$this->logger->log( $message, $level, 'file_protection' );
		}
	}

	/**
	 * Create database table for file changes
	 */
	public static function create_table() {
		global $wpdb;
		$table_name = $wpdb->prefix . 'wph_file_changes';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			file_path varchar(500) NOT NULL,
			change_type varchar(20) NOT NULL,
			old_hash varchar(32) DEFAULT NULL,
			new_hash varchar(32) DEFAULT NULL,
			file_size bigint(20) DEFAULT NULL,
			detected_at datetime NOT NULL,
			is_reviewed tinyint(1) DEFAULT 0,
			PRIMARY KEY (id),
			KEY file_path (file_path(191)),
			KEY change_type (change_type),
			KEY detected_at (detected_at)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );

		// Create quarantine table
		$quarantine_table = $wpdb->prefix . 'wph_quarantine';
		$sql_quarantine = "CREATE TABLE IF NOT EXISTS {$quarantine_table} (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			original_path varchar(500) NOT NULL,
			quarantine_path varchar(500) NOT NULL,
			reason text,
			file_size bigint(20) DEFAULT NULL,
			file_hash varchar(32) DEFAULT NULL,
			quarantined_at datetime NOT NULL,
			is_restored tinyint(1) DEFAULT 0,
			restored_at datetime DEFAULT NULL,
			PRIMARY KEY (id),
			KEY original_path (original_path(191)),
			KEY quarantined_at (quarantined_at)
		) {$charset_collate};";

		dbDelta( $sql_quarantine );
	}
}
