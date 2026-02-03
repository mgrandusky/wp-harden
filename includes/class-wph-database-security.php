<?php
/**
 * Database Security Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Database_Security
 *
 * Manages database security features including prefix randomization,
 * backups, encryption, optimization, and query monitoring
 */
class WPH_Database_Security {

	/**
	 * Singleton instance
	 *
	 * @var WPH_Database_Security
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
	 * Backup directory path
	 *
	 * @var string
	 */
	private $backup_dir;

	/**
	 * Suspicious query patterns
	 *
	 * @var array
	 */
	private $suspicious_patterns = array(
		'/UNION\s+(ALL\s+)?SELECT/i',
		'/DROP\s+(TABLE|DATABASE)/i',
		'/DELETE\s+FROM\s+\w+\s*(?!WHERE)/i',
		'/UPDATE\s+\w+\s+SET\s+.*(?!WHERE)/i',
		'/LOAD_FILE\s*\(/i',
		'/INTO\s+(OUT|DUMP)FILE/i',
		'/SLEEP\s*\(/i',
		'/BENCHMARK\s*\(/i',
		'/INFORMATION_SCHEMA/i',
		'/\'\s*OR\s*[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/i',
		'/;.*DROP/i',
		'/;.*DELETE/i',
		'/;.*UPDATE/i',
		'/--\s*$/m',
		'/\/\*.*\*\//s',
	);

	/**
	 * Get singleton instance
	 *
	 * @return WPH_Database_Security
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
		$this->settings   = WPH_Settings::get_instance();
		$this->logger     = WPH_Logger::get_instance();
		$this->backup_dir = $this->get_backup_directory();
		$this->init_hooks();
		$this->ensure_backup_directory();
		$this->ensure_backup_table();
	}

	/**
	 * Initialize hooks
	 *
	 * @since 1.0.0
	 */
	private function init_hooks() {
		// Query monitoring
		if ( $this->settings->get( 'db_query_monitoring' ) ) {
			add_filter( 'query', array( $this, 'monitor_query' ) );
		}

		// Scheduled backups
		add_action( 'wph_database_backup', array( $this, 'scheduled_backup' ) );
		add_action( 'wph_database_cleanup', array( $this, 'scheduled_cleanup' ) );
		add_action( 'wph_database_optimize', array( $this, 'optimize_tables' ) );
	}

	/**
	 * Get backup directory path
	 *
	 * @return string
	 * @since 1.0.0
	 */
	private function get_backup_directory() {
		$upload_dir = wp_upload_dir();
		$backup_dir = $upload_dir['basedir'] . '/wph-backups';
		
		// Try to use a location outside webroot if possible
		$custom_dir = WP_CONTENT_DIR . '/../wph-backups';
		if ( is_writable( dirname( $custom_dir ) ) ) {
			$backup_dir = $custom_dir;
		}

		return $backup_dir;
	}

	/**
	 * Ensure backup directory exists and is protected
	 *
	 * @return bool
	 * @since 1.0.0
	 */
	private function ensure_backup_directory() {
		if ( ! file_exists( $this->backup_dir ) ) {
			if ( ! wp_mkdir_p( $this->backup_dir ) ) {
				$this->logger->log( 'database', 'high', 'Failed to create backup directory: ' . $this->backup_dir );
				return false;
			}
		}

		// Create .htaccess to deny access
		$htaccess = $this->backup_dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			$content = "Order deny,allow\nDeny from all";
			file_put_contents( $htaccess, $content );
		}

		// Create index.php to prevent directory listing
		$index = $this->backup_dir . '/index.php';
		if ( ! file_exists( $index ) ) {
			file_put_contents( $index, '<?php // Silence is golden' );
		}

		return true;
	}

	/**
	 * Ensure backup table exists
	 *
	 * @since 1.0.0
	 */
	private function ensure_backup_table() {
		global $wpdb;

		$table_name      = $wpdb->prefix . 'wph_backups';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS $table_name (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			backup_file varchar(255) NOT NULL,
			backup_size bigint(20) NOT NULL,
			is_encrypted tinyint(1) DEFAULT 0,
			created_at datetime NOT NULL,
			expires_at datetime DEFAULT NULL,
			PRIMARY KEY (id),
			KEY created_at (created_at)
		) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Randomize database table prefix
	 *
	 * @return array Result with success status and message
	 * @since 1.0.0
	 */
	public function randomize_prefix() {
		global $wpdb;

		// Create backup first
		$backup_result = $this->backup_database();
		if ( ! $backup_result['success'] ) {
			return array(
				'success' => false,
				'message' => 'Failed to create backup before prefix change: ' . $backup_result['message'],
			);
		}

		$old_prefix = $wpdb->prefix;
		$new_prefix = 'wp_' . substr( md5( uniqid( rand(), true ) ), 0, 8 ) . '_';

		$this->logger->log( 'database', 'medium', "Attempting to change prefix from {$old_prefix} to {$new_prefix}" );

		// Get all tables with old prefix
		$tables = $wpdb->get_results( "SHOW TABLES LIKE '{$old_prefix}%'", ARRAY_N );

		if ( empty( $tables ) ) {
			return array(
				'success' => false,
				'message' => 'No tables found with current prefix',
			);
		}

		// Rename tables
		foreach ( $tables as $table ) {
			$old_table = $table[0];
			$new_table = str_replace( $old_prefix, $new_prefix, $old_table );

			// Validate table names to prevent SQL injection
			if ( ! preg_match( '/^[a-zA-Z0-9_]+$/', $old_table ) || ! preg_match( '/^[a-zA-Z0-9_]+$/', $new_table ) ) {
				$this->logger->log(
					'database',
					'high',
					"Invalid table name detected during prefix change: {$old_table} -> {$new_table}",
					array(
						'old_table' => $old_table,
						'new_table' => $new_table,
					)
				);
				continue;
			}

			$result = $wpdb->query( "RENAME TABLE `{$old_table}` TO `{$new_table}`" );

			if ( false === $result ) {
				$this->logger->log( 'database', 'high', "Failed to rename table {$old_table}" );
				// Attempt rollback
				$this->rollback_prefix_change( $old_prefix, $new_prefix );
				return array(
					'success' => false,
					'message' => "Failed to rename table {$old_table}",
				);
			}
		}

		// Update wp-config.php
		$config_updated = $this->update_wp_config_prefix( $new_prefix );
		if ( ! $config_updated ) {
			// Rollback table changes
			$this->rollback_prefix_change( $old_prefix, $new_prefix );
			return array(
				'success' => false,
				'message' => 'Failed to update wp-config.php',
			);
		}

		// Update options table references
		$this->update_option_references( $old_prefix, $new_prefix );

		// Update user meta references
		$this->update_user_meta_references( $old_prefix, $new_prefix );

		$this->logger->log( 'database', 'medium', "Successfully changed prefix from {$old_prefix} to {$new_prefix}" );

		return array(
			'success' => true,
			'message' => 'Database prefix changed successfully',
			'old_prefix' => $old_prefix,
			'new_prefix' => $new_prefix,
		);
	}

	/**
	 * Update wp-config.php with new prefix
	 *
	 * @param string $new_prefix New table prefix.
	 * @return bool
	 * @since 1.0.0
	 */
	private function update_wp_config_prefix( $new_prefix ) {
		$config_file = ABSPATH . 'wp-config.php';
		
		// Check if one level up (common for Bedrock and similar setups)
		if ( ! file_exists( $config_file ) ) {
			$config_file = dirname( ABSPATH ) . '/wp-config.php';
		}

		if ( ! file_exists( $config_file ) || ! is_writable( $config_file ) ) {
			return false;
		}

		$config_content = file_get_contents( $config_file );
		if ( false === $config_content ) {
			return false;
		}

		// Replace table prefix
		$pattern = '/(\$table_prefix\s*=\s*[\'"]).+?([\'"];)/';
		$replacement = '${1}' . $new_prefix . '${2}';
		$new_content = preg_replace( $pattern, $replacement, $config_content );

		if ( null === $new_content || $new_content === $config_content ) {
			return false;
		}

		return false !== file_put_contents( $config_file, $new_content );
	}

	/**
	 * Update option references with new prefix
	 *
	 * @param string $old_prefix Old table prefix.
	 * @param string $new_prefix New table prefix.
	 * @since 1.0.0
	 */
	private function update_option_references( $old_prefix, $new_prefix ) {
		global $wpdb;

		$options_table = $new_prefix . 'options';

		// Update user roles option
		$wpdb->update(
			$options_table,
			array( 'option_name' => $new_prefix . 'user_roles' ),
			array( 'option_name' => $old_prefix . 'user_roles' )
		);
	}

	/**
	 * Update user meta references with new prefix
	 *
	 * @param string $old_prefix Old table prefix.
	 * @param string $new_prefix New table prefix.
	 * @since 1.0.0
	 */
	private function update_user_meta_references( $old_prefix, $new_prefix ) {
		global $wpdb;

		$usermeta_table = $new_prefix . 'usermeta';

		// Update user capabilities and user level meta keys
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$usermeta_table} SET meta_key = REPLACE(meta_key, %s, %s) WHERE meta_key LIKE %s",
				$old_prefix,
				$new_prefix,
				$old_prefix . '%'
			)
		);
	}

	/**
	 * Rollback prefix change
	 *
	 * @param string $old_prefix Old prefix to restore.
	 * @param string $new_prefix New prefix to revert.
	 * @return bool
	 * @since 1.0.0
	 */
	private function rollback_prefix_change( $old_prefix, $new_prefix ) {
		global $wpdb;

		$this->logger->log( 'database', 'high', "Rolling back prefix change from {$new_prefix} to {$old_prefix}" );

		$tables = $wpdb->get_results( "SHOW TABLES LIKE '{$new_prefix}%'", ARRAY_N );

		foreach ( $tables as $table ) {
			$new_table = $table[0];
			$old_table = str_replace( $new_prefix, $old_prefix, $new_table );
			
			// Validate table names to prevent SQL injection
			if ( ! preg_match( '/^[a-zA-Z0-9_]+$/', $old_table ) || ! preg_match( '/^[a-zA-Z0-9_]+$/', $new_table ) ) {
				continue;
			}
			
			$wpdb->query( "RENAME TABLE `{$new_table}` TO `{$old_table}`" );
		}

		return true;
	}

	/**
	 * Create full database backup
	 *
	 * @return array Result with success status and message
	 * @since 1.0.0
	 */
	public function backup_database() {
		global $wpdb;

		// Check memory limit
		$available_memory = $this->get_available_memory();
		if ( $available_memory < 50 * 1024 * 1024 ) { // 50MB minimum
			return array(
				'success' => false,
				'message' => 'Insufficient memory for backup operation',
			);
		}

		$timestamp = date( 'Y-m-d_H-i-s' );
		$filename  = 'backup_' . $timestamp . '.sql';
		$filepath  = $this->backup_dir . '/' . $filename;

		$this->logger->log( 'database', 'low', 'Starting database backup: ' . $filename );

		// Open file for writing
		$handle = fopen( $filepath, 'w' );
		if ( false === $handle ) {
			return array(
				'success' => false,
				'message' => 'Failed to create backup file',
			);
		}

		// Write header
		fwrite( $handle, "-- WordPress Database Backup\n" );
		fwrite( $handle, "-- Created: " . current_time( 'mysql' ) . "\n" );
		fwrite( $handle, "-- Host: " . DB_HOST . "\n" );
		fwrite( $handle, "-- Database: " . DB_NAME . "\n\n" );
		fwrite( $handle, "SET SQL_MODE = \"NO_AUTO_VALUE_ON_ZERO\";\n" );
		fwrite( $handle, "SET time_zone = \"+00:00\";\n\n" );

		// Get all tables
		$tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );

		foreach ( $tables as $table ) {
			$table_name = $table[0];

			// Get table structure
			$create_table = $wpdb->get_row( "SHOW CREATE TABLE `{$table_name}`", ARRAY_N );
			fwrite( $handle, "\n\n-- Table structure for `{$table_name}`\n" );
			fwrite( $handle, "DROP TABLE IF EXISTS `{$table_name}`;\n" );
			fwrite( $handle, $create_table[1] . ";\n\n" );

			// Get table data in chunks
			$row_count = $wpdb->get_var( "SELECT COUNT(*) FROM `{$table_name}`" );
			$chunk_size = 1000;
			$chunks = ceil( $row_count / $chunk_size );

			fwrite( $handle, "-- Data for `{$table_name}`\n" );

			for ( $i = 0; $i < $chunks; $i++ ) {
				$offset = $i * $chunk_size;
				$rows = $wpdb->get_results( "SELECT * FROM `{$table_name}` LIMIT {$chunk_size} OFFSET {$offset}", ARRAY_A );

				foreach ( $rows as $row ) {
					$values = array();
					foreach ( $row as $value ) {
						if ( null === $value ) {
							$values[] = 'NULL';
						} else {
							$values[] = "'" . $wpdb->_real_escape( $value ) . "'";
						}
					}
					$insert = "INSERT INTO `{$table_name}` VALUES (" . implode( ', ', $values ) . ");\n";
					fwrite( $handle, $insert );
				}
			}
		}

		fclose( $handle );

		// Get file size
		$filesize = filesize( $filepath );

		// Encrypt if enabled
		$is_encrypted = false;
		if ( $this->settings->get( 'db_backup_encryption' ) ) {
			$encryption_key = $this->get_encryption_key();
			$encrypted_file = $filepath . '.enc';
			
			if ( $this->encrypt_backup( $filepath, $encrypted_file, $encryption_key ) ) {
				unlink( $filepath );
				$filepath = $encrypted_file;
				$filename = basename( $encrypted_file );
				$filesize = filesize( $filepath );
				$is_encrypted = true;
			}
		}

		// Compress
		if ( function_exists( 'gzopen' ) ) {
			$compressed_file = $filepath . '.gz';
			$gz = gzopen( $compressed_file, 'w9' );
			if ( $gz ) {
				gzwrite( $gz, file_get_contents( $filepath ) );
				gzclose( $gz );
				unlink( $filepath );
				$filepath = $compressed_file;
				$filename = basename( $compressed_file );
				$filesize = filesize( $filepath );
			}
		}

		// Save backup metadata
		$retention_days = intval( $this->settings->get( 'db_backup_retention', 30 ) );
		$expires_at = date( 'Y-m-d H:i:s', strtotime( "+{$retention_days} days" ) );

		$wpdb->insert(
			$wpdb->prefix . 'wph_backups',
			array(
				'backup_file' => $filename,
				'backup_size' => $filesize,
				'is_encrypted' => $is_encrypted ? 1 : 0,
				'created_at' => current_time( 'mysql' ),
				'expires_at' => $expires_at,
			)
		);

		$backup_id = $wpdb->insert_id;

		$this->logger->log( 'database', 'low', 'Database backup completed: ' . $filename );

		// Rotate old backups
		$this->rotate_backups();

		return array(
			'success' => true,
			'message' => 'Database backup created successfully',
			'backup_id' => $backup_id,
			'filename' => $filename,
			'size' => $filesize,
		);
	}

	/**
	 * Encrypt backup file
	 *
	 * @param string $source_file Source file path.
	 * @param string $dest_file Destination file path.
	 * @param string $password Encryption password.
	 * @return bool
	 * @since 1.0.0
	 */
	public function encrypt_backup( $source_file, $dest_file, $password ) {
		if ( ! file_exists( $source_file ) ) {
			return false;
		}

		$data = file_get_contents( $source_file );
		if ( false === $data ) {
			return false;
		}

		$method = 'AES-256-CBC';
		$key = hash( 'sha256', $password, true );
		$iv = openssl_random_pseudo_bytes( openssl_cipher_iv_length( $method ) );

		$encrypted = openssl_encrypt( $data, $method, $key, 0, $iv );
		if ( false === $encrypted ) {
			return false;
		}

		// Prepend IV to encrypted data
		$encrypted_data = base64_encode( $iv . base64_decode( $encrypted ) );

		return false !== file_put_contents( $dest_file, $encrypted_data );
	}

	/**
	 * Decrypt backup file
	 *
	 * @param string $source_file Source encrypted file path.
	 * @param string $dest_file Destination file path.
	 * @param string $password Decryption password.
	 * @return bool
	 * @since 1.0.0
	 */
	public function decrypt_backup( $source_file, $dest_file, $password ) {
		if ( ! file_exists( $source_file ) ) {
			return false;
		}

		$encrypted_data = file_get_contents( $source_file );
		if ( false === $encrypted_data ) {
			return false;
		}

		$method = 'AES-256-CBC';
		$key = hash( 'sha256', $password, true );
		$iv_length = openssl_cipher_iv_length( $method );

		$decoded = base64_decode( $encrypted_data );
		$iv = substr( $decoded, 0, $iv_length );
		$encrypted = base64_encode( substr( $decoded, $iv_length ) );

		$decrypted = openssl_decrypt( $encrypted, $method, $key, 0, $iv );
		if ( false === $decrypted ) {
			return false;
		}

		return false !== file_put_contents( $dest_file, $decrypted );
	}

	/**
	 * Restore database from backup
	 *
	 * @param int $backup_id Backup ID.
	 * @return array Result with success status and message
	 * @since 1.0.0
	 */
	public function restore_backup( $backup_id ) {
		global $wpdb;

		// Get backup info
		$backup = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}wph_backups WHERE id = %d",
				$backup_id
			)
		);

		if ( ! $backup ) {
			return array(
				'success' => false,
				'message' => 'Backup not found',
			);
		}

		$backup_file = $this->backup_dir . '/' . $backup->backup_file;

		if ( ! file_exists( $backup_file ) ) {
			return array(
				'success' => false,
				'message' => 'Backup file not found',
			);
		}

		// Create a safety backup before restore
		$this->backup_database();

		$this->logger->log( 'database', 'high', 'Starting database restore from: ' . $backup->backup_file );

		// Decompress if needed
		$working_file = $backup_file;
		if ( substr( $backup_file, -3 ) === '.gz' ) {
			$working_file = $this->backup_dir . '/restore_temp.sql';
			$gz = gzopen( $backup_file, 'r' );
			$fp = fopen( $working_file, 'w' );
			if ( $gz && $fp ) {
				while ( ! gzeof( $gz ) ) {
					fwrite( $fp, gzread( $gz, 4096 ) );
				}
				gzclose( $gz );
				fclose( $fp );
			} else {
				return array(
					'success' => false,
					'message' => 'Failed to decompress backup',
				);
			}
		}

		// Decrypt if needed
		if ( $backup->is_encrypted ) {
			$encrypted_file = $working_file;
			$working_file = $this->backup_dir . '/restore_decrypted.sql';
			$encryption_key = $this->get_encryption_key();
			
			if ( ! $this->decrypt_backup( $encrypted_file, $working_file, $encryption_key ) ) {
				return array(
					'success' => false,
					'message' => 'Failed to decrypt backup',
				);
			}
		}

		// Execute SQL file
		$sql_content = file_get_contents( $working_file );
		if ( false === $sql_content ) {
			return array(
				'success' => false,
				'message' => 'Failed to read backup file',
			);
		}

		// Split queries and execute
		$queries = array_filter( array_map( 'trim', explode( ";\n", $sql_content ) ) );
		
		foreach ( $queries as $query ) {
			if ( empty( $query ) || strpos( $query, '--' ) === 0 ) {
				continue;
			}
			
			$result = $wpdb->query( $query );
			if ( false === $result && ! empty( $wpdb->last_error ) ) {
				$this->logger->log( 'database', 'high', 'Restore query failed: ' . $wpdb->last_error );
			}
		}

		// Clean up temp files
		if ( $working_file !== $backup_file ) {
			unlink( $working_file );
		}

		$this->logger->log( 'database', 'medium', 'Database restore completed from: ' . $backup->backup_file );

		return array(
			'success' => true,
			'message' => 'Database restored successfully',
		);
	}

	/**
	 * Optimize all database tables
	 *
	 * @return array Result with success status and message
	 * @since 1.0.0
	 */
	public function optimize_tables() {
		global $wpdb;

		$this->logger->log( 'database', 'low', 'Starting database optimization' );

		$tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );
		$optimized = 0;

		foreach ( $tables as $table ) {
			$table_name = $table[0];
			$result = $wpdb->query( "OPTIMIZE TABLE `{$table_name}`" );
			if ( false !== $result ) {
				$optimized++;
			}
		}

		$this->logger->log( 'database', 'low', "Optimized {$optimized} tables" );

		return array(
			'success' => true,
			'message' => "Optimized {$optimized} tables",
			'count' => $optimized,
		);
	}

	/**
	 * Repair corrupted database tables
	 *
	 * @return array Result with success status and message
	 * @since 1.0.0
	 */
	public function repair_tables() {
		global $wpdb;

		$this->logger->log( 'database', 'medium', 'Starting table repair' );

		$tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );
		$repaired = 0;

		foreach ( $tables as $table ) {
			$table_name = $table[0];
			$check = $wpdb->get_row( "CHECK TABLE `{$table_name}`", ARRAY_A );
			
			if ( isset( $check['Msg_text'] ) && 'OK' !== $check['Msg_text'] ) {
				$result = $wpdb->query( "REPAIR TABLE `{$table_name}`" );
				if ( false !== $result ) {
					$repaired++;
					$this->logger->log( 'database', 'medium', "Repaired table: {$table_name}" );
				}
			}
		}

		return array(
			'success' => true,
			'message' => "Repaired {$repaired} tables",
			'count' => $repaired,
		);
	}

	/**
	 * Cleanup old post revisions
	 *
	 * @param int $limit Number of revisions to keep per post.
	 * @return array Result with success status and message
	 * @since 1.0.0
	 */
	public function cleanup_revisions( $limit = 5 ) {
		global $wpdb;

		$this->logger->log( 'database', 'low', "Cleaning up post revisions, keeping last {$limit}" );

		// Get all posts with revisions
		$posts = $wpdb->get_results(
			"SELECT ID FROM {$wpdb->posts} WHERE post_type NOT IN ('revision', 'attachment')"
		);

		$deleted = 0;

		foreach ( $posts as $post ) {
			$revisions = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT ID FROM {$wpdb->posts} 
					WHERE post_parent = %d 
					AND post_type = 'revision' 
					ORDER BY post_modified DESC",
					$post->ID
				)
			);

			if ( count( $revisions ) > $limit ) {
				$revisions_to_delete = array_slice( $revisions, $limit );
				
				foreach ( $revisions_to_delete as $revision ) {
					wp_delete_post_revision( $revision->ID );
					$deleted++;
				}
			}
		}

		$this->logger->log( 'database', 'low', "Deleted {$deleted} post revisions" );

		return array(
			'success' => true,
			'message' => "Deleted {$deleted} post revisions",
			'count' => $deleted,
		);
	}

	/**
	 * Cleanup spam comments
	 *
	 * @return array Result with success status and message
	 * @since 1.0.0
	 */
	public function cleanup_spam() {
		global $wpdb;

		$this->logger->log( 'database', 'low', 'Cleaning up spam comments' );

		$deleted = $wpdb->query(
			"DELETE FROM {$wpdb->comments} WHERE comment_approved = 'spam'"
		);

		$this->logger->log( 'database', 'low', "Deleted {$deleted} spam comments" );

		return array(
			'success' => true,
			'message' => "Deleted {$deleted} spam comments",
			'count' => $deleted,
		);
	}

	/**
	 * Cleanup expired transients
	 *
	 * @return array Result with success status and message
	 * @since 1.0.0
	 */
	public function cleanup_transients() {
		global $wpdb;

		$this->logger->log( 'database', 'low', 'Cleaning up expired transients' );

		$time = time();
		$deleted = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} 
				WHERE option_name LIKE %s 
				AND option_value < %d",
				$wpdb->esc_like( '_transient_timeout_' ) . '%',
				$time
			)
		);

		// Delete corresponding transient options
		$wpdb->query(
			"DELETE FROM {$wpdb->options} 
			WHERE option_name LIKE '_transient_%' 
			AND option_name NOT LIKE '_transient_timeout_%' 
			AND option_name NOT IN (
				SELECT REPLACE(option_name, '_transient_timeout_', '_transient_') 
				FROM {$wpdb->options} 
				WHERE option_name LIKE '_transient_timeout_%'
			)"
		);

		$this->logger->log( 'database', 'low', "Deleted {$deleted} expired transients" );

		return array(
			'success' => true,
			'message' => "Deleted expired transients",
			'count' => $deleted,
		);
	}

	/**
	 * Analyze table statistics
	 *
	 * @return array Result with success status and message
	 * @since 1.0.0
	 */
	public function analyze_tables() {
		global $wpdb;

		$tables = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );
		$analyzed = 0;

		foreach ( $tables as $table ) {
			$table_name = $table[0];
			$result = $wpdb->query( "ANALYZE TABLE `{$table_name}`" );
			if ( false !== $result ) {
				$analyzed++;
			}
		}

		return array(
			'success' => true,
			'message' => "Analyzed {$analyzed} tables",
			'count' => $analyzed,
		);
	}

	/**
	 * Monitor database query
	 *
	 * @param string $query SQL query.
	 * @return string Filtered query
	 * @since 1.0.0
	 */
	public function monitor_query( $query ) {
		// Check for suspicious patterns
		$is_suspicious = $this->detect_suspicious_query( $query );
		
		if ( $is_suspicious ) {
			$this->logger->log(
				'database',
				'high',
				'Suspicious query detected: ' . substr( $query, 0, 200 ),
				array( 'query' => $query )
			);

			// Block if enabled
			if ( $this->settings->get( 'db_security_enabled' ) ) {
				return 'SELECT 1';  // Return harmless query
			}
		}

		// Log slow queries
		$threshold = floatval( $this->settings->get( 'db_slow_query_threshold', 2.0 ) );
		$start_time = microtime( true );
		
		register_shutdown_function( function() use ( $query, $start_time, $threshold ) {
			$execution_time = microtime( true ) - $start_time;
			if ( $execution_time > $threshold ) {
				$this->logger->log(
					'database',
					'medium',
					sprintf( 'Slow query detected (%.2fs): %s', $execution_time, substr( $query, 0, 200 ) ),
					array(
						'query' => $query,
						'execution_time' => $execution_time,
					)
				);
			}
		} );

		return $query;
	}

	/**
	 * Detect suspicious SQL query patterns
	 *
	 * @param string $query SQL query.
	 * @return bool True if suspicious
	 * @since 1.0.0
	 */
	public function detect_suspicious_query( $query ) {
		foreach ( $this->suspicious_patterns as $pattern ) {
			if ( preg_match( $pattern, $query ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get total database size
	 *
	 * @return int Size in bytes
	 * @since 1.0.0
	 */
	public function get_database_size() {
		global $wpdb;

		$result = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT SUM(data_length + index_length) 
				FROM information_schema.TABLES 
				WHERE table_schema = %s",
				DB_NAME
			)
		);

		return intval( $result );
	}

	/**
	 * Get size for each table
	 *
	 * @return array Table sizes
	 * @since 1.0.0
	 */
	public function get_table_sizes() {
		global $wpdb;

		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT table_name AS name, 
				(data_length + index_length) AS size,
				table_rows AS rows
				FROM information_schema.TABLES 
				WHERE table_schema = %s 
				ORDER BY (data_length + index_length) DESC",
				DB_NAME
			)
		);

		return $results;
	}

	/**
	 * Rotate old backups based on retention policy
	 *
	 * @since 1.0.0
	 */
	public function rotate_backups() {
		global $wpdb;

		// Delete expired backups
		$expired = $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}wph_backups 
			WHERE expires_at < NOW()"
		);

		foreach ( $expired as $backup ) {
			$filepath = $this->backup_dir . '/' . $backup->backup_file;
			if ( file_exists( $filepath ) ) {
				unlink( $filepath );
			}
			$wpdb->delete( $wpdb->prefix . 'wph_backups', array( 'id' => $backup->id ) );
		}

		// Keep only last N backups if needed
		$max_backups = 10;
		$total = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}wph_backups" );
		
		if ( $total > $max_backups ) {
			$to_delete = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT * FROM {$wpdb->prefix}wph_backups 
					ORDER BY created_at ASC 
					LIMIT %d",
					$total - $max_backups
				)
			);

			foreach ( $to_delete as $backup ) {
				$filepath = $this->backup_dir . '/' . $backup->backup_file;
				if ( file_exists( $filepath ) ) {
					unlink( $filepath );
				}
				$wpdb->delete( $wpdb->prefix . 'wph_backups', array( 'id' => $backup->id ) );
			}
		}
	}

	/**
	 * Schedule database backup
	 *
	 * @since 1.0.0
	 */
	public function schedule_backup() {
		if ( ! $this->settings->get( 'db_backup_enabled' ) ) {
			return;
		}

		$schedule = $this->settings->get( 'db_backup_schedule', 'daily' );

		if ( ! wp_next_scheduled( 'wph_database_backup' ) ) {
			wp_schedule_event( time(), $schedule, 'wph_database_backup' );
		}
	}

	/**
	 * Scheduled backup callback
	 *
	 * @since 1.0.0
	 */
	public function scheduled_backup() {
		if ( $this->settings->get( 'db_backup_enabled' ) ) {
			$this->backup_database();
		}
	}

	/**
	 * Scheduled cleanup callback
	 *
	 * @since 1.0.0
	 */
	public function scheduled_cleanup() {
		if ( $this->settings->get( 'db_optimization_enabled' ) ) {
			$max_revisions = intval( $this->settings->get( 'db_max_revisions', 5 ) );
			
			if ( $this->settings->get( 'db_cleanup_revisions' ) ) {
				$this->cleanup_revisions( $max_revisions );
			}
			
			$this->cleanup_spam();
			$this->cleanup_transients();
		}
	}

	/**
	 * Get available backups
	 *
	 * @return array List of backups
	 * @since 1.0.0
	 */
	public function get_backups() {
		global $wpdb;

		return $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}wph_backups 
			ORDER BY created_at DESC"
		);
	}

	/**
	 * Get encryption key
	 *
	 * @return string Encryption key
	 * @since 1.0.0
	 */
	private function get_encryption_key() {
		$key = $this->settings->get( 'db_backup_encryption_key' );
		
		if ( empty( $key ) ) {
			$key = wp_generate_password( 64, true, true );
			$this->settings->set( 'db_backup_encryption_key', $key );
		}

		return $key;
	}

	/**
	 * Get available memory
	 *
	 * @return int Available memory in bytes
	 * @since 1.0.0
	 */
	private function get_available_memory() {
		$memory_limit = ini_get( 'memory_limit' );
		
		if ( preg_match( '/^(\d+)(.)$/', $memory_limit, $matches ) ) {
			$value = intval( $matches[1] );
			$unit = strtoupper( $matches[2] );
			
			switch ( $unit ) {
				case 'G':
					$value *= 1024 * 1024 * 1024;
					break;
				case 'M':
					$value *= 1024 * 1024;
					break;
				case 'K':
					$value *= 1024;
					break;
			}
			
			return $value - memory_get_usage();
		}

		return 0;
	}
}
