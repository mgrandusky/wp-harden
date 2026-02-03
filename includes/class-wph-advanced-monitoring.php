<?php
/**
 * Advanced Monitoring Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Advanced_Monitoring
 *
 * Provides real-time security monitoring, audit trails, and reporting
 */
class WPH_Advanced_Monitoring {

	/**
	 * Singleton instance
	 *
	 * @var WPH_Advanced_Monitoring
	 */
	private static $instance = null;

	/**
	 * Table name for audit trail
	 *
	 * @var string
	 */
	private $audit_table;

	/**
	 * Get singleton instance
	 *
	 * @return WPH_Advanced_Monitoring
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
		$this->audit_table = $wpdb->prefix . 'wph_audit_trail';
		$this->init_hooks();
	}

	/**
	 * Initialize hooks
	 *
	 * @since 1.0.0
	 */
	private function init_hooks() {
		// Admin action hooks
		add_action( 'activated_plugin', array( $this, 'log_plugin_activation' ), 10, 2 );
		add_action( 'deactivated_plugin', array( $this, 'log_plugin_deactivation' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( $this, 'log_update_complete' ), 10, 2 );
		add_action( 'switch_theme', array( $this, 'log_theme_change' ), 10, 3 );
		add_action( 'deleted_plugin', array( $this, 'log_plugin_deletion' ), 10, 2 );
		add_action( 'deleted_theme', array( $this, 'log_theme_deletion' ) );
		
		// User action hooks
		add_action( 'user_register', array( $this, 'log_user_creation' ) );
		add_action( 'delete_user', array( $this, 'log_user_deletion' ) );
		add_action( 'set_user_role', array( $this, 'log_role_change' ), 10, 3 );
		add_action( 'profile_update', array( $this, 'log_profile_update' ), 10, 2 );
		
		// Post/page action hooks
		add_action( 'save_post', array( $this, 'log_post_save' ), 10, 3 );
		add_action( 'before_delete_post', array( $this, 'log_post_deletion' ) );
		add_action( 'add_attachment', array( $this, 'log_media_upload' ) );
		
		// Settings changes
		add_action( 'update_option', array( $this, 'log_option_update' ), 10, 3 );
		
		// Scheduled tasks
		add_action( 'wph_daily_security_report', array( $this, 'send_daily_report' ) );
		add_action( 'wph_weekly_security_report', array( $this, 'send_weekly_report' ) );
		
		// Track page views for admin users
		add_action( 'admin_init', array( $this, 'track_admin_page_view' ) );
	}

	/**
	 * Create audit trail table
	 *
	 * @since 1.0.0
	 */
	public function create_table() {
		global $wpdb;
		
		$charset_collate = $wpdb->get_charset_collate();
		
		$sql = "CREATE TABLE IF NOT EXISTS {$this->audit_table} (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			user_id bigint(20) NOT NULL,
			action varchar(100) NOT NULL,
			object_type varchar(50) NOT NULL,
			object_id bigint(20) DEFAULT NULL,
			old_value longtext DEFAULT NULL,
			new_value longtext DEFAULT NULL,
			ip_address varchar(45) NOT NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY user_id (user_id),
			KEY action (action),
			KEY created_at (created_at)
		) $charset_collate;";
		
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Log admin action
	 *
	 * @param string $action      Action performed.
	 * @param string $object_type Type of object affected.
	 * @param int    $object_id   Object ID.
	 * @param mixed  $old_value   Previous value.
	 * @param mixed  $new_value   New value.
	 * @return int|false Insert ID or false on failure
	 * @since 1.0.0
	 */
	public function log_admin_action( $action, $object_type, $object_id = null, $old_value = null, $new_value = null ) {
		global $wpdb;
		
		$data = array(
			'user_id'     => get_current_user_id(),
			'action'      => sanitize_text_field( $action ),
			'object_type' => sanitize_text_field( $object_type ),
			'object_id'   => $object_id ? absint( $object_id ) : null,
			'old_value'   => is_array( $old_value ) || is_object( $old_value ) ? wp_json_encode( $old_value ) : $old_value,
			'new_value'   => is_array( $new_value ) || is_object( $new_value ) ? wp_json_encode( $new_value ) : $new_value,
			'ip_address'  => $this->get_client_ip(),
			'created_at'  => current_time( 'mysql' ),
		);
		
		$result = $wpdb->insert( $this->audit_table, $data );
		
		return $result ? $wpdb->insert_id : false;
	}

	/**
	 * Track user activity
	 *
	 * @param int    $user_id       User ID.
	 * @param string $activity_type Activity type.
	 * @param array  $data          Activity data.
	 * @return int|false
	 * @since 1.0.0
	 */
	public function track_user_activity( $user_id, $activity_type, $data = array() ) {
		return $this->log_admin_action(
			$activity_type,
			'user_activity',
			$user_id,
			null,
			$data
		);
	}

	/**
	 * Get security score (0-100)
	 *
	 * @return int Security score
	 * @since 1.0.0
	 */
	public function get_security_score() {
		$score = 100;
		$settings = WPH_Settings::get_instance();
		
		// Check firewall status
		if ( ! $settings->get( 'firewall_enabled', true ) ) {
			$score -= 15;
		}
		
		// Check login security
		if ( ! $settings->get( 'login_security_enabled', true ) ) {
			$score -= 15;
		}
		
		// Check recent threats
		$threats = $this->get_active_threats( 24 );
		if ( $threats > 10 ) {
			$score -= min( 20, $threats );
		}
		
		// Check failed logins
		$failed_logins = $this->get_failed_login_count( 24 );
		if ( $failed_logins > 50 ) {
			$score -= 10;
		}
		
		// Check for outdated plugins/themes
		$outdated = $this->check_outdated_components();
		$score -= min( 15, $outdated * 3 );
		
		// Check SSL
		if ( ! is_ssl() ) {
			$score -= 10;
		}
		
		// Check file integrity
		if ( ! $settings->get( 'file_integrity_enabled', false ) ) {
			$score -= 10;
		}
		
		return max( 0, $score );
	}

	/**
	 * Get active threats count
	 *
	 * @param int $hours Timeframe in hours.
	 * @return int Number of threats
	 * @since 1.0.0
	 */
	public function get_active_threats( $hours = 24 ) {
		global $wpdb;
		
		$logs_table = $wpdb->prefix . 'wph_logs';
		$since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$hours} hours" ) );
		
		$count = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$logs_table} 
			WHERE severity IN ('high', 'critical') 
			AND created_at >= %s",
			$since
		) );
		
		return absint( $count );
	}

	/**
	 * Detect failed authentication patterns
	 *
	 * @return array Detected patterns
	 * @since 1.0.0
	 */
	public function detect_failed_auth_pattern() {
		global $wpdb;
		
		$logs_table = $wpdb->prefix . 'wph_logs';
		$since = gmdate( 'Y-m-d H:i:s', strtotime( '-1 hour' ) );
		
		// Get failed login attempts grouped by IP
		$results = $wpdb->get_results( $wpdb->prepare(
			"SELECT ip_address, COUNT(*) as attempts
			FROM {$logs_table}
			WHERE log_type = 'login'
			AND severity = 'high'
			AND message LIKE %s
			AND created_at >= %s
			GROUP BY ip_address
			HAVING attempts > 5
			ORDER BY attempts DESC",
			'%failed%',
			$since
		), ARRAY_A );
		
		$patterns = array();
		
		foreach ( $results as $row ) {
			$patterns[] = array(
				'type'      => 'brute_force',
				'ip'        => $row['ip_address'],
				'attempts'  => $row['attempts'],
				'severity'  => $row['attempts'] > 20 ? 'critical' : 'high',
				'timeframe' => '1 hour',
			);
		}
		
		// Check for distributed attacks
		$total_failed = array_sum( wp_list_pluck( $results, 'attempts' ) );
		$unique_ips = count( $results );
		
		if ( $unique_ips > 10 && $total_failed > 50 ) {
			$patterns[] = array(
				'type'      => 'distributed_attack',
				'unique_ips' => $unique_ips,
				'total_attempts' => $total_failed,
				'severity'  => 'critical',
			);
		}
		
		return $patterns;
	}

	/**
	 * Generate security report
	 *
	 * @param string $period Report period (daily, weekly, monthly).
	 * @return array Report data
	 * @since 1.0.0
	 */
	public function generate_security_report( $period = 'daily' ) {
		$hours = array(
			'daily'   => 24,
			'weekly'  => 168,
			'monthly' => 720,
		);
		
		$timeframe = isset( $hours[ $period ] ) ? $hours[ $period ] : 24;
		
		$report = array(
			'period'        => $period,
			'generated_at'  => current_time( 'mysql' ),
			'security_score' => $this->get_security_score(),
			'threats'       => $this->get_threats_summary( $timeframe ),
			'failed_logins' => $this->get_failed_login_count( $timeframe ),
			'blocked_ips'   => $this->get_blocked_ips_count(),
			'audit_events'  => $this->get_audit_events_count( $timeframe ),
			'top_threats'   => $this->get_top_threat_types( $timeframe ),
			'patterns'      => $this->detect_failed_auth_pattern(),
		);
		
		return $report;
	}

	/**
	 * Schedule security reports
	 *
	 * @since 1.0.0
	 */
	public function schedule_reports() {
		if ( ! wp_next_scheduled( 'wph_daily_security_report' ) ) {
			wp_schedule_event( time(), 'daily', 'wph_daily_security_report' );
		}
		
		if ( ! wp_next_scheduled( 'wph_weekly_security_report' ) ) {
			wp_schedule_event( time(), 'weekly', 'wph_weekly_security_report' );
		}
	}

	/**
	 * Send security report
	 *
	 * @param array  $report_data Report data.
	 * @param array  $recipients  Email recipients.
	 * @return bool
	 * @since 1.0.0
	 */
	public function send_security_report( $report_data, $recipients = array() ) {
		$settings = WPH_Settings::get_instance();
		
		if ( empty( $recipients ) ) {
			$recipients = array( $settings->get( 'notification_email', get_option( 'admin_email' ) ) );
		}
		
		$subject = sprintf(
			'[%s] %s Security Report - %s',
			get_bloginfo( 'name' ),
			ucfirst( $report_data['period'] ),
			gmdate( 'Y-m-d' )
		);
		
		$body = $this->format_report_email( $report_data );
		$headers = array( 'Content-Type: text/html; charset=UTF-8' );
		
		$sent = true;
		foreach ( $recipients as $recipient ) {
			if ( ! wp_mail( $recipient, $subject, $body, $headers ) ) {
				$sent = false;
			}
		}
		
		return $sent;
	}

	/**
	 * Send daily security report
	 *
	 * @since 1.0.0
	 */
	public function send_daily_report() {
		$settings = WPH_Settings::get_instance();
		
		if ( ! $settings->get( 'daily_reports_enabled', false ) ) {
			return;
		}
		
		$report = $this->generate_security_report( 'daily' );
		$this->send_security_report( $report );
	}

	/**
	 * Send weekly security report
	 *
	 * @since 1.0.0
	 */
	public function send_weekly_report() {
		$settings = WPH_Settings::get_instance();
		
		if ( ! $settings->get( 'weekly_reports_enabled', false ) ) {
			return;
		}
		
		$report = $this->generate_security_report( 'weekly' );
		$this->send_security_report( $report );
	}

	/**
	 * Log plugin activation
	 *
	 * @param string $plugin       Plugin path.
	 * @param bool   $network_wide Network activation.
	 * @since 1.0.0
	 */
	public function log_plugin_activation( $plugin, $network_wide ) {
		$this->log_admin_action(
			'plugin_activated',
			'plugin',
			null,
			null,
			array(
				'plugin'       => $plugin,
				'network_wide' => $network_wide,
			)
		);
	}

	/**
	 * Log plugin deactivation
	 *
	 * @param string $plugin       Plugin path.
	 * @param bool   $network_wide Network deactivation.
	 * @since 1.0.0
	 */
	public function log_plugin_deactivation( $plugin, $network_wide ) {
		$this->log_admin_action(
			'plugin_deactivated',
			'plugin',
			null,
			null,
			array(
				'plugin'       => $plugin,
				'network_wide' => $network_wide,
			)
		);
	}

	/**
	 * Log update completion
	 *
	 * @param WP_Upgrader $upgrader WP_Upgrader instance.
	 * @param array       $options  Update options.
	 * @since 1.0.0
	 */
	public function log_update_complete( $upgrader, $options ) {
		$this->log_admin_action(
			'update_completed',
			$options['type'],
			null,
			null,
			$options
		);
	}

	/**
	 * Log theme change
	 *
	 * @param string   $new_name  New theme name.
	 * @param WP_Theme $new_theme New theme object.
	 * @param WP_Theme $old_theme Old theme object.
	 * @since 1.0.0
	 */
	public function log_theme_change( $new_name, $new_theme, $old_theme ) {
		$this->log_admin_action(
			'theme_switched',
			'theme',
			null,
			$old_theme->get( 'Name' ),
			$new_name
		);
	}

	/**
	 * Log plugin deletion
	 *
	 * @param string $plugin_file Plugin file.
	 * @param bool   $deleted     Whether deletion was successful.
	 * @since 1.0.0
	 */
	public function log_plugin_deletion( $plugin_file, $deleted ) {
		if ( $deleted ) {
			$this->log_admin_action(
				'plugin_deleted',
				'plugin',
				null,
				$plugin_file,
				null
			);
		}
	}

	/**
	 * Log theme deletion
	 *
	 * @param string $stylesheet Theme stylesheet.
	 * @since 1.0.0
	 */
	public function log_theme_deletion( $stylesheet ) {
		$this->log_admin_action(
			'theme_deleted',
			'theme',
			null,
			$stylesheet,
			null
		);
	}

	/**
	 * Log user creation
	 *
	 * @param int $user_id User ID.
	 * @since 1.0.0
	 */
	public function log_user_creation( $user_id ) {
		$user = get_userdata( $user_id );
		
		$this->log_admin_action(
			'user_created',
			'user',
			$user_id,
			null,
			array(
				'username' => $user->user_login,
				'email'    => $user->user_email,
				'role'     => $user->roles[0] ?? 'none',
			)
		);
	}

	/**
	 * Log user deletion
	 *
	 * @param int $user_id User ID.
	 * @since 1.0.0
	 */
	public function log_user_deletion( $user_id ) {
		$user = get_userdata( $user_id );
		
		$this->log_admin_action(
			'user_deleted',
			'user',
			$user_id,
			array(
				'username' => $user->user_login,
				'email'    => $user->user_email,
			),
			null
		);
	}

	/**
	 * Log role change
	 *
	 * @param int    $user_id  User ID.
	 * @param string $new_role New role.
	 * @param array  $old_roles Old roles.
	 * @since 1.0.0
	 */
	public function log_role_change( $user_id, $new_role, $old_roles ) {
		$this->log_admin_action(
			'user_role_changed',
			'user',
			$user_id,
			implode( ', ', $old_roles ),
			$new_role
		);
	}

	/**
	 * Log profile update
	 *
	 * @param int     $user_id       User ID.
	 * @param WP_User $old_user_data Old user data.
	 * @since 1.0.0
	 */
	public function log_profile_update( $user_id, $old_user_data ) {
		$this->log_admin_action(
			'profile_updated',
			'user',
			$user_id,
			null,
			null
		);
	}

	/**
	 * Log post save
	 *
	 * @param int     $post_id Post ID.
	 * @param WP_Post $post    Post object.
	 * @param bool    $update  Whether this is an update.
	 * @since 1.0.0
	 */
	public function log_post_save( $post_id, $post, $update ) {
		// Skip autosaves and revisions
		if ( wp_is_post_autosave( $post_id ) || wp_is_post_revision( $post_id ) ) {
			return;
		}
		
		$action = $update ? 'post_updated' : 'post_created';
		
		$this->log_admin_action(
			$action,
			$post->post_type,
			$post_id,
			null,
			array(
				'title'  => $post->post_title,
				'status' => $post->post_status,
			)
		);
	}

	/**
	 * Log post deletion
	 *
	 * @param int $post_id Post ID.
	 * @since 1.0.0
	 */
	public function log_post_deletion( $post_id ) {
		$post = get_post( $post_id );
		
		if ( $post ) {
			$this->log_admin_action(
				'post_deleted',
				$post->post_type,
				$post_id,
				array(
					'title' => $post->post_title,
				),
				null
			);
		}
	}

	/**
	 * Log media upload
	 *
	 * @param int $attachment_id Attachment ID.
	 * @since 1.0.0
	 */
	public function log_media_upload( $attachment_id ) {
		$file = get_attached_file( $attachment_id );
		
		$this->log_admin_action(
			'media_uploaded',
			'attachment',
			$attachment_id,
			null,
			array(
				'file' => basename( $file ),
				'type' => get_post_mime_type( $attachment_id ),
			)
		);
	}

	/**
	 * Log option update
	 *
	 * @param string $option    Option name.
	 * @param mixed  $old_value Old value.
	 * @param mixed  $new_value New value.
	 * @since 1.0.0
	 */
	public function log_option_update( $option, $old_value, $new_value ) {
		// Only log important options
		$important_options = array(
			'siteurl',
			'home',
			'admin_email',
			'users_can_register',
			'default_role',
			'permalink_structure',
		);
		
		if ( in_array( $option, $important_options, true ) ) {
			$this->log_admin_action(
				'option_updated',
				'option',
				null,
				$old_value,
				$new_value
			);
		}
	}

	/**
	 * Track admin page view
	 *
	 * @since 1.0.0
	 */
	public function track_admin_page_view() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		
		$settings = WPH_Settings::get_instance();
		if ( ! $settings->get( 'track_admin_activity', false ) ) {
			return;
		}
		
		global $pagenow;
		
		$this->track_user_activity(
			get_current_user_id(),
			'page_view',
			array(
				'page'      => $pagenow,
				'query_var' => isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '',
			)
		);
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

	/**
	 * Get threats summary
	 *
	 * @param int $hours Timeframe in hours.
	 * @return array Threats summary
	 * @since 1.0.0
	 */
	private function get_threats_summary( $hours ) {
		global $wpdb;
		
		$logs_table = $wpdb->prefix . 'wph_logs';
		$since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$hours} hours" ) );
		
		$results = $wpdb->get_results( $wpdb->prepare(
			"SELECT severity, COUNT(*) as count
			FROM {$logs_table}
			WHERE created_at >= %s
			GROUP BY severity",
			$since
		), ARRAY_A );
		
		$summary = array(
			'low'      => 0,
			'medium'   => 0,
			'high'     => 0,
			'critical' => 0,
		);
		
		foreach ( $results as $row ) {
			$summary[ $row['severity'] ] = absint( $row['count'] );
		}
		
		return $summary;
	}

	/**
	 * Get failed login count
	 *
	 * @param int $hours Timeframe in hours.
	 * @return int Failed login count
	 * @since 1.0.0
	 */
	private function get_failed_login_count( $hours ) {
		global $wpdb;
		
		$logs_table = $wpdb->prefix . 'wph_logs';
		$since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$hours} hours" ) );
		
		$count = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$logs_table}
			WHERE log_type = 'login'
			AND message LIKE %s
			AND created_at >= %s",
			'%failed%',
			$since
		) );
		
		return absint( $count );
	}

	/**
	 * Get blocked IPs count
	 *
	 * @return int Blocked IPs count
	 * @since 1.0.0
	 */
	private function get_blocked_ips_count() {
		global $wpdb;
		
		$ip_table = $wpdb->prefix . 'wph_blocked_ips';
		
		$count = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$ip_table} WHERE status = 'blocked'"
		);
		
		return absint( $count );
	}

	/**
	 * Get audit events count
	 *
	 * @param int $hours Timeframe in hours.
	 * @return int Events count
	 * @since 1.0.0
	 */
	private function get_audit_events_count( $hours ) {
		global $wpdb;
		
		$since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$hours} hours" ) );
		
		$count = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$this->audit_table} WHERE created_at >= %s",
			$since
		) );
		
		return absint( $count );
	}

	/**
	 * Get top threat types
	 *
	 * @param int $hours Timeframe in hours.
	 * @return array Top threats
	 * @since 1.0.0
	 */
	private function get_top_threat_types( $hours ) {
		global $wpdb;
		
		$logs_table = $wpdb->prefix . 'wph_logs';
		$since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$hours} hours" ) );
		
		$results = $wpdb->get_results( $wpdb->prepare(
			"SELECT log_type, COUNT(*) as count
			FROM {$logs_table}
			WHERE severity IN ('high', 'critical')
			AND created_at >= %s
			GROUP BY log_type
			ORDER BY count DESC
			LIMIT 5",
			$since
		), ARRAY_A );
		
		return $results;
	}

	/**
	 * Check outdated components
	 *
	 * @return int Number of outdated components
	 * @since 1.0.0
	 */
	private function check_outdated_components() {
		$outdated = 0;
		
		// Check plugins
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		
		$plugins = get_plugins();
		$updates = get_site_transient( 'update_plugins' );
		
		if ( ! empty( $updates->response ) ) {
			$outdated += count( $updates->response );
		}
		
		// Check themes
		$themes = wp_get_themes();
		$theme_updates = get_site_transient( 'update_themes' );
		
		if ( ! empty( $theme_updates->response ) ) {
			$outdated += count( $theme_updates->response );
		}
		
		return $outdated;
	}

	/**
	 * Format report email
	 *
	 * @param array $report_data Report data.
	 * @return string HTML email body
	 * @since 1.0.0
	 */
	private function format_report_email( $report_data ) {
		ob_start();
		?>
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<style>
				body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
				.container { max-width: 600px; margin: 0 auto; padding: 20px; }
				.header { background: #0073aa; color: white; padding: 20px; text-align: center; }
				.metric { padding: 15px; margin: 10px 0; border-left: 4px solid #0073aa; background: #f9f9f9; }
				.metric-label { font-weight: bold; color: #0073aa; }
				.metric-value { font-size: 24px; margin: 5px 0; }
				.score { text-align: center; font-size: 48px; font-weight: bold; margin: 20px 0; }
				.score.good { color: #46b450; }
				.score.warning { color: #ffb900; }
				.score.critical { color: #dc3232; }
				.footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; }
			</style>
		</head>
		<body>
			<div class="container">
				<div class="header">
					<h1><?php echo esc_html( ucfirst( $report_data['period'] ) ); ?> Security Report</h1>
					<p><?php echo esc_html( get_bloginfo( 'name' ) ); ?></p>
					<p><?php echo esc_html( gmdate( 'F j, Y' ) ); ?></p>
				</div>
				
				<div class="score <?php echo absint( $report_data['security_score'] ) >= 80 ? 'good' : ( absint( $report_data['security_score'] ) >= 60 ? 'warning' : 'critical' ); ?>">
					Security Score: <?php echo absint( $report_data['security_score'] ); ?>/100
				</div>
				
				<div class="metric">
					<div class="metric-label">Total Threats Detected</div>
					<div class="metric-value">
						<?php echo absint( array_sum( $report_data['threats'] ) ); ?>
					</div>
					<div>
						Critical: <?php echo absint( $report_data['threats']['critical'] ); ?> | 
						High: <?php echo absint( $report_data['threats']['high'] ); ?> | 
						Medium: <?php echo absint( $report_data['threats']['medium'] ); ?>
					</div>
				</div>
				
				<div class="metric">
					<div class="metric-label">Failed Login Attempts</div>
					<div class="metric-value"><?php echo absint( $report_data['failed_logins'] ); ?></div>
				</div>
				
				<div class="metric">
					<div class="metric-label">Blocked IP Addresses</div>
					<div class="metric-value"><?php echo absint( $report_data['blocked_ips'] ); ?></div>
				</div>
				
				<div class="metric">
					<div class="metric-label">Audit Events Logged</div>
					<div class="metric-value"><?php echo absint( $report_data['audit_events'] ); ?></div>
				</div>
				
				<?php if ( ! empty( $report_data['patterns'] ) ) : ?>
				<div class="metric">
					<div class="metric-label">Security Patterns Detected</div>
					<ul>
						<?php foreach ( $report_data['patterns'] as $pattern ) : ?>
							<li><?php echo esc_html( ucwords( str_replace( '_', ' ', $pattern['type'] ) ) ); ?>
							- Severity: <?php echo esc_html( $pattern['severity'] ); ?></li>
						<?php endforeach; ?>
					</ul>
				</div>
				<?php endif; ?>
				
				<div class="footer">
					<p>This is an automated security report from WP Harden.</p>
					<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden' ) ); ?>">View Full Dashboard</a></p>
				</div>
			</div>
		</body>
		</html>
		<?php
		return ob_get_clean();
	}
}
