<?php
/**
 * Plugin Uninstall Handler
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If uninstall not called from WordPress, exit
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// Delete plugin tables
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wph_logs" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wph_blocked_ips" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wph_login_attempts" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wph_scan_results" );

// Delete plugin options
delete_option( 'wph_settings' );
delete_option( 'wph_version' );
delete_option( 'wph_activated_at' );

// Delete transients
delete_transient( 'wph_scan_status' );
delete_transient( 'wph_threat_count' );
delete_transient( 'wph_security_score' );

// Clear scheduled events
wp_clear_scheduled_hook( 'wph_daily_scan' );
wp_clear_scheduled_hook( 'wph_cleanup_logs' );
wp_clear_scheduled_hook( 'wph_cleanup_expired_blocks' );

// Clear caches
wp_cache_flush();
