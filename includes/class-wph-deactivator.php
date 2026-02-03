<?php
/**
 * Plugin Deactivator
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Deactivator
 *
 * Handles plugin deactivation tasks
 */
class WPH_Deactivator {

	/**
	 * Deactivate the plugin
	 *
	 * Cleans up scheduled events and clears caches
	 *
	 * @since 1.0.0
	 */
	public static function deactivate() {
		// Clear scheduled cron events
		wp_clear_scheduled_hook( 'wph_daily_scan' );
		wp_clear_scheduled_hook( 'wph_cleanup_logs' );
		wp_clear_scheduled_hook( 'wph_cleanup_expired_blocks' );

		// Clear any cached data
		wp_cache_flush();
	}
}
