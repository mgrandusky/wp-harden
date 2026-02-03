<?php
/**
 * Dashboard View Template
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

$logger     = WPH_Logger::get_instance();
$ip_manager = WPH_IP_Manager::get_instance();

// Get statistics
$total_logs           = $logger->get_log_count();
$critical_logs        = $logger->get_log_count( array( 'severity' => 'critical' ) );
$blocked_ips          = count( $ip_manager->get_blocked_ips() );
$recent_logs          = $logger->get_logs( array( 'limit' => 10 ) );

// Get latest scan
global $wpdb;
$latest_scan = $wpdb->get_row(
	"SELECT * FROM {$wpdb->prefix}wph_scan_results 
	WHERE status = 'completed' 
	ORDER BY completed_at DESC LIMIT 1"
);

// Calculate security score
$security_score = 85; // Base score
if ( $latest_scan && $latest_scan->issues_found > 0 ) {
	$security_score -= min( $latest_scan->issues_found * 5, 50 );
}
if ( $critical_logs > 10 ) {
	$security_score -= 10;
}
$security_score = max( $security_score, 0 );

// Determine score color
$score_class = 'good';
if ( $security_score < 50 ) {
	$score_class = 'critical';
} elseif ( $security_score < 70 ) {
	$score_class = 'warning';
}
?>

<div class="wrap wph-dashboard">
	<h1><?php esc_html_e( 'WP Harden Security Dashboard', 'wp-harden' ); ?></h1>

	<div class="wph-stats-grid">
		<div class="wph-stat-card">
			<div class="wph-stat-icon">🛡️</div>
			<div class="wph-stat-content">
				<h3><?php esc_html_e( 'Security Score', 'wp-harden' ); ?></h3>
				<div class="wph-security-score <?php echo esc_attr( $score_class ); ?>">
					<?php echo absint( $security_score ); ?>/100
				</div>
			</div>
		</div>

		<div class="wph-stat-card">
			<div class="wph-stat-icon">📊</div>
			<div class="wph-stat-content">
				<h3><?php esc_html_e( 'Total Logs', 'wp-harden' ); ?></h3>
				<div class="wph-stat-number"><?php echo absint( $total_logs ); ?></div>
			</div>
		</div>

		<div class="wph-stat-card">
			<div class="wph-stat-icon">⚠️</div>
			<div class="wph-stat-content">
				<h3><?php esc_html_e( 'Critical Events', 'wp-harden' ); ?></h3>
				<div class="wph-stat-number critical"><?php echo absint( $critical_logs ); ?></div>
			</div>
		</div>

		<div class="wph-stat-card">
			<div class="wph-stat-icon">🚫</div>
			<div class="wph-stat-content">
				<h3><?php esc_html_e( 'Blocked IPs', 'wp-harden' ); ?></h3>
				<div class="wph-stat-number"><?php echo absint( $blocked_ips ); ?></div>
			</div>
		</div>
	</div>

	<div class="wph-grid-2col">
		<div class="wph-panel">
			<h2><?php esc_html_e( 'Recent Activity', 'wp-harden' ); ?></h2>
			
			<?php if ( ! empty( $recent_logs ) ) : ?>
				<table class="wp-list-table widefat fixed striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Time', 'wp-harden' ); ?></th>
							<th><?php esc_html_e( 'Type', 'wp-harden' ); ?></th>
							<th><?php esc_html_e( 'Severity', 'wp-harden' ); ?></th>
							<th><?php esc_html_e( 'Message', 'wp-harden' ); ?></th>
							<th><?php esc_html_e( 'IP', 'wp-harden' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $recent_logs as $log ) : ?>
							<tr>
								<td><?php echo esc_html( $log->created_at ); ?></td>
								<td><?php echo esc_html( $log->log_type ); ?></td>
								<td>
									<span class="wph-severity wph-severity-<?php echo esc_attr( $log->severity ); ?>">
										<?php echo esc_html( ucfirst( $log->severity ) ); ?>
									</span>
								</td>
								<td><?php echo esc_html( $log->message ); ?></td>
								<td><?php echo esc_html( $log->ip_address ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<p>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-logs' ) ); ?>" class="button">
						<?php esc_html_e( 'View All Logs', 'wp-harden' ); ?>
					</a>
				</p>
			<?php else : ?>
				<p><?php esc_html_e( 'No activity logged yet.', 'wp-harden' ); ?></p>
			<?php endif; ?>
		</div>

		<div class="wph-panel">
			<h2><?php esc_html_e( 'Latest Security Scan', 'wp-harden' ); ?></h2>
			
			<?php if ( $latest_scan ) : ?>
				<div class="wph-scan-summary">
					<p><strong><?php esc_html_e( 'Completed:', 'wp-harden' ); ?></strong> <?php echo esc_html( $latest_scan->completed_at ); ?></p>
					<p><strong><?php esc_html_e( 'Issues Found:', 'wp-harden' ); ?></strong> <?php echo absint( $latest_scan->issues_found ); ?></p>
					<p><strong><?php esc_html_e( 'Status:', 'wp-harden' ); ?></strong> 
						<span class="wph-status-<?php echo esc_attr( $latest_scan->status ); ?>">
							<?php echo esc_html( ucfirst( $latest_scan->status ) ); ?>
						</span>
					</p>
				</div>
				<p>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-scanner' ) ); ?>" class="button button-primary">
						<?php esc_html_e( 'View Scan Details', 'wp-harden' ); ?>
					</a>
				</p>
			<?php else : ?>
				<p><?php esc_html_e( 'No scans have been run yet.', 'wp-harden' ); ?></p>
				<p>
					<button id="wph-run-scan" class="button button-primary">
						<?php esc_html_e( 'Run Security Scan Now', 'wp-harden' ); ?>
					</button>
				</p>
			<?php endif; ?>
		</div>
	</div>

	<div class="wph-panel">
		<h2><?php esc_html_e( 'Quick Actions', 'wp-harden' ); ?></h2>
		<div class="wph-quick-actions">
			<button id="wph-run-scan" class="button button-primary">
				<?php esc_html_e( '🔍 Run Security Scan', 'wp-harden' ); ?>
			</button>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-logs' ) ); ?>" class="button">
				<?php esc_html_e( '📊 View Logs', 'wp-harden' ); ?>
			</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-ip-management' ) ); ?>" class="button">
				<?php esc_html_e( '🚫 Manage IPs', 'wp-harden' ); ?>
			</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-settings' ) ); ?>" class="button">
				<?php esc_html_e( '⚙️ Settings', 'wp-harden' ); ?>
			</a>
		</div>
	</div>
</div>
