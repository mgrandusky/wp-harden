<?php
/**
 * Scanner View Template
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

global $wpdb;

// Get recent scans
$recent_scans = $wpdb->get_results(
	"SELECT * FROM {$wpdb->prefix}wph_scan_results 
	ORDER BY started_at DESC 
	LIMIT 10"
);

// Get latest completed scan
$latest_scan = $wpdb->get_row(
	"SELECT * FROM {$wpdb->prefix}wph_scan_results 
	WHERE status = 'completed' 
	ORDER BY completed_at DESC 
	LIMIT 1"
);

$scan_results = array();
if ( $latest_scan && ! empty( $latest_scan->scan_data ) ) {
	$scan_results = json_decode( $latest_scan->scan_data, true );
}
?>

<div class="wrap wph-scanner">
	<h1><?php esc_html_e( 'Security Scanner', 'wp-harden' ); ?></h1>

	<div class="wph-panel">
		<h2><?php esc_html_e( 'Run Security Scan', 'wp-harden' ); ?></h2>
		<p><?php esc_html_e( 'Perform a comprehensive security scan of your WordPress installation.', 'wp-harden' ); ?></p>
		
		<button id="wph-run-scan" class="button button-primary button-large">
			<?php esc_html_e( '🔍 Start Security Scan', 'wp-harden' ); ?>
		</button>
		
		<div id="wph-scan-progress" style="display: none;">
			<p><span class="spinner is-active"></span> <?php esc_html_e( 'Scanning... Please wait.', 'wp-harden' ); ?></p>
		</div>
		
		<div id="wph-scan-results" style="display: none;">
			<!-- Results will be loaded here via AJAX -->
		</div>
	</div>

	<?php if ( ! empty( $scan_results ) ) : ?>
	<div class="wph-panel">
		<h2><?php esc_html_e( 'Latest Scan Results', 'wp-harden' ); ?></h2>
		<p><strong><?php esc_html_e( 'Scan Date:', 'wp-harden' ); ?></strong> <?php echo esc_html( $latest_scan->completed_at ); ?></p>
		<p><strong><?php esc_html_e( 'Total Issues:', 'wp-harden' ); ?></strong> <?php echo absint( $latest_scan->issues_found ); ?></p>

		<?php foreach ( $scan_results as $scan_type => $result ) : ?>
			<div class="wph-scan-result">
				<h3><?php echo esc_html( ucwords( str_replace( '_', ' ', $result['scan_type'] ) ) ); ?></h3>
				<p>
					<strong><?php esc_html_e( 'Status:', 'wp-harden' ); ?></strong>
					<span class="wph-status wph-status-<?php echo esc_attr( $result['status'] ); ?>">
						<?php echo esc_html( ucfirst( $result['status'] ) ); ?>
					</span>
				</p>

				<?php if ( ! empty( $result['issues'] ) ) : ?>
					<table class="wp-list-table widefat fixed striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Issue', 'wp-harden' ); ?></th>
								<th><?php esc_html_e( 'Severity', 'wp-harden' ); ?></th>
								<th><?php esc_html_e( 'Details', 'wp-harden' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $result['issues'] as $issue ) : ?>
								<tr>
									<td>
										<strong><?php echo esc_html( $issue['issue'] ?? 'Security Issue' ); ?></strong>
										<?php if ( isset( $issue['file'] ) ) : ?>
											<br><code><?php echo esc_html( $issue['file'] ); ?></code>
										<?php endif; ?>
									</td>
									<td>
										<?php if ( isset( $issue['severity'] ) ) : ?>
											<span class="wph-severity wph-severity-<?php echo esc_attr( $issue['severity'] ); ?>">
												<?php echo esc_html( ucfirst( $issue['severity'] ) ); ?>
											</span>
										<?php endif; ?>
									</td>
									<td>
										<?php if ( isset( $issue['recommendation'] ) ) : ?>
											<em><?php echo esc_html( $issue['recommendation'] ); ?></em>
										<?php endif; ?>
										<?php if ( isset( $issue['current'] ) ) : ?>
											<br><strong><?php esc_html_e( 'Current:', 'wp-harden' ); ?></strong> <?php echo esc_html( $issue['current'] ); ?>
										<?php endif; ?>
										<?php if ( isset( $issue['expected'] ) ) : ?>
											<br><strong><?php esc_html_e( 'Expected:', 'wp-harden' ); ?></strong> <?php echo esc_html( $issue['expected'] ); ?>
										<?php endif; ?>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php else : ?>
					<p class="wph-success">✅ <?php esc_html_e( 'No issues found in this scan.', 'wp-harden' ); ?></p>
				<?php endif; ?>
			</div>
		<?php endforeach; ?>
	</div>
	<?php endif; ?>

	<?php if ( ! empty( $recent_scans ) ) : ?>
	<div class="wph-panel">
		<h2><?php esc_html_e( 'Scan History', 'wp-harden' ); ?></h2>
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Scan ID', 'wp-harden' ); ?></th>
					<th><?php esc_html_e( 'Type', 'wp-harden' ); ?></th>
					<th><?php esc_html_e( 'Status', 'wp-harden' ); ?></th>
					<th><?php esc_html_e( 'Issues Found', 'wp-harden' ); ?></th>
					<th><?php esc_html_e( 'Started', 'wp-harden' ); ?></th>
					<th><?php esc_html_e( 'Completed', 'wp-harden' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $recent_scans as $scan ) : ?>
					<tr>
						<td><?php echo absint( $scan->id ); ?></td>
						<td><?php echo esc_html( ucfirst( $scan->scan_type ) ); ?></td>
						<td>
							<span class="wph-status wph-status-<?php echo esc_attr( $scan->status ); ?>">
								<?php echo esc_html( ucfirst( $scan->status ) ); ?>
							</span>
						</td>
						<td><?php echo absint( $scan->issues_found ); ?></td>
						<td><?php echo esc_html( $scan->started_at ); ?></td>
						<td><?php echo esc_html( $scan->completed_at ?? '-' ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<?php endif; ?>
</div>
