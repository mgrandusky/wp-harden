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
		
		<div class="wph-scan-controls">
			<button id="wph-run-full-scan" class="button button-primary button-large">
				<?php esc_html_e( '🔍 Start Full Scan', 'wp-harden' ); ?>
			</button>
			<button id="wph-run-quick-scan" class="button button-large">
				<?php esc_html_e( '⚡ Quick Scan', 'wp-harden' ); ?>
			</button>
			
			<div class="wph-scan-schedule">
				<?php
				$settings = WPH_Settings::get_instance();
				$scan_schedule = $settings->get( 'scan_schedule', 'daily' );
				?>
				<label for="scan-schedule-select">
					<strong><?php esc_html_e( 'Automatic Scans:', 'wp-harden' ); ?></strong>
				</label>
				<select id="scan-schedule-select" class="wph-schedule-select">
					<option value="disabled" <?php selected( $scan_schedule, 'disabled' ); ?>>
						<?php esc_html_e( 'Disabled', 'wp-harden' ); ?>
					</option>
					<option value="daily" <?php selected( $scan_schedule, 'daily' ); ?>>
						<?php esc_html_e( 'Daily', 'wp-harden' ); ?>
					</option>
					<option value="weekly" <?php selected( $scan_schedule, 'weekly' ); ?>>
						<?php esc_html_e( 'Weekly', 'wp-harden' ); ?>
					</option>
					<option value="monthly" <?php selected( $scan_schedule, 'monthly' ); ?>>
						<?php esc_html_e( 'Monthly', 'wp-harden' ); ?>
					</option>
				</select>
			</div>
		</div>
		
		<div id="wph-scan-progress" style="display: none;">
			<div class="wph-progress-bar">
				<div class="wph-progress-fill" style="width: 0%"></div>
			</div>
			<p><span class="spinner is-active"></span> <span class="wph-scan-status"><?php esc_html_e( 'Scanning... Please wait.', 'wp-harden' ); ?></span></p>
		</div>
		
		<div id="wph-scan-results" style="display: none;">
			<!-- Results will be loaded here via AJAX -->
		</div>
	</div>

	<?php if ( ! empty( $scan_results ) ) : ?>
	<div class="wph-panel">
		<div class="wph-panel-header">
			<h2><?php esc_html_e( 'Latest Scan Results', 'wp-harden' ); ?></h2>
			<div class="wph-panel-actions">
				<button id="wph-export-scan" class="button">
					<?php esc_html_e( '📥 Export Results', 'wp-harden' ); ?>
				</button>
				<?php if ( $latest_scan->issues_found > 0 ) : ?>
				<button id="wph-fix-all-issues" class="button button-primary">
					<?php esc_html_e( '🔧 Fix All Issues', 'wp-harden' ); ?>
				</button>
				<?php endif; ?>
			</div>
		</div>
		
		<div class="wph-scan-meta">
			<p><strong><?php esc_html_e( 'Scan Date:', 'wp-harden' ); ?></strong> <?php echo esc_html( $latest_scan->completed_at ); ?></p>
			<p><strong><?php esc_html_e( 'Scan Type:', 'wp-harden' ); ?></strong> <?php echo esc_html( ucfirst( $latest_scan->scan_type ?? 'full' ) ); ?></p>
			<p><strong><?php esc_html_e( 'Total Issues:', 'wp-harden' ); ?></strong> 
				<span class="wph-issue-badge <?php echo $latest_scan->issues_found > 0 ? 'has-issues' : 'no-issues'; ?>">
					<?php echo absint( $latest_scan->issues_found ); ?>
				</span>
			</p>
		</div>

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
								<th style="width: 5%">
									<input type="checkbox" class="wph-select-all-issues">
								</th>
								<th style="width: 25%"><?php esc_html_e( 'Issue', 'wp-harden' ); ?></th>
								<th style="width: 10%"><?php esc_html_e( 'Severity', 'wp-harden' ); ?></th>
								<th style="width: 40%"><?php esc_html_e( 'Details', 'wp-harden' ); ?></th>
								<th style="width: 20%"><?php esc_html_e( 'Action', 'wp-harden' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $result['issues'] as $idx => $issue ) : ?>
								<tr>
									<td>
										<input type="checkbox" class="wph-issue-checkbox" 
											   data-issue-type="<?php echo esc_attr( $scan_type ); ?>"
											   data-issue-data="<?php echo esc_attr( wp_json_encode( $issue ) ); ?>" />
									</td>
									<td>
										<strong><?php echo esc_html( $issue['issue'] ?? 'Security Issue' ); ?></strong>
										<?php if ( isset( $issue['file'] ) ) : ?>
											<br><code class="wph-file-path"><?php echo esc_html( $issue['file'] ); ?></code>
										<?php endif; ?>
										<?php if ( isset( $issue['cve'] ) ) : ?>
											<br><a href="https://nvd.nist.gov/vuln/detail/<?php echo esc_attr( $issue['cve'] ); ?>" target="_blank" class="wph-cve-link">
												<?php echo esc_html( $issue['cve'] ); ?>
											</a>
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
											<div class="wph-recommendation">
												<em><?php echo esc_html( $issue['recommendation'] ); ?></em>
											</div>
										<?php endif; ?>
										<?php if ( isset( $issue['current'] ) ) : ?>
											<div class="wph-detail-item">
												<strong><?php esc_html_e( 'Current:', 'wp-harden' ); ?></strong> <?php echo esc_html( $issue['current'] ); ?>
											</div>
										<?php endif; ?>
										<?php if ( isset( $issue['expected'] ) ) : ?>
											<div class="wph-detail-item">
												<strong><?php esc_html_e( 'Expected:', 'wp-harden' ); ?></strong> <?php echo esc_html( $issue['expected'] ); ?>
											</div>
										<?php endif; ?>
									</td>
									<td>
										<button class="button button-small wph-fix-issue" 
												data-issue-type="<?php echo esc_attr( $scan_type ); ?>"
												data-issue-data="<?php echo esc_attr( wp_json_encode( $issue ) ); ?>">
											<?php esc_html_e( 'Fix', 'wp-harden' ); ?>
										</button>
										<button class="button button-small wph-ignore-issue"
												data-issue-type="<?php echo esc_attr( $scan_type ); ?>"
												data-issue-data="<?php echo esc_attr( wp_json_encode( $issue ) ); ?>">
											<?php esc_html_e( 'Ignore', 'wp-harden' ); ?>
										</button>
										<?php if ( isset( $issue['file'] ) ) : ?>
										<button class="button button-small wph-quarantine-file" data-file="<?php echo esc_attr( $issue['file'] ); ?>">
											<?php esc_html_e( 'Quarantine', 'wp-harden' ); ?>
										</button>
										<?php endif; ?>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					
					<div class="wph-bulk-actions">
						<button class="button wph-fix-selected">
							<?php esc_html_e( '🔧 Fix Selected', 'wp-harden' ); ?>
						</button>
						<button class="button wph-ignore-selected">
							<?php esc_html_e( '👁️ Ignore Selected', 'wp-harden' ); ?>
						</button>
					</div>
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
					<th><?php esc_html_e( 'Actions', 'wp-harden' ); ?></th>
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
						<td>
							<span class="wph-issue-badge <?php echo $scan->issues_found > 0 ? 'has-issues' : 'no-issues'; ?>">
								<?php echo absint( $scan->issues_found ); ?>
							</span>
						</td>
						<td><?php echo esc_html( $scan->started_at ); ?></td>
						<td><?php echo esc_html( $scan->completed_at ?? '-' ); ?></td>
						<td>
							<button class="button button-small wph-view-scan" data-scan-id="<?php echo absint( $scan->id ); ?>">
								<?php esc_html_e( 'View Details', 'wp-harden' ); ?>
							</button>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<?php endif; ?>
</div>
