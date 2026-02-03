<?php
/**
 * Logs View Template
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

$logger = WPH_Logger::get_instance();

// Handle filters
$log_type   = isset( $_GET['log_type'] ) ? sanitize_text_field( wp_unslash( $_GET['log_type'] ) ) : '';
$severity   = isset( $_GET['severity'] ) ? sanitize_text_field( wp_unslash( $_GET['severity'] ) ) : '';
$ip_search  = isset( $_GET['ip_search'] ) ? sanitize_text_field( wp_unslash( $_GET['ip_search'] ) ) : '';
$user_id    = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
$search     = isset( $_GET['search'] ) ? sanitize_text_field( wp_unslash( $_GET['search'] ) ) : '';

// Pagination
$per_page     = 50;
$current_page = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1;
$offset       = ( $current_page - 1 ) * $per_page;

$args = array(
	'limit'  => $per_page,
	'offset' => $offset,
);

if ( ! empty( $log_type ) ) {
	$args['log_type'] = $log_type;
}
if ( ! empty( $severity ) ) {
	$args['severity'] = $severity;
}
if ( ! empty( $ip_search ) ) {
	$args['ip_address'] = $ip_search;
}
if ( ! empty( $user_id ) ) {
	$args['user_id'] = $user_id;
}
if ( ! empty( $search ) ) {
	$args['search'] = $search;
}

$logs       = $logger->get_logs( $args );
$total_logs = $logger->get_log_count( $args );
$total_pages = ceil( $total_logs / $per_page );
?>

<div class="wrap wph-logs">
	<h1><?php esc_html_e( 'Activity Logs', 'wp-harden' ); ?></h1>

	<div class="wph-panel">
		<div class="wph-filter-header">
			<h3><?php esc_html_e( 'Filter Logs', 'wp-harden' ); ?></h3>
			<div class="wph-filter-actions">
				<label>
					<input type="checkbox" id="wph-auto-refresh" value="1">
					<?php esc_html_e( 'Auto-refresh (10s)', 'wp-harden' ); ?>
				</label>
			</div>
		</div>
		
		<form method="get" class="wph-filter-form">
			<input type="hidden" name="page" value="wp-harden-logs">
			
			<div class="wph-filter-row">
				<div class="wph-filter-field">
					<label for="log_type"><?php esc_html_e( 'Type:', 'wp-harden' ); ?></label>
					<select name="log_type" id="log_type">
						<option value=""><?php esc_html_e( 'All Types', 'wp-harden' ); ?></option>
						<option value="login" <?php selected( $log_type, 'login' ); ?>><?php esc_html_e( 'Login', 'wp-harden' ); ?></option>
						<option value="firewall" <?php selected( $log_type, 'firewall' ); ?>><?php esc_html_e( 'Firewall', 'wp-harden' ); ?></option>
						<option value="scanner" <?php selected( $log_type, 'scanner' ); ?>><?php esc_html_e( 'Scanner', 'wp-harden' ); ?></option>
						<option value="database" <?php selected( $log_type, 'database' ); ?>><?php esc_html_e( 'Database', 'wp-harden' ); ?></option>
					</select>
				</div>

				<div class="wph-filter-field">
					<label for="severity"><?php esc_html_e( 'Severity:', 'wp-harden' ); ?></label>
					<select name="severity" id="severity">
						<option value=""><?php esc_html_e( 'All Severities', 'wp-harden' ); ?></option>
						<option value="low" <?php selected( $severity, 'low' ); ?>><?php esc_html_e( 'Low', 'wp-harden' ); ?></option>
						<option value="medium" <?php selected( $severity, 'medium' ); ?>><?php esc_html_e( 'Medium', 'wp-harden' ); ?></option>
						<option value="high" <?php selected( $severity, 'high' ); ?>><?php esc_html_e( 'High', 'wp-harden' ); ?></option>
						<option value="critical" <?php selected( $severity, 'critical' ); ?>><?php esc_html_e( 'Critical', 'wp-harden' ); ?></option>
					</select>
				</div>

				<div class="wph-filter-field">
					<label for="ip_search"><?php esc_html_e( 'IP Address:', 'wp-harden' ); ?></label>
					<input type="text" name="ip_search" id="ip_search" 
						value="<?php echo esc_attr( $ip_search ); ?>" 
						placeholder="<?php esc_attr_e( 'e.g., 192.168.1.1', 'wp-harden' ); ?>"
						class="wph-search-input">
				</div>

				<div class="wph-filter-field">
					<label for="search"><?php esc_html_e( 'Search:', 'wp-harden' ); ?></label>
					<input type="text" name="search" id="search" 
						value="<?php echo esc_attr( $search ); ?>" 
						placeholder="<?php esc_attr_e( 'Search message...', 'wp-harden' ); ?>"
						class="wph-search-input">
				</div>
			</div>

			<div class="wph-filter-buttons">
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Apply Filters', 'wp-harden' ); ?></button>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-logs' ) ); ?>" class="button">
					<?php esc_html_e( 'Clear Filters', 'wp-harden' ); ?>
				</a>
				<button type="button" id="wph-export-logs" class="button">
					<?php esc_html_e( '📥 Export CSV', 'wp-harden' ); ?>
				</button>
				<button type="button" id="wph-delete-selected" class="button" disabled>
					<?php esc_html_e( '🗑️ Delete Selected', 'wp-harden' ); ?>
				</button>
			</div>
		</form>

		<div class="wph-log-stats">
			<span>
				<?php
				printf(
					/* translators: %d: number of logs */
					esc_html__( 'Showing %d logs', 'wp-harden' ),
					absint( $total_logs )
				);
				?>
			</span>
			<?php if ( ! empty( $log_type ) || ! empty( $severity ) || ! empty( $ip_search ) || ! empty( $search ) ) : ?>
				<span class="wph-active-filters">
					<?php esc_html_e( '(Filtered)', 'wp-harden' ); ?>
				</span>
			<?php endif; ?>
		</div>

		<?php if ( ! empty( $logs ) ) : ?>
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th style="width: 3%">
							<input type="checkbox" id="wph-select-all-logs">
						</th>
						<th style="width: 5%"><?php esc_html_e( 'ID', 'wp-harden' ); ?></th>
						<th style="width: 12%"><?php esc_html_e( 'Time', 'wp-harden' ); ?></th>
						<th style="width: 10%"><?php esc_html_e( 'Type', 'wp-harden' ); ?></th>
						<th style="width: 10%"><?php esc_html_e( 'Severity', 'wp-harden' ); ?></th>
						<th style="width: 30%"><?php esc_html_e( 'Message', 'wp-harden' ); ?></th>
						<th style="width: 12%"><?php esc_html_e( 'IP Address', 'wp-harden' ); ?></th>
						<th style="width: 10%"><?php esc_html_e( 'User', 'wp-harden' ); ?></th>
						<th style="width: 8%"><?php esc_html_e( 'Actions', 'wp-harden' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $logs as $log ) : ?>
						<tr>
							<td>
								<input type="checkbox" class="wph-log-checkbox" data-log-id="<?php echo absint( $log->id ); ?>">
							</td>
							<td><?php echo absint( $log->id ); ?></td>
							<td>
								<abbr title="<?php echo esc_attr( $log->created_at ); ?>">
									<?php
									$timestamp = strtotime( $log->created_at );
									if ( false !== $timestamp ) {
										echo esc_html( human_time_diff( $timestamp, current_time( 'timestamp' ) ) . ' ago' );
									} else {
										echo esc_html( $log->created_at );
									}
									?>
								</abbr>
							</td>
							<td>
								<span class="wph-badge wph-badge-<?php echo esc_attr( $log->log_type ); ?>">
									<?php echo esc_html( ucfirst( $log->log_type ) ); ?>
								</span>
							</td>
							<td>
								<span class="wph-severity wph-severity-<?php echo esc_attr( $log->severity ); ?>">
									<?php echo esc_html( ucfirst( $log->severity ) ); ?>
								</span>
							</td>
							<td>
								<div class="wph-log-message">
									<?php echo esc_html( $log->message ); ?>
								</div>
							</td>
							<td>
								<code class="wph-ip-address"><?php echo esc_html( $log->ip_address ); ?></code>
								<div class="wph-ip-actions">
									<a href="https://www.abuseipdb.com/check/<?php echo esc_attr( $log->ip_address ); ?>" 
									   target="_blank" class="wph-ip-lookup" title="<?php esc_attr_e( 'Lookup IP', 'wp-harden' ); ?>">
										🔍
									</a>
									<button class="wph-block-ip-btn" data-ip="<?php echo esc_attr( $log->ip_address ); ?>" title="<?php esc_attr_e( 'Block IP', 'wp-harden' ); ?>">
										🚫
									</button>
								</div>
							</td>
							<td>
								<?php
								if ( $log->user_id ) {
									$user = get_userdata( $log->user_id );
									echo $user ? esc_html( $user->user_login ) : esc_html__( 'Unknown', 'wp-harden' );
								} else {
									echo '—';
								}
								?>
							</td>
							<td>
								<button class="button button-small wph-view-log-details" data-log-id="<?php echo absint( $log->id ); ?>">
									<?php esc_html_e( 'Details', 'wp-harden' ); ?>
								</button>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>

			<?php if ( $total_pages > 1 ) : ?>
				<div class="tablenav">
					<div class="tablenav-pages">
						<?php
						$page_links = paginate_links(
							array(
								'base'      => add_query_arg( 'paged', '%#%' ),
								'format'    => '',
								'prev_text' => __( '&laquo;', 'wp-harden' ),
								'next_text' => __( '&raquo;', 'wp-harden' ),
								'total'     => $total_pages,
								'current'   => $current_page,
							)
						);
						echo $page_links;
						?>
					</div>
				</div>
			<?php endif; ?>

		<?php else : ?>
			<p><?php esc_html_e( 'No logs found.', 'wp-harden' ); ?></p>
		<?php endif; ?>
	</div>
</div>
