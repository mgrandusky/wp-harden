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
$log_type = isset( $_GET['log_type'] ) ? sanitize_text_field( wp_unslash( $_GET['log_type'] ) ) : '';
$severity = isset( $_GET['severity'] ) ? sanitize_text_field( wp_unslash( $_GET['severity'] ) ) : '';

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

$logs       = $logger->get_logs( $args );
$total_logs = $logger->get_log_count( $args );
$total_pages = ceil( $total_logs / $per_page );
?>

<div class="wrap wph-logs">
	<h1><?php esc_html_e( 'Activity Logs', 'wp-harden' ); ?></h1>

	<div class="wph-panel">
		<form method="get" class="wph-filter-form">
			<input type="hidden" name="page" value="wp-harden-logs">
			
			<label for="log_type"><?php esc_html_e( 'Type:', 'wp-harden' ); ?></label>
			<select name="log_type" id="log_type">
				<option value=""><?php esc_html_e( 'All Types', 'wp-harden' ); ?></option>
				<option value="login" <?php selected( $log_type, 'login' ); ?>><?php esc_html_e( 'Login', 'wp-harden' ); ?></option>
				<option value="firewall" <?php selected( $log_type, 'firewall' ); ?>><?php esc_html_e( 'Firewall', 'wp-harden' ); ?></option>
				<option value="scanner" <?php selected( $log_type, 'scanner' ); ?>><?php esc_html_e( 'Scanner', 'wp-harden' ); ?></option>
			</select>

			<label for="severity"><?php esc_html_e( 'Severity:', 'wp-harden' ); ?></label>
			<select name="severity" id="severity">
				<option value=""><?php esc_html_e( 'All Severities', 'wp-harden' ); ?></option>
				<option value="low" <?php selected( $severity, 'low' ); ?>><?php esc_html_e( 'Low', 'wp-harden' ); ?></option>
				<option value="medium" <?php selected( $severity, 'medium' ); ?>><?php esc_html_e( 'Medium', 'wp-harden' ); ?></option>
				<option value="high" <?php selected( $severity, 'high' ); ?>><?php esc_html_e( 'High', 'wp-harden' ); ?></option>
				<option value="critical" <?php selected( $severity, 'critical' ); ?>><?php esc_html_e( 'Critical', 'wp-harden' ); ?></option>
			</select>

			<button type="submit" class="button"><?php esc_html_e( 'Filter', 'wp-harden' ); ?></button>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-logs' ) ); ?>" class="button">
				<?php esc_html_e( 'Clear Filters', 'wp-harden' ); ?>
			</a>
			<button type="button" id="wph-export-logs" class="button">
				<?php esc_html_e( '📥 Export CSV', 'wp-harden' ); ?>
			</button>
		</form>

		<p class="wph-log-count">
			<?php
			printf(
				/* translators: %d: number of logs */
				esc_html__( 'Showing %d logs', 'wp-harden' ),
				absint( $total_logs )
			);
			?>
		</p>

		<?php if ( ! empty( $logs ) ) : ?>
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'ID', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'Time', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'Type', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'Severity', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'Message', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'IP Address', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'User', 'wp-harden' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $logs as $log ) : ?>
						<tr>
							<td><?php echo absint( $log->id ); ?></td>
							<td><?php echo esc_html( $log->created_at ); ?></td>
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
							<td><?php echo esc_html( $log->message ); ?></td>
							<td>
								<code><?php echo esc_html( $log->ip_address ); ?></code>
								<br>
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-ip-management&action=block&ip=' . urlencode( $log->ip_address ) ) ); ?>" class="wph-link-small">
									<?php esc_html_e( 'Block', 'wp-harden' ); ?>
								</a>
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
