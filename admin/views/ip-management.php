<?php
/**
 * IP Management View Template
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

$ip_manager = WPH_IP_Manager::get_instance();
$settings   = WPH_Settings::get_instance();

// Handle form submissions
if ( isset( $_POST['wph_block_ip_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wph_block_ip_nonce'] ) ), 'wph_block_ip' ) ) {
	$ip_address = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';
	$reason     = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : 'Manual block';
	$block_type = isset( $_POST['block_type'] ) ? sanitize_text_field( wp_unslash( $_POST['block_type'] ) ) : 'permanent';

	if ( ! empty( $ip_address ) ) {
		$ip_manager->block_ip( $ip_address, $reason, $block_type );
		echo '<div class="notice notice-success"><p>' . esc_html__( 'IP address blocked successfully.', 'wp-harden' ) . '</p></div>';
	}
}

if ( isset( $_GET['action'] ) && $_GET['action'] === 'unblock' && isset( $_GET['ip'] ) && isset( $_GET['_wpnonce'] ) ) {
	if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'wph_unblock_ip' ) ) {
		$ip_address = sanitize_text_field( wp_unslash( $_GET['ip'] ) );
		$ip_manager->unblock_ip( $ip_address );
		echo '<div class="notice notice-success"><p>' . esc_html__( 'IP address unblocked successfully.', 'wp-harden' ) . '</p></div>';
	}
}

// Get blocked IPs
$blocked_ips = $ip_manager->get_blocked_ips( array( 'limit' => 100 ) );

// Get whitelist and blacklist
$whitelist = $settings->get( 'ip_whitelist', array() );
$blacklist = $settings->get( 'ip_blacklist', array() );
?>

<div class="wrap wph-ip-management">
	<h1><?php esc_html_e( 'IP Management', 'wp-harden' ); ?></h1>

	<div class="wph-grid-2col">
		<div class="wph-panel">
			<h2><?php esc_html_e( 'Block IP Address', 'wp-harden' ); ?></h2>
			<form method="post" action="">
				<?php wp_nonce_field( 'wph_block_ip', 'wph_block_ip_nonce' ); ?>
				
				<table class="form-table">
					<tr>
						<th scope="row">
							<label for="ip_address"><?php esc_html_e( 'IP Address', 'wp-harden' ); ?></label>
						</th>
						<td>
							<input type="text" id="ip_address" name="ip_address" class="regular-text" required 
								   placeholder="<?php esc_attr_e( 'e.g., 192.168.1.1 or 192.168.1.0/24', 'wp-harden' ); ?>">
							<p class="description">
								<?php esc_html_e( 'Enter an IP address or CIDR range (e.g., 192.168.1.0/24)', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="reason"><?php esc_html_e( 'Reason', 'wp-harden' ); ?></label>
						</th>
						<td>
							<input type="text" id="reason" name="reason" class="regular-text" 
								   placeholder="<?php esc_attr_e( 'e.g., Suspicious activity', 'wp-harden' ); ?>">
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="block_type"><?php esc_html_e( 'Block Type', 'wp-harden' ); ?></label>
						</th>
						<td>
							<select id="block_type" name="block_type">
								<option value="permanent"><?php esc_html_e( 'Permanent', 'wp-harden' ); ?></option>
								<option value="temporary"><?php esc_html_e( 'Temporary (1 hour)', 'wp-harden' ); ?></option>
							</select>
						</td>
					</tr>
				</table>

				<p class="submit">
					<button type="submit" class="button button-primary">
						<?php esc_html_e( 'Block IP Address', 'wp-harden' ); ?>
					</button>
				</p>
			</form>
		</div>

		<div class="wph-panel">
			<h2><?php esc_html_e( 'Current IP', 'wp-harden' ); ?></h2>
			<p>
				<strong><?php esc_html_e( 'Your IP Address:', 'wp-harden' ); ?></strong>
				<code><?php echo esc_html( $ip_manager->get_client_ip() ); ?></code>
			</p>
			<p class="description">
				<?php esc_html_e( 'Be careful not to block your own IP address!', 'wp-harden' ); ?>
			</p>
		</div>
	</div>

	<div class="wph-panel">
		<h2><?php esc_html_e( 'Blocked IP Addresses', 'wp-harden' ); ?></h2>
		
		<?php if ( ! empty( $blocked_ips ) ) : ?>
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'IP Address', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'Type', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'Blocked At', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'Expires At', 'wp-harden' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'wp-harden' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $blocked_ips as $blocked_ip ) : ?>
						<tr>
							<td><code><?php echo esc_html( $blocked_ip->ip_address ); ?></code></td>
							<td>
								<span class="wph-badge wph-badge-<?php echo esc_attr( $blocked_ip->block_type ); ?>">
									<?php echo esc_html( ucfirst( $blocked_ip->block_type ) ); ?>
								</span>
							</td>
							<td><?php echo esc_html( $blocked_ip->reason ); ?></td>
							<td><?php echo esc_html( $blocked_ip->blocked_at ); ?></td>
							<td><?php echo esc_html( $blocked_ip->expires_at ?? '—' ); ?></td>
							<td>
								<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=wp-harden-ip-management&action=unblock&ip=' . urlencode( $blocked_ip->ip_address ) ), 'wph_unblock_ip' ) ); ?>" 
								   class="button button-small">
									<?php esc_html_e( 'Unblock', 'wp-harden' ); ?>
								</a>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		<?php else : ?>
			<p><?php esc_html_e( 'No blocked IP addresses.', 'wp-harden' ); ?></p>
		<?php endif; ?>
	</div>

	<div class="wph-grid-2col">
		<div class="wph-panel">
			<h2><?php esc_html_e( 'IP Whitelist', 'wp-harden' ); ?></h2>
			<?php if ( ! empty( $whitelist ) ) : ?>
				<ul class="wph-ip-list">
					<?php foreach ( $whitelist as $ip ) : ?>
						<li><code><?php echo esc_html( $ip ); ?></code></li>
					<?php endforeach; ?>
				</ul>
			<?php else : ?>
				<p><?php esc_html_e( 'No whitelisted IPs.', 'wp-harden' ); ?></p>
			<?php endif; ?>
			<p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-settings' ) ); ?>" class="button">
					<?php esc_html_e( 'Manage Whitelist', 'wp-harden' ); ?>
				</a>
			</p>
		</div>

		<div class="wph-panel">
			<h2><?php esc_html_e( 'IP Blacklist', 'wp-harden' ); ?></h2>
			<?php if ( ! empty( $blacklist ) ) : ?>
				<ul class="wph-ip-list">
					<?php foreach ( $blacklist as $ip ) : ?>
						<li><code><?php echo esc_html( $ip ); ?></code></li>
					<?php endforeach; ?>
				</ul>
			<?php else : ?>
				<p><?php esc_html_e( 'No blacklisted IPs.', 'wp-harden' ); ?></p>
			<?php endif; ?>
			<p>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-settings' ) ); ?>" class="button">
					<?php esc_html_e( 'Manage Blacklist', 'wp-harden' ); ?>
				</a>
			</p>
		</div>
	</div>
</div>
