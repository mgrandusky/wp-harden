<?php
/**
 * Settings View Template
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

$settings = WPH_Settings::get_instance();

// Handle form submission
if ( isset( $_POST['wph_settings_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wph_settings_nonce'] ) ), 'wph_save_settings' ) ) {
	$new_settings = array();

	// Boolean settings
	$boolean_fields = array(
		'firewall_enabled',
		'login_security_enabled',
		'scanner_enabled',
		'email_notifications',
		'rate_limit_enabled',
		'strong_password_enforcement',
		'prevent_username_enumeration',
	);

	foreach ( $boolean_fields as $field ) {
		$new_settings[ $field ] = isset( $_POST[ $field ] ) ? true : false;
	}

	// Text settings
	if ( isset( $_POST['firewall_sensitivity'] ) ) {
		$new_settings['firewall_sensitivity'] = sanitize_text_field( wp_unslash( $_POST['firewall_sensitivity'] ) );
	}

	if ( isset( $_POST['scan_schedule'] ) ) {
		$new_settings['scan_schedule'] = sanitize_text_field( wp_unslash( $_POST['scan_schedule'] ) );
	}

	if ( isset( $_POST['notification_email'] ) ) {
		$new_settings['notification_email'] = sanitize_email( wp_unslash( $_POST['notification_email'] ) );
	}

	// Integer settings
	$integer_fields = array(
		'max_login_attempts',
		'login_lockout_duration',
		'log_retention_days',
		'rate_limit_requests',
		'rate_limit_period',
	);

	foreach ( $integer_fields as $field ) {
		if ( isset( $_POST[ $field ] ) ) {
			$new_settings[ $field ] = absint( $_POST[ $field ] );
		}
	}

	// Array settings - IP lists
	if ( isset( $_POST['ip_whitelist'] ) ) {
		$whitelist_raw = sanitize_textarea_field( wp_unslash( $_POST['ip_whitelist'] ) );
		$new_settings['ip_whitelist'] = array_filter( array_map( 'trim', explode( "\n", $whitelist_raw ) ) );
	}

	if ( isset( $_POST['ip_blacklist'] ) ) {
		$blacklist_raw = sanitize_textarea_field( wp_unslash( $_POST['ip_blacklist'] ) );
		$new_settings['ip_blacklist'] = array_filter( array_map( 'trim', explode( "\n", $blacklist_raw ) ) );
	}

	update_option( 'wph_settings', $new_settings );
	echo '<div class="notice notice-success"><p>' . esc_html__( 'Settings saved successfully.', 'wp-harden' ) . '</p></div>';
}

$current_settings = $settings->get_all();
?>

<div class="wrap wph-settings">
	<h1><?php esc_html_e( 'WP Harden Settings', 'wp-harden' ); ?></h1>

	<form method="post" action="">
		<?php wp_nonce_field( 'wph_save_settings', 'wph_settings_nonce' ); ?>

		<div class="wph-tabs">
			<nav class="nav-tab-wrapper">
				<a href="#firewall" class="nav-tab nav-tab-active"><?php esc_html_e( 'Firewall', 'wp-harden' ); ?></a>
				<a href="#login-security" class="nav-tab"><?php esc_html_e( 'Login Security', 'wp-harden' ); ?></a>
				<a href="#scanner" class="nav-tab"><?php esc_html_e( 'Scanner', 'wp-harden' ); ?></a>
				<a href="#notifications" class="nav-tab"><?php esc_html_e( 'Notifications', 'wp-harden' ); ?></a>
				<a href="#ip-lists" class="nav-tab"><?php esc_html_e( 'IP Lists', 'wp-harden' ); ?></a>
			</nav>

			<!-- Firewall Tab -->
			<div id="firewall" class="wph-tab-content wph-tab-active">
				<h2><?php esc_html_e( 'Firewall Settings', 'wp-harden' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Firewall', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="firewall_enabled" value="1" 
									<?php checked( $current_settings['firewall_enabled'] ?? true ); ?>>
								<?php esc_html_e( 'Enable Web Application Firewall protection', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Firewall Sensitivity', 'wp-harden' ); ?></th>
						<td>
							<select name="firewall_sensitivity">
								<option value="low" <?php selected( $current_settings['firewall_sensitivity'] ?? 'medium', 'low' ); ?>>
									<?php esc_html_e( 'Low', 'wp-harden' ); ?>
								</option>
								<option value="medium" <?php selected( $current_settings['firewall_sensitivity'] ?? 'medium', 'medium' ); ?>>
									<?php esc_html_e( 'Medium (Recommended)', 'wp-harden' ); ?>
								</option>
								<option value="high" <?php selected( $current_settings['firewall_sensitivity'] ?? 'medium', 'high' ); ?>>
									<?php esc_html_e( 'High', 'wp-harden' ); ?>
								</option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Rate Limiting', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="rate_limit_enabled" value="1" 
									<?php checked( $current_settings['rate_limit_enabled'] ?? true ); ?>>
								<?php esc_html_e( 'Enable rate limiting', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Limit the number of requests from a single IP address', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Rate Limit', 'wp-harden' ); ?></th>
						<td>
							<input type="number" name="rate_limit_requests" value="<?php echo absint( $current_settings['rate_limit_requests'] ?? 60 ); ?>" min="1" max="1000">
							<?php esc_html_e( 'requests per', 'wp-harden' ); ?>
							<input type="number" name="rate_limit_period" value="<?php echo absint( $current_settings['rate_limit_period'] ?? 60 ); ?>" min="1" max="3600">
							<?php esc_html_e( 'seconds', 'wp-harden' ); ?>
						</td>
					</tr>
				</table>
			</div>

			<!-- Login Security Tab -->
			<div id="login-security" class="wph-tab-content">
				<h2><?php esc_html_e( 'Login Security Settings', 'wp-harden' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Login Security', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="login_security_enabled" value="1" 
									<?php checked( $current_settings['login_security_enabled'] ?? true ); ?>>
								<?php esc_html_e( 'Enable brute force protection', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Max Login Attempts', 'wp-harden' ); ?></th>
						<td>
							<input type="number" name="max_login_attempts" value="<?php echo absint( $current_settings['max_login_attempts'] ?? 5 ); ?>" min="1" max="20">
							<p class="description">
								<?php esc_html_e( 'Number of failed login attempts before blocking', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Lockout Duration', 'wp-harden' ); ?></th>
						<td>
							<input type="number" name="login_lockout_duration" value="<?php echo absint( $current_settings['login_lockout_duration'] ?? 900 ); ?>" min="60" max="86400">
							<?php esc_html_e( 'seconds', 'wp-harden' ); ?>
							<p class="description">
								<?php esc_html_e( 'How long to block IP after failed attempts (default: 900 seconds = 15 minutes)', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Strong Passwords', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="strong_password_enforcement" value="1" 
									<?php checked( $current_settings['strong_password_enforcement'] ?? true ); ?>>
								<?php esc_html_e( 'Enforce strong password requirements', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Username Enumeration', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="prevent_username_enumeration" value="1" 
									<?php checked( $current_settings['prevent_username_enumeration'] ?? true ); ?>>
								<?php esc_html_e( 'Prevent username enumeration attacks', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
				</table>
			</div>

			<!-- Scanner Tab -->
			<div id="scanner" class="wph-tab-content">
				<h2><?php esc_html_e( 'Scanner Settings', 'wp-harden' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Scanner', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="scanner_enabled" value="1" 
									<?php checked( $current_settings['scanner_enabled'] ?? true ); ?>>
								<?php esc_html_e( 'Enable automatic security scanning', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Scan Schedule', 'wp-harden' ); ?></th>
						<td>
							<select name="scan_schedule">
								<option value="daily" <?php selected( $current_settings['scan_schedule'] ?? 'daily', 'daily' ); ?>>
									<?php esc_html_e( 'Daily', 'wp-harden' ); ?>
								</option>
								<option value="weekly" <?php selected( $current_settings['scan_schedule'] ?? 'daily', 'weekly' ); ?>>
									<?php esc_html_e( 'Weekly', 'wp-harden' ); ?>
								</option>
								<option value="monthly" <?php selected( $current_settings['scan_schedule'] ?? 'daily', 'monthly' ); ?>>
									<?php esc_html_e( 'Monthly', 'wp-harden' ); ?>
								</option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Log Retention', 'wp-harden' ); ?></th>
						<td>
							<input type="number" name="log_retention_days" value="<?php echo absint( $current_settings['log_retention_days'] ?? 30 ); ?>" min="1" max="365">
							<?php esc_html_e( 'days', 'wp-harden' ); ?>
							<p class="description">
								<?php esc_html_e( 'How long to keep security logs', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
				</table>
			</div>

			<!-- Notifications Tab -->
			<div id="notifications" class="wph-tab-content">
				<h2><?php esc_html_e( 'Notification Settings', 'wp-harden' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Email Notifications', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="email_notifications" value="1" 
									<?php checked( $current_settings['email_notifications'] ?? true ); ?>>
								<?php esc_html_e( 'Send email alerts for security events', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Notification Email', 'wp-harden' ); ?></th>
						<td>
							<input type="email" name="notification_email" class="regular-text" 
								value="<?php echo esc_attr( $current_settings['notification_email'] ?? get_option( 'admin_email' ) ); ?>">
							<p class="description">
								<?php esc_html_e( 'Email address to receive security notifications', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
				</table>
			</div>

			<!-- IP Lists Tab -->
			<div id="ip-lists" class="wph-tab-content">
				<h2><?php esc_html_e( 'IP Whitelist & Blacklist', 'wp-harden' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'IP Whitelist', 'wp-harden' ); ?></th>
						<td>
							<textarea name="ip_whitelist" rows="10" class="large-text code"><?php 
								$whitelist = $current_settings['ip_whitelist'] ?? array();
								echo esc_textarea( implode( "\n", $whitelist ) ); 
							?></textarea>
							<p class="description">
								<?php esc_html_e( 'One IP address or CIDR range per line. These IPs will never be blocked.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'IP Blacklist', 'wp-harden' ); ?></th>
						<td>
							<textarea name="ip_blacklist" rows="10" class="large-text code"><?php 
								$blacklist = $current_settings['ip_blacklist'] ?? array();
								echo esc_textarea( implode( "\n", $blacklist ) ); 
							?></textarea>
							<p class="description">
								<?php esc_html_e( 'One IP address or CIDR range per line. These IPs will always be blocked.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
				</table>
			</div>
		</div>

		<p class="submit">
			<button type="submit" class="button button-primary button-large">
				<?php esc_html_e( 'Save All Settings', 'wp-harden' ); ?>
			</button>
		</p>
	</form>
</div>
