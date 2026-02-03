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
		'sql_injection_protection',
		'xss_protection',
		'file_inclusion_protection',
		'enable_captcha',
		'twofa_enabled',
		'twofa_force_admins',
		'twofa_force_editors',
		'twofa_backup_codes',
		'database_backups_enabled',
		'database_encryption',
		'query_monitoring',
		'auto_optimize_database',
		'disable_xmlrpc',
		'disable_file_editing',
		'remove_wp_version',
		'enable_security_headers',
		'disable_rest_api_unauth',
		'force_ssl_admin',
		'disable_pingbacks',
		'debug_mode',
	);

	foreach ( $boolean_fields as $field ) {
		$new_settings[ $field ] = isset( $_POST[ $field ] ) ? true : false;
	}

	// Text settings
	$text_fields = array(
		'firewall_sensitivity',
		'scan_schedule',
		'notification_email',
		'security_level',
		'captcha_type',
		'recaptcha_site_key',
		'recaptcha_secret_key',
		'backup_frequency',
		'abuseipdb_api_key',
		'wpscan_api_key',
		'maxmind_license_key',
		'virustotal_api_key',
		'custom_firewall_rules',
		'excluded_urls',
	);

	foreach ( $text_fields as $field ) {
		if ( isset( $_POST[ $field ] ) ) {
			if ( strpos( $field, '_key' ) !== false || strpos( $field, '_secret' ) !== false ) {
				// For API keys and secrets, encrypt before storing
				$new_settings[ $field ] = sanitize_text_field( wp_unslash( $_POST[ $field ] ) );
			} elseif ( in_array( $field, array( 'custom_firewall_rules', 'excluded_urls' ), true ) ) {
				$new_settings[ $field ] = sanitize_textarea_field( wp_unslash( $_POST[ $field ] ) );
			} else {
				$new_settings[ $field ] = sanitize_text_field( wp_unslash( $_POST[ $field ] ) );
			}
		}
	}

	// Email field
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
		'rate_limit_lockout',
		'twofa_backup_codes_count',
		'twofa_grace_period',
		'twofa_qr_size',
		'backup_retention_days',
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
				<a href="#general" class="nav-tab nav-tab-active"><?php esc_html_e( 'General', 'wp-harden' ); ?></a>
				<a href="#api-keys" class="nav-tab"><?php esc_html_e( 'API Keys', 'wp-harden' ); ?></a>
				<a href="#twofa" class="nav-tab"><?php esc_html_e( '2FA', 'wp-harden' ); ?></a>
				<a href="#firewall" class="nav-tab"><?php esc_html_e( 'Firewall', 'wp-harden' ); ?></a>
				<a href="#login-security" class="nav-tab"><?php esc_html_e( 'Login Security', 'wp-harden' ); ?></a>
				<a href="#database" class="nav-tab"><?php esc_html_e( 'Database', 'wp-harden' ); ?></a>
				<a href="#hardening" class="nav-tab"><?php esc_html_e( 'Hardening', 'wp-harden' ); ?></a>
				<a href="#advanced" class="nav-tab"><?php esc_html_e( 'Advanced', 'wp-harden' ); ?></a>
			</nav>

			<!-- General Settings Tab -->
			<div id="general" class="wph-tab-content wph-tab-active">
				<h2><?php esc_html_e( 'General Settings', 'wp-harden' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Firewall', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="firewall_enabled" value="1" 
									<?php checked( $current_settings['firewall_enabled'] ?? true ); ?>>
								<?php esc_html_e( 'Enable Web Application Firewall protection', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Protects your site from common web attacks like SQL injection and XSS.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Login Security', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="login_security_enabled" value="1" 
									<?php checked( $current_settings['login_security_enabled'] ?? true ); ?>>
								<?php esc_html_e( 'Enable brute force protection and login monitoring', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Protects against brute force login attacks by limiting login attempts.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Scanner', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="scanner_enabled" value="1" 
									<?php checked( $current_settings['scanner_enabled'] ?? true ); ?>>
								<?php esc_html_e( 'Enable automatic security scanning', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Regularly scans your site for vulnerabilities and malware.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
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
					<tr>
						<th scope="row"><?php esc_html_e( 'Security Sensitivity Level', 'wp-harden' ); ?></th>
						<td>
							<select name="security_level">
								<option value="low" <?php selected( $current_settings['security_level'] ?? 'medium', 'low' ); ?>>
									<?php esc_html_e( 'Low - Minimal security checks', 'wp-harden' ); ?>
								</option>
								<option value="medium" <?php selected( $current_settings['security_level'] ?? 'medium', 'medium' ); ?>>
									<?php esc_html_e( 'Medium - Recommended balance (Default)', 'wp-harden' ); ?>
								</option>
								<option value="high" <?php selected( $current_settings['security_level'] ?? 'medium', 'high' ); ?>>
									<?php esc_html_e( 'High - Maximum security', 'wp-harden' ); ?>
								</option>
							</select>
							<p class="description">
								<?php esc_html_e( 'Higher sensitivity levels provide more protection but may cause false positives.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
				</table>
			</div>

			<!-- API Keys Configuration Tab -->
			<div id="api-keys" class="wph-tab-content">
				<h2><?php esc_html_e( 'API Keys Configuration', 'wp-harden' ); ?></h2>
				<p><?php esc_html_e( 'Configure external API integrations for enhanced security features.', 'wp-harden' ); ?></p>
				
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'AbuseIPDB API Key', 'wp-harden' ); ?></th>
						<td>
							<input type="password" name="abuseipdb_api_key" class="regular-text" 
								value="<?php echo esc_attr( $current_settings['abuseipdb_api_key'] ?? '' ); ?>"
								placeholder="<?php esc_attr_e( 'Enter your AbuseIPDB API key', 'wp-harden' ); ?>">
							<p class="description">
								<?php esc_html_e( 'Used for IP reputation checking. ', 'wp-harden' ); ?>
								<a href="https://www.abuseipdb.com/" target="_blank"><?php esc_html_e( 'Get API Key', 'wp-harden' ); ?></a>
							</p>
							<button type="button" class="button wph-test-api" data-api="abuseipdb">
								<?php esc_html_e( 'Test Connection', 'wp-harden' ); ?>
							</button>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'WPScan API Key', 'wp-harden' ); ?></th>
						<td>
							<input type="password" name="wpscan_api_key" class="regular-text" 
								value="<?php echo esc_attr( $current_settings['wpscan_api_key'] ?? '' ); ?>"
								placeholder="<?php esc_attr_e( 'Enter your WPScan API key', 'wp-harden' ); ?>">
							<p class="description">
								<?php esc_html_e( 'Used for vulnerability scanning. ', 'wp-harden' ); ?>
								<a href="https://wpscan.com/api" target="_blank"><?php esc_html_e( 'Get API Key', 'wp-harden' ); ?></a>
							</p>
							<button type="button" class="button wph-test-api" data-api="wpscan">
								<?php esc_html_e( 'Test Connection', 'wp-harden' ); ?>
							</button>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'MaxMind GeoIP License Key', 'wp-harden' ); ?></th>
						<td>
							<input type="password" name="maxmind_license_key" class="regular-text" 
								value="<?php echo esc_attr( $current_settings['maxmind_license_key'] ?? '' ); ?>"
								placeholder="<?php esc_attr_e( 'Enter your MaxMind license key', 'wp-harden' ); ?>">
							<p class="description">
								<?php esc_html_e( 'Used for geographic IP blocking. ', 'wp-harden' ); ?>
								<a href="https://www.maxmind.com/" target="_blank"><?php esc_html_e( 'Get License Key', 'wp-harden' ); ?></a>
							</p>
							<button type="button" class="button wph-download-geoip">
								<?php esc_html_e( 'Download Database', 'wp-harden' ); ?>
							</button>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'VirusTotal API Key', 'wp-harden' ); ?></th>
						<td>
							<input type="password" name="virustotal_api_key" class="regular-text" 
								value="<?php echo esc_attr( $current_settings['virustotal_api_key'] ?? '' ); ?>"
								placeholder="<?php esc_attr_e( 'Enter your VirusTotal API key (Optional)', 'wp-harden' ); ?>">
							<p class="description">
								<?php esc_html_e( 'Optional - Used for enhanced file scanning. ', 'wp-harden' ); ?>
								<a href="https://www.virustotal.com/" target="_blank"><?php esc_html_e( 'Get API Key', 'wp-harden' ); ?></a>
							</p>
							<button type="button" class="button wph-test-api" data-api="virustotal">
								<?php esc_html_e( 'Test Connection', 'wp-harden' ); ?>
							</button>
						</td>
					</tr>
				</table>
			</div>

			<!-- Two-Factor Authentication Tab -->
			<div id="twofa" class="wph-tab-content">
				<h2><?php esc_html_e( 'Two-Factor Authentication (2FA)', 'wp-harden' ); ?></h2>
				<p><?php esc_html_e( 'Add an extra layer of security to user logins with two-factor authentication.', 'wp-harden' ); ?></p>
				
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable 2FA', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="twofa_enabled" value="1" 
									<?php checked( $current_settings['twofa_enabled'] ?? false ); ?>>
								<?php esc_html_e( 'Enable two-factor authentication for users', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Users will need to enter a code from their authenticator app in addition to their password.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Force 2FA for Administrators', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="twofa_force_admins" value="1" 
									<?php checked( $current_settings['twofa_force_admins'] ?? false ); ?>>
								<?php esc_html_e( 'Require all administrators to use 2FA', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Force 2FA for Editors', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="twofa_force_editors" value="1" 
									<?php checked( $current_settings['twofa_force_editors'] ?? false ); ?>>
								<?php esc_html_e( 'Require all editors to use 2FA', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Allow Backup Codes', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="twofa_backup_codes" value="1" 
									<?php checked( $current_settings['twofa_backup_codes'] ?? true ); ?>>
								<?php esc_html_e( 'Allow users to generate backup codes for account recovery', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Backup Codes to Generate', 'wp-harden' ); ?></th>
						<td>
							<input type="number" name="twofa_backup_codes_count" 
								value="<?php echo absint( $current_settings['twofa_backup_codes_count'] ?? 10 ); ?>" 
								min="5" max="20">
							<p class="description">
								<?php esc_html_e( 'Number of backup codes to generate (default: 10)', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Grace Period for Setup', 'wp-harden' ); ?></th>
						<td>
							<input type="number" name="twofa_grace_period" 
								value="<?php echo absint( $current_settings['twofa_grace_period'] ?? 7 ); ?>" 
								min="1" max="30">
							<?php esc_html_e( 'days', 'wp-harden' ); ?>
							<p class="description">
								<?php esc_html_e( 'Number of days users have to set up 2FA before being locked out (default: 7)', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'QR Code Size', 'wp-harden' ); ?></th>
						<td>
							<input type="number" name="twofa_qr_size" 
								value="<?php echo absint( $current_settings['twofa_qr_size'] ?? 200 ); ?>" 
								min="100" max="400">
							<?php esc_html_e( 'pixels', 'wp-harden' ); ?>
							<p class="description">
								<?php esc_html_e( 'Size of the QR code displayed during setup (default: 200px)', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
				</table>
				
				<div class="wph-notice">
					<h3><?php esc_html_e( '📱 How to Set Up 2FA', 'wp-harden' ); ?></h3>
					<ol>
						<li><?php esc_html_e( 'Enable 2FA using the settings above', 'wp-harden' ); ?></li>
						<li><?php esc_html_e( 'Users can set up 2FA from their profile page', 'wp-harden' ); ?></li>
						<li><?php esc_html_e( 'Users need an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator', 'wp-harden' ); ?></li>
						<li><?php esc_html_e( 'They will scan a QR code to link their account', 'wp-harden' ); ?></li>
						<li><?php esc_html_e( 'On each login, they will enter the 6-digit code from their app', 'wp-harden' ); ?></li>
					</ol>
				</div>
			</div>

			<!-- Firewall Tab -->
			<div id="firewall" class="wph-tab-content">
				<h2><?php esc_html_e( 'Firewall Settings', 'wp-harden' ); ?></h2>
				<table class="form-table">
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
								<option value="custom" <?php selected( $current_settings['firewall_sensitivity'] ?? 'medium', 'custom' ); ?>>
									<?php esc_html_e( 'Custom', 'wp-harden' ); ?>
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
						<th scope="row"><?php esc_html_e( 'Max Requests Per Minute', 'wp-harden' ); ?></th>
						<td>
							<input type="number" name="rate_limit_requests" value="<?php echo absint( $current_settings['rate_limit_requests'] ?? 60 ); ?>" min="1" max="1000">
							<p class="description">
								<?php esc_html_e( 'Maximum number of requests allowed per IP address per minute', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Lockout Duration', 'wp-harden' ); ?></th>
						<td>
							<input type="number" name="rate_limit_lockout" value="<?php echo absint( $current_settings['rate_limit_lockout'] ?? 15 ); ?>" min="1" max="120">
							<?php esc_html_e( 'minutes', 'wp-harden' ); ?>
							<p class="description">
								<?php esc_html_e( 'How long to block an IP that exceeds the rate limit', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'SQL Injection Protection', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="sql_injection_protection" value="1" 
									<?php checked( $current_settings['sql_injection_protection'] ?? true ); ?>>
								<?php esc_html_e( 'Block SQL injection attempts', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'XSS Protection', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="xss_protection" value="1" 
									<?php checked( $current_settings['xss_protection'] ?? true ); ?>>
								<?php esc_html_e( 'Block cross-site scripting (XSS) attempts', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'File Inclusion Protection', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="file_inclusion_protection" value="1" 
									<?php checked( $current_settings['file_inclusion_protection'] ?? true ); ?>>
								<?php esc_html_e( 'Block local and remote file inclusion attempts', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Custom Firewall Rules', 'wp-harden' ); ?></th>
						<td>
							<textarea name="custom_firewall_rules" rows="8" class="large-text code"><?php 
								echo esc_textarea( $current_settings['custom_firewall_rules'] ?? '' ); 
							?></textarea>
							<p class="description">
								<?php esc_html_e( 'Advanced: Add custom firewall rules (one per line, regex supported)', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
				</table>
			</div>

			<!-- Login Security Tab -->
			<div id="login-security" class="wph-tab-content">
				<h2><?php esc_html_e( 'Login Security Settings', 'wp-harden' ); ?></h2>
				<table class="form-table">
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
						<th scope="row"><?php esc_html_e( 'Enable CAPTCHA', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="enable_captcha" value="1" 
									<?php checked( $current_settings['enable_captcha'] ?? false ); ?>>
								<?php esc_html_e( 'Enable CAPTCHA on login page', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'CAPTCHA Type', 'wp-harden' ); ?></th>
						<td>
							<select name="captcha_type">
								<option value="recaptcha_v2" <?php selected( $current_settings['captcha_type'] ?? 'recaptcha_v2', 'recaptcha_v2' ); ?>>
									<?php esc_html_e( 'reCAPTCHA v2', 'wp-harden' ); ?>
								</option>
								<option value="recaptcha_v3" <?php selected( $current_settings['captcha_type'] ?? 'recaptcha_v2', 'recaptcha_v3' ); ?>>
									<?php esc_html_e( 'reCAPTCHA v3', 'wp-harden' ); ?>
								</option>
								<option value="hcaptcha" <?php selected( $current_settings['captcha_type'] ?? 'recaptcha_v2', 'hcaptcha' ); ?>>
									<?php esc_html_e( 'hCaptcha', 'wp-harden' ); ?>
								</option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'reCAPTCHA Site Key', 'wp-harden' ); ?></th>
						<td>
							<input type="text" name="recaptcha_site_key" class="regular-text" 
								value="<?php echo esc_attr( $current_settings['recaptcha_site_key'] ?? '' ); ?>">
							<p class="description">
								<?php
								echo wp_kses_post(
									sprintf(
										/* translators: %s: Google reCAPTCHA URL */
										__( 'Get your keys from <a href="%s" target="_blank">Google reCAPTCHA</a>', 'wp-harden' ),
										'https://www.google.com/recaptcha/admin'
									)
								);
								?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'reCAPTCHA Secret Key', 'wp-harden' ); ?></th>
						<td>
							<input type="password" name="recaptcha_secret_key" class="regular-text" 
								value="<?php echo esc_attr( $current_settings['recaptcha_secret_key'] ?? '' ); ?>">
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

			<!-- Database Security Tab -->
			<div id="database" class="wph-tab-content">
				<h2><?php esc_html_e( 'Database Security Settings', 'wp-harden' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Database Backups', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="database_backups_enabled" value="1" 
									<?php checked( $current_settings['database_backups_enabled'] ?? false ); ?>>
								<?php esc_html_e( 'Enable automatic database backups', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Backup Frequency', 'wp-harden' ); ?></th>
						<td>
							<select name="backup_frequency">
								<option value="daily" <?php selected( $current_settings['backup_frequency'] ?? 'weekly', 'daily' ); ?>>
									<?php esc_html_e( 'Daily', 'wp-harden' ); ?>
								</option>
								<option value="weekly" <?php selected( $current_settings['backup_frequency'] ?? 'weekly', 'weekly' ); ?>>
									<?php esc_html_e( 'Weekly', 'wp-harden' ); ?>
								</option>
								<option value="monthly" <?php selected( $current_settings['backup_frequency'] ?? 'weekly', 'monthly' ); ?>>
									<?php esc_html_e( 'Monthly', 'wp-harden' ); ?>
								</option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Backup Retention Days', 'wp-harden' ); ?></th>
						<td>
							<input type="number" name="backup_retention_days" value="<?php echo absint( $current_settings['backup_retention_days'] ?? 30 ); ?>" min="1" max="365">
							<?php esc_html_e( 'days', 'wp-harden' ); ?>
							<p class="description">
								<?php esc_html_e( 'How long to keep database backups before deletion', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Encryption for Backups', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="database_encryption" value="1" 
									<?php checked( $current_settings['database_encryption'] ?? false ); ?>>
								<?php esc_html_e( 'Encrypt database backups', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Query Monitoring', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="query_monitoring" value="1" 
									<?php checked( $current_settings['query_monitoring'] ?? false ); ?>>
								<?php esc_html_e( 'Monitor and log suspicious database queries', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Auto-Optimize Database', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="auto_optimize_database" value="1" 
									<?php checked( $current_settings['auto_optimize_database'] ?? false ); ?>>
								<?php esc_html_e( 'Automatically optimize database tables weekly', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
				</table>
			</div>

			<!-- Security Hardening Tab -->
			<div id="hardening" class="wph-tab-content">
				<h2><?php esc_html_e( 'Security Hardening Settings', 'wp-harden' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Disable XML-RPC', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="disable_xmlrpc" value="1" 
									<?php checked( $current_settings['disable_xmlrpc'] ?? true ); ?>>
								<?php esc_html_e( 'Disable XML-RPC functionality', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Recommended unless you need XML-RPC for specific features.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Disable File Editing', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="disable_file_editing" value="1" 
									<?php checked( $current_settings['disable_file_editing'] ?? true ); ?>>
								<?php esc_html_e( 'Disable theme and plugin file editor in admin', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Prevents attackers from editing theme/plugin files if they gain admin access.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Remove WordPress Version', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="remove_wp_version" value="1" 
									<?php checked( $current_settings['remove_wp_version'] ?? true ); ?>>
								<?php esc_html_e( 'Hide WordPress version from public pages', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Makes it harder for attackers to identify your WordPress version.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Security Headers', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="enable_security_headers" value="1" 
									<?php checked( $current_settings['enable_security_headers'] ?? true ); ?>>
								<?php esc_html_e( 'Add security headers (X-Frame-Options, X-Content-Type-Options, etc.)', 'wp-harden' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Disable REST API for Unauthenticated Users', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="disable_rest_api_unauth" value="1" 
									<?php checked( $current_settings['disable_rest_api_unauth'] ?? false ); ?>>
								<?php esc_html_e( 'Restrict REST API to authenticated users only', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'May break some plugins that rely on public REST API access.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Force SSL for Admin', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="force_ssl_admin" value="1" 
									<?php checked( $current_settings['force_ssl_admin'] ?? false ); ?>>
								<?php esc_html_e( 'Require SSL for admin area', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Only enable if you have SSL certificate installed.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Disable Pingbacks/Trackbacks', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="disable_pingbacks" value="1" 
									<?php checked( $current_settings['disable_pingbacks'] ?? true ); ?>>
								<?php esc_html_e( 'Disable pingbacks and trackbacks', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Prevents DDoS attacks using pingbacks.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
				</table>
			</div>

			<!-- Advanced Settings Tab -->
			<div id="advanced" class="wph-tab-content">
				<h2><?php esc_html_e( 'Advanced Settings', 'wp-harden' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Scanner Schedule', 'wp-harden' ); ?></th>
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
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable Debug Mode', 'wp-harden' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="debug_mode" value="1" 
									<?php checked( $current_settings['debug_mode'] ?? false ); ?>>
								<?php esc_html_e( 'Enable debug logging for troubleshooting', 'wp-harden' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Only enable temporarily for troubleshooting. Creates verbose logs.', 'wp-harden' ); ?>
							</p>
						</td>
					</tr>
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
					<tr>
						<th scope="row"><?php esc_html_e( 'Excluded URLs from Firewall', 'wp-harden' ); ?></th>
						<td>
							<textarea name="excluded_urls" rows="8" class="large-text code"><?php 
								echo esc_textarea( $current_settings['excluded_urls'] ?? '' ); 
							?></textarea>
							<p class="description">
								<?php esc_html_e( 'One URL path per line. These URLs will bypass firewall checks. Use with caution.', 'wp-harden' ); ?>
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
