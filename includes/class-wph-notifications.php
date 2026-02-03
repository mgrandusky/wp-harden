<?php
/**
 * Email Notifications Class
 *
 * @package WP_Harden
 * @since 1.0.0
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Class WPH_Notifications
 *
 * Handles email notifications for security events
 */
class WPH_Notifications {

	/**
	 * Singleton instance
	 *
	 * @var WPH_Notifications
	 */
	private static $instance = null;

	/**
	 * Get singleton instance
	 *
	 * @return WPH_Notifications
	 * @since 1.0.0
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor
	 *
	 * @since 1.0.0
	 */
	private function __construct() {
		$this->init_hooks();
	}

	/**
	 * Initialize hooks
	 *
	 * @since 1.0.0
	 */
	private function init_hooks() {
		add_action( 'wph_critical_event', array( $this, 'handle_critical_event' ), 10, 3 );
	}

	/**
	 * Handle critical security event
	 *
	 * @param string $event_type Event type.
	 * @param string $message    Event message.
	 * @param array  $metadata   Event metadata.
	 * @since 1.0.0
	 */
	public function handle_critical_event( $event_type, $message, $metadata ) {
		// Don't send notifications during early initialization
		if ( ! did_action( 'init' ) ) {
			error_log( sprintf( 'WP Harden: Critical event during init - %s: %s', $event_type, $message ) );
			return;
		}

		$settings = WPH_Settings::get_instance();

		if ( ! $settings->get( 'email_notifications', true ) ) {
			return;
		}

		$this->send_security_alert( $event_type, $message, $metadata );
	}

	/**
	 * Send security alert email
	 *
	 * @param string $event_type Event type.
	 * @param string $message    Event message.
	 * @param array  $metadata   Event metadata.
	 * @return bool
	 * @since 1.0.0
	 */
	public function send_security_alert( $event_type, $message, $metadata ) {
		// Check if wp_mail is available
		if ( ! function_exists( 'wp_mail' ) ) {
			error_log( 'WP Harden: Cannot send email - wp_mail not available' );
			return false;
		}

		$settings = WPH_Settings::get_instance();
		$to       = $settings->get( 'notification_email', get_option( 'admin_email' ) );

		$subject = sprintf(
			'[%s] Security Alert: %s',
			get_bloginfo( 'name' ),
			ucfirst( $event_type )
		);

		$body = $this->get_alert_email_body( $event_type, $message, $metadata );

		$headers = array( 'Content-Type: text/html; charset=UTF-8' );

		return wp_mail( $to, $subject, $body, $headers );
	}

	/**
	 * Send scan alert email
	 *
	 * @param array $scan_results Scan results.
	 * @return bool
	 * @since 1.0.0
	 */
	public function send_scan_alert( $scan_results ) {
		// Check if wp_mail is available
		if ( ! function_exists( 'wp_mail' ) ) {
			error_log( 'WP Harden: Cannot send email - wp_mail not available' );
			return false;
		}

		$settings = WPH_Settings::get_instance();
		$to       = $settings->get( 'notification_email', get_option( 'admin_email' ) );

		$subject = sprintf(
			'[%s] Security Scan Completed',
			get_bloginfo( 'name' )
		);

		$body = $this->get_scan_email_body( $scan_results );

		$headers = array( 'Content-Type: text/html; charset=UTF-8' );

		return wp_mail( $to, $subject, $body, $headers );
	}

	/**
	 * Get alert email body
	 *
	 * @param string $event_type Event type.
	 * @param string $message    Event message.
	 * @param array  $metadata   Event metadata.
	 * @return string
	 * @since 1.0.0
	 */
	private function get_alert_email_body( $event_type, $message, $metadata ) {
		$site_name = get_bloginfo( 'name' );
		$site_url  = get_site_url();

		ob_start();
		?>
		<html>
		<head>
			<style>
				body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
				.container { max-width: 600px; margin: 0 auto; padding: 20px; }
				.header { background-color: #dc3232; color: white; padding: 20px; text-align: center; }
				.content { background-color: #f9f9f9; padding: 20px; }
				.footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
				.metadata { background-color: #fff; padding: 15px; margin-top: 15px; border-left: 4px solid #dc3232; }
				.metadata strong { display: block; margin-bottom: 5px; }
			</style>
		</head>
		<body>
			<div class="container">
				<div class="header">
					<h2>⚠️ Security Alert</h2>
				</div>
				<div class="content">
					<h3>Security Event Detected</h3>
					<p><strong>Site:</strong> <?php echo esc_html( $site_name ); ?></p>
					<p><strong>Event Type:</strong> <?php echo esc_html( ucfirst( $event_type ) ); ?></p>
					<p><strong>Message:</strong> <?php echo esc_html( $message ); ?></p>
					<p><strong>Time:</strong> <?php echo esc_html( current_time( 'mysql' ) ); ?></p>
					
					<?php if ( ! empty( $metadata ) ) : ?>
					<div class="metadata">
						<strong>Additional Details:</strong>
						<?php foreach ( $metadata as $key => $value ) : ?>
							<p><strong><?php echo esc_html( ucfirst( $key ) ); ?>:</strong> <?php echo esc_html( is_array( $value ) ? wp_json_encode( $value ) : $value ); ?></p>
						<?php endforeach; ?>
					</div>
					<?php endif; ?>
					
					<p style="margin-top: 20px;">
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden' ) ); ?>" style="background-color: #0073aa; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px;">View Dashboard</a>
					</p>
				</div>
				<div class="footer">
					<p>This is an automated message from WP Harden Security Plugin</p>
					<p><?php echo esc_html( $site_url ); ?></p>
				</div>
			</div>
		</body>
		</html>
		<?php
		return ob_get_clean();
	}

	/**
	 * Get scan email body
	 *
	 * @param array $scan_results Scan results.
	 * @return string
	 * @since 1.0.0
	 */
	private function get_scan_email_body( $scan_results ) {
		$site_name = get_bloginfo( 'name' );
		$site_url  = get_site_url();

		$total_issues = 0;
		foreach ( $scan_results as $result ) {
			$total_issues += count( $result['issues'] );
		}

		ob_start();
		?>
		<html>
		<head>
			<style>
				body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
				.container { max-width: 600px; margin: 0 auto; padding: 20px; }
				.header { background-color: #0073aa; color: white; padding: 20px; text-align: center; }
				.content { background-color: #f9f9f9; padding: 20px; }
				.footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
				.scan-result { background-color: #fff; padding: 15px; margin-bottom: 15px; border-left: 4px solid #0073aa; }
				.issue { padding: 10px; margin: 5px 0; background-color: #fff3cd; border-left: 3px solid #ffc107; }
				.critical { border-left-color: #dc3232; background-color: #ffe5e5; }
				.high { border-left-color: #ff6900; background-color: #fff3e5; }
			</style>
		</head>
		<body>
			<div class="container">
				<div class="header">
					<h2>🛡️ Security Scan Report</h2>
				</div>
				<div class="content">
					<h3>Scan Complete</h3>
					<p><strong>Site:</strong> <?php echo esc_html( $site_name ); ?></p>
					<p><strong>Scan Date:</strong> <?php echo esc_html( current_time( 'mysql' ) ); ?></p>
					<p><strong>Total Issues Found:</strong> <?php echo absint( $total_issues ); ?></p>
					
					<?php foreach ( $scan_results as $result ) : ?>
						<?php if ( ! empty( $result['issues'] ) ) : ?>
						<div class="scan-result">
							<h4><?php echo esc_html( ucwords( str_replace( '_', ' ', $result['scan_type'] ) ) ); ?></h4>
							<?php foreach ( $result['issues'] as $issue ) : ?>
								<div class="issue <?php echo isset( $issue['severity'] ) ? esc_attr( $issue['severity'] ) : ''; ?>">
									<strong><?php echo esc_html( $issue['issue'] ?? 'Security Issue' ); ?></strong>
									<?php if ( isset( $issue['severity'] ) ) : ?>
										<span style="float: right; color: #dc3232;"><?php echo esc_html( ucfirst( $issue['severity'] ) ); ?></span>
									<?php endif; ?>
									<?php if ( isset( $issue['recommendation'] ) ) : ?>
										<p><em><?php echo esc_html( $issue['recommendation'] ); ?></em></p>
									<?php endif; ?>
								</div>
							<?php endforeach; ?>
						</div>
						<?php endif; ?>
					<?php endforeach; ?>
					
					<p style="margin-top: 20px;">
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-harden-scanner' ) ); ?>" style="background-color: #0073aa; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px;">View Full Report</a>
					</p>
				</div>
				<div class="footer">
					<p>This is an automated message from WP Harden Security Plugin</p>
					<p><?php echo esc_html( $site_url ); ?></p>
				</div>
			</div>
		</body>
		</html>
		<?php
		return ob_get_clean();
	}
}
