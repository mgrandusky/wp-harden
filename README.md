# WP Harden

A comprehensive WordPress security plugin providing firewall protection, malware scanning, login security, and real-time threat monitoring.

## Description

WP Harden is a production-ready WordPress security plugin designed to protect your WordPress site from common security threats. Similar to WordFence, it provides multiple layers of security including a Web Application Firewall (WAF), login security, malware scanning, and comprehensive activity logging.

## Features

### 🛡️ Web Application Firewall (WAF)
- Real-time request filtering and sanitization
- SQL injection detection and prevention
- XSS (Cross-Site Scripting) protection
- File inclusion vulnerability protection
- Known malicious pattern detection
- IP-based blocking with whitelist/blacklist support
- Rate limiting per IP address
- Threat level scoring system

### 🔐 Login Security System
- Brute force attack prevention
- Configurable login attempt limiting
- Automatic temporary IP blocking after failed attempts
- Login attempt logging with timestamps
- CAPTCHA integration support (hooks for reCAPTCHA)
- Two-factor authentication preparation hooks
- Strong password enforcement
- Username enumeration prevention

### 🔍 Security Scanner
- WordPress core file integrity checking
- Plugin and theme vulnerability detection
- Malware signature scanning
- Suspicious file detection (backdoors, shells)
- Database security audit
- File permission checking
- Automated scan scheduling
- Detailed scan reports with actionable recommendations

### 📊 Activity Logger
- Comprehensive security event logging
- Multiple log types: login attempts, blocked requests, file changes, scans
- Database table with optimized indexing
- Configurable log retention policy
- Export logs functionality (CSV format)
- Real-time activity monitoring
- Critical event email notifications

### 🚫 IP Management System
- IP address blocking and unblocking
- IP whitelist management
- IP range blocking (CIDR notation support)
- Country-based blocking ready (GeoIP integration hooks)
- Automatic blocking based on threat score
- Temporary and permanent blocks
- Block reason logging and tracking

### 📧 Email Notification System
- Email alerts for critical security events
- Customizable HTML email templates
- Alert types: blocked attacks, failed logins, scan results, file changes
- Configurable notification frequency
- Multiple recipient support
- Professional email formatting

### ⚙️ Admin Dashboard Interface
- Security overview dashboard with real-time statistics
- Security score/rating display
- Real-time threat monitoring
- Quick action buttons for common tasks
- Settings page with intuitive tabbed interface
- Recent activity feed
- Responsive design for mobile access

## Installation

1. Upload the `wp-harden` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Navigate to the WP Harden menu in the WordPress admin
4. Configure your security settings according to your needs

## Requirements

- WordPress 5.8 or higher
- PHP 7.4 or higher
- MySQL 5.6 or higher

## Configuration

### Initial Setup

After activation, the plugin will:
1. Create necessary database tables
2. Set secure default configuration
3. Begin monitoring for security threats

### Recommended Settings

For optimal security, we recommend:
- Enable all security modules (Firewall, Login Security, Scanner)
- Set login attempts to maximum 5 attempts
- Set lockout duration to 15 minutes (900 seconds)
- Enable email notifications
- Configure daily security scans
- Add your IP address to the whitelist

### Firewall Configuration

The firewall has three sensitivity levels:
- **Low**: Basic protection, fewer false positives
- **Medium**: Recommended for most sites, balanced protection
- **High**: Maximum protection, may require whitelist tuning

### Login Security

Configure the following:
- **Max Login Attempts**: 5 (recommended)
- **Lockout Duration**: 900 seconds (15 minutes)
- **Strong Password Enforcement**: Enabled
- **Username Enumeration Prevention**: Enabled

## Usage

### Running Security Scans

1. Navigate to WP Harden → Scanner
2. Click "Run Security Scan"
3. Review the results and follow recommendations
4. Address critical and high-severity issues first

### Managing Blocked IPs

1. Navigate to WP Harden → IP Management
2. View currently blocked IP addresses
3. Block new IPs manually or they will be blocked automatically
4. Unblock IPs as needed
5. Manage whitelist and blacklist in Settings

### Viewing Activity Logs

1. Navigate to WP Harden → Logs
2. Filter by log type or severity
3. Review security events
4. Export logs for analysis or compliance

### Configuring Settings

1. Navigate to WP Harden → Settings
2. Configure each tab:
   - **Firewall**: WAF settings and rate limiting
   - **Login Security**: Login protection settings
   - **Scanner**: Scan schedule and retention
   - **Notifications**: Email alert settings
   - **IP Lists**: Whitelist and blacklist management

## Database Tables

The plugin creates the following tables:

- `wp_wph_logs` - Security event logs
- `wp_wph_blocked_ips` - Blocked IP addresses
- `wp_wph_login_attempts` - Failed login tracking
- `wp_wph_scan_results` - Scan history and results

## Hooks and Filters

### Actions

- `wph_loaded` - Fires when plugin is fully loaded
- `wph_critical_event` - Fires on critical security events
- `wph_daily_scan` - Fires during scheduled scans
- `wph_cleanup_logs` - Fires during log cleanup
- `wph_cleanup_expired_blocks` - Fires during IP block cleanup

### Filters

Developers can extend WP Harden using WordPress filters and actions.

## Performance Considerations

WP Harden is optimized for performance:
- Database queries use indexes for fast lookups
- Transients are used for caching frequently accessed data
- Firewall checks run early in the WordPress lifecycle
- Scans can be scheduled during low-traffic periods

## Security Best Practices

- Keep WordPress, themes, and plugins updated
- Use strong passwords for all user accounts
- Regularly review security logs
- Run security scans weekly at minimum
- Add trusted IPs to whitelist
- Configure email notifications for critical events
- Back up your site regularly

## Troubleshooting

### Locked Out of Admin?

If you're accidentally locked out:
1. Access your database via phpMyAdmin
2. Navigate to the `wp_wph_blocked_ips` table
3. Find your IP address and set `is_active` to 0
4. Add your IP to the whitelist in settings

### False Positives?

If legitimate traffic is being blocked:
1. Review the firewall sensitivity setting
2. Add trusted IPs to the whitelist
3. Check the logs to identify the triggering pattern
4. Adjust settings as needed

### Performance Issues?

If experiencing performance issues:
1. Increase log retention to reduce table size
2. Disable real-time scanning temporarily
3. Optimize database tables
4. Consider upgrading hosting

## Changelog

### 1.0.0
- Initial release
- Web Application Firewall
- Login Security System
- Security Scanner
- Activity Logger
- IP Management
- Email Notifications
- Admin Dashboard

## Support

For support, feature requests, or bug reports, please visit:
https://github.com/mgrandusky/wp-harden/issues

## License

This plugin is licensed under the GPL v2 or later.

## Credits

Developed by the WP Harden Team

## Contributing

Contributions are welcome! Please submit pull requests to:
https://github.com/mgrandusky/wp-harden

## Disclaimer

While WP Harden provides comprehensive security features, no security solution is 100% foolproof. Always maintain regular backups and follow WordPress security best practices.
