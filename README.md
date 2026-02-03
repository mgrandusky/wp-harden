# WP Harden - Enterprise Security Plugin

A comprehensive, enterprise-grade WordPress security plugin providing advanced firewall protection, threat intelligence, malware scanning, two-factor authentication, and complete compliance tools.

## Description

WP Harden is a production-ready, enterprise-grade WordPress security plugin designed to protect your WordPress site from advanced threats. Going beyond basic security, it provides multiple layers of defense including an advanced Web Application Firewall (WAF), threat intelligence, two-factor authentication, real-time file monitoring, database security, vulnerability management, incident response, and full compliance reporting.

## 🌟 Enterprise Features

### 🛡️ Advanced Web Application Firewall (WAF)
**Basic Protection:**
- Real-time request filtering and sanitization
- SQL injection detection and prevention (7+ patterns)
- XSS (Cross-Site Scripting) protection (6+ patterns)
- File inclusion vulnerability protection
- Path traversal detection
- Known malicious pattern detection
- IP-based blocking with whitelist/blacklist support
- Threat level scoring system (0-100)

**Advanced Features (NEW):**
- **Per-endpoint rate limiting** with sliding window algorithm (wp-login: 5/min, xmlrpc: 10/min, wp-admin: 30/min)
- **DDoS Protection** with traffic spike detection and JavaScript challenge-response
- **HTTP method filtering** per endpoint (blocks TRACE, TRACK, DEBUG)
- **File upload security** with MIME validation, extension checking, double-extension detection
- **Request header anomaly detection** (missing headers, spoofed headers, CRLF injection)
- **Cookie security hardening** (Secure, HttpOnly, SameSite attributes)
- Burst detection and mitigation
- Configurable thresholds for all protections

### 🔐 Advanced Authentication System
**Two-Factor Authentication (TOTP):**
- Full RFC 6238 implementation with authenticator app support
- QR code generation for easy setup
- 10 single-use backup codes
- Grace period for 2FA setup
- Recovery options for lost devices
- Per-role 2FA requirements

**Passwordless Login:**
- Magic link authentication via email
- Time-limited single-use tokens (15 minutes)
- WebAuthn/FIDO2 preparation hooks

**Session Management:**
- Session hijacking prevention with IP binding
- Device fingerprinting
- Concurrent session limiting (configurable)
- Force logout all sessions
- Session timeout configuration

**Password Policies:**
- Password expiry (configurable, default 90 days)
- Password history (prevent reusing last 5 passwords)
- Strong password requirements (12+ chars, mixed case, numbers, symbols)
- Admin-triggered password reset for all users

### 🔒 Security Hardening
- **XML-RPC Control:** Complete disable or selective method blocking with Jetpack whitelist
- **File Editing Disable:** Set DISALLOW_FILE_EDIT and DISALLOW_FILE_MODS constants
- **WordPress Version Hiding:** Remove from meta tags, scripts, styles, RSS feeds
- **Security Headers:** CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **REST API Control:** Disable for unauthenticated users, endpoint whitelisting, rate limiting
- **Meta Tag Removal:** Remove RSD, wlwmanifest, shortlink, adjacent posts
- **User Enumeration Prevention:** Block ?author=N queries and author archives
- **Login Error Hiding:** Generic error messages
- **Pingback/Trackback Disabling:** Remove X-Pingback header and methods
- **SSL Admin Enforcement:** Force HTTPS for admin with FORCE_SSL_ADMIN
- **Application Passwords Control:** Disable WordPress 5.6+ app passwords

### 🎯 Threat Intelligence System
- **IP Reputation Checking:** AbuseIPDB API integration with 24-hour caching
- **Malicious Bot Detection:** Pattern matching for 20+ attack tools (sqlmap, nikto, nmap, metasploit)
- **Behavioral Analysis:** Detects rapid requests and suspicious patterns
- **Tor/VPN/Proxy Detection:** Tor exit node list + ProxyCheck.io API support
- **Threat Score Calculation:** Weighted algorithm (IP: 40%, Bot: 30%, Proxy: 30%)
- **Automatic IP Blocking:** Configurable threshold-based blocking (default: 75/100)
- **Whitelist Override:** Admin IPs automatically bypass all checks
- **Statistics & Reporting:** Comprehensive threat analytics

### 📁 File System Protection
- **Real-time File Change Monitoring:** MD5 hash-based detection with baseline storage
- **Critical File Alerts:** Immediate notifications for wp-config.php, .htaccess changes
- **File Upload Restrictions:** Blocks executables, detects double extensions (.php.jpg)
- **Null Byte Injection Prevention:** Blocks \0 and %00 in filenames
- **Directory Protection:** Automatic index.php creation to prevent listing
- **.htaccess Hardening:** Auto-generated security rules, blocks sensitive files
- **wp-config.php Protection:** File permission checks (sets to 0400), security constant verification
- **PHP Execution Prevention:** .htaccess in uploads directory blocks PHP execution
- **File Quarantine System:** Base64 encoding, metadata logging, restore/delete functionality
- **Suspicious Pattern Detection:** Detects eval(), base64_decode(), system() calls

### 💾 Database Security
- **Database Prefix Randomization:** Change from wp_ to random prefix with safety checks
- **SQL Query Monitoring:** Real-time monitoring with 15+ suspicious pattern detection
- **Database Backup & Encryption:** AES-256-CBC encryption, gzip compression, automated backups
- **Backup Rotation:** Configurable retention with automatic cleanup
- **Database Optimization:** OPTIMIZE TABLE, REPAIR TABLE, ANALYZE TABLE
- **Post Revision Cleanup:** Keep last N revisions (configurable, default 5)
- **Spam Comment Deletion:** Automated cleanup
- **Transient Cleanup:** Remove expired transients
- **Suspicious Query Detection:** Real-time SQL injection attempt blocking
- **Slow Query Detection:** Configurable threshold (default 2 seconds)

### 📊 Advanced Monitoring
- **Real-time Security Dashboard:** Live threat statistics, active attacks counter, security score (0-100)
- **Detailed Audit Trail:** Tracks all admin actions with before/after values, user role changes, settings modifications
- **User Activity Tracking:** Logins, page views, post modifications, media uploads
- **Admin Action Logging:** Plugin/theme installations/updates/deletions, user creation/deletion, role assignments
- **Plugin/Theme Change Detection:** Alerts on new installations, version changes
- **Failed Authentication Pattern Detection:** Identifies brute-force and distributed attacks
- **Scheduled Security Reports:** Daily/weekly/monthly with email delivery and CSV export

### 🔍 Vulnerability Management
- **WordPress Core Vulnerability Checking:** WPScan API integration
- **Plugin/Theme Vulnerability Scanning:** Daily automated scans with CVE tracking
- **Automatic Security Updates:** Per-component control (core, plugins, themes)
- **Outdated Software Detection:** Identifies plugins not updated in 2+ years
- **CVE Tracking & Alerts:** Email notifications with severity classifications (critical, high, medium, low)
- **Update Recommendations:** Shows which updates fix known vulnerabilities

### 🚨 Incident Response
- **Automated Response Workflows:** Define actions per threat type with automatic IP blocking
- **Malware Scanning:** 16+ signature patterns (eval, base64_decode, shell_exec, etc.)
- **One-Click Malware Removal:** Automated cleanup with automatic backups
- **File Quarantine:** Suspicious files moved to protected directory
- **Rollback Functionality:** Restore quarantined files or database backups
- **Emergency Lockdown Mode:** Disable all logins except whitelisted admins, block all traffic except whitelisted IPs
- **Security Event Playbooks:** Predefined procedures for malware, brute-force, data breach, unauthorized access

### 📋 Compliance & Reporting
**GDPR Compliance:**
- Data access request handling (export all user data)
- Data deletion requests (right to be forgotten)
- WordPress Privacy API integration
- Data breach notification system

**Compliance Reporting:**
- **SOC 2:** 40+ controls mapped to SOC 2 requirements
- **PCI-DSS:** 12 requirements with implementation status
- **HIPAA:** 8 key requirements for healthcare sites
- **ISO 27001:** 10 key controls alignment

**Audit Logs:**
- Tamper-proof logging with hash verification
- Long-term retention (configurable, default 365 days)
- CSV export with date range filtering
- Comprehensive audit trail for all admin actions

**Custom Reporting:**
- Scheduled report generation (daily/weekly/monthly)
- Email distribution lists
- Executive summary format

### 🔍 Security Scanner (Enhanced)
- WordPress core file integrity checking
- Plugin and theme vulnerability detection
- Malware signature scanning
- Suspicious file detection (backdoors, shells)
- Database security audit
- File permission checking
- Automated scan scheduling
- Detailed scan reports with actionable recommendations

### 📊 Activity Logger (Enhanced)
- Comprehensive security event logging
- 10+ log types: login attempts, blocked requests, file changes, scans, threats, incidents
- Database tables with optimized indexing (13 tables total)
- Configurable log retention policy
- Export logs functionality (CSV format)
- Real-time activity monitoring
- Critical event email notifications

### 🚫 IP Management System
- IP address blocking and unblocking
- IP whitelist management
- IP range blocking (CIDR notation support)
- Threat intelligence-based blocking
- Automatic blocking based on threat score
- Temporary and permanent blocks
- Block reason logging and tracking

### 📧 Email Notification System
- Email alerts for critical security events
- Customizable HTML email templates
- Alert types: blocked attacks, failed logins, scan results, file changes, vulnerabilities, incidents
- Configurable notification frequency
- Multiple recipient support
- Professional email formatting

### ⚙️ Admin Dashboard Interface
- Security overview dashboard with real-time statistics
- Security score/rating display (0-100)
- Real-time threat monitoring
- Quick action buttons for common tasks
- Settings page with intuitive tabbed interface
- Recent activity feed
- Responsive design for mobile access
- 13 database tables with comprehensive data storage

## Installation

1. Upload the `wp-harden` folder to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Navigate to the WP Harden menu in the WordPress admin
4. Configure your security settings according to your needs
5. (Optional) Configure API keys for threat intelligence:
   - AbuseIPDB API key for IP reputation checking
   - WPScan API key for vulnerability scanning
   - ProxyCheck.io API key for proxy/VPN detection

## Requirements

- WordPress 5.8 or higher
- PHP 7.4 or higher (PHP 8.0+ recommended)
- MySQL 5.6 or higher (MySQL 8.0+ recommended)
- 64MB+ PHP memory limit (128MB+ recommended for large sites)
- OpenSSL extension for encryption features
- cURL extension for API integrations

## Configuration

### Initial Setup

After activation, the plugin will:
1. Create 13 database tables for comprehensive security tracking
2. Set secure default configuration
3. Begin monitoring for security threats
4. Enable basic firewall protection
5. Initialize security hardening features

### Recommended Settings

For optimal enterprise-grade security, we recommend:

**Firewall & WAF:**
- Enable advanced rate limiting
- Enable DDoS protection
- Set file upload security to strict
- Enable header anomaly detection
- Enable cookie security hardening

**Authentication:**
- Enable 2FA for all administrator accounts
- Set password expiry to 90 days
- Enable session IP binding
- Limit concurrent sessions to 3

**Threat Intelligence:**
- Configure AbuseIPDB API key
- Enable automatic IP blocking (threshold: 75)
- Enable Tor/VPN/proxy detection
- Set cache TTL to 24 hours

**File Protection:**
- Enable file monitoring with daily scans
- Enable file quarantine
- Enable .htaccess hardening
- Enable wp-config.php protection

**Database Security:**
- Enable encrypted backups
- Set backup schedule to weekly
- Enable database optimization
- Set backup retention to 30 days

**Hardening:**
- Disable XML-RPC (unless using Jetpack)
- Enable all security headers
- Disable REST API for unauthenticated users
- Hide WordPress version
- Disable user enumeration

**Monitoring:**
- Enable audit trail
- Enable security reports (weekly)
- Track all admin actions
- Set log retention to 365 days

**Vulnerability Management:**
- Configure WPScan API key
- Enable daily vulnerability scans
- Enable auto-updates for core (recommended)
- Consider auto-updates for trusted plugins

**Incident Response:**
- Enable automated incident response
- Enable auto-quarantine for malware
- Configure lockdown mode whitelist
- Review security event playbooks

**Compliance:**
- Enable GDPR tools (if applicable)
- Set audit log retention to 365 days
- Configure compliance report schedule
- Review compliance checklists for your industry

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
3. Block new IPs manually or they will be blocked automatically based on threat intelligence
4. Unblock IPs as needed
5. Manage whitelist and blacklist in Settings

### Viewing Activity Logs

1. Navigate to WP Harden → Logs
2. Filter by log type or severity
3. Review security events
4. Export logs for analysis or compliance (CSV format)

### Managing Two-Factor Authentication

1. Navigate to WP Harden → Authentication
2. Enable 2FA for your account
3. Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
4. Save backup codes in a secure location
5. Test 2FA login before logging out

### Configuring Security Hardening

1. Navigate to WP Harden → Hardening
2. Review and enable recommended hardening options
3. Disable XML-RPC if not needed
4. Enable security headers
5. Hide WordPress version information
6. Disable user enumeration

### Monitoring Threats

1. Navigate to WP Harden → Threat Intelligence
2. View real-time threat feed
3. Check IP reputation scores
4. Review blocked threats
5. Configure automatic blocking thresholds

### Managing File Protection

1. Navigate to WP Harden → File Protection
2. Run file integrity scan
3. Review changed files
4. Manage quarantined files
5. Configure monitoring schedule

### Database Security

1. Navigate to WP Harden → Database
2. Create encrypted backups
3. Optimize database tables
4. Review query monitoring logs
5. Configure backup schedule

### Vulnerability Management

1. Navigate to WP Harden → Vulnerabilities
2. Run vulnerability scan
3. Review detected vulnerabilities
4. Apply recommended updates
5. Configure automatic updates

### Incident Response

1. Navigate to WP Harden → Incidents
2. View active incidents
3. Review security event playbooks
4. Enable emergency lockdown if needed
5. Restore from backups if compromised

### Compliance Reporting

1. Navigate to WP Harden → Compliance
2. Generate compliance reports (SOC 2, PCI-DSS, HIPAA, ISO 27001)
3. Export security audit logs
4. Handle GDPR data requests
5. Schedule automated compliance reports

### Configuring Settings

1. Navigate to WP Harden → Settings
2. Configure each module:
   - **Firewall**: WAF settings, rate limiting, DDoS protection
   - **Authentication**: 2FA, session management, password policies
   - **Hardening**: Security headers, XML-RPC, REST API control
   - **Threat Intelligence**: API keys, blocking thresholds
   - **File Protection**: Monitoring schedule, quarantine settings
   - **Database**: Backup schedule, encryption, optimization
   - **Monitoring**: Audit trail, security reports, activity tracking
   - **Vulnerabilities**: Scan schedule, auto-updates, API keys
   - **Incident Response**: Auto-quarantine, lockdown mode, playbooks
   - **Compliance**: GDPR tools, report schedule, retention policies
   - **Notifications**: Email alert settings, recipients
   - **IP Lists**: Whitelist and blacklist management

## Database Tables

The plugin creates 13 database tables for comprehensive security tracking:

### Core Tables
- `wp_wph_logs` - Security event logs (all types)
- `wp_wph_blocked_ips` - Blocked IP addresses with expiry tracking
- `wp_wph_login_attempts` - Failed login tracking with user agents
- `wp_wph_scan_results` - Scan history and results

### Advanced Security Tables
- `wp_wph_2fa_tokens` - Two-factor authentication secrets and backup codes
- `wp_wph_sessions` - Session management with IP binding and device fingerprinting
- `wp_wph_threat_intelligence` - Cached threat data from external APIs
- `wp_wph_file_changes` - File integrity monitoring with MD5 hashes
- `wp_wph_backups` - Database backup metadata and encryption info
- `wp_wph_audit_trail` - Detailed admin action audit logs with before/after values
- `wp_wph_vulnerabilities` - Discovered vulnerabilities with CVE tracking
- `wp_wph_incidents` - Security incident logs with response actions
- `wp_wph_compliance_reports` - Generated compliance reports for various standards

All tables use proper indexing for optimal performance and include keys on frequently queried columns.

## Hooks and Filters

### Actions

**Core Actions:**
- `wph_loaded` - Fires when plugin is fully loaded
- `wph_critical_event` - Fires on critical security events
- `wph_daily_scan` - Fires during scheduled scans
- `wph_cleanup_logs` - Fires during log cleanup
- `wph_cleanup_expired_blocks` - Fires during IP block cleanup

**Authentication Actions:**
- `wph_2fa_enabled` - Fires when 2FA is enabled for a user
- `wph_2fa_verified` - Fires when 2FA code is successfully verified
- `wph_session_created` - Fires when a new session is created
- `wph_session_destroyed` - Fires when a session is destroyed

**File Protection Actions:**
- `wph_file_changed` - Fires when a file change is detected
- `wph_file_quarantined` - Fires when a file is moved to quarantine
- `wph_suspicious_file_detected` - Fires when a suspicious file pattern is found

**Incident Response Actions:**
- `wph_incident_detected` - Fires when a security incident is logged
- `wph_lockdown_enabled` - Fires when emergency lockdown is activated
- `wph_lockdown_disabled` - Fires when emergency lockdown is deactivated
- `wph_malware_detected` - Fires when malware is found

### Filters

**Firewall Filters:**
- `wph_security_headers` - Customize security headers
- `wph_rate_limit_threshold` - Modify rate limiting thresholds
- `wph_blocked_user_agents` - Add/remove blocked user agents
- `wph_allowed_upload_mimes` - Customize allowed MIME types

**Authentication Filters:**
- `wph_2fa_required_roles` - Which roles require 2FA (default: administrator)
- `wph_session_timeout` - Customize session timeout duration
- `wph_password_requirements` - Modify password complexity rules
- `wph_webauthn_enabled` - Enable WebAuthn/FIDO2 support
- `wph_oauth_providers` - Configure OAuth providers

**Threat Intelligence Filters:**
- `wph_threat_score_threshold` - Modify automatic blocking threshold
- `wph_tor_exit_nodes` - Customize Tor exit node list
- `wph_ip_whitelist` - Add IPs to whitelist programmatically

**File Protection Filters:**
- `wph_monitored_paths` - Customize monitored directories
- `wph_quarantine_path` - Change quarantine directory location
- `wph_suspicious_patterns` - Add custom malware patterns

**Database Filters:**
- `wph_backup_path` - Customize backup storage location
- `wph_suspicious_queries` - Add custom SQL injection patterns

**Vulnerability Filters:**
- `wph_auto_update_plugins` - Control which plugins auto-update
- `wph_auto_update_themes` - Control which themes auto-update

**Compliance Filters:**
- `wph_compliance_standards` - Add custom compliance standards
- `wph_gdpr_export_data` - Customize GDPR data export

Developers can extend WP Harden using these hooks and many more throughout the codebase.

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
4. Adjust rate limiting thresholds for specific endpoints
5. Configure threat intelligence blocking threshold
6. Review header anomaly detection settings

### Performance Issues?

If experiencing performance issues:
1. Adjust log retention to reduce table size (default: 30 days)
2. Increase threat intelligence cache TTL
3. Disable query monitoring if not needed
4. Optimize database tables via Database Security module
5. Reduce file monitoring scan frequency
6. Consider upgrading hosting for large sites

### API Rate Limits Reached?

If you're hitting API rate limits:
1. Increase threat intelligence cache TTL to 48 hours
2. Reduce vulnerability scan frequency to weekly
3. Consider upgrading API plans for high-traffic sites
4. Use local detection methods when APIs are unavailable

## Third-Party API Integrations

### Optional API Keys

For full enterprise features, configure these optional API keys:

**AbuseIPDB** (IP Reputation):
- Purpose: Check IP addresses against abuse database
- Free tier: 1,000 checks/day
- Get key: https://www.abuseipdb.com/api
- Configure: WP Harden → Settings → Threat Intelligence

**WPScan** (Vulnerability Database):
- Purpose: Check WordPress core, plugins, themes for vulnerabilities
- Free tier: 25 requests/day
- Get key: https://wpscan.com/api
- Configure: WP Harden → Settings → Vulnerability Management

**ProxyCheck.io** (Proxy/VPN Detection):
- Purpose: Detect proxies, VPNs, and Tor exit nodes
- Free tier: 1,000 queries/day
- Get key: https://proxycheck.io/
- Configure: WP Harden → Settings → Threat Intelligence

**Note:** All features work without API keys using local detection methods, but API integrations provide enhanced accuracy and threat intelligence.

## Changelog

### 2.0.0 (Current) - Enterprise Security Release
**Major Features:**
- ✅ Advanced WAF with per-endpoint rate limiting and DDoS protection
- ✅ Two-Factor Authentication (TOTP) with QR codes and backup codes
- ✅ Comprehensive security hardening (XML-RPC, security headers, REST API control)
- ✅ Threat intelligence system with IP reputation checking
- ✅ Real-time file change monitoring with quarantine system
- ✅ Database security with encrypted backups (AES-256)
- ✅ Advanced monitoring with audit trail and security scoring
- ✅ Vulnerability management with WPScan API integration
- ✅ Incident response with automated workflows and lockdown mode
- ✅ Compliance & reporting (SOC 2, PCI-DSS, HIPAA, ISO 27001)

**New Modules:**
- `class-wph-advanced-auth.php` - Two-factor authentication and session management
- `class-wph-hardening.php` - Security hardening controls
- `class-wph-threat-intelligence.php` - Threat intelligence and IP reputation
- `class-wph-file-protection.php` - File monitoring and quarantine
- `class-wph-database-security.php` - Database backups and optimization
- `class-wph-advanced-monitoring.php` - Audit trail and security scoring
- `class-wph-vulnerability-manager.php` - Vulnerability scanning and CVE tracking
- `class-wph-incident-response.php` - Incident management and malware removal
- `class-wph-compliance.php` - GDPR tools and compliance reporting

**New Database Tables (13 total):**
- `wp_wph_2fa_tokens` - Two-factor authentication data
- `wp_wph_sessions` - Enhanced session management
- `wp_wph_threat_intelligence` - Cached threat data
- `wp_wph_file_changes` - File integrity monitoring
- `wp_wph_backups` - Database backup metadata
- `wp_wph_audit_trail` - Detailed admin action logs
- `wp_wph_vulnerabilities` - Known vulnerability tracking
- `wp_wph_incidents` - Security incident logs
- `wp_wph_compliance_reports` - Generated compliance reports

**Enhanced Features:**
- Advanced rate limiting with sliding window algorithm
- HTTP method filtering per endpoint
- File upload security with MIME validation
- Request header anomaly detection
- Cookie security hardening (Secure, HttpOnly, SameSite)
- JavaScript challenge for DDoS protection
- Traffic spike detection with baseline comparison
- Session hijacking prevention with IP binding
- Password policies with history tracking
- Malware scanning with 16+ signature patterns
- Emergency lockdown mode
- Passwordless login with magic links
- Database prefix randomization
- SQL query monitoring with pattern detection
- Automated encrypted backups with rotation
- Security score calculation (0-100)
- Comprehensive audit trail
- CVE tracking with email alerts
- One-click malware removal
- GDPR compliance tools (data access/deletion)
- Tamper-proof audit logs with hash verification

**Performance Improvements:**
- Optimized database queries with proper indexing
- Threat data caching (24-hour TTL)
- Chunked operations for large databases
- Efficient file scanning algorithms

**Security Improvements:**
- All inputs sanitized, all outputs escaped
- Prepared statements for SQL queries
- Nonce verification on all forms
- Capability checks on all admin actions
- AES-256-CBC encryption for backups
- Secure random token generation
- OWASP Top 10 mitigation

### 1.0.0 - Initial Release
- Web Application Firewall (Basic)
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

While WP Harden provides comprehensive enterprise-grade security features, no security solution is 100% foolproof. Always maintain regular backups and follow WordPress security best practices. This plugin is provided "as-is" without warranty of any kind.
