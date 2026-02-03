/**
 * Admin Scripts
 * 
 * @package WP_Harden
 * @since 1.0.0
 */

(function($) {
	'use strict';

	$(document).ready(function() {
		
		// Tab Navigation
		$('.nav-tab-wrapper .nav-tab').on('click', function(e) {
			e.preventDefault();
			
			var target = $(this).attr('href');
			
			// Update active tab
			$('.nav-tab').removeClass('nav-tab-active');
			$(this).addClass('nav-tab-active');
			
			// Show target content
			$('.wph-tab-content').removeClass('wph-tab-active');
			$(target).addClass('wph-tab-active');
		});

		// Run Security Scan
		$('#wph-run-scan, #wph-run-full-scan, #wph-run-quick-scan').on('click', function(e) {
			e.preventDefault();
			
			var $button = $(this);
			var scanType = $(this).attr('id') === 'wph-run-quick-scan' ? 'quick' : 'full';
			var $progress = $('#wph-scan-progress');
			var $results = $('#wph-scan-results');
			var $progressFill = $('.wph-progress-fill');
			var $scanStatus = $('.wph-scan-status');
			
			// Disable button and show progress
			$button.prop('disabled', true).text('Scanning...');
			$progress.show();
			$results.hide().html('');
			
			// Simulate progress
			var progress = 0;
			var progressInterval = setInterval(function() {
				progress += 5;
				if (progress <= 95) {
					$progressFill.css('width', progress + '%');
					$scanStatus.text('Scanning... ' + progress + '%');
				}
			}, 500);
			
			// Make AJAX request
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_run_scan',
					nonce: wphAjax.nonce,
					scan_type: scanType
				},
				success: function(response) {
					clearInterval(progressInterval);
					$progressFill.css('width', '100%');
					$scanStatus.text('Scan complete!');
					
					if (response.success) {
						displayScanResults(response.data.results);
						$results.show();
						setTimeout(function() {
							alert('Security scan completed successfully!');
							location.reload();
						}, 1000);
					} else {
						alert('Error: ' + (response.data.message || 'Unknown error'));
					}
				},
				error: function() {
					clearInterval(progressInterval);
					alert('Failed to run security scan. Please try again.');
				},
				complete: function() {
					$button.prop('disabled', false).text('🔍 ' + (scanType === 'quick' ? 'Quick Scan' : 'Start Full Scan'));
					setTimeout(function() {
						$progress.hide();
						$progressFill.css('width', '0%');
					}, 2000);
				}
			});
		});

		// Display scan results
		function displayScanResults(results) {
			var html = '<h3>Scan Results</h3>';
			
			$.each(results, function(scanType, result) {
				html += '<div class="wph-scan-result">';
				html += '<h4>' + ucwords(result.scan_type.replace(/_/g, ' ')) + '</h4>';
				html += '<p><strong>Status:</strong> <span class="wph-status wph-status-' + result.status + '">' + ucfirst(result.status) + '</span></p>';
				
				if (result.issues && result.issues.length > 0) {
					html += '<ul>';
					$.each(result.issues, function(i, issue) {
						html += '<li>';
						html += '<strong>' + (issue.issue || 'Security Issue') + '</strong>';
						if (issue.severity) {
							html += ' <span class="wph-severity wph-severity-' + issue.severity + '">' + ucfirst(issue.severity) + '</span>';
						}
						if (issue.recommendation) {
							html += '<br><em>' + issue.recommendation + '</em>';
						}
						html += '</li>';
					});
					html += '</ul>';
				} else {
					html += '<p class="wph-success">✅ No issues found in this scan.</p>';
				}
				
				html += '</div>';
			});
			
			$('#wph-scan-results').html(html);
		}

		// Block IP Address
		$('.wph-block-ip-btn').on('click', function(e) {
			e.preventDefault();
			
			var ip = prompt('Enter IP address to block:');
			if (!ip) return;
			
			var reason = prompt('Reason for blocking:', 'Suspicious activity');
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_block_ip',
					nonce: wphAjax.nonce,
					ip: ip,
					reason: reason,
					type: 'permanent'
				},
				success: function(response) {
					if (response.success) {
						alert('IP blocked successfully!');
						location.reload();
					} else {
						alert('Error: ' + (response.data.message || 'Unknown error'));
					}
				},
				error: function() {
					alert('Failed to block IP. Please try again.');
				}
			});
		});

		// Export Logs
		$('#wph-export-logs').on('click', function(e) {
			e.preventDefault();
			
			// Create a temporary form and submit it
			var form = $('<form>', {
				'method': 'POST',
				'action': wphAjax.ajaxurl
			});
			
			form.append($('<input>', {
				'type': 'hidden',
				'name': 'action',
				'value': 'wph_export_logs'
			}));
			
			form.append($('<input>', {
				'type': 'hidden',
				'name': 'nonce',
				'value': wphAjax.nonce
			}));
			
			$('body').append(form);
			form.submit();
			form.remove();
		});

		// Test API Connection
		$('.wph-test-api').on('click', function(e) {
			e.preventDefault();
			
			var $button = $(this);
			var apiType = $button.data('api');
			var apiKeyField = $('input[name="' + apiType + '_api_key"]');
			var apiKey = apiKeyField.val();
			
			if (!apiKey) {
				alert('Please enter an API key first.');
				return;
			}
			
			// Add loading state
			$button.addClass('wph-loading').prop('disabled', true);
			var originalText = $button.text();
			$button.text('Testing...');
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_test_api_key',
					nonce: wphAjax.nonce,
					api_type: apiType,
					api_key: apiKey
				},
				success: function(response) {
					if (response.success) {
						alert('✅ Connection successful! API key is valid.');
					} else {
						alert('❌ Connection failed: ' + (response.data.message || 'Invalid API key'));
					}
				},
				error: function() {
					alert('❌ Connection failed. Please try again.');
				},
				complete: function() {
					$button.removeClass('wph-loading').prop('disabled', false).text(originalText);
				}
			});
		});

		// Download GeoIP Database
		$('.wph-download-geoip').on('click', function(e) {
			e.preventDefault();
			
			var $button = $(this);
			var licenseKey = $('input[name="maxmind_license_key"]').val();
			
			if (!licenseKey) {
				alert('Please enter a MaxMind license key first.');
				return;
			}
			
			if (!confirm('This will download the MaxMind GeoIP database. Continue?')) {
				return;
			}
			
			$button.addClass('wph-loading').prop('disabled', true);
			var originalText = $button.text();
			$button.text('Downloading...');
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_download_geoip',
					nonce: wphAjax.nonce,
					license_key: licenseKey
				},
				success: function(response) {
					if (response.success) {
						alert('✅ GeoIP database downloaded successfully!');
					} else {
						alert('❌ Download failed: ' + (response.data.message || 'Unknown error'));
					}
				},
				error: function() {
					alert('❌ Download failed. Please try again.');
				},
				complete: function() {
					$button.removeClass('wph-loading').prop('disabled', false).text(originalText);
				}
			});
		});

		// Clear Old Logs
		$('#wph-clear-logs').on('click', function(e) {
			e.preventDefault();
			
			if (!confirm('This will delete old security logs. Continue?')) {
				return;
			}
			
			var $button = $(this);
			$button.addClass('wph-loading').prop('disabled', true);
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_clear_logs',
					nonce: wphAjax.nonce
				},
				success: function(response) {
					if (response.success) {
						alert('✅ Old logs cleared successfully!');
						location.reload();
					} else {
						alert('❌ Failed to clear logs: ' + (response.data.message || 'Unknown error'));
					}
				},
				error: function() {
					alert('❌ Failed to clear logs. Please try again.');
				},
				complete: function() {
					$button.removeClass('wph-loading').prop('disabled', false);
				}
			});
		});

		// Export Security Report
		$('#wph-export-report').on('click', function(e) {
			e.preventDefault();
			
			var $button = $(this);
			$button.addClass('wph-loading').prop('disabled', true);
			
			// Create a temporary form and submit it
			var form = $('<form>', {
				'method': 'POST',
				'action': wphAjax.ajaxurl
			});
			
			form.append($('<input>', {
				'type': 'hidden',
				'name': 'action',
				'value': 'wph_export_report'
			}));
			
			form.append($('<input>', {
				'type': 'hidden',
				'name': 'nonce',
				'value': wphAjax.nonce
			}));
			
			$('body').append(form);
			form.submit();
			form.remove();
			
			setTimeout(function() {
				$button.removeClass('wph-loading').prop('disabled', false);
			}, 2000);
		});

		// Select All Issues
		$('.wph-select-all-issues').on('change', function() {
			var isChecked = $(this).prop('checked');
			$(this).closest('table').find('.wph-issue-checkbox').prop('checked', isChecked);
		});

		// Update scan schedule
		$('#scan-schedule-select').on('change', function() {
			var schedule = $(this).val();
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_update_scan_schedule',
					nonce: wphAjax.nonce,
					schedule: schedule
				},
				success: function(response) {
					if (response.success) {
						alert('✅ Scan schedule updated successfully!');
					}
				}
			});
		});

		// Handle individual Fix button
		$(document).on('click', '.wph-fix-issue', function(e) {
			e.preventDefault();
			
			var $button = $(this);
			var issueType = $button.data('issue-type');
			var issueData = $button.data('issue-data');
			var $row = $button.closest('tr');
			
			if (!confirm('Attempt to automatically fix this issue?')) {
				return;
			}
			
			$button.prop('disabled', true).text('Fixing...');
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_fix_issue',
					nonce: wphAjax.nonce,
					issue_type: issueType,
					issue_data: JSON.stringify(issueData)
				},
				success: function(response) {
					if (response.success) {
						showNotice('success', response.data.message);
						$row.fadeOut(400, function() {
							$(this).remove();
							updateIssueCount();
						});
					} else {
						showNotice('error', response.data.message);
						$button.prop('disabled', false).text('Fix');
					}
				},
				error: function() {
					showNotice('error', 'An error occurred while fixing the issue.');
					$button.prop('disabled', false).text('Fix');
				}
			});
		});

		// Handle individual Ignore button
		$(document).on('click', '.wph-ignore-issue', function(e) {
			e.preventDefault();
			
			var $button = $(this);
			var issueType = $button.data('issue-type');
			var issueData = $button.data('issue-data');
			var $row = $button.closest('tr');
			
			var reason = prompt('Why are you ignoring this issue? (optional)');
			if (reason === null) {
				return; // User cancelled
			}
			
			$button.prop('disabled', true).text('Ignoring...');
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_ignore_issue',
					nonce: wphAjax.nonce,
					issue_type: issueType,
					issue_data: JSON.stringify(issueData),
					reason: reason
				},
				success: function(response) {
					if (response.success) {
						showNotice('success', response.data.message);
						$row.fadeOut(400, function() {
							$(this).remove();
							updateIssueCount();
						});
					} else {
						showNotice('error', response.data.message);
						$button.prop('disabled', false).text('Ignore');
					}
				},
				error: function() {
					showNotice('error', 'An error occurred while ignoring the issue.');
					$button.prop('disabled', false).text('Ignore');
				}
			});
		});

		// Handle bulk Fix Selected button
		$(document).on('click', '.wph-fix-selected', function(e) {
			e.preventDefault();
			
			var $button = $(this);
			var $section = $button.closest('.wph-scan-result');
			var $checkboxes = $section.find('.wph-issue-checkbox:checked');
			
			if ($checkboxes.length === 0) {
				alert('Please select issues to fix.');
				return;
			}
			
			if (!confirm('Attempt to fix ' + $checkboxes.length + ' selected issues?')) {
				return;
			}
			
			var issues = [];
			$checkboxes.each(function() {
				issues.push({
					type: $(this).data('issue-type'),
					data: $(this).data('issue-data')
				});
			});
			
			$button.prop('disabled', true).text('Fixing...');
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_bulk_fix',
					nonce: wphAjax.nonce,
					issues: JSON.stringify(issues)
				},
				success: function(response) {
					if (response.success) {
						showNotice('success', response.data.message);
						if (response.data.details && response.data.details.length > 0) {
							console.log('Fix details:', response.data.details);
						}
						$checkboxes.closest('tr').fadeOut(400, function() {
							$(this).remove();
							updateIssueCount();
						});
					} else {
						showNotice('error', response.data.message);
					}
					$button.prop('disabled', false).text('🔧 Fix Selected');
				},
				error: function() {
					showNotice('error', 'An error occurred during bulk fix.');
					$button.prop('disabled', false).text('🔧 Fix Selected');
				}
			});
		});

		// Handle bulk Ignore Selected button
		$(document).on('click', '.wph-ignore-selected', function(e) {
			e.preventDefault();
			
			var $button = $(this);
			var $section = $button.closest('.wph-scan-result');
			var $checkboxes = $section.find('.wph-issue-checkbox:checked');
			
			if ($checkboxes.length === 0) {
				alert('Please select issues to ignore.');
				return;
			}
			
			var reason = prompt('Why are you ignoring these issues? (optional)');
			if (reason === null) {
				return;
			}
			
			var issues = [];
			$checkboxes.each(function() {
				issues.push({
					type: $(this).data('issue-type'),
					data: $(this).data('issue-data')
				});
			});
			
			$button.prop('disabled', true).text('Ignoring...');
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_bulk_ignore',
					nonce: wphAjax.nonce,
					issues: JSON.stringify(issues),
					reason: reason
				},
				success: function(response) {
					if (response.success) {
						showNotice('success', response.data.message);
						$checkboxes.closest('tr').fadeOut(400, function() {
							$(this).remove();
							updateIssueCount();
						});
					} else {
						showNotice('error', response.data.message);
					}
					$button.prop('disabled', false).text('👁️ Ignore Selected');
				},
				error: function() {
					showNotice('error', 'An error occurred during bulk ignore.');
					$button.prop('disabled', false).text('👁️ Ignore Selected');
				}
			});
		});

		// Helper function to show admin notices
		function showNotice(type, message) {
			var noticeClass = type === 'success' ? 'notice-success' : 'notice-error';
			var $notice = $('<div class="notice ' + noticeClass + ' is-dismissible"><p>' + message + '</p></div>');
			$('.wrap h1').after($notice);
			
			// Auto-dismiss after 5 seconds
			setTimeout(function() {
				$notice.fadeOut(400, function() {
					$(this).remove();
				});
			}, 5000);
		}

		// Update total issues count
		function updateIssueCount() {
			var totalIssues = $('.wph-scan-result table tbody tr:visible').length;
			$('.wph-total-issues').text(totalIssues);
		}

		// Quarantine file
		$(document).on('click', '.wph-quarantine-file', function() {
			var file = $(this).data('file');
			
			if (!confirm('Quarantine this file? It will be moved to a safe location.')) {
				return;
			}
			
			var $button = $(this);
			$button.addClass('wph-loading').prop('disabled', true);
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_quarantine_file',
					nonce: wphAjax.nonce,
					file: file
				},
				success: function(response) {
					if (response.success) {
						alert('✅ File quarantined successfully!');
						location.reload();
					} else {
						alert('❌ Failed to quarantine file: ' + (response.data.message || 'Unknown error'));
					}
				},
				error: function() {
					alert('❌ Failed to quarantine file. Please try again.');
				},
				complete: function() {
					$button.removeClass('wph-loading').prop('disabled', false);
				}
			});
		});

		// Select all logs
		$('#wph-select-all-logs').on('change', function() {
			var isChecked = $(this).prop('checked');
			$('.wph-log-checkbox').prop('checked', isChecked);
			updateDeleteButtonState();
		});

		// Update delete button state
		$('.wph-log-checkbox').on('change', function() {
			updateDeleteButtonState();
		});

		function updateDeleteButtonState() {
			var checkedCount = $('.wph-log-checkbox:checked').length;
			$('#wph-delete-selected').prop('disabled', checkedCount === 0);
		}

		// Delete selected logs
		$('#wph-delete-selected').on('click', function() {
			var logIds = [];
			$('.wph-log-checkbox:checked').each(function() {
				logIds.push($(this).data('log-id'));
			});
			
			if (logIds.length === 0) {
				return;
			}
			
			if (!confirm('Delete ' + logIds.length + ' selected log(s)?')) {
				return;
			}
			
			var $button = $(this);
			$button.addClass('wph-loading').prop('disabled', true);
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_delete_logs',
					nonce: wphAjax.nonce,
					log_ids: logIds
				},
				success: function(response) {
					if (response.success) {
						alert('✅ Logs deleted successfully!');
						location.reload();
					} else {
						alert('❌ Failed to delete logs.');
					}
				},
				error: function() {
					alert('❌ Failed to delete logs. Please try again.');
				},
				complete: function() {
					$button.removeClass('wph-loading').prop('disabled', false);
				}
			});
		});

		// Block IP from log
		$(document).on('click', '.wph-block-ip-btn', function(e) {
			e.preventDefault();
			
			var ip = $(this).data('ip');
			
			if (!confirm('Block IP address: ' + ip + '?')) {
				return;
			}
			
			var $button = $(this);
			$button.addClass('wph-loading').prop('disabled', true);
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_block_ip',
					nonce: wphAjax.nonce,
					ip: ip,
					reason: 'Blocked from activity logs',
					type: 'permanent'
				},
				success: function(response) {
					if (response.success) {
						alert('✅ IP blocked successfully!');
						$button.text('✓').removeClass('wph-loading');
					} else {
						alert('❌ Failed to block IP.');
						$button.removeClass('wph-loading').prop('disabled', false);
					}
				},
				error: function() {
					alert('❌ Failed to block IP. Please try again.');
					$button.removeClass('wph-loading').prop('disabled', false);
				}
			});
		});

		// Auto-refresh logs
		var refreshInterval;
		$('#wph-auto-refresh').on('change', function() {
			if ($(this).is(':checked')) {
				refreshInterval = setInterval(function() {
					location.reload();
				}, 10000); // 10 seconds
			} else {
				clearInterval(refreshInterval);
			}
		});

		// View log details
		$(document).on('click', '.wph-view-log-details', function() {
			var logId = $(this).data('log-id');
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_get_log_details',
					nonce: wphAjax.nonce,
					log_id: logId
				},
				success: function(response) {
					if (response.success) {
						// Display log details in a modal or alert
						var details = response.data.log;
						var message = 'Log Details:\n\n';
						message += 'ID: ' + details.id + '\n';
						message += 'Time: ' + details.created_at + '\n';
						message += 'Type: ' + details.log_type + '\n';
						message += 'Severity: ' + details.severity + '\n';
						message += 'Message: ' + details.message + '\n';
						message += 'IP: ' + details.ip_address + '\n';
						if (details.context) {
							try {
								var contextData = typeof details.context === 'string' ? JSON.parse(details.context) : details.context;
								message += '\nContext:\n' + JSON.stringify(contextData, null, 2);
							} catch (e) {
								message += '\nContext: ' + details.context;
							}
						}
						alert(message);
					}
				}
			});
		});

		// Helper functions
		function ucfirst(str) {
			return str.charAt(0).toUpperCase() + str.slice(1);
		}

		function ucwords(str) {
			return str.replace(/\b\w/g, function(char) {
				return char.toUpperCase();
			});
		}

	});

})(jQuery);
