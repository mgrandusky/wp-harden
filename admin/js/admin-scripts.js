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

		// Fix issue
		$(document).on('click', '.wph-fix-issue', function() {
			var issueId = $(this).data('issue-id');
			
			if (!confirm('Attempt to automatically fix this issue?')) {
				return;
			}
			
			var $button = $(this);
			$button.addClass('wph-loading').prop('disabled', true);
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_fix_issue',
					nonce: wphAjax.nonce,
					issue_id: issueId
				},
				success: function(response) {
					if (response.success) {
						alert('✅ Issue fixed successfully!');
						location.reload();
					} else {
						alert('❌ Failed to fix issue: ' + (response.data.message || 'Unknown error'));
					}
				},
				error: function() {
					alert('❌ Failed to fix issue. Please try again.');
				},
				complete: function() {
					$button.removeClass('wph-loading').prop('disabled', false);
				}
			});
		});

		// Ignore issue
		$(document).on('click', '.wph-ignore-issue', function() {
			var issueId = $(this).data('issue-id');
			var $row = $(this).closest('tr');
			
			if (!confirm('Ignore this issue? It will not appear in future scans.')) {
				return;
			}
			
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_ignore_issue',
					nonce: wphAjax.nonce,
					issue_id: issueId
				},
				success: function(response) {
					if (response.success) {
						$row.fadeOut(300, function() {
							$(this).remove();
						});
					} else {
						alert('❌ Failed to ignore issue.');
					}
				}
			});
		});

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
							message += '\nContext:\n' + JSON.stringify(JSON.parse(details.context), null, 2);
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
