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
		$('#wph-run-scan').on('click', function(e) {
			e.preventDefault();
			
			var $button = $(this);
			var $progress = $('#wph-scan-progress');
			var $results = $('#wph-scan-results');
			
			// Disable button and show progress
			$button.prop('disabled', true).text('Scanning...');
			$progress.show();
			$results.hide().html('');
			
			// Make AJAX request
			$.ajax({
				url: wphAjax.ajaxurl,
				type: 'POST',
				data: {
					action: 'wph_run_scan',
					nonce: wphAjax.nonce
				},
				success: function(response) {
					if (response.success) {
						displayScanResults(response.data.results);
						$results.show();
						alert('Security scan completed successfully!');
					} else {
						alert('Error: ' + (response.data.message || 'Unknown error'));
					}
				},
				error: function() {
					alert('Failed to run security scan. Please try again.');
				},
				complete: function() {
					$button.prop('disabled', false).text('🔍 Run Security Scan');
					$progress.hide();
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
