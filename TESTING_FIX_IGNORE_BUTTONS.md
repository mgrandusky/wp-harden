# Testing Guide: Fix and Ignore Buttons Functionality

## Overview
This guide provides step-by-step instructions to test the newly implemented Fix and Ignore buttons functionality in the WP Harden Security Scanner.

## Prerequisites
1. WordPress installation with WP Harden plugin activated
2. Administrator access to WordPress dashboard
3. Browser with JavaScript enabled
4. Developer tools access (optional, for debugging)

## Test Scenarios

### Test 1: Individual Fix Button
**Objective**: Verify that clicking the Fix button on a single issue attempts to fix it.

**Steps**:
1. Navigate to **WP Harden > Scanner** in WordPress admin
2. Click **"Start Full Scan"** button
3. Wait for scan to complete
4. Locate an issue in the results table (preferably a file permission issue)
5. Click the **"Fix"** button next to the issue
6. Confirm the action in the confirmation dialog
7. Observe the button text change to "Fixing..."
8. Wait for the AJAX response

**Expected Results**:
- Confirmation dialog appears: "Attempt to automatically fix this issue?"
- Button is disabled and shows "Fixing..." during the process
- On success: Success notice appears, row fades out and is removed
- On failure: Error notice appears with explanation, button returns to enabled state

**Pass Criteria**:
- ✅ No JavaScript console errors
- ✅ Appropriate success/error message displayed
- ✅ Fixed issues disappear from the table
- ✅ Issue count updates correctly

---

### Test 2: Individual Ignore Button
**Objective**: Verify that clicking the Ignore button stores the issue in the database.

**Steps**:
1. Navigate to **WP Harden > Scanner**
2. Ensure scan results are displayed
3. Locate an issue in the results table
4. Click the **"Ignore"** button next to the issue
5. When prompted, enter a reason (e.g., "False positive") or leave blank
6. Click OK
7. Wait for the AJAX response

**Expected Results**:
- Prompt appears: "Why are you ignoring this issue? (optional)"
- Button text changes to "Ignoring..." during the process
- On success: Success notice appears, row fades out and is removed
- Issue is stored in `wp_wph_ignored_issues` database table
- On cancel (clicking Cancel in prompt): No action taken

**Pass Criteria**:
- ✅ No JavaScript console errors
- ✅ Success message: "Issue ignored successfully."
- ✅ Ignored issues disappear from the table
- ✅ Database record created in `wp_wph_ignored_issues` table
- ✅ Issue count updates correctly

---

### Test 3: Bulk Fix Selected
**Objective**: Verify that multiple issues can be fixed at once.

**Steps**:
1. Navigate to **WP Harden > Scanner**
2. Ensure scan results with multiple issues are displayed
3. Check the checkbox next to 2-3 issues
4. Click the **"🔧 Fix Selected"** button at the bottom of the section
5. Confirm the action in the confirmation dialog
6. Wait for the bulk operation to complete

**Expected Results**:
- Alert if no issues selected: "Please select issues to fix."
- Confirmation dialog: "Attempt to fix X selected issues?"
- Button text changes to "Fixing..." during the process
- Success notice shows: "Fixed X of Y issues."
- All successfully fixed rows fade out and are removed
- Any failures are logged in the browser console

**Pass Criteria**:
- ✅ No JavaScript console errors
- ✅ All fixable issues are removed from the table
- ✅ Appropriate success message with counts
- ✅ Issue count updates correctly
- ✅ Failed fixes are reported (if any)

---

### Test 4: Bulk Ignore Selected
**Objective**: Verify that multiple issues can be ignored at once.

**Steps**:
1. Navigate to **WP Harden > Scanner**
2. Ensure scan results with multiple issues are displayed
3. Check the checkbox next to 2-3 issues
4. Click the **"👁️ Ignore Selected"** button at the bottom of the section
5. When prompted, enter a reason (optional)
6. Click OK
7. Wait for the bulk operation to complete

**Expected Results**:
- Alert if no issues selected: "Please select issues to ignore."
- Prompt appears: "Why are you ignoring these issues? (optional)"
- Button text changes to "Ignoring..." during the process
- Success notice: "Ignored X issues."
- All selected rows fade out and are removed
- All issues stored in database

**Pass Criteria**:
- ✅ No JavaScript console errors
- ✅ All ignored issues are removed from the table
- ✅ Database records created for each issue
- ✅ Issue count updates correctly

---

### Test 5: Select All Checkbox
**Objective**: Verify that the "select all" checkbox works correctly.

**Steps**:
1. Navigate to **WP Harden > Scanner**
2. Ensure scan results with multiple issues are displayed
3. Click the checkbox in the table header (first column)
4. Observe all checkboxes in that section
5. Uncheck the header checkbox
6. Observe all checkboxes again

**Expected Results**:
- Checking header checkbox: All issue checkboxes in that section are checked
- Unchecking header checkbox: All issue checkboxes in that section are unchecked
- Each scan section (Core Integrity, File Permissions, etc.) has independent "select all" behavior

**Pass Criteria**:
- ✅ Select all works per section
- ✅ Unselect all works per section
- ✅ No JavaScript console errors

---

### Test 6: Database Table Verification
**Objective**: Verify that the ignored issues table exists and stores data correctly.

**Steps**:
1. Access WordPress database via phpMyAdmin or CLI
2. Check for table: `wp_wph_ignored_issues` (where `wp_` is your prefix)
3. Ignore an issue via the UI
4. Query the table to verify the record

**SQL Query**:
```sql
SELECT * FROM wp_wph_ignored_issues ORDER BY ignored_at DESC LIMIT 10;
```

**Expected Results**:
- Table exists with correct schema:
  - `id` (bigint, primary key)
  - `issue_type` (varchar 50)
  - `issue_key` (varchar 32, unique)
  - `issue_data` (longtext)
  - `ignored_by` (bigint)
  - `ignored_at` (datetime)
  - `reason` (varchar 500)
- Ignored issues appear in the table
- `issue_key` is an MD5 hash
- `ignored_by` matches the WordPress user ID
- `ignored_at` timestamp is correct

**Pass Criteria**:
- ✅ Table exists with correct schema
- ✅ Data is properly stored
- ✅ Unique constraint on `issue_key` prevents duplicates

---

### Test 7: Permission Checks
**Objective**: Verify that non-admin users cannot access the functionality.

**Steps**:
1. Create a test user with Editor or Subscriber role
2. Install a plugin like "User Switching" to switch users easily
3. Switch to the non-admin user
4. Try to access **WP Harden > Scanner** page
5. If accessible (shouldn't be), try to trigger AJAX calls via browser console

**Expected Results**:
- Non-admin users cannot see the WP Harden menu
- Direct AJAX calls return permission error: "Permission denied."

**Pass Criteria**:
- ✅ Menu not visible to non-admins
- ✅ AJAX handlers check `manage_options` capability
- ✅ Error returned for unauthorized access

---

### Test 8: Fix Functionality by Issue Type
**Objective**: Test that different issue types are handled correctly.

#### 8a. File Permission Issues
**Steps**:
1. Create a test file with wrong permissions: `chmod 777 wp-config.php`
2. Run a scan
3. Attempt to fix the file permission issue

**Expected**:
- Success message: "Permissions updated to 0600 for wp-config.php"
- File permissions actually changed

#### 8b. Core Integrity Issues
**Steps**:
1. If WP_DEBUG is true, try to fix it
2. Check for database prefix issues

**Expected**:
- Manual instructions provided (cannot auto-fix config changes)
- Clear guidance message displayed

#### 8c. Malware Signatures
**Steps**:
1. If malware detected, try to fix it

**Expected**:
- Error message: "Malware issues must be manually reviewed. Please quarantine the file or remove it manually."

**Pass Criteria**:
- ✅ Each issue type returns appropriate response
- ✅ Fixable issues are fixed
- ✅ Non-fixable issues provide clear guidance

---

## Browser Compatibility Testing
Test in the following browsers:
- ✅ Chrome/Edge (latest)
- ✅ Firefox (latest)
- ✅ Safari (latest)

## Performance Testing
- Bulk operations with 10+ issues should complete within 10 seconds
- UI should remain responsive during AJAX operations
- No memory leaks after multiple operations

## Security Testing Checklist
- ✅ Nonce verification on all AJAX handlers
- ✅ Capability checks (`manage_options`) on all handlers
- ✅ Input sanitization on all user inputs
- ✅ SQL prepared statements used
- ✅ Output escaping in HTML
- ✅ XSS prevention in JavaScript

## Troubleshooting

### JavaScript Errors
- Check browser console for errors
- Verify `wphAjax` object is available
- Ensure nonce is valid

### AJAX Failures
- Check WordPress debug log
- Verify AJAX URL is correct
- Check for PHP errors in server logs

### Database Issues
- Verify table was created during plugin activation
- Check database user has correct permissions
- Manually create table if needed using SQL from activator class

## Logging
All ignore actions are logged to the WP Harden activity log:
- Log type: `scanner`
- Severity: `low`
- Message: "Security issue ignored: [issue_type]"

Check logs at: **WP Harden > Logs**

## Success Criteria Summary
A successful implementation should:
1. ✅ Allow individual issue fixing with confirmation
2. ✅ Allow individual issue ignoring with optional reason
3. ✅ Support bulk operations on selected issues
4. ✅ Store ignored issues in database
5. ✅ Provide clear user feedback (notices)
6. ✅ Update UI dynamically (remove fixed/ignored issues)
7. ✅ Maintain security (nonce, capability checks)
8. ✅ Handle errors gracefully
9. ✅ Work across modern browsers
10. ✅ Pass CodeQL security scan

## Report Issues
If any test fails, document:
- Test number and description
- Steps to reproduce
- Expected vs actual behavior
- Browser and WordPress version
- JavaScript console errors
- PHP error logs
