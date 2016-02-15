<?php
/**
 * @file
 * This is for the administrative settings for this module.
 */

/**
 * Email Verify administration settings form.
 *
 * @return array
 *   The admin settings form.
 */
function email_verify_admin_settings($form, &$form_state) {
  $form['email_verify_activate'] = array(
    '#type' => 'fieldset',
    '#title' => t('Activate module'),
    '#collapsible' => TRUE,
  );
  $form['email_verify_activate']['email_verify_active'] = array(
    '#type' => 'checkbox',
    '#title' => t('Activate this module to verify email adresses'),
    '#default_value' => variable_get('email_verify_active', 0),
    '#description' => t('When activated, Email Verify will check email addresses for validity.'),
  );
  $form['email_verify_activate']['email_verify_test_options'] = array(
    '#type' => 'fieldset',
    '#title' => t('Testing options'),
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
    '#description' => t("If the test fails when checking whether this module will work on your system or not, you can try changing the options below to see if they will work better for you."),
  );
  $form['email_verify_activate']['email_verify_test_options']['email_verify_test_options_host_name'] = array(
    '#type' => 'textfield',
    '#title' => t("Host name"),
    '#default_value' => variable_get('email_verify_test_options_host_name', 'drupal.org'),
    '#description' => t('The name of the host to test with. The default is "drupal.org".'),
  );
  // The test is to see if port 25 is open, so offering to change the port
  // number will not give the correct results. However, there might be some
  // valid use case for being able to set the port number, so this is being left
  // here, but commented out, for now.
//  $form['email_verify_enable']['email_verify_test_options']['email_verify_test_options_port_number'] = array(
//    '#type' => 'textfield',
//    '#title' => t("Port number"),
//    '#default_value' => variable_get('email_verify_test_options_port_number', 25),
//    '#description' => t('The number of the port to test with. The default is "25".'),
//  );
  $form['email_verify_activate']['email_verify_test_options']['email_verify_test_options_timeout'] = array(
    '#type' => 'textfield',
    '#title' => t("Timeout"),
    '#default_value' => variable_get('email_verify_test_options_timeout', 15),
    '#description' => t('The connection timeout, in seconds. The default is "15".'),
  );

  $form['email_verify_forms'] = array(
    '#type' => 'fieldset',
    '#title' => t('Forms to check'),
    '#collapsible' => TRUE,
    '#description' => t("Check the boxes for the forms you want to have this module check email addresses on."),
  );
  $form['email_verify_forms']['email_verify_user_registration'] = array(
    '#type' => 'checkbox',
    '#title' => t("User registration"),
    '#default_value' => variable_get('email_verify_user_registration', 1),
  );
  $form['email_verify_forms']['email_verify_user_profile'] = array(
    '#type' => 'checkbox',
    '#title' => t("User profile"),
    '#default_value' => variable_get('email_verify_user_profile', 1),
  );
  if (module_exists('contact')) {
    $form['email_verify_forms']['email_verify_site_contact'] = array(
      '#type' => 'checkbox',
      '#title' => t("Site-wide contact"),
      '#default_value' => variable_get('email_verify_site_contact', 0),
    );
    $form['email_verify_forms']['email_verify_personal_contact'] = array(
      '#type' => 'checkbox',
      '#title' => t("Personal contact"),
      '#default_value' => variable_get('email_verify_personal_contact', 0),
    );
  }

  $form['email_verify_methods'] = array(
    '#type' => 'fieldset',
    '#title' => t('Methods to use'),
    '#collapsible' => TRUE,
    '#description' => t("Check the boxes for the various methods to use when verifying email addresses. If you find you're getting lots of false positives and/or false negatives, try changing which options are enabled."),
  );
  $form['email_verify_methods']['email_verify_methods_checkdnsrr'] = array(
    '#type' => 'checkbox',
    '#title' => t("Check for any DNS records"),
    '#default_value' => variable_get('email_verify_methods_checkdnsrr', 1),
    '#description' => t("Use PHP's checkdnsrr() function to see if there are any DNS records associated with the email address' domain name."),
  );
  $form['email_verify_methods']['email_verify_methods_gethostbyname'] = array(
    '#type' => 'checkbox',
    '#title' => t("Check for a valid IPv4 address"),
    '#default_value' => variable_get('email_verify_methods_gethostbyname', 1),
    '#description' => t("Use PHP's gethostbyname() function to see if a valid IPv4 address is associated with the email address' domain name."),
  );
  $form['email_verify_methods']['email_verify_methods_add_dot'] = array(
    '#type' => 'checkbox',
    '#title' => t("Add a dot to the domain"),
    '#default_value' => variable_get('email_verify_methods_add_dot', 1),
    '#description' => t("For hosts that add their own domain to the end of the domain in the email address, this adds an additional '.' to the end of the email address domain, so that the check will not fail at the wrong time."),
  );
//  $form['email_verify_methods']['email_verify_methods_extra_chars'] = array(
//    '#type' => 'checkbox',
//    '#title' => t("Allow non-basic ASCII characters"),
//    '#default_value' => variable_get('email_verify_methods_extra_chars', 1),
//    '#description' => t("Check email addresses with domains with characters that are not in the basic ASCII set: http://php.net/manual/en/function.idn-to-ascii.php."),
//  );

  $form['#submit'] = array('email_verify_admin_settings_submit');

  return system_settings_form($form);
}

/**
 * Form submit function.
 */
function email_verify_admin_settings_submit($form, &$form_state) {
  // Enable/disable mail sending subsystem.
  if ($form_state['values']['email_verify_active']) {
    if (!email_verify_activated()) {
      email_verify_enable_module();
    }
  }
}

/**
 * Checks the system for the capability to use this module.
 *
 * @todo
 *   This function works, but it needs some thought and potential rework, now
 *   that it is not in email_verify.install.
 */
function email_verify_enable_module() {
  // Check that fsockopen() works on port 25.
  // @see: http://drupal.org/node/147883

  // What follows is an adapted version of email_verify_check().
  // The documentation http://api.drupal.org/api/5/function/hook_install says:
  //   "Note that since this function is called from a full bootstrap, all
  //    functions (including those in modules enabled by the current page
  //    request) are available when this hook is called. Use cases could be
  //    displaying a user message, or calling a module function necessary for
  //    initial setup, etc."
  // However, this does not seem to be the case, so we can't reuse
  // email_verify_check().

  // If a previous enable found port 25 closed or fsockopen() disabled, don't
  // test it again. Testing can cause a long delay on module enable. Completely
  // uninstall and then re-install this module to re-test.
  If (variable_get('email_verify_skip_mailbox', FALSE)) {
    return;
  }

  // Check if fsockopen() is disabled.
  if (!function_exists('fsockopen')) {
    $message = t('Email Verify will test email domains but not mailboxes because the fsockopen() function has been disabled.');
    variable_set('email_verify_skip_mailbox', TRUE);
    drupal_set_message($message, 'warning');
    return;
  }

  $host = variable_get('email_verify_test_options_host_name', 'drupal.org');
  // What SMTP servers should we contact?
  $mx_hosts = array();

  if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
    module_load_include('inc', 'email_verify', 'windows_compat');
  }

  if (!getmxrr($host, $mx_hosts)) {
    // When there is no MX record, the host itself should be used.
    $mx_hosts[] = $host;
  }

  $timeout = variable_get('email_verify_test_options_timeout', 15);
  // Try to connect to one SMTP server.
  foreach ($mx_hosts as $smtp) {
    $connect = @fsockopen($smtp, 25, $errno, $errstr, $timeout);
    if (!$connect) {
      continue;
    }

    if (preg_match("/^220/", $out = fgets($connect, 1024))) {
      // OK, we have a SMTP connection.
      break;
    }
  }

  if (!$connect) {
    variable_set('email_verify_skip_mailbox', TRUE);
    $message = t('Email Verify will test email domains but not mailboxes because port 25 is closed on your host\'s firewall for security.');
    watchdog('email_verify', $message, array(), WATCHDOG_WARNING);
    drupal_set_message($message, 'warning');
  }
}
