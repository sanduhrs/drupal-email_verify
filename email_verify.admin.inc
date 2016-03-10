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
    '#default_value' => email_verify_activated(),
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

  $form['email_verify_debug_mode'] = array(
    '#type' => 'fieldset',
    '#title' => t('Debug mode'),
    '#collapsible' => TRUE,
  );
  $form['email_verify_debug_mode']['email_verify_debug_mode'] = array(
    '#type' => 'checkbox',
    '#title' => t('Enable'),
    '#default_value' => variable_get('email_verify_debug_mode', FALSE),
    '#description' => t('Check this box to get verbose information about each email address verification made.'),
  );
  $form['email_verify_debug_mode']['email_verify_debug_mode_record_log'] = array(
    '#type' => 'checkbox',
    '#title' => t('Record debugging information in the database log'),
    '#default_value' => variable_get('email_verify_debug_mode_record_log', FALSE),
    '#states' => array(
      'enabled' => array(
        ':input[name="email_verify_debug_mode"]' => array(
          'checked' => TRUE
        )
      )
    ),
  );
  $form['email_verify_debug_mode']['email_verify_debug_mode_display_page'] = array(
    '#type' => 'checkbox',
    '#title' => t('Display debugging information on the page'),
    '#default_value' => variable_get('email_verify_debug_mode_display_page', FALSE),
    '#states' => array(
      'enabled' => array(
        ':input[name="email_verify_debug_mode"]' => array(
          'checked' => TRUE
        )
      )
    ),
  );
  $date_types = system_get_date_types();
  $options = array();
  foreach ($date_types as $date_type) {
    $options[$date_type['type']] = $date_type['title'];
  }
  $form['email_verify_debug_mode']['email_verify_debug_mode_date_format'] = array(
    '#type' => 'select',
    '#title' => t('Date/time format'),
    '#default_value' => variable_get('email_verify_debug_mode_date_format', ''),
    '#options' => $options,
    '#description' => t('Select the date format to use when displaying the dates and times in the debug information.<br />
      Date types and formats can be modified in the system !datetime settings pages.', array('!datetime' => l(t('Date and time'), 'admin/config/regional/date-time'))),
    '#states' => array(
      'enabled' => array(
        ':input[name="email_verify_debug_mode"]' => array(
          'checked' => TRUE
        )
      )
    ),
  );

  $form['email_verify_forms_to_check'] = array(
    '#type' => 'fieldset',
    '#title' => t('Forms to check'),
    '#collapsible' => TRUE,
  );
  $form['email_verify_forms_to_check']['email_verify_forms'] = array(
    '#type' => 'textarea',
    '#description' => t('
      Enter a list of form IDs and field IDs of the forms and corresponding
      email address fields on which to verify the email addresses. Each
      form/field combination should be on a separate line and the form ID and
      field ID should be separated with a comma and should look something like
      this: <br />user_register_form, mail<br />user_profile_form, mail
    '),
    '#default_value' => variable_get('email_verify_forms', ''),
  );

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
 *
 * This runs the module verification check, if activating, and logs whether the
 * module was activated or inactivated.
 */
function email_verify_admin_settings_submit($form, &$form_state) {
  // Enable/disable mail sending subsystem.
  if ($form_state['values']['email_verify_active']) {
    if (!email_verify_activated()) {
      $debugging_text = email_verify_enable_module();
      watchdog('email_verify', 'The Email Verify module was activated.');
      if (!empty($debugging_text)) {
        // Log and/or display the debugging information.
        email_verify_process_debug_information($debugging_text);
      }
    }
  }
  elseif (email_verify_activated()) {
    watchdog('email_verify', 'The Email Verify module was inactivated.');
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
  $debugging_mode = variable_get('email_verify_debug_mode', FALSE);
  $date_time_format = variable_get('email_verify_debug_mode_date_format', 'long');
  $debugging_text = array();
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Beginning the system capability checks for the Email Verify module (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }

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
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking to see if the system capability checks have already been run (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  if (variable_get('email_verify_skip_mailbox', FALSE)) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The system capability checks have already been run, so the system capability check is stopping (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    return $debugging_text;
  }
  if ($debugging_mode) {
    $debugging_text[] = t(
      'The system capability checks have not been run, so the system capability check is continuing (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }

  // Check if fsockopen() is disabled.
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking to see if fsockopen() is enabled or disabled (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  if (!function_exists('fsockopen')) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The fsockopen() function does not exist, so the system capability check is stopping (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    $message = t('Email Verify will test email domains but not mailboxes because the fsockopen() function has been disabled.');
    variable_set('email_verify_skip_mailbox', TRUE);
    drupal_set_message($message, 'warning');
    return $debugging_text;
  }
  if ($debugging_mode) {
    $debugging_text[] = t(
      'The fsockopen() function exists, so the system capability check is continuing (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }

  $host = variable_get('email_verify_test_options_host_name', 'drupal.org');
  if ($debugging_mode) {
    $debugging_text[] = t(
      'The host that will be used for checking the system capability is "%host" (!date_time).',
      array(
        '%host' => $host,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }

  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking to see if Microsoft Windows compatible functions are needed (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'Microsoft Windows was detected, so the compatible functions are being loaded (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    module_load_include('inc', 'email_verify', 'windows_compat');
  }
  else {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'Microsoft Windows was not detected, so the compatible functions are not being loaded (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
  }

  // What SMTP servers should we contact?
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Retrieving any MX records corresponding to the specified host "%host" (!date_time).',
      array(
        '%host' => $host,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }
  $mx_hosts = array();
  if (!getmxrr($host, $mx_hosts)) {
    // When there is no MX record, the host itself should be used.
    if ($debugging_mode) {
      $debugging_text[] = t(
        'No MX records were found, so the host itself will be used to check the system capability (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    $mx_hosts[] = $host;
  }
  else {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'MX records were found, so they will be used to check the system capability (!date_time): !mx_hosts',
        array(
          '!date_time' => format_date(time(), $date_time_format),
          '!mx_hosts' => '<pre>' . print_r($mx_hosts, TRUE) . '</pre>',
        )
      );
    }
  }

  $timeout = variable_get('email_verify_test_options_timeout', 15);
  if ($debugging_mode) {
    $debugging_text[] = t(
      'The timeout setting for checking the system capability is "%timeout" seconds (!date_time).',
      array(
        '%timeout' => $timeout,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }

  // Try to connect to one SMTP server.
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking the host(s) to see if a connection can be made to any of them (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  foreach ($mx_hosts as $smtp) {
    $connect = @fsockopen($smtp, 25, $errno, $errstr, $timeout);
    if ($debugging_mode) {
      if ($connect === FALSE) {
        $debugging_text[] = t(
          'The attempt to connect to host "%smtp" failed. If provided, the error number was "%errno", and the error string was "%errstr" (!date_time).',
          array(
            '%smtp' => $smtp,
            '%errno' => $errno,
            '%errstr' => $errstr,
            '!date_time' => format_date(time(), $date_time_format),
          )
        );
      }
      else {
        $debugging_text[] = t(
          'The attempt to connect to host "%smtp" succeeded. If provided, the error number was "%errno", and the error string was "%errstr" (!date_time).',
          array(
            '%smtp' => $smtp,
            '%errno' => $errno,
            '%errstr' => $errstr,
            '!date_time' => format_date(time(), $date_time_format),
          )
        );
      }
    }
    if (!$connect) {
      if ($debugging_mode) {
        $debugging_text[] = t(
          'The system could not connect to "%smtp" and is continuing to the next host in the list (!date_time).',
          array(
            '%smtp' => $smtp,
            '!date_time' => format_date(time(), $date_time_format),
          )
        );
      }
      if ($connect === FALSE && $errno === 0) {
        if ($debugging_mode) {
          $debugging_text[] = t(
            'The result of fsockopen() was FALSE, and the error number was 0, which indicates a potential problem initializing the socket. This is the error string: "%errstr" (!date_time).',
            array(
              '%errstr' => $errstr,
              '!date_time' => format_date(time(), $date_time_format),
            )
          );
        }
        watchdog('email_verify', 'There was a potential problem initializing the socket when attempting to check an email address.', array(), WATCHDOG_WARNING);
      }
      continue;
    }

    if (preg_match("/^220/", $out = fgets($connect, 1024))) {
      // OK, we have a SMTP connection.
      if ($debugging_mode) {
        $debugging_text[] = t(
          'A connection was made to "%smtp", and so the system capability check is continuing (!date_time).',
          array(
            '%smtp' => $smtp,
            '!date_time' => format_date(time(), $date_time_format),
          )
        );
      }
      break;
    }
  }

  if (!$connect) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'No connection could be made to any host. Domains will be checked for validity, but mailboxes cannot be checked (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    variable_set('email_verify_skip_mailbox', TRUE);
    $message = t('Email Verify will test email domains but not mailboxes because port 25 is closed on your host\'s firewall for security.');
    watchdog('email_verify', $message, array(), WATCHDOG_WARNING);
    drupal_set_message($message, 'warning');
  }
  else {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'A connection was made to a host, so the system has passed the capability check (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
  }

  if ($debugging_mode) {
    $debugging_text[] = t(
      'Ending the system capability checks for the Email Verify module (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  return $debugging_text;
}
