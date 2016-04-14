<?php
/**
 * @file
 * Checks the email address for validity.
 */

/**
 * Manage cache before calling internal verification function.
 */
function _email_verify_check($mail, $use_caching = FALSE) {
  // Check to see if debugging is enables, and if it is, start collectiong
  // debugging information.
  $debugging_mode = variable_get('email_verify_debug_mode', FALSE);
  $date_time_format = variable_get('email_verify_debug_mode_date_format', 'long');
  $debugging_text = array();
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Beginning the verification of email address "%mail" (!date_time).',
      array(
        '%mail' => $mail,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }

  $results = array();

  // SMTP servers will eventually block the IP address used to verify email
  // addresses, so it is better to try and cache them.
  $cache_key = 'email_block_' . $mail;
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking to see if the results will be returned from the cache (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  if ($use_caching && $cache = cache_get($cache_key, 'cache_email_verify')) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'Caching has been selected, so the results will be returned from the cache (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    // An empty data property means the email verification had some issue
    // (rejected, etc.).
    if (!empty($cache->data)) {
      watchdog('email_verify', 'Cached verification for [@mail]: @result', array('@mail' => $mail, '@result' => $cache->data));
    }
    $results = $cache->data;
  }
  else {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'Caching was not selected, so the results will be returned from a fresh verification (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    $results = _email_verify_check_internal($mail, $debugging_mode, $debugging_text, $date_time_format);
    cache_set($cache_key, $results, 'cache_email_verify', CACHE_TEMPORARY);
  }

  if ($debugging_mode) {
    $results['debugging_text'][] = t(
      'Ending the verification of email address "%mail". It %verification_results verification (!date_time).',
      array(
        '%mail' => $mail,
        '%verification_results' => empty($results['verification_message']) ? 'passed' : 'failed',
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }

  return $results;
}

/**
 * Checks the email address for validity.
 */
function _email_verify_check_internal($mail, $debugging_mode, $debugging_text, $date_time_format) {
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking if the address is syntactically incorrect (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  if (!valid_email_address($mail)) {
    // The address is syntactically incorrect. The problem will be caught by the
    // user module, so avoid duplicating the error reporting by just returning.
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The address is not syntactically correct, so verification is stopping here (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    return array(
      'verification_message' => '',
      'debugging_text' => $debugging_text,
    );
  }
  else {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The address is syntactically correct, so verification is continuing (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
  }

  // If this is a Windows based computer, load the Windows compatibilty file.
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

  $host = drupal_substr(strstr($mail, '@'), 1);
  if ($debugging_mode) {
    $debugging_text[] = t(
      'The host that will be used for verifying the email address is "%host" (!date_time).',
      array(
        '%host' => $host,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }

  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking to see if a dot should be added to the domain name (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  if (variable_get('email_verify_methods_add_dot', 1)) {
    $host = $host . '.';
    if ($debugging_mode) {
      $debugging_text[] = t(
        'Adding a dot to the domain name. The new host to use for verification is "%host" (!date_time).',
        array(
          '%host' => $host,
          '!date_time' => format_date(time(), $date_time_format),
        )
      );
    }
  }
  else {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'Not adding a dot to the domain name (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
  }

  // Check the DNS records of the email address' domain name to see if anything
  // is reported.
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking to see if the checkdnsrr() method should be used to verify the domain name (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  if (variable_get('email_verify_methods_checkdnsrr', 1)) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The checkdnsrr() method will be used to verify the domain name (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    if (!checkdnsrr($host, 'ANY')) {
      if ($debugging_mode) {
        $debugging_text[] = t(
          'No DNS records were found for host "%host", so verification is stopping here (!date_time).',
          array(
            '%host' => $host,
            '!date_time' => format_date(time(), $date_time_format),
          )
        );
      }
      watchdog('email_verify', 'No DNS records were found, using checkdnsrr() with "%host" for host and "ANY" for type.', array('%host' => $host));
      if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
        return array(
          'verification_message' => t('No DNS records were found, using checkdnsrr() with "%host" for host and "ANY" for type.', array('%host' => $host)),
          'debugging_text' => $debugging_text,
        );
      }
      else {
        return array(
          'verification_message' => t('%host is not a valid email host. Please check the spelling and try again.', array('%host' => "$host")),
          'debugging_text' => $debugging_text,
        );
      }
    }
    else {
      if ($debugging_mode) {
        $debugging_text[] = t(
          'DNS records were found for host "%host", so verification is continuing (!date_time).',
          array(
            '%host' => $host,
            '!date_time' => format_date(time(), $date_time_format),
          )
        );
      }
    }
  }
  else {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The checkdnsrr() method will not be used to verify the domain name (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
  }

  // Check to see if the email address' domain name resolves to an IPv4 address.
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking to see if the gethostbyname() method should be used to verify the domain name (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  if (variable_get('email_verify_methods_gethostbyname', 1)) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The gethostbyname() method will be used to verify the domain name (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    if (gethostbyname($host) == $host) {
      if ($debugging_mode) {
        $debugging_text[] = t(
          'No IPv4 address was found for host "%host", so verification is stopping here (!date_time).',
          array(
            '%host' => $host,
            '!date_time' => format_date(time(), $date_time_format),
          )
        );
      }
      watchdog('email_verify', 'No IPv4 address was found, using gethostbyname() with %host.', array('%host' => $host));
      if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
        return array(
          'verification_message' => t('No IPv4 address was found, using gethostbyname() with %host.', array('%host' => $host)),
          'debugging_text' => $debugging_text,
        );
      }
      else {
        return array(
          'verification_message' => t('%host is not a valid email host. Please check the spelling and try again.', array('%host' => "$host")),
          'debugging_text' => $debugging_text,
        );
      }
    }
    else {
      if ($debugging_mode) {
        $debugging_text[] = t(
          'IPv4 address was found for host "%host", so verification is continuing (!date_time).',
          array(
            '%host' => $host,
            '!date_time' => format_date(time(), $date_time_format),
          )
        );
      }
    }
  }
  else {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The gethostbyname() method will not be used to verify the domain name (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
  }

  // If install found port 25 closed or fsockopen() disabled, we can't test
  // mailboxes.
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking to see if the "email_verify_skip_mailbox" variable is set to TRUE, indicating that the system is unable to check mailboxes (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  if (variable_get('email_verify_skip_mailbox', FALSE)) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The "email_verify_skip_mailbox" variable is set to TRUE, so verification is stopping here (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    return array(
      'verification_message' => '',
      'debugging_text' => $debugging_text,
    );
  }
  else {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The "email_verify_skip_mailbox" variable is set to FALSE, so verification is continuing (!date_time).',
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
            'The result of fsockopen() was FALSE, and the error number was 0, which indicates a potential problem initializing initializing the socket. This is the error string: "%errstr" (!date_time).',
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

    // Set a limit on the amount of time to wait for a socket to be opened.
    stream_set_timeout($connect, 60);
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The timeout setting for opening a socket is "60" seconds (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }

    if (preg_match("/^220/", $connect_result = fgets($connect, 1024))) {
      // An SMTP connection was made.
      if ($debugging_mode) {
        $debugging_text[] = t(
          'A connection was made to "%smtp", and so verification will stop connecting to hosts and continue (!date_time).',
          array(
            '%smtp' => $smtp,
            '!date_time' => format_date(time(), $date_time_format),
          )
        );
      }
      break;
    }
    else {
      // The SMTP server probably does not like us (dynamic/residential IP for
      // aol.com for instance).
      // Be on the safe side and accept the address. At least it has a valid
      // domain part.
      // The connection might have timed-out, or there might have been some
      // other network related errors. The details can be obtained from
      // stream_get_meta_data().
      $metadata = stream_get_meta_data($connect);
      if ($debugging_mode) {
        $debugging_text[] = t(
          'A connection was made to "%smtp", but a positive response was not recieved. There may be additional information from the server: "%metadata". Verification is stopping here (!date_time).',
          array(
            '%smtp' => $smtp,
            '%metadata' => $metadata,
            '!date_time' => format_date(time(), $date_time_format),
          )
        );
      }
      watchdog(
        'email_verify',
        'Could not verify email address "%address" at host "%host": "%connect_result". Timed out at: %timedout',
        array(
          '%address' => $mail,
          '%host' => $host,
          '%connect_result' => $connect_result,
          '%timedout' => $metadata['timed_out'],
        ),
        WATCHDOG_WARNING
      );
      if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
        return array(
          'verification_message' => t('Could not verify email address at host %host: %connect_result', array('%host' => $host, '%connect_result' => $connect_result)),
          'debugging_text' => $debugging_text,
        );
      }
      else {
        return array(
          'verification_message' => '',
          'debugging_text' => $debugging_text,
        );
      }
    }
  }

  if (!$connect) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'No connection could be made to any host, so verification is stopping here (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    return array(
      'verification_message' => t('%host is not a valid email host. Please check the spelling and try again or contact us for clarification.', array('%host' => "$host")),
      'debugging_text' => $debugging_text,
    );
  }

  $from_address = variable_get('site_mail', ini_get('sendmail_from'));
  if ($debugging_mode) {
    $debugging_text[] = t(
      'The email address to use as the From address for the verification tests is "%from_address" (!date_time).',
      array(
        '%from_address' => $from_address,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }

  // Extract the <...> part, if there is one.
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Checking to see if From address needs to have non-email address text removed (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  if (preg_match('/\<(.*)\>/', $from_address, $match) > 0) {
    $from_address = $match[1];
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The From address needed to have non-email address text removed. The new From address to use for verification is "%from_address" (!date_time).',
        array(
          '%from_address' => $from_address,
          '!date_time' => format_date(time(), $date_time_format),
        )
      );
    }
  }
  else {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The From address did not need to have non-email address text removed (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
  }

  // Should be good enough for RFC compliant SMTP servers.
  $localhost = $_SERVER["HTTP_HOST"];
  if ($debugging_mode) {
    $debugging_text[] = t(
      'The domain to use as the From host for the verification tests is "%localhost" (!date_time).',
      array(
        '%localhost' => $localhost,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }
  if (!$localhost) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The domain to use as the From host was empty, "localhost" wil be used instead (!date_time).',
        array('!date_time' => format_date(time(), $date_time_format))
      );
    }
    $localhost = 'localhost';
  }

  // Conduct the test.
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Connecting to the host with the command "HELO %localhost" (!date_time).',
      array(
        '%localhost' => $localhost,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }
  fwrite($connect, "HELO $localhost\r\n");
  $connect_result = _email_verify_read_all_lines($connect, $debugging_mode, $debugging_text, $date_time_format);
  if ($debugging_mode) {
    $debugging_text[] = t(
      'The first 1024 charcters of the response to the HELO command: "%connect_result" (!date_time).',
      array(
        '%connect_result' => $connect_result,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Connecting to the host with the command "MAIL FROM: %from_address" (!date_time).',
      array(
        '%from_address' => $from_address,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }
  fwrite($connect, "MAIL FROM: <$from_address>\r\n");
  $from_result = _email_verify_read_all_lines($connect, $debugging_mode, $debugging_text, $date_time_format);
  if ($debugging_mode) {
    $debugging_text[] = t(
      'The first 1024 charcters of the response to the MAIL FROM command: "%from_result" (!date_time).',
      array(
        '%from_result' => $from_result,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Connecting to the host with the command "RCPT TO: {%mail}" (!date_time).',
      array(
        '%mail' => $mail,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }
  fwrite($connect, "RCPT TO: <{$mail}>\r\n");
  $to_result = _email_verify_read_all_lines($connect, $debugging_mode, $debugging_text, $date_time_format);
  if ($debugging_mode) {
    $debugging_text[] = t(
      'The first 1024 charcters of the response to the RCPT TO command: "%to_result" (!date_time).',
      array(
        '%to_result' => $to_result,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Connecting to the host with the command "QUIT" (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  fwrite($connect, "QUIT\r\n");
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Closing the connection to the host (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }
  fclose($connect);

  // Check the results.
  if (!preg_match("/^250/", $from_result)) {
    // Again, something went wrong before we could really test the address.
    // Be on the safe side and accept it.
    if ($debugging_mode) {
      $debugging_text[] = t(
        'A positive response was not recieved from the mail server. The result was "%from_result". Verification is stopping here (!date_time).',
        array(
          '%from_result' => $from_result,
          '!date_time' => format_date(time(), $date_time_format),
        )
      );
    }
    watchdog(
      'email_verify',
      'Could not verify email address "%address" at host "%host": <p>Results: Connection: %connect_result</p><p>From address: %from_result</p><p>To address: %to_result</p>',
      array(
        '%address' => $mail,
        '%host' => $host,
        '%connect_result' => $connect_result,
        '%from_result' => $from_result,
        '%to_result' => $to_result,
      ),
      WATCHDOG_WARNING
    );
    if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
      return array(
        'verification_message' => t('Could not verify email address at host %host: %from_result', array('%host' => $host, '%from_result' => $from_result)),
        'debugging_text' => $debugging_text,
      );
    }
    else {
      return array(
        'verification_message' => '',
        'debugging_text' => $debugging_text,
      );
    }
  }
  if (
    // This server does not like us (noos.fr behaves like this for instance).
    preg_match("/(Client host|Helo command) rejected/", $to_result) ||
    // Any 4xx response means we couldn't really check, usually due to being
    // temporarily unavailable. However, these can also be Greylisting responses
    // from the receiving mail server, used to filter incoming mail.
    preg_match("/^4/", $to_result)) {
    // In those cases, accept the email, but log a warning.
    if ($debugging_mode) {
      $debugging_text[] = t(
        'A positive response was not recieved from the mail server. The result was "%to_result". Verification is stopping here (!date_time).',
        array(
          '%to_result' => $to_result,
          '!date_time' => format_date(time(), $date_time_format),
        )
      );
    }
    watchdog(
      'email_verify',
      'Could not verify email address "%address" at host "%host": <p>Results: Connection: %connect_result</p><p>From address: %from_result</p><p>To address: %to_result</p>',
      array(
        '%address' => $mail,
        '%host' => $host,
        '%connect_result' => $connect_result,
        '%from_result' => $from_result,
        '%to_result' => $to_result,
      ),
      WATCHDOG_WARNING
    );
    if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
      return array(
        'verification_message' => t('Could not verify email address at host %host: %to_result', array('%host' => $host, '%to_result' => $to_result)),
        'debugging_text' => $debugging_text,
      );
    }
    else {
      return array(
        'verification_message' => '',
        'debugging_text' => $debugging_text,
      );
    }
  }

  // If there is a network level error, such as timeout, $to_result will be
  // empty.
  if (empty($to_result)) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'There was potentially a network related error, as the result from the To address "%mail" check was empty. The result was "%to_result". Verification is stopping here (!date_time).',
        array(
          '%mail' => $mail,
          '%to_result' => $to_result,
          '!date_time' => format_date(time(), $date_time_format),
        )
      );
    }
    watchdog(
      'email_verify',
      'Could not verify email address "%address" at host "%host": <p>Results: Connection: %connect_result</p><p>From address: %from_result</p><p>To address: %to_result</p>',
      array(
        '%address' => $mail,
        '%host' => $host,
        '%connect_result' => $connect_result,
        '%from_result' => $from_result,
        '%to_result' => $to_result,
      )
    );
    if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
      return array(
        'verification_message' => t('Could not verify email address "%mail", potentially due to a network error. Reason: %to_result', array('%mail' => $mail, '%to_result' => $to_result)),
        'debugging_text' => $debugging_text,
      );
    }
    else {
      return array(
        'verification_message' => t('Could not verify email address "%mail", potentially due to a network error. Please check the spelling, wait a moment, and try again or contact us for clarification.', array('%mail' => "$mail")),
        'debugging_text' => $debugging_text,
      );
    }
  }

  // This is an explicit rejection.
  if (!preg_match("/^250/", $to_result)) {
    if ($debugging_mode) {
      $debugging_text[] = t(
        'The To "%mail" address was rejected from the mail server. The result was "%to_result". Verification is stopping here (!date_time).',
        array(
          '%mail' => $mail,
          '%to_result' => $to_result,
          '!date_time' => format_date(time(), $date_time_format),
        )
      );
    }
    watchdog(
      'email_verify',
      'Rejected email address: "%address". Reason: <p>Connection: %connect_result</p><p>From address: %from_result</p><p>To address: %to_result</p>',
      array(
        '%address' => $mail,
        '%connect_result' => $connect_result,
        '%from_result' => $from_result,
        '%to_result' => $to_result,
      ),
      WATCHDOG_WARNING
    );
    if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
      return array(
        'verification_message' => t('Rejected email address: %mail. Reason: %to_result', array('%mail' => $mail, '%to_result' => $to_result)),
        'debugging_text' => $debugging_text,
      );
    }
    else {
      return array(
        'verification_message' => t('%mail is not a valid email address. Please check the spelling and try again or contact us for clarification.', array('%mail' => "$mail")),
        'debugging_text' => $debugging_text,
      );
    }
  }

  // A pass is signified by returning an empty verification_message string.
  return array(
    'verification_message' => '',
    'debugging_text' => $debugging_text,
  );
}

/**
 * Read response from SMTP server, multiline compatible.
 *
 * @param string $connect
 *   The connection response string from the server.
 * @param bool $debugging_mode
 *   Whether to collect debugging information or not.
 * @param array $debugging_text
 *   An array of strings, each of which are a line of debugging information.
 * @param string $date_time_format
 *   The data and time format to use for the debugging information.
 *
 * @return string
 *   The response from the server, formatted for use by this module.
 */
function _email_verify_read_all_lines($connect, $debugging_mode, array &$debugging_text, $date_time_format) {
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Reading all lines of the connection response (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }

  $result = '';
  do {
    $line = _email_verify_read_line($connect, $debugging_mode, $debugging_text, $date_time_format);
    $result .= $line['line'];
  } while ($line['next_char'] == '-');

  if ($debugging_mode) {
    $debugging_text[] = t(
      'Done reading all lines of the connection response. The result was: "%result" (!date_time).',
      array(
        '%result' => $result,
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }
  return $result;
}

/**
 * SMTP Single line read.
 *
 * Reads a single response line from SMTP server and identifies response CODE
 * and Following Character (" " or "-")
 *
 * @param string $connect
 *   A single line from the connection response string from the server.
 * @param bool $debugging_mode
 *   Whether to collect debugging information or not.
 * @param array $debugging_text
 *   An array of strings, each of which are a line of debugging information.
 * @param string $date_time_format
 *   The data and time format to use for the debugging information.
 *
 * @return array
 *   A sinlge line of the response from the server, formatted for use by this
 *   module. THe array consists of three elements:
 *   - code: The numeric response code from the server.
 *   - next_char: A character indicating if there are more lines to follow, or
 *     if this is the last line. A "-" indicates that more text is following,
 *     and a " " (space) indicates that there is no more text.
 *   - line: The string of text for this line from the server's response.
 */
function _email_verify_read_line($connect, $debugging_mode, array &$debugging_text, $date_time_format) {
  if ($debugging_mode) {
    $debugging_text[] = t(
      'Reading a single line of the connection response (!date_time).',
      array('!date_time' => format_date(time(), $date_time_format))
    );
  }

  $response = fgets($connect, 1024);
  $strlen = strlen($response);
  $code = '';

  // Try to get response code: all numeric characters at the begginging of the
  // response string.
  $i = 0;
  for ($i = 0; $i <= $strlen; $i++) {
    $char = substr($response, $i, 1);
    if (!is_numeric($char)) {
      break;
    }
    $code .= $char;
  }

  // If there is a slash character after the response code then more lines are
  // to be expected.
  // @see https://bugs.php.net/bug.php?id=6537
  // (That bug was fixed in PHP between 2001-01-10 and 2002-06-02. The reference
  // is included here for background information.)
  $next_char = substr($response, $i, 1);

  if ($debugging_mode) {
    $debugging_text[] = t(
      'Done reading a single line of the connection response. The results were: Code: "%code", More lines: "@next_char" (!more_lines), Response: "%response" (!date_time).',
      array(
        '%code' => $code,
        '@next_char' => $next_char,
        '%response' => $response,
        '!more_lines' => ($next_char == " ") ? 'no' : 'yes',
        '!date_time' => format_date(time(), $date_time_format),
      )
    );
  }
  return array('code' => $code, 'next_char' => $next_char, 'line' => $response);
}
