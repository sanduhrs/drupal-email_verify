<?php
/**
 * @file
 * Checks the email address for validity.
 */

/**
 * Checks the email address for validity.
 */
function _email_verify_check($mail) {
  if (!valid_email_address($mail)) {
    // The address is syntactically incorrect. The problem will be caught by the
    // user module, so avoid duplicating the error reporting by just returning.
    return;
  }

  // If this is a Windows based computer, load the Windows compatibilty file.
  if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
    module_load_include('inc', 'email_verify', 'windows_compat');
  }

  $host = drupal_substr(strchr($mail, '@'), 1);
  if (variable_get('email_verify_methods_add_dot', 1)) {
    $host = $host . '.';
  }

  // Check the DNS records of the email address' domain name to see if anything
  // is reported.
  if (variable_get('email_verify_methods_checkdnsrr', 1)) {
    if (!checkdnsrr($host, 'ANY')) {
      watchdog('email_verify', "No DNS records were found, using checkdnsrr() with '%host' for host and 'ANY' for type.", array('%host' => $host));
      if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
        return t("No DNS records were found, using checkdnsrr() with '%host' for host and 'ANY' for type.", array('%host' => $host));
      }
      else {
        return t('%host is not a valid email host. Please check the spelling and try again.', array('%host' => "$host"));
      }
    }
  }

  // Check to see if the email address' domain name resolves to an IPv4 address.
  if (variable_get('email_verify_methods_gethostbyname', 1)) {
    if (gethostbyname($host) == $host) {
      watchdog('email_verify', 'No IPv4 address was found, using gethostbyname() with %host.', array('%host' => $host));
      if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
        return t('No IPv4 address was found, using gethostbyname() with %host.', array('%host' => $host));
      }
      else {
        return t('%host is not a valid email host. Please check the spelling and try again.', array('%host' => "$host"));
      }
    }
  }

  // If install found port 25 closed or fsockopen() disabled, we can't test
  // mailboxes.
  If (variable_get('email_verify_skip_mailbox', FALSE)) {
    return;
  }

  // What SMTP servers should we contact?
  $mx_hosts = array();
  if (!getmxrr($host, $mx_hosts)) {
    // When there is no MX record, the host itself should be used.
    $mx_hosts[] = $host;
  }

  // Try to connect to one SMTP server.
  foreach ($mx_hosts as $smtp) {
    /**
     * @todo
     *   This needs to be examined and possibly corrected.
     */
    $connect = @fsockopen($smtp, 25, $errno, $errstr, 15);

    if (!$connect) {
      if ($connect === FALSE && $errno === 0) {
        watchdog('email_verify', 'There was a potential problem initializing the socket when attempting to check an email address.', array(), WATCHDOG_WARNING);
      }

      continue;
    }

    if (preg_match("/^220/", $out = fgets($connect, 1024))) {
      // An SMTP connection was made.
      break;
    }
    else {
      // The SMTP server probably does not like us (dynamic/residential IP for
      // aol.com for instance).
      // Be on the safe side and accept the address, at least it has a valid
      // domain part.
      watchdog('email_verify', 'Could not verify email address at host @host: @out', array('@host' => $host, '@out' => $out), WATCHDOG_WARNING);
      if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
        return t('Could not verify email address at host @host: @out', array('@host' => $host, '@out' => $out));
      }
      else {
        return;
      }
    }
  }

  if (!$connect) {
    return t('%host is not a valid email host. Please check the spelling and try again or contact us for clarification.', array('%host' => "$host"));
  }

  $from = variable_get('site_mail', ini_get('sendmail_from'));

  // Extract the <...> part, if there is one.
  if (preg_match('/\<(.*)\>/', $from, $match) > 0) {
    $from = $match[1];
  }

  // Should be good enough for RFC compliant SMTP servers.
  $localhost = $_SERVER["HTTP_HOST"];
  if (!$localhost) {
    $localhost = 'localhost';
  }

  // Conduct the test.
  fputs($connect, "HELO $localhost\r\n");
  $out = fgets($connect, 1024);
  fputs($connect, "MAIL FROM: <$from>\r\n");
  $from = fgets($connect, 1024);
  fputs($connect, "RCPT TO: <{$mail}>\r\n");
  $to = fgets($connect, 1024);
  fputs($connect, "QUIT\r\n");
  fclose($connect);

  // Check the results.
  if (!preg_match("/^250/", $from)) {
    // Again, something went wrong before we could really test the address.
    // Be on the safe side and accept it.
    watchdog('email_verify', 'Could not verify email address at host @host: @from', array('@host' => $host, '@from' => $from), WATCHDOG_WARNING);
    if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
      return t('Could not verify email address at host @host: @from', array('@host' => $host, '@from' => $from));
    }
    else {
      return;
    }
  }
  if (
      // This server does not like us (noos.fr behaves like this for instance).
      preg_match("/(Client host|Helo command) rejected/", $to) ||
      // Any 4xx error also means we couldn't really check except 450, which is
      // explcitely a non-existing mailbox: 450 = "Requested mail action not
      // taken: mailbox unavailable".
      preg_match("/^4/", $to) && !preg_match("/^450/", $to)) {
    // In those cases, accept the email, but log a warning.
    watchdog('email_verify', 'Could not verify email address at host @host: @to', array('@host' => $host, '@to' => $to), WATCHDOG_WARNING);
    if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
      return t('Could not verify email address at host @host: @to', array('@host' => $host, '@to' => $to));
    }
    else {
      return;
    }
  }
  if (!preg_match("/^250/", $to)) {
    watchdog('email_verify', 'Rejected email address: @mail. Reason: @to', array('@mail' => $mail, '@to' => $to), WATCHDOG_WARNING);
    if (function_exists('email_verify_access_people_email_verify') && email_verify_access_people_email_verify()) {
      return t('Rejected email address: @mail. Reason: @to', array('@mail' => $mail, '@to' => $to));
    }
    else {
      return t('%mail is not a valid email address. Please check the spelling and try again or contact us for clarification.', array('%mail' => "$mail"));
    }
  }

  // Everything is OK, so don't return anything.
  return;
}
