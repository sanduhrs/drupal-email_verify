<?php

/**
 * @file
 * Definitions for functions missing from the Windows implementation of PHP.
 *
 * @see http://drupal.org/node/508004
 */

if (!function_exists('getmxrr')) {

  /**
   * Checks for getmxrr() before replacing it with win_getmxrr().
   *
   * @return bool
   *   The results of the win_getmxrr() function.
   *
   * @see win_getmxrr()
   */
  function getmxrr($hostname, array &$mxhosts, array &$mxweight = array()) {
    return win_getmxrr($hostname, $mxhosts, $mxweight);
  }

}

/**
 * Implements getmxrr() for Windows prior to PHP 5.3.0.
 *
 * Code originally by HM2K <php [at] hm2k.org>.
 *
 * @param string $hostname
 *   The Internet host name.
 * @param array $mxhosts
 *   A list of the MX records found is placed into the array mxhosts.
 * @param array $mxweight
 *   If the weight array is given, it will be filled with the weight information
 *   gathered.
 *
 * @return bool
 *   Returns TRUE if any records are found; returns FALSE if no records were
 *   found or if an error occurred.
 *
 * @see http://php.net/manual/function.getmxrr.php#88033
 */
function win_getmxrr($hostname, array &$mxhosts, array &$mxweight = array()) {
  if (empty($hostname)) {
    return FALSE;
  }
  if (strtoupper(substr(PHP_OS, 0, 3)) != 'WIN') {
    return FALSE;
  }

  if (!is_array($mxhosts)) {
    $mxhosts = array();
  }

  $exec = 'nslookup -type=MX ' . escapeshellarg($hostname);
  @exec($exec, $output);
  if (empty($output)) {
    return FALSE;
  }

  $i = -1;
  foreach ($output as $line) {
    $i++;
    if (preg_match("/^$hostname\tMX preference = ([0-9]+), mail exchanger = (.+)$/i", $line, $parts)) {
      $mxweight[$i] = trim($parts[1]);
      $mxhosts[$i] = trim($parts[2]);
    }
    if (preg_match('/responsible mail addr = (.+)$/i', $line, $parts)) {
      $mxweight[$i] = $i;
      $mxhosts[$i] = trim($parts[1]);
    }
  }

  return ($i != -1);
}

if (!function_exists('checkdnsrr')) {

  /**
   * Implements checkdnsrr() for Windows prior to PHP 5.3.0.
   *
   * @param string $host
   *   May either be the IP address in dotted-quad notation or the host name.
   * @param string $type
   *   May be any one of: A, MX, NS, SOA, PTR, CNAME, AAAA, A6, SRV, NAPTR, TXT
   *   or ANY.
   *
   * @return bool
   *   Returns TRUE if any records are found; returns FALSE if no records were
   *   found or if an error occurred.
   *
   * @see http://php.net/manual/function.checkdnsrr.php
   */
  function checkdnsrr($host, $type = '') {
    if (!empty($host)) {
      $type = (empty($type)) ? 'MX' : $type;
      exec('nslookup -type=' . $type . ' ' . escapeshellcmd($host), $result);
      $it = new ArrayIterator($result);
      foreach (new RegexIterator($it, '~^' . $host . '~', RegexIterator::GET_MATCH) as $result) {
        if ($result) {
          return TRUE;
        }
      }
    }

    return FALSE;
  }

}
