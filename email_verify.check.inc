<?php
/**
 * @file
 * User email check menu callback file for email_verify module.
 */

/**
 * Menu callback; look though the whole user base for invalid emails.
 *
 * Can be very long when hosts timeout.
 */
function email_verify_checkall() {
  $content = "<table>";
  $found = 0;

  $results = db_select('users', 'u')
    ->fields('u', array('uid', 'name', 'mail'))
    ->execute();
  foreach ($results as $row) {
    if (email_verify_check($row->mail)) {
      $content .= "<tr><td><a href='?q=user/$row->uid/edit'>" . check_plain($row->name) . "</a><td>" . check_plain($row->mail);

      if (++$found >= 100) {
        break;
      }
    }
  }

  $content .= "</table>";

  // Destroy variables.
  unset($found, $result, $row);

  // TODO Please change this theme call as discussed at
  // http://drupal.org/node/224333#theme_page.
  // print theme("page", $content);
  print $content;
}
