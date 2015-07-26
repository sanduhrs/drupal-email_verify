<?php
/**
 * @file
 * User email check menu callback file for email_verify module.
 */

/**
 * Look though the users table for invalid emails.
 *
 * @param array $form
 *   The form definition.
 * @param array $form_state
 *   The current state of the form.
 *
 * @return array
 *   The form definition.
 */
function email_verify_user_check_form($form, &$form_state) {
  $form['header'] = array(
    '#type' => 'fieldset',
    '#title' => t('User check'),
    '#collapsible' => TRUE,
    '#description' => t('On this page, you can list all existing users for whom their email address is not valid.
       Simply click the Start button to begin the process.
       Depending on the number of users, the process may take a while.
       If you make changes to the users, you will need to click the Update button to see the new data.'),
  );
  $form['header']['description'] = array(
    '#markup' => t(
      '<p>Because the checking process can take a very long time,
      especially for sites with thousands of users,
      to the point of this page being entirely useless,
      you may specify the number of users to check with the fields below.</p>'
    ),
  );
  $form['header']['number'] = array(
    '#type' => 'textfield',
    '#title' => t("Number"),
    '#size' => 15,
    '#description' => t('The number of users to check.'),
  );
  $form['header']['offset'] = array(
    '#type' => 'textfield',
    '#title' => t("Offset"),
    '#size' => 15,
    '#description' => t('The number of users to skip before counting the number.'),
  );
  $all_user_count = db_query("SELECT COUNT(DISTINCT uid) FROM users")->fetchField();
  $active_user_count = db_query("SELECT COUNT(DISTINCT uid) FROM users WHERE status = 1")->fetchField();
  $form['header']['disabled'] = array(
    '#type' => 'checkbox',
    '#title' => t('Include blocked/disabled users'),
    '#description' => t(
      'There are %all_user_count users registed with this site, of which, %active_user_count are active.',
      array(
        '%all_user_count' => $all_user_count,
        '%active_user_count' => $active_user_count,
      )
    ),
  );
  $form['header']['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Start'),
  );

  // Get any records that have been stored to display.
  $rows = variable_get('email_verify_users_to_display', array());
  if (!empty($rows)) {
    // Rename the button.
    $form['header']['submit']['#value'] = t('Update');

    $headers = _email_verify_get_header();

    $form_count = format_plural(
      count($rows),
      'Found 1 user whose email address is not valid.',
      'Found @count users whose email addresses are not valid.'
    );

    // Set up the sorting.
    _email_verify_sort_rows($headers, $rows);

    // Set up the pager.
    $current_page = pager_default_initialize(count($rows), 25);
    // Break the total data set into page sized chunks.
    $pages = array_chunk($rows, 25, TRUE);

    // Add the users.
    if (empty($pages)) {
      $user_rows = $rows;
    }
    else {
      $user_rows = $pages[$current_page];
    }

    $form['table'] = array(
      '#markup' => theme(
        'table',
        array(
          'header' => $headers,
          'rows' => $user_rows,
          'caption' => $form_count,
        )
      ),
    );

    // Add the pager.
    $form['pager'] = array('#markup' => theme('pager'));
  }

  return $form;
}

/**
 * Submit handler for the user check form.
 */
function email_verify_user_check_form_submit($form, &$form_state) {
  // Clear any saved data.
  variable_del('email_verify_users_to_display');

  // Prepare the operations.
  if (empty($form_state['values']['number'])) {
    $count_query = "SELECT COUNT(DISTINCT uid) FROM users";
    // Check for whether to include blocked users.
    if (empty($form_state['values']['disabled'])) {
      $count_query .= " WHERE status = 1";
    }
    $user_count = db_query($count_query)->fetchField();
  }
  elseif (is_numeric($form_state['values']['number'])) {
    $user_count = check_plain($form_state['values']['number']);
  }
  else {
    drupal_set_error(t('There was an error checking for the number of users to check. Please verify your entries in the Number and Offest fields.'));
    return;
  }

  $offset = 0;
  if (!empty($form_state['values']['offset']) && is_numeric($form_state['values']['offset'])) {
    $offset = check_plain($form_state['values']['offset']);
  }

  $operations = array();
  $operations[] = array(
    '_email_verify_batch_display_process_batch',
    array(
      $user_count,
      $offset,
      $form_state['input']['disabled'],
    ),
  );

  // Prepare the batch.
  $batch = array(
    'title' => t('Checking the email addresses of @user_count users. You may want to go get a cup of coffee now. Or maybe a sandwich.', array('@user_count' => $user_count)),
    'operations' => $operations,
    'progress_message' => t('Completed @current of @total operations.'),
    'error_message' => t('One or more errors were encountered processing the users.'),
    'finished' => '_email_verify_batch_finish_batch',
    'file' => drupal_get_path('module', 'email_verify') . '/email_verify.check.inc',
  );

  // Set the batch.
  batch_set($batch);
}

/**
 * The batch process for checking the users.
 *
 * @param object $user
 *   An object containing the ID, name and email address of the user to process.
 * @param array $context
 *   Used by the Batch API to keep track of and pass data from one operation to
 *   the next.
 */
function _email_verify_batch_display_process_batch($user_count, $offset, $disabled, &$context) {
  // Used to store information to track progression between successive calls.
  if (empty($context['sandbox'])) {
    $context['sandbox'] = array();
    $context['sandbox']['current_count'] = 0;
    $context['sandbox']['max'] = $user_count;
  }

  $count_increment = 5;

  // Create and execute the query for selecting the user data.
  $query = "SELECT uid, name, mail FROM users";
  // Check for whether to include blocked users.
  if (empty($disabled)) {
    $query .= " WHERE status = 1";
  }
  $query .= " ORDER BY uid ASC";
  $users = db_query_range(
    $query,
    $context['sandbox']['current_count'] + $offset,
    $count_increment
  )->fetchAll();

  // Process the user list.
  foreach ($users as $user) {
    $account = user_load($user->uid);
    // Check the user account.
    $check_results = email_verify_check($account->mail);
    if ($check_results) {
      // Add the user to the list.
      $context['results']['users_to_display'][$account->uid] = array(
        'uid' => $account->uid,
        'name' => $account->name,
        'mail' => $account->mail,
        'reason' => $check_results,
        'link' => l('account', 'user/' . $account->uid),
      );
    }

    // Update the progress information.
    $context['sandbox']['current_count']++;
    $context['message'] = t('Processed user') . ' ' . check_plain($account->name) . ' (' . t('ID') . ' ' . $account->uid . ')';
  }

  // Inform the batch engine the operations have not been completed, and provide
  // an estimation of the current completion level.
  if ($context['sandbox']['current_count'] != $context['sandbox']['max']) {
    $context['finished'] = ($context['sandbox']['current_count'] >= $context['sandbox']['max']);
  }
}

/**
 * The function that is called when the batch is complete.
 */
function _email_verify_batch_finish_batch($success, $results, $operations) {
  if ($success) {
    if (!empty($results['users_to_display'])) {
      // Save the collected data for display.
      variable_set('email_verify_users_to_display', $results['users_to_display']);
    }
  }
  else {
    // An error occurred. $operations contains the operations that remained
    // unprocessed.
    $error_operation = reset($operations);
    drupal_set_message(
      t('An error occurred while processing @operation with arguments : @args',
        array(
          '@operation' => $error_operation[0],
          '@args' => print_r($error_operation[0], TRUE),
        )
      )
    );
  }
}

/**
 * Returns the header to use for the display table.
 *
 * @return array
 *   The header to use.
 */
function _email_verify_get_header() {
  return array(
    'uid' => array(
      'data' => t('User Id'),
      'field' => 'uid',
    ),
    'name' => array(
      'data' => t('Name'),
      'field' => 'name',
    ),
    'mail' => array(
      'data' => t('Email address'),
      'field' => 'mail',
    ),
    'reason' => array(
      'data' => t('Reason'),
    ),
    'account' => array(
      'data' => t(''),
    ),
  );
}

/**
 * Sorts the table rows.
 *
 * @param array $headers
 *   The headers of the table.
 * @param array $rows
 *   The data to sort.
 */
function _email_verify_sort_rows($headers, &$rows) {
  $order_field = tablesort_get_order($headers);
  $order = tablesort_get_sort($headers);
  if (!empty($order_field['sql'])) {
    $order_by = $order_field['sql'];

    switch ($order) {
      case 'desc':
        uasort($rows, function($a, $b) use($order_by) {
          if ($a[$order_by] == $b[$order_by]) {
            return 0;
          }
          return ($a[$order_by] > $b[$order_by]) ? -1 : 1;
        });
        break;

      case 'asc':
        uasort($rows, function($a, $b) use ($order_by) {
          if ($a == $b) {
            return 0;
          }
          return ($a[$order_by] < $b[$order_by]) ? -1 : 1;
        });
        break;
    }
  }
}
