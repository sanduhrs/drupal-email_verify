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
  $form = array();

  $form['email_verify_email'] = array(
    '#type' => 'fieldset',
    '#title' => t('Forms to check'),
    '#collapsible' => TRUE,
    '#description' => t("Check the boxes for the forms you want to have this module check email addresses on."),
  );
  $form['email_verify_email']['email_verify_user_registration'] = array(
    '#type' => 'checkbox',
    '#title' => t("User registration"),
    '#default_value' => variable_get('email_verify_user_registration', 1),
  );
  $form['email_verify_email']['email_verify_user_profile'] = array(
    '#type' => 'checkbox',
    '#title' => t("User profile"),
    '#default_value' => variable_get('email_verify_user_profile', 1),
  );

  if (module_exists('contact')) {
    $form['email_verify_email']['email_verify_site_contact'] = array(
      '#type' => 'checkbox',
      '#title' => t("Site-wide contact"),
      '#default_value' => variable_get('email_verify_site_contact', 0),
    );
    $form['email_verify_email']['email_verify_personal_contact'] = array(
      '#type' => 'checkbox',
      '#title' => t("Personal contact"),
      '#default_value' => variable_get('email_verify_personal_contact', 0),
    );
  }

  return system_settings_form($form);
}
