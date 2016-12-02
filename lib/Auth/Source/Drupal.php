<?php
/**
 * Created by Vincenzo Gambino
 * Date: 26/11/2016
 * Time: 20:19
 */

use Drupal\Core\DrupalKernel;
use Symfony\Component\HttpFoundation\Request;


class sspmod_authdrupal_Auth_Source_Drupal extends SimpleSAML_Auth_Source{
  /**
   * Debug mode
   * true or false
   */
  private $debug_mode;

  /**
   * Cookie name
   */
  private $cookie_name;

  /**
   * Path of the cookie
   */
  private $cookie_path;

  /**
   * Cookie salt
   */
  private $cookie_salt;

  /**
   * Drupal directory
   */
  private $drupal_dir;

  /**
   * Drupal logout URL
   */
  private $drupal_logout_url;

  /**
   * Drupal login URL
   */
  private $drupal_login_url;

  /**
   * Drupal user id
   */
  private $uid;

  /**
   * Drupal user properties
   */
  private $properties;

  /**
   * Drupal entity manager
   */
  private $em;

  /**
   * Constructor for this authentication source.
   *
   * @param array $info  Information about this authentication source.
   * @param array $config  Configuration.
   */
  public function __construct($info, $config) {
    assert('is_array($info)');
    assert('is_array($config)');
    $this->config = $config;

    /* Call the parent constructor first, as required by the interface. */
    parent::__construct($info, $config);
    /* Get the configuration for this module */

    if (!array_key_exists('drupal_dir', $config)) {
      throw new SimpleSAML_Error_Exception('Drupal authentication source is not properly configured: missing [drupal_root]');
    }
    $this->drupal_dir = $config['drupal_dir'];

    if (!array_key_exists('debug_mode', $config)) {
      throw new SimpleSAML_Error_Exception('Drupal authentication source is not properly configured: missing [debug_mode]');
    }
    $this->debug_mode = $config['debug_mode'];

    if (!array_key_exists('properties', $config)) {
      throw new SimpleSAML_Error_Exception('Drupal authentication source is not properly configured: missing [properties]');
    }

    if (!array_key_exists('cookie_name', $config)) {
      $this->cookie_name = 'drupal_ssp_idp';
    }
    else {
      $this->cookie_name = $config['cookie_name'];
    }

    if (!array_key_exists('drupal_logout_url', $config)) {
      throw new SimpleSAML_Error_Exception('Drupal authentication source is not properly configured: missing [drupal_logout_url]');
    }
    $this->drupal_logout_url = $config['drupal_logout_url'];

    if (!array_key_exists('drupal_login_url', $config)) {
      throw new SimpleSAML_Error_Exception('Drupal authentication source is not properly configured: missing [drupal_login_url]');
    }
    $this->drupal_login_url = $config['drupal_login_url'];

    if (!defined('DRUPAL_DIR')) {
      define('DRUPAL_DIR', $config['drupal_dir']);
    }
    $ssp_config = SimpleSAML_Configuration::getInstance();
    $this->cookie_path = '/' . $ssp_config->getValue('baseurlpath');
    $this->cookie_salt = $ssp_config->getValue('secretsalt');
    $this->uid = NULL;
  }

  /**
   * Log in using Drupal login form.
   *
   * @param array &$state  Information about the current authentication.
   */
  public function authenticate(&$state) {
    assert('is_array($state)');

    $user_attributes = $this->getDrupalUser();

    // The user is logged in.
    if ($user_attributes !== NULL) {
      // Add user attribute to the $state array.
      $state['Attributes'] = $user_attributes;
      return;
    }
    
    // Identifier of authentication source.
    $state['authdrupal:AuthID'] = $this->authId;

    $stateId = SimpleSAML_Auth_State::saveState($state, 'authdrupal:Drupal');

    $returnTo = SimpleSAML_Module::getModuleURL('authdrupal/linkback.php', array(
      'State' => $stateId,
    ));

    // URL of the authentication page.
    $authPage = $this->drupal_login_url . '?ReturnTo=' . $returnTo;
    
    // Redirect to the authentication page.     
    SimpleSAML_Utilities::redirect($authPage, array(
      'ReturnTo' => $returnTo,
    ));

    assert('FALSE');
  }

  private function getDrupalUser() {

    // User uid is included in the cookie. It will be taken from the cookie.
    if(isset($_COOKIE[$this->cookie_name]) && $_COOKIE[$this->cookie_name]) {
      $cookie = $_COOKIE[$this->cookie_name];
      $cookie = explode(':',$cookie);

      // Check for any manipulation.
      if( (isset($cookie[0]) && $cookie[0]) && (isset($cookie[1]) && $cookie[1]) ) {
        if(sha1($this->cookie_salt . $cookie[1]) == $cookie[0]) {
          $this->uid = $cookie[1];
        } else {
          throw new SimpleSAML_Error_Exception('You entered an invalid cookie.');
        }
      }
    }

    // Update the cookie so it expires.
    if(isset($_COOKIE[$this->cookie_name])) {
      setcookie($this->cookie_name, "", time() - 3600, $this->cookie_path);
    }

    // Get user data from Drupal.
    if (!empty($this->uid)) {
      require_once DRUPAL_DIR . '/core/includes/database.inc';
      require_once DRUPAL_DIR . '/core/includes/schema.inc';
      
      // Specify relative path to the drupal root.
      $autoloader = require_once DRUPAL_DIR . '/autoload.php';
  
      $request = Request::createFromGlobals();
  
      // Bootstrap drupal to different levels
      $kernel = DrupalKernel::createFromRequest($request, $autoloader, 'prod');
      $kernel->boot();
      
      $kernel->prepareLegacyRequest($request);
  
      $this->em = $kernel->getContainer()->get('entity.manager');

      // load the user from Drupal
      $users = $this->em->getStorage('user')->loadByProperties(['uid' => $this->uid]);

      $user = array_shift($users);
      
      // get all the attributes we need from the user object.
      foreach ($this->config['properties'] as $field) {
        $this->properties[$field][] = $user->get($field)->value;
      }
    }
    return $this->properties;
  }

  /**
   * Resume authentication process.
   */
  public static function linkback() {

    if (!isset($_REQUEST['State'])) {
      throw new SimpleSAML_Error_BadRequest('Error: Missing State from Request.');
    }
    $state_id = (string)$_REQUEST['State'];

    $state = SimpleSAML_Auth_State::loadState($state_id, 'authdrupal:Drupal');
    $authentication_source = SimpleSAML_Auth_Source::getById($state['authdrupal:AuthID']);
    
    if ($authentication_source === NULL) {
      throw new SimpleSAML_Error_Exception('Error: No Authentication method found with name: ' . $state[self::AUTHID]);
    }

    $user_attributes = $authentication_source->getDrupalUser();
    if ($user_attributes === NULL) {

      throw new SimpleSAML_Error_Exception('Error: user has not been authenticated.');
    }

    $state['Attributes'] = $user_attributes;

    SimpleSAML_Auth_Source::completeAuth($state);

    assert('FALSE');
  }

  /**
   * Logout function.
   * @param array &$state.
   */
  public function logout(&$state) {
    assert('is_array($state)');

    if (!session_id()) {
      session_start();
    }

    unset($_SESSION['uid']);

    // Remove cookie.
    if (isset($_COOKIE[$this->cookie_name])) {
      setcookie($this->cookie_name, "", time() - 3600, $this->cookie_path);
    }

    header('Location: ' . $this->drupal_logout_url);
    die;
  }

}