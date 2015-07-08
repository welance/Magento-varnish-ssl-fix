<?php

/**
 * Magento enterprise fix for varnish ssl
 */

class Crasx_VarnishSSLFix_Model_Session extends Mage_Core_Model_Session
{
  /**
   * Configure and start session
   *
   * @param string $sessionName
   * @return Mage_Core_Model_Session_Abstract_Varien
   */
  public function start($sessionName=null)
  {
    if (isset($_SESSION) && !$this->getSkipEmptySessionCheck()) {
      return $this;
    }

    // getSessionSaveMethod has to return correct version of handler in any case
    $moduleName = $this->getSessionSaveMethod();
    switch ($moduleName) {
      /**
       * backward compatibility with db argument (option is @deprecated after 1.12.0.2)
       */
      case 'db':
        $moduleName = 'user';
        /* @var $sessionResource Mage_Core_Model_Resource_Session */
        $sessionResource = Mage::getResourceSingleton('core/session');
        $sessionResource->setSaveHandler();
        break;
      case 'user':
        // getSessionSavePath represents static function for custom session handler setup
        call_user_func($this->getSessionSavePath());
        break;
      case 'files':
        //don't change path if it's not writable
        if (!is_writable($this->getSessionSavePath())) {
          break;
        }
      default:
        session_save_path($this->getSessionSavePath());
        break;
    }
    session_module_name($moduleName);

    $cookie = $this->getCookie();
    if (Mage::app()->getStore()->isAdmin()) {
      $sessionMaxLifetime = Mage_Core_Model_Resource_Session::SEESION_MAX_COOKIE_LIFETIME;
      $adminSessionLifetime = (int)Mage::getStoreConfig('admin/security/session_cookie_lifetime');
      if ($adminSessionLifetime > $sessionMaxLifetime) {
        $adminSessionLifetime = $sessionMaxLifetime;
      }
      if ($adminSessionLifetime > 60) {
        $cookie->setLifetime($adminSessionLifetime);
      }
    }

    // session cookie params
    $cookieParams = array(
      'lifetime' => $cookie->getLifetime(),
      'path'     => $cookie->getPath(),
      'domain'   => $cookie->getConfigDomain(),
      'secure'   => $cookie->isSecure(),
      'httponly' => $cookie->getHttponly()
    );

    if (!$cookieParams['httponly']) {
      unset($cookieParams['httponly']);
      if (!$cookieParams['secure']) {
        unset($cookieParams['secure']);
        if (!$cookieParams['domain']) {
          unset($cookieParams['domain']);
        }
      }
    }

    if (isset($cookieParams['domain'])) {
      $cookieParams['domain'] = $cookie->getDomain();
    }

    call_user_func_array('session_set_cookie_params', $cookieParams);

    if (!empty($sessionName)) {
      $this->setSessionName($sessionName);
    }

    // potential custom logic for session id (ex. switching between hosts)
    $this->setSessionId();

    Varien_Profiler::start(__METHOD__.'/start');
    $sessionCacheLimiter = Mage::getConfig()->getNode('global/session_cache_limiter');
    if ($sessionCacheLimiter) {
      session_cache_limiter((string)$sessionCacheLimiter);
    }

    session_start();

    /*
    if (Mage::app()->getFrontController()->getRequest()->isSecure() && empty($cookieParams['secure'])) {
      // secure cookie check to prevent MITM attack
      $secureCookieName = $sessionName . '_cid';
      if (isset($_SESSION[self::SECURE_COOKIE_CHECK_KEY])
        && $_SESSION[self::SECURE_COOKIE_CHECK_KEY] !== md5($cookie->get($secureCookieName))
      ) {
        session_regenerate_id(false);
        $sessionHosts = $this->getSessionHosts();
        $currentCookieDomain = $cookie->getDomain();
        foreach (array_keys($sessionHosts) as $host) {
          // Delete cookies with the same name for parent domains
          if (strpos($currentCookieDomain, $host) > 0) {
            $cookie->delete($this->getSessionName(), null, $host);
          }
        }
        $_SESSION = array();
      }
      if (!isset($_SESSION[self::SECURE_COOKIE_CHECK_KEY])) {
        $checkId = Mage::helper('core')->getRandomString(16);
        $cookie->set($secureCookieName, $checkId, null, null, null, true);
        $_SESSION[self::SECURE_COOKIE_CHECK_KEY] = md5($checkId);
      }
    }
    */

    /**
     * Renew cookie expiration time if session id did not change
     */
    if ($cookie->get(session_name()) == $this->getSessionId()) {
      $cookie->renew(session_name());
    }
    Varien_Profiler::stop(__METHOD__.'/start');

    return $this;
  }

}
		
