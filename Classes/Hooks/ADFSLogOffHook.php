<?php
namespace Causal\IgLdapSsoAuth\Hooks;

use Causal\IgLdapSsoAuth\Library\Configuration;
use Causal\IgLdapSsoAuth\Utility\ADFSUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Install\Service\SessionService;

/**
 * Class CasLogOffHook
 *
 * @package Causal\IgLdapSsoAuth\Hooks;
 */
class ADFSLogOffHook {

    /**
     * @param array $_params
     * @param \TYPO3\CMS\Core\Authentication\AbstractUserAuthentication $pObj
     */
    public function postProcessing($_params, $pObj) {
        if( TYPO3_MODE == 'FE' ){
          $session = new SessionService();
          $session->startSession();
          if( ADFSUtility::instance()->isAuthenticated() ) {
            ADFSUtility::instance()->logout();
          }

          $session->destroySession();
        }
    }
}
