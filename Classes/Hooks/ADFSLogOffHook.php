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
        session_start();

        if( TYPO3_MODE == 'FE' ){
          if( ADFSUtility::instance()->isAuthenticated() ) {
            ADFSUtility::instance()->logout(self::getRequestUri());
          }
        }
    }

    private static function getRequestUri() {
      $pluginConfig = $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['ig_ldap_sso_auth'] ?? [];
      $redirectUrl = $pluginConfig['ADFSRedirectUriPrefix'] . $_SERVER['REQUEST_URI'];
      $tempUrl = parse_url($redirectUrl);
      parse_str($tempUrl['query'], $items);

      unset($items['logintype']);
      unset($items['code']);
      unset($items['state']);

      $tempUrl['query']= http_build_query($items);
      $queryParameters = !empty($tempUrl['query']) ? '?'.$tempUrl['query'] : '';

      return $tempUrl['scheme'].'://'.$tempUrl['host'].$tempUrl['path'].$queryParameters;
    }
}
