<?php
namespace Causal\IgLdapSsoAuth\Hooks;

use Causal\IgLdapSsoAuth\Library\Configuration;
use phpCAS;
use TYPO3\CMS\Core\Utility\GeneralUtility;
/**
 * Class CasLogOffHook
 *
 * @package Causal\IgLdapSsoAuth\Hooks;
 */
class CasLogOffHook {

    /**
     * @param array $_params
     * @param \TYPO3\CMS\Core\Authentication\AbstractUserAuthentication $pObj
     */
    public function postProcessing($_params, $pObj) {
        if( TYPO3_MODE == 'FE' ){
            /** @var \Causal\IgLdapSsoAuth\Domain\Repository\ConfigurationRepository $configurationRepository */
            $configurationRepository = GeneralUtility::makeInstance('Causal\\IgLdapSsoAuth\\Domain\\Repository\\ConfigurationRepository');
            $configurationRecords = $configurationRepository->findAll();

            $params = GeneralUtility::_GET();
            $urlWithoutParam = GeneralUtility::getIndpEnv( 'TYPO3_REQUEST_URL' );
            $temps = explode('?',$urlWithoutParam);
            $urlWithoutParam=$temps[0];
            $arrayParams = array();

            if (count($configurationRecords) === 0) {
                // Early return since LDAP is not configured
                static::getLogger()->warning('Skipping LDAP authentication as extension is not yet configured');
                return false;
            }

            foreach ($configurationRecords as $configurationRecord) {
                Configuration::initialize(TYPO3_MODE, $configurationRecord);
                $casConfiguration = Configuration::getCASConfiguration();

                phpCAS::client(CAS_VERSION_2_0, (string)$casConfiguration['host'], (integer)$casConfiguration['port'], '');
                phpCAS::setCasServerCACert( '/etc/pki/tls/certs/ca-bundle.crt' );
                if(isset($casConfiguration['logoutUrl'] ) && $casConfiguration['logoutUrl']  !=''){
                    phpCAS::logoutWithRedirectService($casConfiguration['logoutUrl']);
                } else {
                    unset($params['logintype']);
                    unset($params['ticket']);
                    foreach($params as  $key=> $value){
                        $arrayParams[] = $key.'='.$value;
                    }
                    if(is_array($arrayParams) && count( $arrayParams ) > 0){
                        $url = $urlWithoutParam.'?'.implode('&',$arrayParams);
                    } else {
                        $url= $urlWithoutParam;
                    }

                    phpCAS::logoutWithRedirectService($url);
                }
            }
        }
    }
}
