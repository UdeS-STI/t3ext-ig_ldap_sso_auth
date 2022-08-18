<?php
namespace Causal\IgLdapSsoAuth\Controller;

use Psr\EventDispatcher\EventDispatcherInterface;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use TYPO3\CMS\Extbase\Utility\LocalizationUtility;
use Causal\IgLdapSsoAuth\Library\Configuration;
use TYPO3\CMS\FrontendLogin\Service\UserService;

class FeloginController extends ActionController {

    private $userService;
    private $userAspect;

    public function __construct(
        UserService $userService,
        EventDispatcherInterface $eventDispatcher
    ) {
        $this->userService = $userService;
        $this->userAspect = GeneralUtility::makeInstance(Context::class)->getAspect('frontend.user');
    }

    public function indexAction(){
        $configurationRepository = GeneralUtility::makeInstance('Causal\\IgLdapSsoAuth\\Domain\\Repository\\ConfigurationRepository');
        $configuration = $configurationRepository->findAll();
        if( count( $configuration ) == 1 ){
            $configuration = $configuration[0];
        } else {
            //too many configuration DB object, WTF ?!
            exit;
        }
        Configuration::initialize( TYPO3_MODE, $configuration );
        $casAuthentification = Configuration::getValue('CASAuthentication');
        error_log( print_r( $casAuthentification,1 ));
        if( $casAuthentification ){
            $getEnvName = '_ARRAY';
            $EnvVar = GeneralUtility::getIndpEnv( $getEnvName );
            $params = GeneralUtility::_GET();

            // Remove the ticket from URL if present
            if( ( !empty($_REQUEST['ticket']) || !empty($_REQUEST['logintype']) ) ){
              $url = $EnvVar['TYPO3_REQUEST_URL'];
              $tempUrl = parse_url($url);
              parse_str($tempUrl['query'], $items);
              if (isset($items['logintype'])) {
                unset($items['logintype']);
              }
              if (isset($items['ticket'])) {
                unset($items['ticket']);
              }
              $tempUrl['query'] = http_build_query($items);
              $url = $tempUrl['scheme'] . '://' . $tempUrl['host'] . $tempUrl['path'] . (!empty($tempUrl['query']) ? '?' . $tempUrl['query'] : '');
              header("Location: " . $url);
            }

            $authText = "";
            $url = $EnvVar['TYPO3_REQUEST_URL'];
            $url = preg_replace( '/logintype=(login|logout)/', '', $url );
            if( preg_match('/\?$/', $url ) ){
                $url = str_replace( '?', '', $url );
            }

            $sep = ( strpos( $url , '?' ) > 0 ) ? "&" : "?";
            if( $GLOBALS["TSFE"]->fe_user->user ){
                $url .= $sep . "logintype=logout";
                $authText = LocalizationUtility::translate( 'tx_igldapssoauth_pi1.label.logout', 'ig_ldap_sso_auth', NULL);
            } else {
                $url .= $sep . "logintype=login";
                $authText = LocalizationUtility::translate( 'tx_igldapssoauth_pi1.label.login', 'ig_ldap_sso_auth', NULL);
            }

            if ( $this->userAspect->isLoggedIn()) {
              $userData = $this->userService->getFeUserData();
            } else {
              $userData = null;
            }

            $this->view->assign( 'user', $userData );
            $this->view->assign( 'authText', $authText );
            $this->view->assign( 'url', $url );
        }
        return $this->view->render();
    }

}
