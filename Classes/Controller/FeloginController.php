<?php
namespace Causal\IgLdapSsoAuth\Controller;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use TYPO3\CMS\Extbase\Utility\LocalizationUtility;
use Causal\IgLdapSsoAuth\Library\Configuration;
use TYPO3\CMS\FrontendLogin\Service\UserService;
use Causal\IgLdapSsoAuth\Utility\ADFSUtility;

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

    public function indexAction() {
        if( !empty($_REQUEST['logintype']) ) {
            if( $_REQUEST['logintype'] == "login" ) {
              $this->connexion();
            } elseif( $_REQUEST['logintype'] == "logout" ) {
              $this->deconnexion();
            }
        }

        //$url = Configuration::getValue('ADFSLoginUrl');
      $getEnvName = '_ARRAY';
      $EnvVar = GeneralUtility::getIndpEnv( $getEnvName );
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

    public function connexionAction(): ResponseInterface {
session_start();

      // Check given state against previously stored one to mitigate CSRF attack
      if (!empty($_GET['code']) && !empty($_GET['state']) &&
        (isset($_SESSION['oauth2state']) && $_GET['state'] == $_SESSION['oauth2state'])) {
        if (ADFSUtility::Instance()->saveAccessTokenFromCode($_GET['code'])) {
          ADFSUtility::Instance()->redirectToRequestedUrl();
        }
      }
      if( ADFSUtility::Instance()->isAuthenticated() ) {
        error_log( "authentifié, redirection?");
        //self::redirect("/");
      } else {
        error_log( "pas authentifié exit");
exit;
        ADFSUtility::Instance()->forceAuth();
      }


      return $this->htmlResponse();
    }

    protected function deconnexion() {
      if( ADFSUtility::instance()->isAuthenticated() ) {

        // Affichage de la page par défaut
        ADFSUtility::instance()->logout();
      }
    }

    public function indexAction1(){
error_log( "indexAction");
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
        $adfsAuthentification = Configuration::getValue('ADFSAuthentication');
error_log( "ADFS authentification" );
error_log($adfsAuthentification  );
        if( $adfsAuthentification ) {
            error_log( "ADFS Authentification");
            $getEnvName = '_ARRAY';
            $EnvVar = GeneralUtility::getIndpEnv( $getEnvName );

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
              return 0;
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
        } elseif( $casAuthentification ){
            error_log( "CAS Authentification");
            $getEnvName = '_ARRAY';
            $EnvVar = GeneralUtility::getIndpEnv( $getEnvName );

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
              return 0;
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
