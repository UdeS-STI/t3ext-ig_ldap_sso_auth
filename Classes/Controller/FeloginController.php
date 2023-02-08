<?php
namespace Causal\IgLdapSsoAuth\Controller;

use Causal\IgLdapSsoAuth\Utility\ADFSUtility;
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

    public function indexAction()
    {
      $configurationRepository = GeneralUtility::makeInstance('Causal\\IgLdapSsoAuth\\Domain\\Repository\\ConfigurationRepository');
      $configuration = $configurationRepository->findAll();
      if (count($configuration) == 1) {
        $configuration = $configuration[0];
      } else {
        //too many configuration DB object, WTF ?!
        exit;
      }

      Configuration::initialize(TYPO3_MODE, $configuration);

      $adfsAuthEnabled = Configuration::getValue('ADFSAuthentication');
      $casAuthEnabled = Configuration::getValue('CASAuthentication');

      if ($adfsAuthEnabled || $casAuthEnabled) {
        $getEnvName = '_ARRAY';
        $EnvVar = GeneralUtility::getIndpEnv($getEnvName);

        $hasAuthCodeOrState = !empty($_REQUEST['code']) || !empty($_REQUEST['state']);
        $isAuthenticated = ADFSUtility::Instance()->isAuthenticated();

        // Pour les sites multilingues, la session était perdue alors on doit la repartir si elle ne l'est pas déjà
        // pour se faire redirigé à l'URL souhaité
        if($hasAuthCodeOrState && session_status() !== PHP_SESSION_ACTIVE) {
          session_name(ADFSUtility::getRequestedSiteName());
          session_start();
        }

        $shouldRedirectToUrlRequestedADFS = $adfsAuthEnabled
          && $hasAuthCodeOrState
          && $isAuthenticated
          && isset($_SESSION['url_requested']);

        $shouldRedirectToUrlRequestedCAS = !empty($_REQUEST['ticket']) || !empty($_REQUEST['logintype']);

        // Remove the ticket from URL if present
        if ($shouldRedirectToUrlRequestedADFS) {
          $tempUrl = parse_url($_SESSION['url_requested']);
          parse_str($tempUrl['query'] ?? '', $items);

          unset($items['logintype']);
          unset($items['code']);
          unset($items['state']);

          $tempUrl['query'] = http_build_query($items);
          $url = $tempUrl['path'] . (!empty($tempUrl['query']) ? '?' . $tempUrl['query'] : '');
          $_SESSION['url_requested'] = $url;

          ADFSUtility::Instance()->redirectToRequestedUrl();
        } else if($shouldRedirectToUrlRequestedCAS){
          $url = $EnvVar['TYPO3_REQUEST_URL'];
          $tempUrl = parse_url($url);
          parse_str($tempUrl['query'], $items);

          unset($items['logintype']);
          unset($items['ticket']);

          $tempUrl['query']= http_build_query($items);
          $queryParameters = !empty($tempUrl['query']) ? '?'.$tempUrl['query'] : '';
          $url=$tempUrl['scheme'].'://'.$tempUrl['host'].$tempUrl['path'].$queryParameters;
          header("Location: ".$url);
          exit;
        }

        $authText = "";
        $url = $EnvVar['TYPO3_REQUEST_URL'];
        $url = preg_replace('/logintype=(login|logout)/', '', $url);
        if (preg_match('/\?$/', $url)) {
          $url = str_replace('?', '', $url);
        }

        $sep = (strpos($url, '?') > 0) ? "&" : "?";
        if ($GLOBALS["TSFE"]->fe_user->user) {
          $url .= $sep . "logintype=logout";
          $authText = LocalizationUtility::translate('tx_igldapssoauth_pi1.label.logout', 'ig_ldap_sso_auth', NULL);
        } else {
          $url .= $sep . "logintype=login";
          $authText = LocalizationUtility::translate('tx_igldapssoauth_pi1.label.login', 'ig_ldap_sso_auth', NULL);
        }

        if ($this->userAspect->isLoggedIn()) {
          $userData = $this->userService->getFeUserData();
        } else {
          $userData = null;
        }

        $this->view->assign('user', $userData);
        $this->view->assign('authText', $authText);
        $this->view->assign('url', $url);
      }
      return $this->view->render();
    }

}
