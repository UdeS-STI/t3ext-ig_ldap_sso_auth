<?php

namespace Causal\IgLdapSsoAuth\Utility;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use Okta\JwtVerifier\Adaptors\FirebasePhpJwt;
use Okta\JwtVerifier\Discovery\Oidc;
use TYPO3\CMS\Core\Site\SiteFinder;

/**
 * OAuth authentication
 *
 * This helper class is used to authentify users from a ADFS server
 *
 * We used the following library for getting the access token https://github.com/thephpleague/oauth2-client
 * We used the following library to validate the access token https://github.com/okta/okta-jwt-verifier-php
 *
 * @package Ko3stilib
 * @category ADFS
 */

class ADFSUtility
{

    # Configuration
    protected $config;

    protected $name;

    protected $jwtVerifier;

    protected $provider;

    protected $adaptor;

    private $permissions;

    # ADFS Auth instance
    private static $instances = array();

    /**
     * Singleton pattern
     *
     * @return self
     */
    public static function instance($name = 'default')
    {

        if (!array_key_exists($name, self::$instances)) {
            static::$instances[$name] = new self($name);
        }
        return static::$instances[$name];

    }

  public static function getRequestedSiteName() {
    $requestedUrlSegments = explode('/', $_SERVER['REQUEST_URI']);
    return $requestedUrlSegments[1];
  }

    /**
     * Get specific adfs config
     * @param $key string key of the config
     *
     * @return string config (or NULL if not present)
     */
    public function getConfig($key)
    {
        return isset($this->config[$key]) ? $this->config[$key] : null;
    }

    /**
     * Get specific adfs config
     *
     * @param $onBehalfOf string key of the "onBehalfOf" adfs config
     *
     * @return string config (or NULL if not present)
     */
    public function getAccessToken($onBehalfOf = null)
    {
        if ($this->isAuthenticated($onBehalfOf) ||
            ($onBehalfOf != null && $this->saveOnBehalfOfAccessToken($onBehalfOf))) {

            return $this->getSavedTokenSession($onBehalfOf)->getToken();
        }

        return null;
    }

    /**
     * Get authenticated username
     *
     * @return string username (or NULL if not authenticated)
     */
    public function getUsername()
    {
        return $this->getClaim("cip");
    }

    /**
     * Get specific claim from valid access token
     *
     * @param $claim string Key of the desired claim
     * @param $onBehalfOf string to get the "on behalf of" token
     *
     * @return string claim (or NULL if not present)
     */
    public function getClaim($claim, $onBehalfOf = null)
    {
        return isset($this->getClaims($onBehalfOf)[$claim]) ? $this->getClaims($onBehalfOf)[$claim] : null;
    }

    /**
     * Get all claims from valid access token
     *
     * @param $onBehalfOf string to get the "on behalf of" token
     *
     * @return array claims
     */
    public function getClaims($onBehalfOf = null)
    {

        $token = $this->getSavedTokenSession($onBehalfOf);
        if ($token != null) {
            $jwt = $this->decode($token);

            return $jwt->getClaims();
        }
        return null;
    }

    /**
     * Get permissions from valid access token
     *
     * @return array of permission where the key is the resource
     * and the value is an array of actions
     * Exemple:
     * ["resource"] => ["POST", "PUT"]
     */
    public function getPermissions()
    {
        // Calculate permissions the first access
        if (empty($this->permissions))
            $this->extractPermissions();

        return $this->permissions;
    }

    /**
     * @param $resource to look for
     * @param $action to look for
     * @return bool that indicates if user has permission or not
     */
    public function hasPermission($resource, $action)
    {
        if (empty($this->getPermissions()) ||
            empty($resource) ||
            empty($action)) {

            return false;
        }

        if (array_key_exists($resource, $this->getPermissions()) &&
            in_array(strtoupper($action), $this->getPermissions()[$resource])) {

            return true;
        }

        return false;
    }

    /**
     * Convert the clearances claim into permissions
     */
    private function extractPermissions()
    {
        $clearances = $this->getClaim("clearances");

        if (isset($clearances)) {
            // Convert each clearances into permission by calling parsePermission method.
            $parsedPermissions = array_map(array($this, "parsePermission"), $clearances);

            // Set the resource as the key in the permissions array.
            foreach ($parsedPermissions as $permission) {
                $this->permissions[$permission["resource"]] = $permission["actions"];
            }
        }
    }

    /**
     * Convert an item from clearances claim into a permission.
     *
     * @param $clearance to convert into permission
     * @return array of extracted permission in the following
     * form:
     * ["resource" => "resource1", "actions"  => ["POST", "PUT"]]
     */
    private function parsePermission($clearance)
    {
        // Split the clearance into the resource and actions.
        // Exemple of clearance input: "resource1 <POST PUT>"
        $splittedPermission = preg_split("/(<.+>)/",
            $clearance,
            -1,
            PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

        $resource = $splittedPermission[0];
        $actions = trim($splittedPermission[1], "<>");

        $permission = [
            "resource" => $resource,
            "actions" => explode(" ", strtoupper($actions))
        ];

        return $permission;
    }

    protected function decode($jwt)
    {
        $keys = $this->adaptor->getKeys($this->jwtVerifier->getMetaData()->jwks_uri);

        return $this->adaptor->decode($jwt, $keys);
    }

    /**
     * Loads Session and configuration options.
     *
     * @param $name string Name of the Auth config
     *
     */
    public function __construct($name = 'default')
    {
        # Save the config.samples in the object
        $this->name = $name;
        $pluginConfig = $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['ig_ldap_sso_auth'] ?? [];

        $siteName = self::getRequestedSiteName();
        $siteFinder = new SiteFinder();
        $siteNameWithoutTypo3Prefix = str_replace('typo3_', '', $siteName);
        $site = $siteFinder->getSiteByIdentifier($siteNameWithoutTypo3Prefix);
        $siteConfig = $site->getConfiguration();

        $clientId = $siteConfig['adfs']['clientId'];
        $clientSecret = $siteConfig['adfs']['clientSecret'];
        $issuer = $pluginConfig["ADFSIssuer"];

      $this->config = [
        'issuer' => $issuer,
        'clientId' => "service://$clientId",
        'ressourceId' => "service://$clientId",
        'clientSecret' => $clientSecret,
        'redirectUri' => $pluginConfig['ADFSRedirectUriPrefix'] . '/' . $siteName,
        'scope' => array(
          "allatclaims", "profile", "email", "user_impersonation"
        ),
        'onBehalfOf' => array(
          "ressource-key" => array(
            "ressourceId" => "ressourceId",
            "scope" => array("allatclaims", "profile", "email", "user_impersonation")
          ),
        )
      ];

        $this->adaptor = new FirebasePhpJwt;

        $this->jwtVerifier = (new JwtVerifierBuilder())
            ->setDiscovery(new Oidc)
            ->setAdaptor($this->adaptor)
            ->setAudience($this->config['ressourceId'])
            ->setClientId($this->config['clientId'])
            ->setIssuer($this->config['issuer'])
            ->build();

        $this->provider = new GenericProvider([
            'clientId' => $this->config['clientId'],
            'clientSecret' => $this->config['clientSecret'],
            'redirectUri' => $this->config['redirectUri'],
            'urlAuthorize' => $this->config['issuer'] . "/oauth2/authorize/",
            'urlAccessToken' => $this->config['issuer'] . "/oauth2/token/",
            'urlResourceOwnerDetails' => $this->config['issuer'],
        ]);
    }

    /**
     * Redirect user to ADFS login page and prepare state for authorisation code grant flow
     *
     */
    public function login()
    {
        $this->invalidateSession();
        session_name(ADFSUtility::getRequestedSiteName());
        session_start();

        $_SESSION['url_requested'] = $_SERVER['REQUEST_URI'] ?? '/';

        // Fetch the authorization URL from the provider; this returns the
        // urlAuthorize option and generates and applies any necessary parameters
        // (e.g. state).
        $authorizationUrl = $this->provider->getAuthorizationUrl(
            [
                'scope' => implode(" ", $this->config['scope']),
                'resource' => $this->config['ressourceId']
            ]
        );

        // Get the state generated for you and store it to the session.
        $_SESSION['oauth2state'] = $this->provider->getState();

        // Redirect the user to the authorization URL.
        header('Location: ' . $authorizationUrl);
        exit;
    }

    /**
     * Get the access token from ADFS from authorisation code and save in a session variable
     *
     * @param $code string authorisation code to retrieve the access token
     *
     * @return bool true if access token retrieve
     */
    public function saveAccessTokenFromCode($code)
    {
        // Try to get an access token using the authorization code grant.
        $token = $this->provider->getAccessToken('authorization_code', [
            'code' => $code,
            'scope' => implode(" ", $this->config['scope']),
            'resource' => $this->config['ressourceId']
        ]);

        if ($this->validateAccessToken($token->getToken())) {
            $this->setAccessToken($token);
            return true;
        }

        return false;
    }

    /**
     * Get the access token from ADFS for another ressource (api) to act in the name of the end user
     * in another ressource (api)
     *
     * @param $onBehalfOf string key of the "onBehalfOf" adfs config
     *
     * @return bool true if access token retrieve
     */
    public function saveOnBehalfOfAccessToken($onBehalfOf)
    {
        //If the principal token is authentified
        if ($this->isAuthenticated()) {
            $token = $this->provider->getAccessToken(new Grant_OnBehalfOf(),
                [
                    'resource' => $this->config['onBehalfOf'][$onBehalfOf]['ressourceId'],
                    'requested_token_use' => 'on_behalf_of',
                    'scope' => implode(" ", $this->config['onBehalfOf'][$onBehalfOf]['scope']),
                    'assertion' => $this->getSavedTokenSession()->getToken(),
                ]);

            $this->setAccessToken($token, $onBehalfOf);
            return true;
        }


        return false;
    }

    /**
     * Get the access token saved in the session variable
     *
     * @param $onBehalfOf string key of the "onBehalfOf" adfs config
     *
     * @return AccessToken AccessToken Object
     */
    protected function getSavedTokenSession($onBehalfOf = null)
    {
        $token = null;
        $accessTokenKey = $this->name . '_accessToken';

        if (isset($this->config["onBehalfOf"][$onBehalfOf]) &&
            !empty($_SESSION[$accessTokenKey . '_' . $onBehalfOf])) {
            $token = $_SESSION[$accessTokenKey . '_' . $onBehalfOf];
        } else if ($onBehalfOf == null && !empty($_SESSION[$accessTokenKey])) {
            $token = $_SESSION[$accessTokenKey];
        }

        return $token;
    }

    /**
     * Save access token in the session variable
     *
     * @param $token AccessToken token to save in session variable
     * @param $onBehalfOf string key of the "onBehalfOf" adfs config
     */
    public function setAccessToken($token, $onBehalfOf = null)
    {

        $accessTokenKey = $this->name . '_accessToken';

        if ($onBehalfOf != null) {
            $accessTokenKey = $accessTokenKey . '_' . $onBehalfOf;
        }

        $_SESSION[$accessTokenKey] = $token;
    }

    /**
     * Force authentication on ADFS server with Authorization Code Grant flow
     *
     * @return string username
     */
    public function forceAuth()
    {
        if (!$this->isAuthenticated() || !$this->getUsername()) {
            $this->login();
        }

        return $this->getUsername();
    }

    /**
     * Invalidate session variable linked to the adfs config
     *
     * @param $onBehalfOf string key of the "onBehalfOf" adfs config
     */
    public function invalidateSession($onBehalfOf = null)
    {
        if ($onBehalfOf == null) {
            foreach ($this->config["onBehalfOf"] as $key => $value) {
                $this->setAccessToken(null, $key);
            }
        }

        $this->setAccessToken(null, $onBehalfOf);
        session_destroy();
        setcookie(session_name(), '', time() - 4200);
        setcookie('fe_typo_user', '', time() - 4200);
    }

    /**
     * Validate the access token with current ADFS config
     *
     * @param $token string access token
     *
     * @return bool true if the token is valid
     */
    public function validateAccessToken($token)
    {
        return isset($token) && !empty($token) &&
            $this->jwtVerifier->verify($token);
    }

    /**
     * Tells if user is authenticated
     *
     * Also if the access token is expired we try to refresh
     *
     * @param null $onBehalfOf
     * @return bool true if authenticated
     */
    public function isAuthenticated($onBehalfOf = null)
    {
        $existingAccessToken = $this->getSavedTokenSession($onBehalfOf);

        //Expired saved token must refresh
        if (isset($existingAccessToken) &&
            $existingAccessToken->hasExpired()) {
            return $this->refreshAccessToken($onBehalfOf);
        } //Invalid saved token must login
        else if (!isset($existingAccessToken) ||
            ($onBehalfOf == null && !$this->validateAccessToken($existingAccessToken->getToken()))) {
            return false;
        }

        return true;
    }

    /**
     * Refresh the access token
     *
     * @param $onBehalfOf string key of the "onBehalfOf" adfs config
     *
     * @return bool true if succeed
     */
    public function refreshAccessToken($onBehalfOf = null)
    {
        $existingAccessToken = $this->getSavedTokenSession($onBehalfOf);

        try {
            $newAccessToken = $this->provider->getAccessToken('refresh_token', [
                'refresh_token' => $existingAccessToken->getRefreshToken()
            ]);

            if ($onBehalfOf == null && !$this->validateAccessToken($newAccessToken->getToken())) {
                $this->invalidateSession($onBehalfOf);
                return false;
            }

            $newAccessToken = new AccessToken(
                array_merge(
                    $existingAccessToken->jsonSerialize(),
                    $newAccessToken->jsonSerialize()));

            $this->setAccessToken($newAccessToken, $onBehalfOf);
            return true;
        } catch (IdentityProviderException $e) {
            $this->invalidateSession($onBehalfOf);
            return false;
        }
    }

    /**
     * Redirect the user to the original requested url.
     */
    public function redirectToRequestedUrl()
    {
        if (isset($_SESSION['url_requested'])) {
            $urlRequested = $_SESSION['url_requested'];
            header('Location: ' . $urlRequested);
        }
    }

    /**
     * Logout user by clearing session and redirecting to
     *
     * @param $returnUrl string URL to redirect to after logout from ADFS server (must be trusted by ADFS)
     *
     * @return void
     */
    public function logout($returnUrl = null)
    {
        $idTokenHint = '';

        if ($returnUrl != null &&
            $this->getSavedTokenSession() != null &&
            isset($this->getSavedTokenSession()->getValues()["id_token"])) {
            $idTokenHint = "?id_token_hint=" . $this->getSavedTokenSession()->getValues()["id_token"] .
                "&post_logout_redirect_uri=" . $returnUrl;
        }

        $this->invalidateSession();

        header('Location: ' .
            $this->jwtVerifier->getMetaData()->end_session_endpoint .
            $idTokenHint);
        exit;
    }

    /**
     * Get an authorization code from adfs to a backend
     * that wants to manipulate information
     * @return string token from adfs
     */
    public function getBackEndToken() {
        return $this->provider->getAccessToken(new Grant_BackEndClient(),
            [
                'resource' => $this->config['ressourceId'],
                'scope' => implode(" ", $this->config['scope']),
            ]);
    }
}
