<?php

namespace Causal\IgLdapSsoAuth\Utility;

use Okta\JwtVerifier\Adaptors\Adaptor;
use Okta\JwtVerifier\Discovery\DiscoveryMethod;
use Okta\JwtVerifier\Request;

class JwtVerifier extends \Okta\JwtVerifier\JwtVerifier
{
  public function __construct(
    string          $issuer,
    DiscoveryMethod $discovery = null,
    Adaptor         $adaptor = null,
    Request         $request = null,
    int             $leeway = 120,
    array           $claimsToValidate = []
  )
  {
    parent::__construct($issuer, $discovery, $adaptor, $request, $leeway, $claimsToValidate);

    $this->jwksUri = "$issuer/discovery/keys";
  }

  public function verify($jwt)
  {
    $keys = $this->getKeys();

    $decoded = $this->adaptor->decode($jwt, $keys);

    // This is hard coded to access token since this was the original functionality.
    $this->validateClaims($decoded->getClaims(), "access");

    return $decoded;
  }

  private function validateClaims(array $claims, string $type)
  {
    switch ($type) {
      case 'id':
        $this->validateAudience($claims);
        $this->validateNonce($claims);
        break;
      case 'access':
        $this->validateAudience($claims);
        $this->validateClientId($claims);
        break;
    }
  }

  private function validateNonce($claims)
  {
    if (!isset($claims['nonce']) && $this->claimsToValidate['nonce'] == null) {
      return false;
    }

    if ($claims['nonce'] != $this->claimsToValidate['nonce']) {
      throw new \Exception('Nonce does not match what is expected. Make sure to provide the nonce with
              `setNonce()` from the JwtVerifierBuilder.');
    }
  }

  private function validateAudience($claims)
  {
    if (!isset($claims['aud']) && $this->claimsToValidate['audience'] == null) {
      return false;
    }

    if ($claims['aud'] != $this->claimsToValidate['audience']) {
      throw new \Exception('Audience does not match what is expected. Make sure to provide the audience with
              `setAudience()` from the JwtVerifierBuilder.');
    }
  }

  private function validateClientId($claims)
  {
    if (!isset($claims['appid']) && $this->claimsToValidate['clientId'] == null) {
      return false;
    }

    if ($claims['appid'] != $this->claimsToValidate['clientId']) {
      throw new \Exception('ClientId does not match what is expected. Make sure to provide the client id with
              `setClientId()` from the JwtVerifierBuilder.');
    }
  }
}
