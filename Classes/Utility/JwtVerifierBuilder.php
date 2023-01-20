<?php

namespace Causal\IgLdapSsoAuth\Utility;

class JwtVerifierBuilder extends \Okta\JwtVerifier\JwtVerifierBuilder
{
  /**
   * Build and return the JwtVerifier.
   *
   * @return JwtVerifier
   * @throws \InvalidArgumentException
   */
  public function build(): JwtVerifier
  {
    $this->validateIssuer($this->issuer);
    $this->validateClientId($this->clientId);

    return new JwtVerifier(
      $this->issuer,
      $this->discovery,
      $this->adaptor,
      $this->request,
      $this->leeway,
      [
        'nonce' => $this->nonce,
        'audience' => $this->audience,
        'clientId' => $this->clientId
      ]
    );
  }

  private function validateIssuer($issuer): void
  {
    if (null === $issuer || "" == $issuer) {
      $msg = "Your Issuer is missing. ";
      $msg .= "You can find your issuer from your authorization server settings in the Okta Developer Console. ";
      $msg .= "Find out more information aobut Authorization Servers at ";
      $msg .= "https://developer.okta.com/docs/guides/customize-authz-server/overview/";
      throw new \InvalidArgumentException($msg);
    }

    if (strstr($issuer, "https://") == false) {
      $msg = "Your Issuer must start with https. Current value: {$issuer}. ";
      $msg .= "You can copy your issuer from your authorization server settings in the Okta Developer Console. ";
      $msg .= "Find out more information aobut Authorization Servers at ";
      $msg .= "https://developer.okta.com/docs/guides/customize-authz-server/overview/";
      throw new \InvalidArgumentException($msg);
    }

    if (strstr($issuer, "{yourOktaDomain}") != false) {
      $msg = "Replace {yourOktaDomain} with your Okta domain. ";
      $msg .= "You can copy your domain from the Okta Developer Console. Follow these instructions to find it: ";
      $msg .= "https://bit.ly/finding-okta-domain";
      throw new \InvalidArgumentException($msg);
    }
  }

  /**
   * Validate the client id
   *
   * @param string $cid
   * @return void
   * @throws \InvalidArgumentException
   */
  private function validateClientId($cid): void
  {
    if (null === $cid || "" == $cid) {
      $msg = "Your client ID is missing. You can copy it from the Okta Developer Console in the details for the ";
      $msg .= "Application you created. Follow these instructions to find it: ";
      $msg .= "https://bit.ly/finding-okta-app-credentials";
      throw new \InvalidArgumentException($msg);
    }

    if (strstr($cid, "{clientId}") != false) {
      $msg = "Replace {clientId} with the client ID of your Application. You can copy it from the Okta Developer";
      $msg .= "Console in the details for the Application you created. Follow these instructions to find it: ";
      $msg .= "https://bit.ly/finding-okta-app-credentials";
      throw new \InvalidArgumentException($msg);
    }
  }

}
