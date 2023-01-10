<?php

namespace Causal\IgLdapSsoAuth\Grant;
use League\OAuth2\Client\Grant\AbstractGrant;

/**
 * Represents a backend auth client.
 *
 * @link http://tools.ietf.org/html/rfc6749#section-1.3.4 Client Credentials (RFC 6749, §1.3.4)
 */
class Grant_BackEndClient extends AbstractGrant {

    /**
     * @inheritdoc
     */
    protected function getName()
    {
        return 'client_credentials';
    }

    /**
     * @inheritdoc
     */
    protected function getRequiredRequestParameters()
    {
        return [
            'resource',
            'scope'
        ];
    }
}
