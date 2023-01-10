<?php

namespace Causal\IgLdapSsoAuth\Grant;
use League\OAuth2\Client\Grant\AbstractGrant;

class Grant_OnBehalfOf extends AbstractGrant
{
    /**
     * @inheritdoc
     */
    protected function getName()
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }

    /**
     * @inheritdoc
     */
    protected function getRequiredRequestParameters()
    {
        return [
            'assertion',
            'resource',
            'requested_token_use',
            'scope'
        ];
    }
}
