<?php

namespace Dvsa\Authentication\Ldap;

use Firebase\JWT\JWT;

class TokenFactory implements TokenFactoryInterface
{
    private $secret;

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    public function make(array $claims = []): string
    {
        return JWT::encode($claims, $this->secret, 'HS512');
    }
}
