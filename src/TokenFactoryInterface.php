<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\Exceptions\InvalidTokenException;

interface TokenFactoryInterface
{
    /**
     * Creates a signed JWT with the provided claims.
     */
    public function make(string $sub, array $claims): string;

    /**
     * Checks a token provided by this factory is valid.
     *
     * @throws InvalidTokenException when the token provided is invalid.
     *
     * @return array of the claims in the token.
     */
    public function validate(string $token): array;
}
