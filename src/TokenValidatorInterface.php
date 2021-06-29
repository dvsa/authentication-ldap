<?php

use Dvsa\Contracts\Auth\AccessTokenInterface;

interface TokenValidatorInterface
{
    public function validate(AccessTokenInterface $accessToken): array;
}
