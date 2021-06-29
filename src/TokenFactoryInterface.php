<?php

namespace Dvsa\Authentication\Ldap;

interface TokenFactoryInterface
{
    public function make(array $claims): string;
}
