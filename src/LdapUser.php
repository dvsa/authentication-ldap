<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\AbstractResourceOwner;
use Illuminate\Support\Arr;

/**
 * A Resource owner object, containing helper methods for non-custom attributes.
 *
 * @see https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.5
 */
class LdapUser extends AbstractResourceOwner
{
    public function getId(): string
    {
        return Arr::first($this->get('cn'));
    }
}
