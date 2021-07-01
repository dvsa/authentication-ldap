<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\AbstractResourceOwner;

/**
 * A Resource owner object, containing helper methods for non-custom attributes.
 *
 * @see https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.5
 */
class LdapUser extends AbstractResourceOwner
{
    public function __construct(array $attributes = [])
    {
        if (isset($attributes['dn'])) {
            throw new \RuntimeException('The resource owner must have a `dn` attribute.');
        }

        parent::__construct($attributes);
    }

    public function getId(): string
    {
        return $this->get('dn');
    }
}
