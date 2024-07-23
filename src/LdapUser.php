<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\AbstractResourceOwner;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use Illuminate\Support\Arr;

/**
 * A Resource owner object, containing helper methods for non-custom attributes.
 *
 * @see https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.5
 */
class LdapUser extends AbstractResourceOwner
{
    /**
     * @throws ClientException
     */
    public function getId(): string
    {
        $cn = $this->get('cn');

        if (is_array($cn)) {
            $cn = Arr::first($cn);
        }

        if (!is_string($cn)) {
            throw new ClientException('The "cn" claim is not an array or string.');
        }

        return $cn;
    }
}
