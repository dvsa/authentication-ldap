<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\AccessTokenInterface;
use League\OAuth2\Client\Token\AccessToken as BaseAccessToken;

/**
 * An extension to the AccessToken class to include an OIDC ID token.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html
 *
 * @psalm-suppress PropertyNotSetInConstructor
 */
class AccessToken extends BaseAccessToken implements AccessTokenInterface
{
    protected ?string $idToken;

    /**
     * @inheritDoc
     *
     * @param array<string, mixed> $options
     */
    public function __construct(array $options = [])
    {
        parent::__construct($options);

        if (!empty($this->values['id_token'])) {
            $this->idToken = $this->values['id_token'];

            unset($this->values['id_token']);
        }
    }

    public function getIdToken(): ?string
    {
        return $this->idToken;
    }

    /**
     * @inheritdoc
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $parameters = parent::jsonSerialize();

        if ($this->idToken !== null) {
            $parameters['id_token'] = $this->idToken;
        }

        return $parameters;
    }
}
