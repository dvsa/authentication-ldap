<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\AccessTokenInterface;
use Dvsa\Contracts\Auth\OAuthClientInterface;
use Dvsa\Contracts\Auth\ResourceOwnerInterface;

class Client implements OAuthClientInterface
{
    public function authenticate(string $identifier, string $password): AccessTokenInterface
    {
        // TODO: Implement authenticate() method.
    }

    public function register(string $identifier, string $password, array $attributes = []): ResourceOwnerInterface
    {
        // TODO: Implement register() method.
    }

    public function changePassword(string $identifier, string $newPassword): bool
    {
        // TODO: Implement changePassword() method.
    }

    public function changeAttribute(string $identifier, string $key, string $value): bool
    {
        // TODO: Implement changeAttribute() method.
    }

    public function changeAttributes(string $identifier, array $attributes): bool
    {
        // TODO: Implement changeAttributes() method.
    }

    public function enableUser(string $identifier): bool
    {
        // TODO: Implement enableUser() method.
    }

    public function disableUser(string $identifier): bool
    {
        // TODO: Implement disableUser() method.
    }

    public function getResourceOwner(AccessTokenInterface $token): ResourceOwnerInterface
    {
        // TODO: Implement getResourceOwner() method.
    }

    public function decodeToken(string $token): array
    {
        // TODO: Implement decodeToken() method.
    }

    public function refreshTokens(string $refreshToken, string $identifier): AccessTokenInterface
    {
        // TODO: Implement refreshTokens() method.
    }

    public function getUserByIdentifier(string $identifier): ResourceOwnerInterface
    {
        // TODO: Implement getUserByIdentifier() method.
    }
}
