<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\AccessTokenInterface;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use Dvsa\Contracts\Auth\OAuthClientInterface;
use Dvsa\Contracts\Auth\ResourceOwnerInterface;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Exception\ExceptionInterface;
use Symfony\Component\Ldap\Exception\LdapException;
use Symfony\Component\Ldap\LdapInterface;

class Client implements OAuthClientInterface
{
    /**
     * When checking nbf, iat or expiration times on tokens, we want to provide
     * some extra leeway time to account for clock skew.
     *
     * @var int
     */
    public static $leeway = 0;

    /**
     * @var int
     */
    public static $tokenExpiry = 3600;

    /**
     * @var int
     */
    public static $refreshTokenExpiry = 86400;

    /**
     * @var LdapInterface
     */
    protected $ldap;

    /**
     * @var string
     */
    protected $baseDn;

    /**
     * @var TokenFactory
     */
    protected $tokenFactory;

    /**
     * Ldap Client constructor.
     *
     * @param  LdapInterface  $ldap
     * @param  string         $baseDn
     * @param  string         $secret           secret key to sign the JWT
     */
    public function __construct(LdapInterface $ldap, string $baseDn, string $secret)
    {
        $this->ldap = $ldap;
        $this->baseDn = $baseDn;
    }

    public function authenticate(string $identifier, string $password): AccessTokenInterface
    {
        $dn = $this->buildDn($identifier);

        try {
            // Try the bind with the username/password combination.
            $this->bind($dn, $password);
        } catch (ConnectionException $e) {
            throw new ClientException($e->getMessage(), $e->getCode(), $e);
        }

        $user = $this->getUserByIdentifier($identifier);

        return $this->generateToken($user);
    }

    public function register(string $identifier, string $password, array $attributes = []): ResourceOwnerInterface
    {
        $dn = $this->buildDn($identifier);

        $entry = new Entry($dn, [
            'objectClass' => ['inetOrgPerson'],
            'userPassword' => [$this->generatePassword($password)],
            'sn' => [$identifier],
        ]);

        $entryManager = $this->ldap->getEntryManager();

        try {
            $entryManager->add($entry);
        } catch (LdapException $e) {
            throw new ClientException($e->getMessage(), $e->getCode(), $e);
        }

        return new LdapUser($entry->getAttributes());
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
        $dn = $this->buildDn($identifier);

        // At this point, the bind was successful.
        // Query the directory for the user details to build the OIDC tokens.
        $query = $this->ldap->query($dn, '(objectClass=inetOrgPerson)');
        $entry = $query->execute();

        if (empty($entry)) {
            throw new ClientException('User not found.');
        }

        $user = $entry[0];

        $attributes = [
            'dn' => $user->getDn(),
            'cn' => $user->getAttribute('cn'),
        ];

        return new LdapUser($attributes);
    }

    protected function bind(string $dn, string $password): void
    {
        $this->ldap->bind($dn, $password);
    }

    protected function buildDn(string $identifier): string
    {
        return sprintf('cn=%s,%s', $identifier, $this->baseDn);
    }

    protected function generateToken(LdapUser $entry): AccessTokenInterface
    {
        $options = [];

        $options['access_token'] = $this->getTokenFactory()->make(['username' => $entry->getDn()]);
        $options['id_token'] = $this->getTokenFactory()->make($entry->getAttributes());
        $options['refresh_token'] = bin2hex(openssl_random_pseudo_bytes(8));
        $options['expires_in'] = self::$tokenExpiry;

        return new AccessToken($options);
    }

    protected function generatePassword(string $password): string
    {
        $salt = bin2hex(openssl_random_pseudo_bytes(8));

        return '{SSHA}' . base64_encode(sha1($password . $salt, true) . $salt);
    }

    public function setTokenFactory(TokenFactoryInterface $factory): self
    {
        $this->tokenFactory = $factory;

        return $this;
    }

    public function getTokenFactory(): TokenFactoryInterface
    {
        if (isset($this->tokenFactory)) {
            return $this->tokenFactory;
        }

        $this->tokenFactory = new TokenFactory($this->secret);

        return $this->tokenFactory;
    }
}
