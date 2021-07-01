<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\AccessTokenInterface;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use Dvsa\Contracts\Auth\OAuthClientInterface;
use Dvsa\Contracts\Auth\ResourceOwnerInterface;
use Illuminate\Support\Str;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ExceptionInterface;
use Symfony\Component\Ldap\LdapInterface;

class Client implements OAuthClientInterface
{
    /**
     * @var int
     */
    public static $tokenExpiry = 86400;

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
     * @var ?TokenFactoryInterface
     */
    protected $tokenFactory;

    /**
     * @var string
     */
    protected $secret;

    /**
     * Ldap Client constructor.
     *
     * @param  LdapInterface  $ldap
     * @param  string         $baseDn
     * @param  string         $secret key to sign the JWT
     */
    public function __construct(LdapInterface $ldap, string $baseDn, string $secret)
    {
        $this->ldap = $ldap;
        $this->baseDn = $baseDn;
        $this->secret = $secret;
    }

    /**
     * @inheritDoc
     */
    public function authenticate(string $identifier, string $password): AccessTokenInterface
    {
        $dn = $this->buildDn($identifier);

        try {
            // Try the bind with the username/password combination.
            $this->bind($dn, $password);
        } catch (ExceptionInterface $e) {
            throw new ClientException($e->getMessage(), (int) $e->getCode(), $e);
        }

        $user = $this->getUserByIdentifier($identifier);

        return $this->generateToken($user);
    }

    /**
     * @inheritDoc
     */
    public function register(string $identifier, string $password, array $attributes = []): ResourceOwnerInterface
    {
        $dn = $this->buildDn($identifier);

        $formattedAttributes = $this->formatAttributes($attributes);

        $ldapAttributes = array_merge([
            'objectClass' => ['inetOrgPerson'],
            'userPassword' => [$this->generatePassword($password)],
            'sn' => [$identifier],
        ], $formattedAttributes);

        $entry = new Entry($dn, $ldapAttributes);

        $entryManager = $this->ldap->getEntryManager();

        try {
            $entryManager->add($entry);
        } catch (ExceptionInterface $e) {
            throw new ClientException($e->getMessage(), (int) $e->getCode(), $e);
        }

        return new LdapUser($entry->getAttributes());
    }

    /**
     * @inheritDoc
     */
    public function changePassword(string $identifier, string $newPassword): bool
    {
        // TODO: Implement changePassword() method.
    }

    /**
     * @inheritDoc
     */
    public function changeAttribute(string $identifier, string $key, string $value): bool
    {
        // TODO: Implement changeAttribute() method.
    }

    /**
     * @inheritDoc
     */
    public function changeAttributes(string $identifier, array $attributes): bool
    {
        // TODO: Implement changeAttributes() method.
    }

    /**
     * @inheritDoc
     */
    public function enableUser(string $identifier): bool
    {
        // TODO: Implement enableUser() method.
    }

    /**
     * @inheritDoc
     */
    public function disableUser(string $identifier): bool
    {
        // TODO: Implement disableUser() method.
    }

    /**
     * @inheritDoc
     */
    public function getResourceOwner(AccessTokenInterface $token): ResourceOwnerInterface
    {
        // If the ID token is not null, use to build the resource owner.
        // Otherwise, use the claims from the access token.
        if ($idToken = $token->getIdToken()) {
            $tokenClaims = $this->decodeToken($idToken);
        } else {
            $tokenClaims = $this->decodeToken($token->getToken());
        }

        return $this->createResourceOwner($tokenClaims, $token);
    }

    protected function createResourceOwner(array $claims, AccessTokenInterface $token): ResourceOwnerInterface
    {
        return new LdapUser($claims);
    }

    /**
     * @inheritDoc
     */
    public function decodeToken(string $token): array
    {
        return $this->getTokenFactory()->validate($token);
    }

    /**
     * @inheritDoc
     */
    public function refreshTokens(string $refreshToken, string $identifier): AccessTokenInterface
    {
        throw new ClientException('Refreshing of tokens is not supported.');
    }

    /**
     * @inheritDoc
     */
    public function getUserByIdentifier(string $identifier): ResourceOwnerInterface
    {
        $dn = $this->buildDn($identifier);

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

        return ($this->tokenFactory = new TokenFactory($this->secret));
    }

    /**
     * @throws ExceptionInterface
     */
    protected function bind(string $dn, string $password): void
    {
        $this->ldap->bind($dn, $password);
    }

    protected function buildDn(string $identifier): string
    {
        return sprintf(
            'cn=%s,%s',
            $this->ldap->escape($identifier, '', \LDAP_ESCAPE_DN),
            $this->baseDn
        );
    }

    protected function generateToken(ResourceOwnerInterface $entry): AccessTokenInterface
    {
        $options = [];

        $tokenFactory = $this->getTokenFactory();

        $options['access_token'] = $tokenFactory->make($entry['dn'], ['username' => $entry['dn']]);
        $options['id_token'] = $tokenFactory->make($entry['dn'], $entry->toArray());
        $options['refresh_token'] = Str::random(32);
        $options['expires_in'] = $tokenFactory->getExpiresIn();

        return new AccessToken($options);
    }

    protected function generatePassword(string $password): string
    {
        $salt = Str::random(8);

        return '{SSHA}' . base64_encode(sha1($password . $salt, true) . $salt);
    }

    protected function formatAttributes(array $attributes): array
    {
        $formatted = [];

        foreach ($attributes as $key => $value) {
            $formatted["x-" . $key] = is_array($value) ? $value : [$value];
        }

        return $formatted;
    }
}
