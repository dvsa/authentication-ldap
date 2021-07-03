<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\AccessTokenInterface;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use Dvsa\Contracts\Auth\OAuthClientInterface;
use Dvsa\Contracts\Auth\ResourceOwnerInterface;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Symfony\Component\Ldap\Adapter\ExtLdap\EntryManager;
use Symfony\Component\Ldap\Adapter\ExtLdap\UpdateOperation;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\ExceptionInterface;
use Symfony\Component\Ldap\Exception\LdapException;
use Symfony\Component\Ldap\LdapInterface;

class Client implements OAuthClientInterface
{
    /**
     * Alternative to using custom object classes in LDAP.
     * Will translate attributes passed to this object's methods ($attributes).
     *
     * ['attribute_key_1' => 'ldap_mapped_attribute', ...]
     *
     * @var array
     */
    public static $attributeMap = [];

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
     * @var array
     */
    protected $objectClass;

    /**
     * Ldap Client constructor.
     *
     * @param  LdapInterface $ldap
     * @param  string $baseDn
     * @param  array  $objectClass  without extension of the `register` method, the object classes provided must
     *                              have the attributes: `userPassword` & `userAccountControl`
     * @param  string $secret key to sign the JWT
     */
    public function __construct(LdapInterface $ldap, string $baseDn, array $objectClass, string $secret)
    {
        $this->ldap = $ldap;
        $this->baseDn = $baseDn;
        $this->objectClass = $objectClass;
        $this->secret = $secret;
    }

    /**
     * @inheritDoc
     */
    public function authenticate(string $identifier, string $password): AccessTokenInterface
    {
        $dn = $this->buildDn($identifier);

        try {
            $this->bind($dn, $password);
        } catch (ExceptionInterface $e) {
            throw new ClientException($e->getMessage(), (int) $e->getCode(), $e);
        }

        $user = $this->getUserByIdentifier($identifier);

        $this->throwIfAccountDisabled($user);

        return $this->generateToken($user);
    }

    /**
     * @throws ClientException
     */
    protected function throwIfAccountDisabled(ResourceOwnerInterface $user): void
    {
        if (Arr::first($user['userAccountControl']) === '2') {
            throw new ClientException('Account disabled.');
        }
    }

    /**
     * @inheritDoc
     */
    public function register(string $identifier, string $password, array $attributes = []): ResourceOwnerInterface
    {
        $dn = $this->buildDn($identifier);

        $formattedAttributes = $this->formatAttributes($attributes);

        $ldapAttributes = array_merge([
            'objectClass' => $this->objectClass,
            'userPassword' => [$this->generatePassword($password)],
            'userAccountControl' => [0],
        ], $formattedAttributes);

        $entry = new Entry($dn, $ldapAttributes);

        /**
         * @var EntryManager $entryManager
         */
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
        return $this->changeAttributes($identifier, ['userPassword' => $this->generatePassword($newPassword)]);
    }

    /**
     * @inheritDoc
     */
    public function changeAttribute(string $identifier, string $key, string $value): bool
    {
        return $this->changeAttributes($identifier, [$key => $value]);
    }

    /**
     * @inheritDoc
     */
    public function changeAttributes(string $identifier, array $attributes): bool
    {
        $formattedAttributes = $this->formatAttributes($attributes);

        $operations = [];

        foreach ($formattedAttributes as $key => $value) {
            $operations[$key] = new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, $key, Arr::wrap($value));
        }

        try {
            /**
             * @var EntryManager $entryManager
             */
            $entryManager = $this->ldap->getEntryManager();

            $dn = $this->buildDn($identifier);

            $entry = $this->getLdapEntry($dn);

            $entryManager->applyOperations($entry->getDn(), $operations);
        } catch (ExceptionInterface $e) {
            throw new ClientException($e->getMessage(), (int) $e->getCode(), $e);
        }

        return true;
    }

    /**
     * @inheritDoc
     */
    public function enableUser(string $identifier): bool
    {
        $this->changeAttribute($identifier, 'userAccountControl', '0');

        return true;
    }

    /**
     * @inheritDoc
     */
    public function disableUser(string $identifier): bool
    {
        $this->changeAttribute($identifier, 'userAccountControl', '2');

        return true;
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

        $user = $this->getLdapEntry($dn);

        $attributes = array_merge([
            'dn' => $user->getDn(),
        ], $user->getAttributes());

        return new LdapUser($attributes);
    }

    protected function getLdapEntry(string $dn): Entry
    {
        try {
            $query = $this->ldap->query($dn, '(objectClass=*)');
            $entry = $query->execute();

            return $entry[0];
        } catch (LdapException $e) {
            throw new ClientException($e->getMessage(), (int) $e->getCode(), $e);
        }
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
            if (isset(self::$attributeMap[$key])) {
                $formatted[self::$attributeMap[$key]] = $this->formatAttributeValue($value);

                continue;
            }

            // If the key exists but is null, ignore it.
            if (array_key_exists($key, self::$attributeMap)) {
                continue;
            }

            $formatted[$key] = $this->formatAttributeValue($value);
        }

        return $formatted;
    }

    /**
     * @param mixed $value
     *
     * @return array
     */
    protected function formatAttributeValue($value): array
    {
        // https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.3
        if (is_bool($value)) {
            $value = ($value ? 'TRUE' : 'FALSE');
        }

        return Arr::wrap($value);
    }
}
