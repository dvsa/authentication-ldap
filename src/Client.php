<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\AccessTokenInterface;
use Dvsa\Contracts\Auth\CreatesResourceOwners;
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
    use CreatesResourceOwners;

    const ACCOUNT_ENABLED = 0x0200;
    const ACCOUNT_DISABLED = 0x0002;

    /**
     * Alternative to using custom object classes in LDAP.
     * Will translate attributes passed to this object's methods ($attributes).
     *
     * ['attribute_key_1' => 'ldap_mapped_attribute', ...]
     *
     * @var array<string, string>
     */
    public static array $attributeMap = [];

    protected ?TokenFactoryInterface $tokenFactory = null;

    /**
     * The field that controls user account status (enabled/disabled).
     *
     * Set to `null` to disable account control. This will disable the `enableUser`/`disableUser` methods.
     */
    protected ?string $userAccountControlAttribute = 'userAccountControl';

    /**
     *
     * @param  LdapInterface $ldap
     * @param  string $rdn          the relative distinguished name.
     * @param  string $baseDn
     * @param  string[] $objectClass  without extension of the `register` method, the object classes provided must
     *                              have the attributes: `userPassword` & `userAccountControl`
     * @param  string $secret key to sign the JWT
     */
    public function __construct(
        protected LdapInterface $ldap,
        protected string $rdn,
        protected string $baseDn,
        protected array $objectClass,
        protected string $secret
    ) {
        $this->resourceOwnerClass = LdapUser::class;
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
            throw new ClientException($e->getMessage(), $e->getCode(), $e);
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
        if (Arr::first((array) $user['userAccountControl']) === (string) self::ACCOUNT_DISABLED) {
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

        $defaultAttributes = [
            'objectClass' => $this->objectClass,
            'userPassword' => [$this->generatePassword($password)],
        ];

        if ($this->userAccountControlAttribute !== null) {
            $defaultAttributes[$this->userAccountControlAttribute] = [0];
        }

        $ldapAttributes = array_merge($defaultAttributes, $formattedAttributes);

        $entry = new Entry($dn, $ldapAttributes);

        /**
         * @var EntryManager $entryManager
         */
        $entryManager = $this->ldap->getEntryManager();

        try {
            $entryManager->add($entry);
        } catch (ExceptionInterface $e) {
            throw new ClientException($e->getMessage(), $e->getCode(), $e);
        }

        return $this->createResourceOwner($entry->getAttributes());
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
            $operations[] = new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, $key, Arr::wrap($value));
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
            throw new ClientException($e->getMessage(), $e->getCode(), $e);
        }

        return true;
    }

    /**
     * @inheritDoc
     */
    public function enableUser(string $identifier): bool
    {
        if ($this->userAccountControlAttribute === null) {
            throw new ClientException('This method is not available while `$this->userAccountControlAttribute` is null.');
        }

        $this->changeAttribute($identifier, 'userAccountControl', (string) self::ACCOUNT_ENABLED);

        return true;
    }

    /**
     * @inheritDoc
     */
    public function disableUser(string $identifier): bool
    {
        if ($this->userAccountControlAttribute === null) {
            throw new ClientException('This method is not available while `$this->userAccountControlAttribute` is null.');
        }

        $this->changeAttribute($identifier, 'userAccountControl', (string) self::ACCOUNT_DISABLED);

        return true;
    }

    /**
     * @inheritDoc
     */
    public function getResourceOwner(AccessTokenInterface $token): ResourceOwnerInterface
    {
        // If the ID token is not null, use to build the resource owner.
        // Otherwise, use the claims from the access token.
        $idToken = $token->getIdToken();

        if ($idToken !== null) {
            $tokenClaims = $this->decodeToken($idToken);
        } else {
            $tokenClaims = $this->decodeToken($token->getToken());
        }

        return $this->createResourceOwner($tokenClaims);
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

        return $this->createResourceOwner($attributes);
    }

    protected function getLdapEntry(string $dn): Entry
    {
        try {
            $query = $this->ldap->query($dn, '(objectClass=*)');
            $entry = $query->execute();

            if (empty($entry[0])) {
                throw new ClientException('User not found.', 404);
            }

            return $entry[0];
        } catch (LdapException $e) {
            throw new ClientException($e->getMessage(), $e->getCode(), $e);
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

    public function setUserAccountControlAttribute(?string $attribute): self
    {
        $this->userAccountControlAttribute = $attribute;

        return $this;
    }

    public function getUserAccountControlAttribute(): ?string
    {
        return $this->userAccountControlAttribute;
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
            '%s=%s,%s',
            $this->rdn,
            $this->ldap->escape($identifier, '', \LDAP_ESCAPE_DN),
            $this->baseDn
        );
    }

    protected function generateToken(ResourceOwnerInterface $entry): AccessTokenInterface
    {
        $options = [];

        $tokenFactory = $this->getTokenFactory();

        $dn = $entry['dn'];
        $cn = $entry['cn'];

        if (empty($dn) || empty($cn)) {
            throw new ClientException('Resource owner must have a distinguished name (dn) and common name (cn).');
        }

        if (!is_array($cn)) {
            $cn = [$cn];
        }

        if (!is_string($dn)) {
            throw new ClientException('Resource owner must have a distinguished name (dn) as a string.');
        }

        $options['access_token'] = $tokenFactory->make($dn, ['username' => Arr::first($cn)]);
        $options['id_token'] = $tokenFactory->make($dn, $entry->toArray());
        $options['expires_in'] = $tokenFactory->getExpiresIn();

        return new AccessToken($options);
    }

    protected function generatePassword(string $password): string
    {
        $salt = Str::random(8);

        return '{SSHA}' . base64_encode(sha1($password . $salt, true) . $salt);
    }

    /**
     * @param array<string, mixed> $attributes
     *
     * @return array<string, array<mixed>>
     */
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
     * @return array<mixed>
     */
    protected function formatAttributeValue(mixed $value): array
    {
        // https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.3
        if (is_bool($value)) {
            $value = ($value ? 'TRUE' : 'FALSE');
        }

        // https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.13
        if ($value instanceof \DateTimeInterface) {
            $value = $value->format('YmdHis.v\Z');
        }

        return Arr::wrap($value);
    }
}
