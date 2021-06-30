<?php

namespace Dvsa\Authentication\Ldap;

use Dvsa\Contracts\Auth\Exceptions\InvalidTokenException;
use Firebase\JWT\JWT;

class TokenFactory extends AbstractTokenFactory implements TokenFactoryInterface
{
    /**
     * Secret key that will sign the provided JWT.
     *
     * @var string
     */
    protected $secret;

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    /**
     * @inheritDoc
     */
    public function make(string $sub, array $claims = []): string
    {
        $now = time();

        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
        $claims['sub'] = $sub;
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
        $claims['iss'] = $claims['aud'] = $_SERVER['SERVER_NAME'];
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
        $claims['exp'] = $now + $this->expiresIn;
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
        $claims['nbf'] = $now;
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
        $claims['iat'] = $now;
        // https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
        $claims['jti'] = bin2hex(openssl_random_pseudo_bytes(8));

        return JWT::encode($claims, $this->secret, 'HS512');
    }

    /**
     * @inheritDoc
     */
    public function validate(string $token): array
    {
        try {
            $claims = (array)JWT::decode($token, $this->secret, ['HS512']);
        } catch (\Exception $e) {
            throw new InvalidTokenException($e->getMessage(), (int) $e->getCode(), $e);
        }

        if ($claims['aud'] !== $_SERVER['SERVER_NAME']) {
            throw new InvalidTokenException('Invalid "aud" claim.');
        }

        return $claims;
    }
}
