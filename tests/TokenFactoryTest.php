<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Dvsa\Authentication\Ldap\TokenFactory;
use Dvsa\Contracts\Auth\Exceptions\InvalidTokenException;
use PHPUnit\Framework\TestCase;

class TokenFactoryTest extends TestCase
{
    /**
     * @var TokenFactory
     */
    protected $tokenFactory;

    protected function setUp(): void
    {
        $this->tokenFactory = new TokenFactory('SECRET');

        $_SERVER['SERVER_NAME'] = $_SERVER['SERVER_NAME'] ?? 'PHPUnit';
    }

    public function testTokenCreatedByFactoryCanBeValidatedBySameFactory(): void
    {
        $claims = ['CLAIM_1' => 'VALUE_1'];

        $token = $this->tokenFactory->make('SUB', $claims);

        $actualClaims = $this->tokenFactory->validate($token);

        $this->assertArrayHasKey('CLAIM_1', $actualClaims);
    }

    public function testTokenNotCreatedByFactoryCannotBeValidatedBySameFactory(): void
    {
        $this->expectException(InvalidTokenException::class);

        $factory1 = new TokenFactory('SECRET_1');
        $factory2 = new TokenFactory('SECRET_2');

        $token = $factory1->make('SUB', ['CLAIM_1' => 'VALUE_1']);

        $factory2->validate($token);
    }
}
