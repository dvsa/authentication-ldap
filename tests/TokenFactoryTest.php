<?php

namespace Dvsa\Authentication\Ldap\Tests;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
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

        $_SERVER['SERVER_NAME'] = 'PHPUnit';
    }

    public function testTokenHasStandardClaimsAdded(): void
    {
        // Always return a consistent date object.
        $now = Carbon::now();
        CarbonImmutable::setTestNow($now);

        $factory = new TokenFactory('SECRET_1');

        $token = $factory->make('SUB', ['CLAIM_1' => 'VALUE_1']);

        $claims = $factory->validate($token);

        $this->assertEquals('SUB', $claims['sub']);
        $this->assertEquals('PHPUnit', $claims['aud']);

        $this->assertEquals($now->timestamp, $claims['iat']);
        $this->assertEquals($now->timestamp, $claims['nbf']);
        $this->assertEquals($now->timestamp + $factory->getExpiresIn(), $claims['exp']);

        // Clear the mocked date.
        Carbon::setTestNow();
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
