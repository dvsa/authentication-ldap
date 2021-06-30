<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Dvsa\Authentication\Ldap\Client;
use Dvsa\Contracts\Auth\Exceptions\ClientException;
use PHPUnit\Framework\Constraint\IsAnything;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Ldap\Adapter\EntryManagerInterface;
use Symfony\Component\Ldap\Adapter\QueryInterface;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\Exception\LdapException;
use Symfony\Component\Ldap\LdapInterface;

class ContractExceptionsAreThrownInsteadTest extends TestCase
{
    /**
     * @var MockObject|LdapInterface
     */
    protected $mockLdap;

    /**
     * @var MockObject|EntryManagerInterface
     */
    protected $mockEntryManager;

    /**
     * @var Client
     */
    protected $client;

    protected function setUp(): void
    {
        $this->mockEntryManager = $this->createMock(EntryManagerInterface::class);

        $this->mockLdap = $this->createMock(LdapInterface::class);

        $this->mockLdap->method('getEntryManager')->willReturn($this->mockEntryManager);

        $this->client = new Client($this->mockLdap, 'BASE_DN', 'SECRET');
    }

    /**
     * @dataProvider provideAllClientInterfaceMethods
     */
    public function testMethodsWillThrowContractedException(string $method, array $args = []): void
    {
        $this->mockLdap->method('bind')->willThrowException(new ConnectionException);
        $this->mockEntryManager->method(new IsAnything)->willThrowException(new LdapException);

        $this->expectException(ClientException::class);

        $this->client->{$method}(...$args);
    }

    public function provideAllClientInterfaceMethods(): \Generator
    {
        yield ['authenticate', ['IDENTIFIER', 'PASSWORD']];
        yield ['register', ['IDENTIFIER', 'PASSWORD', []]];
        yield ['changePassword', ['IDENTIFIER', 'NEW_PASSWORD']];
        yield ['changeAttribute', ['IDENTIFIER', 'KEY', 'VALUE']];
        yield ['changeAttributes', ['IDENTIFIER', []]];
        yield ['enableUser', ['IDENTIFIER']];
        yield ['disableUser', ['IDENTIFIER']];
    }

    public function testGetUserWillThrowErrorWhenFindingNonExistentUser(): void
    {
        $queryMock = $this->createMock(QueryInterface::class);

        $this->mockLdap->method('query')->willReturn($queryMock);

        $this->expectException(ClientException::class);

        $this->client->getUserByIdentifier('IDENTIFIER');
    }
}
