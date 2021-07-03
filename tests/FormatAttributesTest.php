<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Dvsa\Authentication\Ldap\Client;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Ldap\Adapter\EntryManagerInterface;
use Symfony\Component\Ldap\Adapter\ExtLdap\EntryManager;
use Symfony\Component\Ldap\Adapter\ExtLdap\UpdateOperation;
use Symfony\Component\Ldap\Adapter\QueryInterface;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\LdapInterface;

class FormatAttributesTest extends TestCase
{
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
        $this->mockEntryManager = $this->createMock(EntryManager::class);

        $mockLdap = $this->createMock(LdapInterface::class);
        $mockLdap->method('getEntryManager')->willReturn($this->mockEntryManager);

        $mockQuery = $this->createMock(QueryInterface::class);
        $mockQuery->method('execute')->willReturn([
            new Entry('cn=PHPUnit,dc=local', [])
        ]);

        $mockLdap->method('query')->willReturn($mockQuery);

        $this->client = new Client($mockLdap, 'BASE_DN', ['OBJECT_CLASS'], 'SECRET');
    }

    /**
     * @dataProvider providesAttributesAndResultingOperations
     */
    public function testAttributesAreFormattedCorrectly(array $before, array $after, array $map = []): void
    {
        $this->client::$attributeMap = $map;

        $this->mockEntryManager
            ->method('applyOperations')
            ->will($this->returnCallback(function ($dn, $operations) use ($after) {
                $this->assertEquals($after, array_values($operations));
            }));

        $this->client->changeAttributes('IDENTIFIER', $before);
    }

    public function providesAttributesAndResultingOperations(): \Generator
    {
        yield 'Ensure attributes are translated to `UpdateOperation` objects' => [
            ['ATTRIBUTE_1' => 'VALUE_1', 'ATTRIBUTE_2' => 'VALUE_2'],
            [
                new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, 'ATTRIBUTE_1', ['VALUE_1']),
                new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, 'ATTRIBUTE_2', ['VALUE_2']),
            ],
        ];

        yield 'Ensure attribute removed if mapped to null' => [
            ['ATTRIBUTE_1' => 'VALUE_1', 'ATTRIBUTE_2' => 'VALUE_2', 'ATTRIBUTE_3' => 'VALUE_3'],
            [
                new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, 'ATTRIBUTE_1', ['VALUE_1']),
                new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, 'ATTRIBUTE_2', ['VALUE_2']),
            ],
            ['ATTRIBUTE_3' => null, ],
        ];

        yield 'Ensure attribute renamed if mapped to a different key' => [
            ['ATTRIBUTE_1' => 'VALUE_1', 'ATTRIBUTE_2' => 'VALUE_2', ],
            [
                new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, 'ATTRIBUTE_1', ['VALUE_1']),
                new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, 'RENAMED_ATTRIBUTE_2', ['VALUE_2']),
            ],
            ['ATTRIBUTE_2' => 'RENAMED_ATTRIBUTE_2', ],
        ];

        yield 'Ensure bool attribute translated to string' => [
            ['ATTRIBUTE_1' => false, 'ATTRIBUTE_2' => true, ],
            [
                new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, 'ATTRIBUTE_1', ['FALSE']),
                new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, 'ATTRIBUTE_2', ['TRUE']),
            ],
        ];
    }
}
