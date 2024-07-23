<?php

namespace Dvsa\Authentication\Ldap\Tests;

use Dvsa\Authentication\Ldap\Client;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Ldap\Adapter\CollectionInterface;
use Symfony\Component\Ldap\Adapter\EntryManagerInterface;
use Symfony\Component\Ldap\Adapter\ExtLdap\EntryManager;
use Symfony\Component\Ldap\Adapter\ExtLdap\UpdateOperation;
use Symfony\Component\Ldap\Adapter\QueryInterface;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\LdapInterface;
use Traversable;

class FormatAttributesTest extends TestCase
{
    protected MockObject|EntryManagerInterface $mockEntryManager;

    protected Client $client;

    protected function setUp(): void
    {
        $this->mockEntryManager = $this->createMock(EntryManager::class);
        $this->mockEntryManager->method('applyOperations')->willReturnSelf();

        $mockLdap = $this->createMock(LdapInterface::class);
        $mockLdap->method('getEntryManager')->willReturn($this->mockEntryManager);

        $collectionClass = new class implements CollectionInterface {
            public array $entries = [];

            public function toArray(): array
            {
                return $this->entries;
            }

            public function offsetExists($offset): bool
            {
                return isset($this->entries[$offset]);
            }

            public function getIterator(): Traversable
            {
                return new \ArrayIterator($this->entries);
            }

            public function offsetGet(mixed $offset): mixed
            {
                return $this->entries[$offset];
            }

            public function offsetSet(mixed $offset, mixed $value): void
            {
                $this->entries[$offset] = $value;
            }

            public function offsetUnset(mixed $offset): void
            {
                unset($this->entries[$offset]);
            }

            public function count(): int
            {
                return count($this->entries);
            }
        };

        $collection = new $collectionClass();
        $collection[0] = new Entry('cn=PHPUnit,dc=local', []);

        $mockQuery = $this->createMock(QueryInterface::class);
        $mockQuery->method('execute')->willReturn($collection);

        $mockLdap->method('query')->willReturn($mockQuery);

        $this->client = new Client($mockLdap, 'RDN', 'BASE_DN', ['OBJECT_CLASS'], 'SECRET');
    }

    public function testUserAccountControlAttributeNotAddedWhenRegistering(): void
    {
        $this->client->setUserAccountControlAttribute(null);

        $this->mockEntryManager
            ->expects($this->atLeastOnce())
            ->method('add')
            ->with(
                $this->callback(function ($entry) {
                    return !$entry->hasAttribute('userAccountControl');
                })
            );

        $this->client->register('IDENTIFIER', 'PASSWORD', []);
    }

    #[DataProvider('providesAttributesAndResultingOperations')]
    public function testAttributesAreFormattedCorrectly(array $before, array $after, array $map = []): void
    {
        $this->client::$attributeMap = $map;

        $this->mockEntryManager
            ->method('applyOperations')
            ->willReturnCallback(function ($dn, $operations) use ($after) {
                $this->assertEquals($after, array_values($operations));
            });

        $this->client->changeAttributes('IDENTIFIER', $before);
    }

    public static function providesAttributesAndResultingOperations(): \Generator
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

        $date = new \DateTime();

        yield 'Ensure date attribute translated to string' => [
          ['ATTRIBUTE_1' => $date, ],
          [
              new UpdateOperation(LDAP_MODIFY_BATCH_REPLACE, 'ATTRIBUTE_1', [$date->format('YmdHis.v\Z')]),
          ],
        ];
    }
}
