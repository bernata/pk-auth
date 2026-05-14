// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import java.util.Objects;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.GlobalSecondaryIndex;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.Projection;
import software.amazon.awssdk.services.dynamodb.model.ProjectionType;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import software.amazon.awssdk.services.dynamodb.model.TimeToLiveSpecification;
import software.amazon.awssdk.services.dynamodb.model.UpdateTimeToLiveRequest;

/**
 * Idempotently creates the pk-auth DynamoDB tables and their GSIs against the supplied {@link
 * DynamoDbClient}. Used by local dev and integration tests; production deployments should use IaC
 * (CloudFormation / Terraform / CDK) instead.
 */
public final class DynamoDbSchemaBootstrapper {

  private final DynamoDbClient client;
  private final PkAuthDynamoTables tables;

  public DynamoDbSchemaBootstrapper(DynamoDbClient client, PkAuthDynamoTables tables) {
    this.client = Objects.requireNonNull(client, "client");
    this.tables = Objects.requireNonNull(tables, "tables");
  }

  /** Creates both tables if missing; enables TTL on the core table for challenges. */
  public void bootstrap() {
    if (!tableExists(tables.core())) {
      createCoreTable();
      enableTtl(tables.core(), "ttl");
    }
    if (!tableExists(tables.users())) {
      createUsersTable();
    }
  }

  private boolean tableExists(String name) {
    try {
      client.describeTable(DescribeTableRequest.builder().tableName(name).build());
      return true;
    } catch (ResourceNotFoundException e) {
      return false;
    }
  }

  private void createCoreTable() {
    client.createTable(
        CreateTableRequest.builder()
            .tableName(tables.core())
            .billingMode(BillingMode.PAY_PER_REQUEST)
            .attributeDefinitions(
                AttributeDefinition.builder()
                    .attributeName("pk")
                    .attributeType(ScalarAttributeType.S)
                    .build(),
                AttributeDefinition.builder()
                    .attributeName("sk")
                    .attributeType(ScalarAttributeType.S)
                    .build(),
                AttributeDefinition.builder()
                    .attributeName("gsi1pk")
                    .attributeType(ScalarAttributeType.S)
                    .build(),
                AttributeDefinition.builder()
                    .attributeName("gsi1sk")
                    .attributeType(ScalarAttributeType.S)
                    .build())
            .keySchema(
                KeySchemaElement.builder().attributeName("pk").keyType(KeyType.HASH).build(),
                KeySchemaElement.builder().attributeName("sk").keyType(KeyType.RANGE).build())
            .globalSecondaryIndexes(
                GlobalSecondaryIndex.builder()
                    .indexName(PkAuthDynamoTables.GSI1_CREDENTIAL_BY_ID)
                    .keySchema(
                        KeySchemaElement.builder()
                            .attributeName("gsi1pk")
                            .keyType(KeyType.HASH)
                            .build(),
                        KeySchemaElement.builder()
                            .attributeName("gsi1sk")
                            .keyType(KeyType.RANGE)
                            .build())
                    .projection(Projection.builder().projectionType(ProjectionType.ALL).build())
                    .build())
            .build());
    waitForActive(tables.core());
  }

  private void createUsersTable() {
    client.createTable(
        CreateTableRequest.builder()
            .tableName(tables.users())
            .billingMode(BillingMode.PAY_PER_REQUEST)
            .attributeDefinitions(
                AttributeDefinition.builder()
                    .attributeName("pk")
                    .attributeType(ScalarAttributeType.S)
                    .build(),
                AttributeDefinition.builder()
                    .attributeName("sk")
                    .attributeType(ScalarAttributeType.S)
                    .build(),
                AttributeDefinition.builder()
                    .attributeName("gsi1pk")
                    .attributeType(ScalarAttributeType.S)
                    .build(),
                AttributeDefinition.builder()
                    .attributeName("gsi1sk")
                    .attributeType(ScalarAttributeType.S)
                    .build())
            .keySchema(
                KeySchemaElement.builder().attributeName("pk").keyType(KeyType.HASH).build(),
                KeySchemaElement.builder().attributeName("sk").keyType(KeyType.RANGE).build())
            .globalSecondaryIndexes(
                GlobalSecondaryIndex.builder()
                    .indexName(PkAuthDynamoTables.GSI1_USER_BY_USERNAME)
                    .keySchema(
                        KeySchemaElement.builder()
                            .attributeName("gsi1pk")
                            .keyType(KeyType.HASH)
                            .build(),
                        KeySchemaElement.builder()
                            .attributeName("gsi1sk")
                            .keyType(KeyType.RANGE)
                            .build())
                    .projection(Projection.builder().projectionType(ProjectionType.ALL).build())
                    .build())
            .build());
    waitForActive(tables.users());
  }

  private void enableTtl(String tableName, String attributeName) {
    client.updateTimeToLive(
        UpdateTimeToLiveRequest.builder()
            .tableName(tableName)
            .timeToLiveSpecification(
                TimeToLiveSpecification.builder()
                    .attributeName(attributeName)
                    .enabled(true)
                    .build())
            .build());
  }

  private void waitForActive(String name) {
    long deadline = System.nanoTime() + java.time.Duration.ofSeconds(30).toNanos();
    while (System.nanoTime() < deadline) {
      var status =
          client
              .describeTable(DescribeTableRequest.builder().tableName(name).build())
              .table()
              .tableStatusAsString();
      if ("ACTIVE".equals(status)) {
        return;
      }
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      }
    }
    throw new IllegalStateException("Table " + name + " did not become ACTIVE");
  }
}
