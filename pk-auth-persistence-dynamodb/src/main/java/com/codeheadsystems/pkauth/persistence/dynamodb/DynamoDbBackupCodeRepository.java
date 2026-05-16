// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

/** {@link BackupCodeRepository} backed by the single-table per ADR 0008. */
public final class DynamoDbBackupCodeRepository implements BackupCodeRepository {

  private final DynamoDbTable<BackupCodeItem> table;
  private final DynamoDbClient client;
  private final String tableName;

  public DynamoDbBackupCodeRepository(
      DynamoDbEnhancedClient enhanced, DynamoDbClient client, PkAuthDynamoTables tables) {
    Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.client = Objects.requireNonNull(client, "client");
    this.tableName = tables.core();
    this.table = enhanced.table(tableName, TableSchema.fromBean(BackupCodeItem.class));
  }

  @Override
  public void save(StoredBackupCode code) {
    table.putItem(BackupCodeItem.fromRecord(code));
  }

  @Override
  public List<StoredBackupCode> findByUserHandle(UserHandle userHandle) {
    String userB64 = Base64Url.encode(userHandle.value());
    return table
        .query(
            QueryConditional.sortBeginsWith(
                Key.builder().partitionValue("USER#" + userB64).sortValue("BACKUP#").build()))
        .stream()
        .flatMap(page -> page.items().stream())
        .map(BackupCodeItem::toRecord)
        .toList();
  }

  @Override
  public void consume(UserHandle userHandle, String codeId, Instant consumedAt) {
    // Single conditional UpdateItem against the exact (pk, sk). No read, no scan. The
    // condition is the security-critical bit: two concurrent verifies both observing
    // consumed=false must NOT both succeed, or the single-use guarantee is broken.
    // attribute_exists(pk) prevents creating a phantom row if the (userHandle, codeId)
    // pair doesn't exist — matching the prior scan-found-nothing semantics.
    String userB64 = Base64Url.encode(userHandle.value());
    try {
      client.updateItem(
          UpdateItemRequest.builder()
              .tableName(tableName)
              .key(
                  Map.of(
                      "pk", AttributeValue.fromS("USER#" + userB64),
                      "sk", AttributeValue.fromS("BACKUP#" + codeId)))
              .updateExpression("SET #c = :true, consumedAt = :consumedAt")
              .conditionExpression("attribute_exists(pk) AND #c = :false")
              .expressionAttributeNames(Map.of("#c", "consumed"))
              .expressionAttributeValues(
                  Map.of(
                      ":true", AttributeValue.fromBool(true),
                      ":false", AttributeValue.fromBool(false),
                      ":consumedAt", AttributeValue.fromS(consumedAt.toString())))
              .build());
    } catch (ConditionalCheckFailedException ignored) {
      // Either the code doesn't exist for this user, or it was already consumed by a
      // concurrent verify. Single-use guarantee preserved server-side.
    }
  }

  @Override
  public void deleteByUserHandle(UserHandle userHandle) {
    String userB64 = Base64Url.encode(userHandle.value());
    table
        .query(
            QueryConditional.sortBeginsWith(
                Key.builder().partitionValue("USER#" + userB64).sortValue("BACKUP#").build()))
        .stream()
        .flatMap(page -> page.items().stream())
        .forEach(
            item ->
                table.deleteItem(
                    Key.builder().partitionValue(item.getPk()).sortValue(item.getSk()).build()));
  }
}
