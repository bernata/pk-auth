// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.BackupCodeRepository;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;

/** {@link BackupCodeRepository} backed by the single-table per ADR 0008. */
public final class DynamoDbBackupCodeRepository implements BackupCodeRepository {

  private final DynamoDbTable<BackupCodeItem> table;

  public DynamoDbBackupCodeRepository(DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.table = enhanced.table(tables.core(), TableSchema.fromBean(BackupCodeItem.class));
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
  public void consume(String codeId, Instant consumedAt) {
    table.scan().items().stream()
        .filter(item -> codeId.equals(item.getCodeId()))
        .filter(item -> !item.isConsumed())
        .findFirst()
        .ifPresent(
            item -> {
              item.setConsumed(true);
              item.setConsumedAt(consumedAt.toString());
              table.updateItem(item);
            });
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
