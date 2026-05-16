// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.credential.CredentialRecord;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.CredentialRepository;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.UpdateItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;

/** {@link CredentialRepository} backed by the {@code PkAuthCore} single-table. */
public final class DynamoDbCredentialRepository implements CredentialRepository {

  private final DynamoDbTable<CredentialItem> table;
  private final DynamoDbIndex<CredentialItem> credentialByIdIndex;

  public DynamoDbCredentialRepository(DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.table = enhanced.table(tables.core(), TableSchema.fromBean(CredentialItem.class));
    this.credentialByIdIndex = table.index(PkAuthDynamoTables.GSI1_CREDENTIAL_BY_ID);
  }

  @Override
  public void save(CredentialRecord record) {
    try {
      table.putItem(
          r ->
              r.item(CredentialItem.fromRecord(record))
                  .conditionExpression(
                      software.amazon.awssdk.enhanced.dynamodb.Expression.builder()
                          .expression("attribute_not_exists(pk)")
                          .build()));
    } catch (ConditionalCheckFailedException e) {
      throw new IllegalStateException(
          "Duplicate credential id; refusing to overwrite an existing credential", e);
    }
  }

  @Override
  public Optional<CredentialRecord> findByCredentialId(byte[] credentialId) {
    String credIdB64 = Base64Url.encode(credentialId);
    return credentialByIdIndex
        .query(
            QueryConditional.keyEqualTo(
                Key.builder().partitionValue("CRED#" + credIdB64).sortValue("META").build()))
        .stream()
        .flatMap(page -> page.items().stream())
        .findFirst()
        .map(CredentialItem::toRecord);
  }

  @Override
  public List<CredentialRecord> findByUserHandle(UserHandle userHandle) {
    String userB64 = Base64Url.encode(userHandle.value());
    return table
        .query(
            QueryConditional.sortBeginsWith(
                Key.builder().partitionValue("USER#" + userB64).sortValue("CRED#").build()))
        .stream()
        .flatMap(page -> page.items().stream())
        .map(CredentialItem::toRecord)
        .toList();
  }

  @Override
  public void updateSignCount(byte[] credentialId, long newCount, Instant lastUsedAt) {
    Optional<CredentialItem> existing = lookupItem(credentialId);
    if (existing.isEmpty()) {
      return;
    }
    CredentialItem item = existing.get();
    item.setSignCount(newCount);
    item.setLastUsedAt(lastUsedAt.toString());
    // Guard against the lost-update race described for the JDBI repository: two concurrent
    // assertions (e.g. a clone vs. the real authenticator) would otherwise be able to overwrite
    // a higher stored counter with a lower one, silently defeating clone detection. The
    // conditional rejects the write unless the in-table value is still strictly less than the
    // value we're trying to store.
    try {
      table.updateItem(
          UpdateItemEnhancedRequest.builder(CredentialItem.class)
              .item(item)
              .conditionExpression(
                  software.amazon.awssdk.enhanced.dynamodb.Expression.builder()
                      .expression("signCount < :newSignCount")
                      .putExpressionValue(
                          ":newSignCount",
                          software.amazon.awssdk.services.dynamodb.model.AttributeValue.fromN(
                              Long.toString(newCount)))
                      .build())
              .build());
    } catch (ConditionalCheckFailedException ignored) {
      // A concurrent write already advanced the counter to at least newCount; nothing to do.
    }
  }

  @Override
  public void updateLabel(byte[] credentialId, String label) {
    lookupItem(credentialId)
        .ifPresent(
            item -> {
              item.setLabel(label);
              table.updateItem(
                  UpdateItemEnhancedRequest.builder(CredentialItem.class).item(item).build());
            });
  }

  @Override
  public void delete(byte[] credentialId) {
    lookupItem(credentialId)
        .ifPresent(
            item ->
                table.deleteItem(
                    Key.builder().partitionValue(item.getPk()).sortValue(item.getSk()).build()));
  }

  private Optional<CredentialItem> lookupItem(byte[] credentialId) {
    String credIdB64 = Base64Url.encode(credentialId);
    return credentialByIdIndex
        .query(
            QueryConditional.keyEqualTo(
                Key.builder().partitionValue("CRED#" + credIdB64).sortValue("META").build()))
        .stream()
        .flatMap(page -> page.items().stream())
        .findFirst();
  }

  /** Diagnostic helper to expose the table name for inspection in tests. */
  Map<String, AttributeValue> asRawKey(String pk, String sk) {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put("pk", AttributeValue.fromS(pk));
    key.put("sk", AttributeValue.fromS(sk));
    return key;
  }
}
