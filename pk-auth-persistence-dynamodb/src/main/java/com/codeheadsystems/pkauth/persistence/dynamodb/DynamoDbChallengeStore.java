// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.ChallengeId;
import com.codeheadsystems.pkauth.spi.ChallengeRecord;
import com.codeheadsystems.pkauth.spi.ChallengeStore;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DeleteItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ReturnValue;

/**
 * {@link ChallengeStore} backed by the {@code PkAuthCore} single-table. {@code takeOnce} is a
 * {@code DeleteItem} with {@code ReturnValues = ALL_OLD}, which is atomic.
 */
public final class DynamoDbChallengeStore implements ChallengeStore {

  private final DynamoDbClient client;
  private final String tableName;

  public DynamoDbChallengeStore(DynamoDbClient client, PkAuthDynamoTables tables) {
    this.client = Objects.requireNonNull(client, "client");
    this.tableName = Objects.requireNonNull(tables, "tables").core();
  }

  @Override
  public void put(ChallengeId id, ChallengeRecord record, Duration ttl) {
    ChallengeItem item = ChallengeItem.build(id, record);
    Map<String, AttributeValue> values = new HashMap<>();
    values.put("pk", AttributeValue.fromS(item.getPk()));
    values.put("sk", AttributeValue.fromS(item.getSk()));
    values.put("entityType", AttributeValue.fromS(item.getEntityType()));
    values.put("ttl", AttributeValue.fromN(Long.toString(item.getTtl())));
    values.put("challenge", AttributeValue.fromS(item.getChallenge()));
    values.put("purpose", AttributeValue.fromS(item.getPurpose()));
    if (item.getUserHandle() != null) {
      values.put("userHandle", AttributeValue.fromS(item.getUserHandle()));
    }
    values.put("expiresAt", AttributeValue.fromS(item.getExpiresAt()));
    client.putItem(PutItemRequest.builder().tableName(tableName).item(values).build());
  }

  @Override
  public Optional<ChallengeRecord> takeOnce(ChallengeId id) {
    Map<String, AttributeValue> key = new HashMap<>();
    key.put("pk", AttributeValue.fromS("CHAL#" + id.value()));
    key.put("sk", AttributeValue.fromS("META"));
    var response =
        client.deleteItem(
            DeleteItemRequest.builder()
                .tableName(tableName)
                .key(key)
                .returnValues(ReturnValue.ALL_OLD)
                .build());
    if (response.attributes() == null || response.attributes().isEmpty()) {
      return Optional.empty();
    }
    Map<String, AttributeValue> attrs = response.attributes();
    ChallengeItem item = new ChallengeItem();
    item.setPk(attrs.get("pk").s());
    item.setSk(attrs.get("sk").s());
    item.setEntityType(attrs.get("entityType").s());
    item.setChallenge(attrs.get("challenge").s());
    item.setPurpose(attrs.get("purpose").s());
    if (attrs.containsKey("userHandle")) {
      item.setUserHandle(attrs.get("userHandle").s());
    }
    item.setExpiresAt(attrs.get("expiresAt").s());
    ChallengeRecord record = item.toRecord();
    // Filter out anything we successfully deleted but which had already expired.
    if (Instant.now().isAfter(record.expiresAt())) {
      return Optional.empty();
    }
    return Optional.of(record);
  }
}
