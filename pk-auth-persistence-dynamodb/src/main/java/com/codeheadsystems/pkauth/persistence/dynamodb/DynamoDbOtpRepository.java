// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.spi.OtpRepository;
import java.time.Instant;
import java.util.Comparator;
import java.util.Objects;
import java.util.Optional;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.UpdateItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;

/** {@link OtpRepository} backed by the single-table per ADR 0008. */
public final class DynamoDbOtpRepository implements OtpRepository {

  private final DynamoDbTable<OtpItem> table;

  public DynamoDbOtpRepository(DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.table = enhanced.table(tables.core(), TableSchema.fromBean(OtpItem.class));
  }

  @Override
  public void save(StoredOtp otp) {
    table.putItem(OtpItem.fromRecord(otp));
  }

  @Override
  public Optional<StoredOtp> findLatestActive(UserHandle userHandle, String phoneE164) {
    String userB64 = Base64Url.encode(userHandle.value());
    return table
        .query(
            QueryConditional.sortBeginsWith(
                Key.builder().partitionValue("USER#" + userB64).sortValue("OTP#").build()))
        .stream()
        .flatMap(page -> page.items().stream())
        .filter(i -> phoneE164.equals(i.getPhoneE164()))
        .filter(i -> !i.isConsumed())
        .max(Comparator.comparing(OtpItem::getCreatedAt))
        .map(OtpItem::toRecord);
  }

  @Override
  public int incrementAttempts(String otpId) {
    Optional<OtpItem> existing = findItemById(otpId);
    if (existing.isEmpty()) {
      return 0;
    }
    OtpItem item = existing.get();
    int prior = item.getAttempts();
    int next = prior + 1;
    item.setAttempts(next);
    // Optimistic concurrency: only apply the increment if the stored counter still
    // matches what we read. A concurrent racing verify will lose the CAS and retry on
    // the next attempt with a fresh read.
    try {
      table.updateItem(
          UpdateItemEnhancedRequest.builder(OtpItem.class)
              .item(item)
              .conditionExpression(
                  Expression.builder()
                      .expression("#a = :prior")
                      .putExpressionName("#a", "attempts") // reserved word
                      .putExpressionValue(":prior", AttributeValue.fromN(Integer.toString(prior)))
                      .build())
              .build());
      return next;
    } catch (ConditionalCheckFailedException ignored) {
      // Another concurrent attempt incremented first; re-read to return accurate count.
      return findItemById(otpId).map(OtpItem::getAttempts).orElse(next);
    }
  }

  @Override
  public void consume(String otpId) {
    // Like backup-code consume, two concurrent verifies must NOT both succeed. The conditional
    // makes DynamoDB enforce single-use server-side.
    findItemById(otpId)
        .ifPresent(
            item -> {
              item.setConsumed(true);
              try {
                table.updateItem(
                    UpdateItemEnhancedRequest.builder(OtpItem.class)
                        .item(item)
                        .conditionExpression(
                            Expression.builder()
                                .expression("#c = :false")
                                .putExpressionName("#c", "consumed") // reserved word
                                .putExpressionValue(":false", AttributeValue.fromBool(false))
                                .build())
                        .build());
              } catch (ConditionalCheckFailedException ignored) {
                // Another concurrent verify already consumed this OTP; race lost cleanly.
              }
            });
  }

  @Override
  public int countSince(UserHandle userHandle, String phoneE164, Instant since) {
    String userB64 = Base64Url.encode(userHandle.value());
    return (int)
        table
            .query(
                QueryConditional.sortBeginsWith(
                    Key.builder().partitionValue("USER#" + userB64).sortValue("OTP#").build()))
            .stream()
            .flatMap(page -> page.items().stream())
            .filter(i -> phoneE164.equals(i.getPhoneE164()))
            .filter(i -> !Instant.parse(i.getCreatedAt()).isBefore(since))
            .count();
  }

  private Optional<OtpItem> findItemById(String otpId) {
    return table.scan().items().stream().filter(i -> otpId.equals(i.getOtpId())).findFirst();
  }
}
