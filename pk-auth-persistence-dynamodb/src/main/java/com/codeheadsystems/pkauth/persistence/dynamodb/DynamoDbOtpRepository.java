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
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;

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
  public void incrementAttempts(String otpId) {
    findItemById(otpId)
        .ifPresent(
            item -> {
              item.setAttempts(item.getAttempts() + 1);
              table.updateItem(item);
            });
  }

  @Override
  public void consume(String otpId) {
    findItemById(otpId)
        .ifPresent(
            item -> {
              item.setConsumed(true);
              table.updateItem(item);
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
