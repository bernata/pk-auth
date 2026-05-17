// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.persistence.dynamodb;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.json.Base64Url;
import com.codeheadsystems.pkauth.refresh.RefreshTokenRecord;
import com.codeheadsystems.pkauth.refresh.RevokeReason;
import com.codeheadsystems.pkauth.refresh.spi.RefreshTokenRepository;
import com.codeheadsystems.pkauth.spi.PkAuthPersistenceException;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.ConditionCheck;
import software.amazon.awssdk.enhanced.dynamodb.model.PutItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactPutItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.TransactWriteItemsEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;

/**
 * {@link RefreshTokenRepository} backed by the {@code PkAuthCore} single table. The load-bearing
 * {@link #rotateAtomically} primitive uses {@code TransactWriteItems} to commit "mark parent used"
 * and "insert successor" as a single atomic operation — without that, a concurrent replay-revoker
 * could miss the freshly-inserted successor.
 *
 * <p>Each issued JTI lives at up to three item addresses (primary + user-index + family-index) —
 * the user-index and family-index items aren't load-bearing for correctness (the primary item is
 * the authority on used/revoked state) but they make {@code revokeAllForUser} and {@code
 * revokeFamily} O(family-size) rather than full-table scans.
 *
 * <p>Native DynamoDB TTL on the {@code ttl} attribute prunes rows in the background; {@link
 * #deleteExpiredBefore(Instant)} provides synchronous cleanup for tests and operator workflows.
 *
 * @since 1.1.0
 */
public final class DynamoDbRefreshTokenRepository implements RefreshTokenRepository {

  private static final String FAMILY_PK_PREFIX = "RTF#";
  private static final String USER_PK_PREFIX = "USER#";
  private static final String PRIMARY_PK_PREFIX = "RT#";
  private static final String INDEX_SK_PREFIX = "RT#";

  private final DynamoDbEnhancedClient enhanced;
  private final DynamoDbTable<RefreshTokenItem> table;

  public DynamoDbRefreshTokenRepository(
      DynamoDbEnhancedClient enhanced, PkAuthDynamoTables tables) {
    this.enhanced = Objects.requireNonNull(enhanced, "enhanced");
    Objects.requireNonNull(tables, "tables");
    this.table = enhanced.table(tables.core(), TableSchema.fromBean(RefreshTokenItem.class));
  }

  @Override
  public void create(RefreshTokenRecord record) {
    Objects.requireNonNull(record, "record");
    wrap(
        "refresh_tokens.create",
        () -> {
          putAllItems(record, /*requirePrimaryAbsent*/ true);
          return null;
        });
  }

  @Override
  public Optional<RefreshTokenRecord> findByRefreshId(String refreshId) {
    return wrap(
        "refresh_tokens.findByRefreshId",
        () -> {
          RefreshTokenItem item =
              table.getItem(
                  Key.builder()
                      .partitionValue(PRIMARY_PK_PREFIX + refreshId)
                      .sortValue(PRIMARY_PK_PREFIX + refreshId)
                      .build());
          return Optional.ofNullable(item).map(DynamoDbRefreshTokenRepository::toRecord);
        });
  }

  @Override
  public boolean rotateAtomically(
      String parentRefreshId, Instant now, RefreshTokenRecord successor) {
    Objects.requireNonNull(parentRefreshId, "parentRefreshId");
    Objects.requireNonNull(now, "now");
    Objects.requireNonNull(successor, "successor");
    return wrap(
        "refresh_tokens.rotateAtomically",
        () -> {
          // We can't read userHandleB64u from the predicate, so we need to look up the parent
          // first to know which user-index item to update. The lookup + transact path is
          // safe because the conditional on the parent UpdateItem inside the transaction is
          // the authoritative freshness check — even if state changed between lookup and
          // transaction, the conditional fails and we return false.
          RefreshTokenItem parent =
              table.getItem(
                  Key.builder()
                      .partitionValue(PRIMARY_PK_PREFIX + parentRefreshId)
                      .sortValue(PRIMARY_PK_PREFIX + parentRefreshId)
                      .build());
          if (parent == null) {
            return false;
          }

          String nowIso = now.toString();
          // Mark the parent's primary item used. The user-index and family-index items aren't
          // authoritative for used_at — only the primary is — so we don't mutate them here.
          RefreshTokenItem updatedParent = copy(parent);
          updatedParent.setUsedAtIso(nowIso);

          // Build the three successor items.
          RefreshTokenItem successorPrimary =
              toItem(
                  successor,
                  PRIMARY_PK_PREFIX + successor.refreshId(),
                  PRIMARY_PK_PREFIX + successor.refreshId());
          RefreshTokenItem successorUser =
              toItem(
                  successor,
                  USER_PK_PREFIX + successor_userB64(successor),
                  INDEX_SK_PREFIX + successor.refreshId());
          RefreshTokenItem successorFamily =
              toItem(
                  successor,
                  FAMILY_PK_PREFIX + successor.familyId(),
                  INDEX_SK_PREFIX + successor.refreshId());

          // Transact: conditional update on parent primary (still fresh) + put successor items.
          // ConditionExpression — fresh iff used_at, revoked_at unset and expires_at > now.
          Expression freshness =
              Expression.builder()
                  .expression(
                      "attribute_not_exists(usedAtIso) AND attribute_not_exists(revokedAtIso)"
                          + " AND expiresAtIso > :now")
                  .putExpressionValue(":now", AttributeValue.fromS(nowIso))
                  .build();

          try {
            enhanced.transactWriteItems(
                TransactWriteItemsEnhancedRequest.builder()
                    .addPutItem(
                        table,
                        TransactPutItemEnhancedRequest.builder(RefreshTokenItem.class)
                            .item(updatedParent)
                            .conditionExpression(freshness)
                            .build())
                    .addPutItem(
                        table,
                        TransactPutItemEnhancedRequest.builder(RefreshTokenItem.class)
                            .item(successorPrimary)
                            .conditionExpression(
                                Expression.builder().expression("attribute_not_exists(pk)").build())
                            .build())
                    .addPutItem(table, successorUser)
                    .addPutItem(table, successorFamily)
                    .build());
            return true;
          } catch (TransactionCanceledException cancelled) {
            return false;
          }
        });
  }

  @Override
  public int revokeFamily(String familyId, Instant now, RevokeReason reason) {
    return wrap(
        "refresh_tokens.revokeFamily",
        () -> {
          // Query the family-index for every member, then mutate the primary item of each (the
          // primary is the authority on revoked_at).
          int[] revoked = {0};
          String nowIso = now.toString();
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(FAMILY_PK_PREFIX + familyId)
                          .sortValue(INDEX_SK_PREFIX)
                          .build()))
              .stream()
              .flatMap(p -> p.items().stream())
              .forEach(
                  indexItem -> {
                    RefreshTokenItem primary =
                        table.getItem(
                            Key.builder()
                                .partitionValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .sortValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .build());
                    if (primary == null || primary.getRevokedAtIso() != null) {
                      return;
                    }
                    primary.setRevokedAtIso(nowIso);
                    primary.setRevokedReason(reason.name());
                    // Conditional put: only set revoked_at if it's still null (idempotent under
                    // concurrent revokers).
                    try {
                      table.putItem(
                          PutItemEnhancedRequest.builder(RefreshTokenItem.class)
                              .item(primary)
                              .conditionExpression(
                                  Expression.builder()
                                      .expression("attribute_not_exists(revokedAtIso)")
                                      .build())
                              .build());
                      revoked[0]++;
                    } catch (ConditionalCheckFailedException raceLost) {
                      // Another revoker won; revokedAt is now set. Nothing to do.
                    }
                  });
          return revoked[0];
        });
  }

  @Override
  public int revokeAllForUser(UserHandle userHandle, Instant now, RevokeReason reason) {
    return wrap(
        "refresh_tokens.revokeAllForUser",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          int[] revoked = {0};
          String nowIso = now.toString();
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(USER_PK_PREFIX + userB64)
                          .sortValue(INDEX_SK_PREFIX)
                          .build()))
              .stream()
              .flatMap(p -> p.items().stream())
              .forEach(
                  indexItem -> {
                    RefreshTokenItem primary =
                        table.getItem(
                            Key.builder()
                                .partitionValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .sortValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .build());
                    if (primary == null || primary.getRevokedAtIso() != null) {
                      return;
                    }
                    primary.setRevokedAtIso(nowIso);
                    primary.setRevokedReason(reason.name());
                    try {
                      table.putItem(
                          PutItemEnhancedRequest.builder(RefreshTokenItem.class)
                              .item(primary)
                              .conditionExpression(
                                  Expression.builder()
                                      .expression("attribute_not_exists(revokedAtIso)")
                                      .build())
                              .build());
                      revoked[0]++;
                    } catch (ConditionalCheckFailedException raceLost) {
                      // Lost race; revoked by someone else.
                    }
                  });
          return revoked[0];
        });
  }

  @Override
  public List<RefreshTokenRecord> findByUserHandle(UserHandle userHandle) {
    return wrap(
        "refresh_tokens.findByUserHandle",
        () -> {
          String userB64 = Base64Url.encode(userHandle.value());
          // Query the user-index for refreshIds, then load each primary item for authoritative
          // used/revoked state.
          Map<String, RefreshTokenRecord> byId = new LinkedHashMap<>();
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(USER_PK_PREFIX + userB64)
                          .sortValue(INDEX_SK_PREFIX)
                          .build()))
              .stream()
              .flatMap(p -> p.items().stream())
              .forEach(
                  indexItem -> {
                    RefreshTokenItem primary =
                        table.getItem(
                            Key.builder()
                                .partitionValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .sortValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .build());
                    if (primary != null) {
                      byId.put(primary.getRefreshId(), toRecord(primary));
                    }
                  });
          return List.copyOf(byId.values());
        });
  }

  @Override
  public List<RefreshTokenRecord> findByFamilyId(String familyId) {
    return wrap(
        "refresh_tokens.findByFamilyId",
        () -> {
          Map<String, RefreshTokenRecord> byId = new LinkedHashMap<>();
          table
              .query(
                  QueryConditional.sortBeginsWith(
                      Key.builder()
                          .partitionValue(FAMILY_PK_PREFIX + familyId)
                          .sortValue(INDEX_SK_PREFIX)
                          .build()))
              .stream()
              .flatMap(p -> p.items().stream())
              .forEach(
                  indexItem -> {
                    RefreshTokenItem primary =
                        table.getItem(
                            Key.builder()
                                .partitionValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .sortValue(PRIMARY_PK_PREFIX + indexItem.getRefreshId())
                                .build());
                    if (primary != null) {
                      byId.put(primary.getRefreshId(), toRecord(primary));
                    }
                  });
          return List.copyOf(byId.values());
        });
  }

  @Override
  public int deleteExpiredBefore(Instant cutoff) {
    return wrap(
        "refresh_tokens.deleteExpiredBefore",
        () -> {
          long cutoffEpoch = cutoff.getEpochSecond();
          int[] removed = {0};
          // Scan only primary items (pk and sk both start with RT#) and filter by the
          // retention predicate that mirrors the JDBI cleanup SQL.
          table.scan().items().stream()
              .filter(item -> item.getPk() != null && item.getPk().startsWith(PRIMARY_PK_PREFIX))
              .filter(item -> item.getPk().equals(item.getSk())) // primary only
              .filter(item -> item.getTtl() != null && item.getTtl() < cutoffEpoch)
              .filter(
                  item ->
                      (item.getUsedAtIso() != null
                              && Instant.parse(item.getUsedAtIso()).isBefore(cutoff))
                          || (item.getRevokedAtIso() != null
                              && Instant.parse(item.getRevokedAtIso()).isBefore(cutoff)))
              .forEach(
                  item -> {
                    deleteAllItems(item);
                    removed[0]++;
                  });
          return removed[0];
        });
  }

  // -- Internals --------------------------------------------------------------------------

  private void putAllItems(RefreshTokenRecord record, boolean requirePrimaryAbsent) {
    String userB64 = Base64Url.encode(record.userHandle().value());
    RefreshTokenItem primary =
        toItem(
            record, PRIMARY_PK_PREFIX + record.refreshId(), PRIMARY_PK_PREFIX + record.refreshId());
    PutItemEnhancedRequest.Builder<RefreshTokenItem> primaryReq =
        PutItemEnhancedRequest.builder(RefreshTokenItem.class).item(primary);
    if (requirePrimaryAbsent) {
      primaryReq.conditionExpression(
          Expression.builder().expression("attribute_not_exists(pk)").build());
    }
    try {
      table.putItem(primaryReq.build());
    } catch (ConditionalCheckFailedException duplicate) {
      throw new IllegalStateException("duplicate refreshId: " + record.refreshId(), duplicate);
    }
    // User-index pointer (best-effort; not load-bearing for correctness).
    table.putItem(toItem(record, USER_PK_PREFIX + userB64, INDEX_SK_PREFIX + record.refreshId()));
    // Family-index pointer (best-effort; not load-bearing for correctness).
    table.putItem(
        toItem(record, FAMILY_PK_PREFIX + record.familyId(), INDEX_SK_PREFIX + record.refreshId()));
  }

  private void deleteAllItems(RefreshTokenItem primary) {
    String refreshId = primary.getRefreshId();
    table.deleteItem(
        Key.builder()
            .partitionValue(PRIMARY_PK_PREFIX + refreshId)
            .sortValue(PRIMARY_PK_PREFIX + refreshId)
            .build());
    if (primary.getUserHandleB64u() != null) {
      table.deleteItem(
          Key.builder()
              .partitionValue(USER_PK_PREFIX + primary.getUserHandleB64u())
              .sortValue(INDEX_SK_PREFIX + refreshId)
              .build());
    }
    if (primary.getFamilyId() != null) {
      table.deleteItem(
          Key.builder()
              .partitionValue(FAMILY_PK_PREFIX + primary.getFamilyId())
              .sortValue(INDEX_SK_PREFIX + refreshId)
              .build());
    }
  }

  private static String successor_userB64(RefreshTokenRecord r) {
    return Base64Url.encode(r.userHandle().value());
  }

  private static RefreshTokenItem toItem(RefreshTokenRecord r, String pk, String sk) {
    RefreshTokenItem item = new RefreshTokenItem();
    item.setPk(pk);
    item.setSk(sk);
    item.setRefreshId(r.refreshId());
    item.setTokenHashB64u(Base64Url.encode(r.tokenHash()));
    item.setUserHandleB64u(Base64Url.encode(r.userHandle().value()));
    item.setAudience(r.audience());
    item.setDeviceId(r.deviceId().orElse(null));
    item.setFamilyId(r.familyId());
    item.setParentRefreshId(r.parentRefreshId().orElse(null));
    item.setIssuedAtIso(r.issuedAt().toString());
    item.setExpiresAtIso(r.expiresAt().toString());
    item.setUsedAtIso(r.usedAt().map(Instant::toString).orElse(null));
    item.setRevokedAtIso(r.revokedAt().map(Instant::toString).orElse(null));
    item.setRevokedReason(r.revokedReason().map(Enum::name).orElse(null));
    item.setTtl(r.expiresAt().getEpochSecond());
    return item;
  }

  private static RefreshTokenItem copy(RefreshTokenItem from) {
    RefreshTokenItem item = new RefreshTokenItem();
    item.setPk(from.getPk());
    item.setSk(from.getSk());
    item.setRefreshId(from.getRefreshId());
    item.setTokenHashB64u(from.getTokenHashB64u());
    item.setUserHandleB64u(from.getUserHandleB64u());
    item.setAudience(from.getAudience());
    item.setDeviceId(from.getDeviceId());
    item.setFamilyId(from.getFamilyId());
    item.setParentRefreshId(from.getParentRefreshId());
    item.setIssuedAtIso(from.getIssuedAtIso());
    item.setExpiresAtIso(from.getExpiresAtIso());
    item.setUsedAtIso(from.getUsedAtIso());
    item.setRevokedAtIso(from.getRevokedAtIso());
    item.setRevokedReason(from.getRevokedReason());
    item.setTtl(from.getTtl());
    return item;
  }

  private static RefreshTokenRecord toRecord(RefreshTokenItem item) {
    Map<String, AttributeValue> ignored = new HashMap<>();
    byte[] hash = Base64Url.decode(item.getTokenHashB64u());
    return new RefreshTokenRecord(
        item.getRefreshId(),
        hash,
        UserHandle.of(Base64Url.decode(item.getUserHandleB64u())),
        item.getAudience(),
        Optional.ofNullable(item.getDeviceId()),
        item.getFamilyId(),
        Optional.ofNullable(item.getParentRefreshId()),
        Instant.parse(item.getIssuedAtIso()),
        Instant.parse(item.getExpiresAtIso()),
        Optional.ofNullable(item.getUsedAtIso()).map(Instant::parse),
        Optional.ofNullable(item.getRevokedAtIso()).map(Instant::parse),
        Optional.ofNullable(item.getRevokedReason()).map(RevokeReason::valueOf));
  }

  private static <T> T wrap(String op, Supplier<T> body) {
    try {
      return body.get();
    } catch (PkAuthPersistenceException already) {
      throw already;
    } catch (SdkException e) {
      throw new PkAuthPersistenceException(op, e.getMessage(), e);
    }
  }

  // Defensive: silence unused-import warnings on classes pulled in for the TransactWrite path.
  @SuppressWarnings("unused")
  private static final ConditionCheck<RefreshTokenItem> UNUSED_CONDITION = null;
}
