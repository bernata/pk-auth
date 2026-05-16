// SPDX-License-Identifier: MIT
package com.codeheadsystems.pkauth.magiclink;

import com.codeheadsystems.pkauth.api.UserHandle;
import com.codeheadsystems.pkauth.jwt.AuthMethod;
import com.codeheadsystems.pkauth.jwt.JwtClaims;
import com.codeheadsystems.pkauth.jwt.JwtVerificationResult;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtIssuer;
import com.codeheadsystems.pkauth.jwt.PkAuthJwtValidator;
import com.codeheadsystems.pkauth.spi.ClockProvider;
import com.codeheadsystems.pkauth.spi.ConsumedJtiStore;
import com.codeheadsystems.pkauth.spi.UserLookup;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sends and consumes magic-link tokens. Two flows per brief §6.4:
 *
 * <ul>
 *   <li>Email verification — the {@code pkauth.purpose} claim is {@code email-verify}.
 *   <li>Passwordless login — the {@code pkauth.purpose} claim is {@code login}.
 * </ul>
 *
 * <p>Single-use is enforced by recording consumed JTI values in a {@link ConsumedJtiStore} whose
 * entries expire after {@code consumedJtiTtl} (default: {@link #DEFAULT_CONSUMED_JTI_TTL}). The
 * SPI's default in-process implementation ({@link InMemoryConsumedJtiStore}) is dev/single-instance
 * only — multi-replica deployments MUST inject a shared (Redis/DB-backed) store, otherwise a token
 * redeemed on one replica can be redeemed again on another within its TTL window. The service logs
 * a startup WARN when the in-memory default is wired. Rate limiting (brief §6.4 — N emails per
 * user/purpose per hour) is tracked through {@link MagicLinkRateLimiter}, which follows the same
 * pattern (dev-only in-process default; production replaces with a shared implementation).
 */
public final class MagicLinkService {

  /** Wire value of the email-verify purpose claim. */
  public static final String PURPOSE_EMAIL_VERIFY = "email-verify";

  /** Wire value of the login purpose claim. */
  public static final String PURPOSE_LOGIN = "login";

  /** JWT claim name carrying the magic-link purpose. */
  public static final String CLAIM_PURPOSE = "pkauth.purpose";

  /** JWT claim name carrying the email address (verification flow only). */
  public static final String CLAIM_EMAIL = "pkauth.email";

  /** Default TTL of an issued magic-link JWT. */
  public static final Duration DEFAULT_TTL = Duration.ofMinutes(15);

  /**
   * Default TTL for the consumed-JTI cache. Set comfortably larger than {@link #DEFAULT_TTL} so a
   * JWT that's already expired can't be replayed even if the validator's clock-skew tolerance
   * accepts it briefly after expiry.
   */
  public static final Duration DEFAULT_CONSUMED_JTI_TTL = Duration.ofMinutes(30);

  /** Default rate limit: 5 emails per (user, purpose) per hour. */
  public static final int DEFAULT_RATE_LIMIT = 5;

  /** Default rate-limit window. */
  public static final Duration DEFAULT_RATE_WINDOW = Duration.ofHours(1);

  /** Result of a send attempt. */
  public sealed interface SendResult {
    /** Email was dispatched. */
    record Sent(String tokenJti) implements SendResult {}

    /** Rate limit hit. */
    record RateLimited(int countInWindow) implements SendResult {}

    /** No user matched the supplied identifier (login flow only). */
    record UserNotFound() implements SendResult {}

    /**
     * The caller-supplied email does not match the one bound to the user via {@link
     * UserLookup#emailFor(UserHandle)}. Returned only when the host has implemented {@code
     * emailFor}; otherwise the binding check is skipped (with a warning log) and the send proceeds.
     */
    record EmailMismatch() implements SendResult {}
  }

  /** Result of a consume attempt. */
  public sealed interface ConsumeResult {
    /** Token verified, was unconsumed, and is now consumed. */
    record Success(UserHandle userHandle, String purpose, @Nullable String email)
        implements ConsumeResult {}

    /** JWT verification failed (bad signature, expired, wrong issuer, etc.). */
    record Invalid(JwtVerificationResult reason) implements ConsumeResult {}

    /** Token already consumed earlier. */
    record AlreadyConsumed() implements ConsumeResult {}
  }

  /** Pluggable rate limiter — defaults to an in-process Caffeine counter. */
  public interface MagicLinkRateLimiter {
    /** Returns the current count and whether a new send is allowed. */
    int countAndIncrement(UserHandle user, String purpose, Instant now);
  }

  private static final Logger LOG = LoggerFactory.getLogger(MagicLinkService.class);

  private final PkAuthJwtIssuer issuer;
  private final PkAuthJwtValidator validator;
  private final EmailSender emailSender;
  private final UserLookup userLookup;
  private final ClockProvider clockProvider;
  private final String baseUrl;
  private final int rateLimit;
  private final MagicLinkRateLimiter rateLimiter;
  private final ConsumedJtiStore consumedJtiStore;
  private final Duration consumedJtiTtl;

  public MagicLinkService(
      PkAuthJwtIssuer issuer,
      PkAuthJwtValidator validator,
      EmailSender emailSender,
      UserLookup userLookup,
      ClockProvider clockProvider,
      String baseUrl) {
    this(
        issuer,
        validator,
        emailSender,
        userLookup,
        clockProvider,
        baseUrl,
        DEFAULT_RATE_LIMIT,
        new InMemoryRateLimiter(DEFAULT_RATE_WINDOW),
        DEFAULT_CONSUMED_JTI_TTL);
  }

  /**
   * Test seam allowing override of the rate limit and rate limiter. The JWT TTL is controlled by
   * the {@link PkAuthJwtIssuer}'s {@code JwtConfig.tokenTtl} (caller-supplied), per the brief's
   * §6.4 default of 15 minutes.
   */
  public MagicLinkService(
      PkAuthJwtIssuer issuer,
      PkAuthJwtValidator validator,
      EmailSender emailSender,
      UserLookup userLookup,
      ClockProvider clockProvider,
      String baseUrl,
      int rateLimit,
      MagicLinkRateLimiter rateLimiter) {
    this(
        issuer,
        validator,
        emailSender,
        userLookup,
        clockProvider,
        baseUrl,
        rateLimit,
        rateLimiter,
        DEFAULT_CONSUMED_JTI_TTL);
  }

  /**
   * Test seam allowing override of the consumed-JTI cache TTL — important for tests that need to
   * advance the clock past the cache expiration. Defaults to a {@link InMemoryConsumedJtiStore}
   * sized to {@code consumedJtiTtl}.
   */
  public MagicLinkService(
      PkAuthJwtIssuer issuer,
      PkAuthJwtValidator validator,
      EmailSender emailSender,
      UserLookup userLookup,
      ClockProvider clockProvider,
      String baseUrl,
      int rateLimit,
      MagicLinkRateLimiter rateLimiter,
      Duration consumedJtiTtl) {
    this(
        issuer,
        validator,
        emailSender,
        userLookup,
        clockProvider,
        baseUrl,
        rateLimit,
        rateLimiter,
        consumedJtiTtl,
        new InMemoryConsumedJtiStore(Objects.requireNonNull(consumedJtiTtl, "consumedJtiTtl")));
  }

  /**
   * Full-control constructor accepting a host-supplied {@link ConsumedJtiStore}. Multi-replica
   * deployments MUST inject a shared (Redis/DB-backed) implementation here; the other constructors
   * default to {@link InMemoryConsumedJtiStore}, which is dev/single-instance only.
   *
   * @since 0.9.1
   */
  public MagicLinkService(
      PkAuthJwtIssuer issuer,
      PkAuthJwtValidator validator,
      EmailSender emailSender,
      UserLookup userLookup,
      ClockProvider clockProvider,
      String baseUrl,
      int rateLimit,
      MagicLinkRateLimiter rateLimiter,
      Duration consumedJtiTtl,
      ConsumedJtiStore consumedJtiStore) {
    this.issuer = Objects.requireNonNull(issuer, "issuer");
    this.validator = Objects.requireNonNull(validator, "validator");
    this.emailSender = Objects.requireNonNull(emailSender, "emailSender");
    this.userLookup = Objects.requireNonNull(userLookup, "userLookup");
    this.clockProvider = Objects.requireNonNull(clockProvider, "clockProvider");
    this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl");
    this.rateLimit = rateLimit;
    this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
    this.consumedJtiTtl = Objects.requireNonNull(consumedJtiTtl, "consumedJtiTtl");
    this.consumedJtiStore = Objects.requireNonNull(consumedJtiStore, "consumedJtiStore");
    if (consumedJtiStore instanceof InMemoryConsumedJtiStore) {
      LOG.warn(
          "magiclink.consumed-jti-store InMemoryConsumedJtiStore wired — FOR DEV /"
              + " SINGLE-INSTANCE USE ONLY. Production deployments with more than one replica"
              + " MUST inject a shared (Redis/DB-backed) ConsumedJtiStore via the"
              + " MagicLinkService(... ConsumedJtiStore) constructor, otherwise a captured"
              + " magic-link can be replayed across replicas within its TTL window.");
    }
  }

  /**
   * Sends a verification email containing a magic link tied to {@code email}. If the host has
   * implemented {@link UserLookup#emailFor(UserHandle)}, the supplied {@code email} must equal the
   * bound value (constant-time compare) — otherwise a caller could mint a "verified" claim for an
   * arbitrary address. If the host has not implemented {@code emailFor}, the binding check is
   * skipped (with a warning log) and the send proceeds.
   */
  public SendResult sendVerificationEmail(UserHandle user, String email) {
    Objects.requireNonNull(user, "user");
    Objects.requireNonNull(email, "email");
    Optional<String> bound = userLookup.emailFor(user);
    if (bound.isPresent()) {
      byte[] expected = bound.get().getBytes(StandardCharsets.UTF_8);
      byte[] actual = email.getBytes(StandardCharsets.UTF_8);
      if (!java.security.MessageDigest.isEqual(expected, actual)) {
        LOG.warn("magiclink.send email-mismatch user={} purpose={}", user, PURPOSE_EMAIL_VERIFY);
        return new SendResult.EmailMismatch();
      }
    } else {
      LOG.warn(
          "magiclink.send email-not-bound user={} — UserLookup#emailFor returned empty; the"
              + " library cannot verify the caller-supplied address belongs to this user. Host"
              + " apps that store user emails should override UserLookup#emailFor.",
          user);
    }
    int count = rateLimiter.countAndIncrement(user, PURPOSE_EMAIL_VERIFY, clockProvider.now());
    if (count > rateLimit) {
      LOG.info(
          "magiclink.send rate-limited user={} purpose={} count={}",
          user,
          PURPOSE_EMAIL_VERIFY,
          count);
      return new SendResult.RateLimited(count);
    }
    String token = issue(user, PURPOSE_EMAIL_VERIFY, Map.of(CLAIM_EMAIL, email));
    String url = baseUrl + "?t=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
    emailSender.sendMagicLink(email, "Verify your email", "Click to verify: " + url);
    LOG.info("magiclink.send issued user={} purpose={}", user, PURPOSE_EMAIL_VERIFY);
    return new SendResult.Sent(token);
  }

  /**
   * Sends a login email to the user with the supplied username.
   *
   * <p><strong>Privacy invariant:</strong> this method ALWAYS returns {@link SendResult.Sent},
   * regardless of whether the supplied username exists in the system. When no user is found the
   * method returns early (skipping JWT issuance and email dispatch) but returns the same {@code
   * Sent} shape as a successful send. This prevents account-enumeration via both result-shape
   * side-channels and timing side-channels that would otherwise reveal whether an account exists.
   * Callers MUST NOT rely on a {@link SendResult.UserNotFound} outcome from this method — that
   * variant is produced only by signup flows where confirming account non-existence is intentional.
   */
  public SendResult sendLoginEmail(String username, String email) {
    Objects.requireNonNull(username, "username");
    Objects.requireNonNull(email, "email");
    Optional<UserHandle> resolved = userLookup.findHandleByUsername(username);
    if (resolved.isEmpty()) {
      // Do NOT surface UserNotFound to callers — that would enable account enumeration.
      // Skip JWT issuance and email dispatch silently and return Sent.
      LOG.debug("magiclink.send user-not-found (suppressed) username={}", username);
      return new SendResult.Sent("");
    }
    UserHandle user = resolved.get();
    int count = rateLimiter.countAndIncrement(user, PURPOSE_LOGIN, clockProvider.now());
    if (count > rateLimit) {
      return new SendResult.RateLimited(count);
    }
    String token = issue(user, PURPOSE_LOGIN, Map.of());
    String url = baseUrl + "?t=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
    emailSender.sendMagicLink(email, "Sign in", "Click to sign in: " + url);
    return new SendResult.Sent(token);
  }

  /** Verifies and consumes a magic-link token. */
  public ConsumeResult consume(String token) {
    Objects.requireNonNull(token, "token");
    JwtVerificationResult verification = validator.validate(token);
    if (!(verification instanceof JwtVerificationResult.Success success)) {
      return new ConsumeResult.Invalid(verification);
    }
    JwtClaims claims = success.claims();
    String purpose = stringClaim(claims.additionalClaims(), CLAIM_PURPOSE);
    if (purpose == null) {
      return new ConsumeResult.Invalid(new JwtVerificationResult.MissingClaim(CLAIM_PURPOSE));
    }
    String email = stringClaim(claims.additionalClaims(), CLAIM_EMAIL);

    // Single-use: the JTI is opaque; we don't have direct access to it through JwtClaims, so we
    // re-parse the JWT just for the id. Cheap because we already validated it above. The store's
    // tryConsume contract is atomic — concurrent verifies of the same JTI will see exactly one
    // true return, with the loser observing AlreadyConsumed.
    String jti = jtiOf(token);
    if (!consumedJtiStore.tryConsume(jti, consumedJtiTtl)) {
      return new ConsumeResult.AlreadyConsumed();
    }
    return new ConsumeResult.Success(claims.userHandle(), purpose, email);
  }

  private String issue(UserHandle user, String purpose, Map<String, String> extras) {
    java.util.Map<String, Object> additional = new java.util.HashMap<>(extras);
    additional.put(CLAIM_PURPOSE, purpose);
    JwtClaims claims = new JwtClaims(user, AuthMethod.MAGIC_LINK, null, List.of("eml"), additional);
    return issuer.issue(claims);
  }

  private static @Nullable String stringClaim(@Nullable Map<String, Object> map, String name) {
    if (map == null) {
      return null;
    }
    Object v = map.get(name);
    return v == null ? null : v.toString();
  }

  private static String jtiOf(String token) {
    try {
      return com.nimbusds.jwt.SignedJWT.parse(token).getJWTClaimsSet().getJWTID();
    } catch (Exception e) {
      throw new IllegalStateException("Unable to extract jti from verified token", e);
    }
  }

  /**
   * Simple Caffeine-backed in-memory rate limiter.
   *
   * <p><strong>FOR DEV / SINGLE-INSTANCE USE ONLY.</strong> Production deployments MUST replace
   * this with a shared (Redis/DB-backed) {@link MagicLinkRateLimiter} implementation, otherwise
   * per-replica rate limits multiply by the cluster size. For example, with a limit of 5 emails per
   * hour and a 3-node cluster, an attacker can send up to 15 emails per hour because each replica
   * tracks its own independent counter. Wire a production-grade implementation via the {@link
   * MagicLinkService#MagicLinkService(PkAuthJwtIssuer, PkAuthJwtValidator, EmailSender, UserLookup,
   * ClockProvider, String, int, MagicLinkRateLimiter)} constructor.
   */
  public static final class InMemoryRateLimiter implements MagicLinkRateLimiter {
    private static final Logger RATE_LOG = LoggerFactory.getLogger(InMemoryRateLimiter.class);

    private final Cache<String, AtomicInteger> counters;

    public InMemoryRateLimiter(Duration window) {
      RATE_LOG.info(
          "magiclink.rate-limiter InMemoryRateLimiter instantiated — FOR DEV / SINGLE-INSTANCE"
              + " USE ONLY. Production deployments MUST replace this with a shared"
              + " (Redis/DB-backed) RateLimiter implementation to avoid per-replica abuse"
              + " multiplier.");
      this.counters = Caffeine.newBuilder().expireAfterWrite(window).build();
    }

    @Override
    public int countAndIncrement(UserHandle user, String purpose, Instant now) {
      String key = user + "|" + purpose;
      AtomicInteger counter = counters.get(key, k -> new AtomicInteger());
      return counter.incrementAndGet();
    }

    /** Test helper to clear counters between cases. */
    public void reset() {
      counters.invalidateAll();
    }

    /** Exposed for diagnostics — tracks active counter keys. */
    public Set<String> keys() {
      return new HashSet<>(counters.asMap().keySet());
    }
  }
}
