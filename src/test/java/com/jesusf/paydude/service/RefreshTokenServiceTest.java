package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.entity.RefreshToken;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.repository.RefreshTokenRepository;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.service.RefreshTokenService.IssuedRefreshToken;
import com.jesusf.paydude.service.RefreshTokenService.RotatedTokens;
import com.jesusf.paydude.support.SecurityPropertiesFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RefreshTokenServiceImpl}.
 *
 * <p>The service is the trust boundary for refresh-token authentication. Every branch of
 * {@code rotate()} maps to a distinct security outcome (success, reuse-detection, expired, user
 * suspended, unknown token), and every one of those branches has to be pinned with a direct test
 * — drift here is exactly the class of bug that lets an attacker keep using a stolen token after
 * the legitimate client thought they had refreshed past it.
 */
@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

  private static final long USER_ID = 42L;
  private static final UUID FAMILY_ID = UUID.fromString("11111111-2222-3333-4444-555555555555");
  private static final String CLIENT_IP = "203.0.113.42";
  private static final String USER_AGENT = "PayDudeAcceptanceTest/1.0";
  private static final Duration TTL = Duration.ofDays(7);

  @Mock
  private RefreshTokenRepository refreshTokenRepository;

  @Mock
  private UserRepository userRepository;

  @Mock
  private RefreshTokenFamilyRevocationService familyRevocationService;

  @Mock
  private SecurityAuditService securityAuditService;

  private SecurityProperties securityProperties;
  private RefreshTokenServiceImpl service;

  @BeforeEach
  void setUp() {
    // The fixture default refresh TTL is 7 days, matching the local TTL used to seed rows; the
    // assertions never depend on its exact value.
    securityProperties = SecurityPropertiesFixture.defaults();
    service = new RefreshTokenServiceImpl(
        refreshTokenRepository, userRepository, securityProperties, familyRevocationService,
        securityAuditService
    );
  }

  // -----------------------------------------------------------------------------------------------
  // deleteExpired — bulk delete behind the scheduled cleanup job (ExpiredDataCleanupJob)
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("deleteExpired — bulk-deletes tokens past their lifetime")
  class DeleteExpired {

    @Test
    @DisplayName("delegates to the repository with the given cutoff and returns the deleted count")
    void delegatesToRepository() {
      Instant cutoff = Instant.parse("2026-01-01T00:00:00Z");
      when(refreshTokenRepository.deleteByExpiresAtBefore(cutoff)).thenReturn(4);

      int deleted = service.deleteExpired(cutoff);

      assertEquals(4, deleted, "the count must be propagated from the repository verbatim");
      verify(refreshTokenRepository).deleteByExpiresAtBefore(cutoff);
    }
  }

  // -----------------------------------------------------------------------------------------------
  // issueNewFamily
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("issueNewFamily — persists a row, returns raw token + expiry")
  class IssueNewFamily {

    @Test
    @DisplayName("persists the row with expected fields and returns the raw token")
    void persistsRowAndReturnsRaw() {
      stubSaveReturnsAssignedId();

      IssuedRefreshToken issued = service.issueNewFamily(USER_ID, CLIENT_IP, USER_AGENT);

      ArgumentCaptor<RefreshToken> saved = ArgumentCaptor.forClass(RefreshToken.class);
      verify(refreshTokenRepository).save(saved.capture());
      RefreshToken row = saved.getValue();

      assertEquals(USER_ID, row.getUserId());
      assertNotNull(row.getFamilyId(), "every issuance must start a new family");
      assertNotNull(row.getTokenHash(), "the hash is what we persist; raw never");
      assertEquals(64, row.getTokenHash().length(), "SHA-256 hex digest is exactly 64 chars");
      assertEquals(CLIENT_IP, row.getCreatedFromIp());
      assertEquals(USER_AGENT, row.getUserAgent());
      assertNull(row.getRevokedAt(), "freshly issued tokens are active");
      assertTrue(row.getExpiresAt().isAfter(row.getIssuedAt()), "expiresAt > issuedAt invariant");

      assertNotNull(issued.rawToken(), "raw token must be returned to the caller");
      assertNotEquals(row.getTokenHash(), issued.rawToken(),
          "the raw must differ from the hash — otherwise the hashing is broken");
      assertEquals(row.getExpiresAt(), issued.expiresAt(), "expiry returned matches the row");
    }

    @Test
    @DisplayName("two consecutive issuances produce distinct tokens and distinct families")
    void successiveIssuancesAreDistinct() {
      stubSaveReturnsAssignedId();

      IssuedRefreshToken a = service.issueNewFamily(USER_ID, CLIENT_IP, USER_AGENT);
      IssuedRefreshToken b = service.issueNewFamily(USER_ID, CLIENT_IP, USER_AGENT);

      // A collision here would be a statistical miracle, not a bug — this is a sanity check
      // that the right branch executed.
      assertNotEquals(a.rawToken(), b.rawToken(),
          "two SecureRandom 256-bit draws must differ");

      ArgumentCaptor<RefreshToken> rows = ArgumentCaptor.forClass(RefreshToken.class);
      verify(refreshTokenRepository, times(2)).save(rows.capture());
      assertNotEquals(rows.getAllValues().get(0).getFamilyId(),
          rows.getAllValues().get(1).getFamilyId(),
          "issueNewFamily must mint a fresh family every time");
    }
  }

  // -----------------------------------------------------------------------------------------------
  // rotate — the core of the security model
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("rotate — single-use rotation with reuse detection")
  class Rotate {

    @Test
    @DisplayName("happy path: marks old revoked, issues new in same family, returns new raw token")
    void happyPath() {
      // The exact hash the service computes is irrelevant to these branches.
      RefreshToken existing = activeToken();
      stubSaveReturnsAssignedId();
      when(refreshTokenRepository.findByTokenHashForUpdate(any()))
          .thenReturn(Optional.of(existing));
      when(userRepository.findById(USER_ID)).thenReturn(Optional.of(activeUser()));

      RotatedTokens rotated = service.rotate("any-raw-presented-by-client", CLIENT_IP, USER_AGENT);

      assertNotNull(rotated.rawRefreshToken(), "rotation must return a new raw token");
      assertEquals(USER_ID, rotated.userId());
      assertNotNull(existing.getRevokedAt(), "presented token must be marked revoked");
      assertNotNull(existing.getReplacedByTokenId(),
          "presented token must link forward to the new row");
    }

    @Test
    @DisplayName("reuse detection: presenting an already-revoked token revokes the whole family")
    void reuseDetectionRevokesFamily() {
      RefreshToken alreadyRevoked = activeToken();
      alreadyRevoked.setRevokedAt(Instant.now().minusSeconds(60));
      when(refreshTokenRepository.findByTokenHashForUpdate(any()))
          .thenReturn(Optional.of(alreadyRevoked));
      when(familyRevocationService.revokeFamilyForReuseDetection(eq(USER_ID), eq(FAMILY_ID), any()))
          .thenReturn(3);

      BadCredentialsException ex = assertThrows(BadCredentialsException.class,
          () -> service.rotate("any-raw-string", CLIENT_IP, USER_AGENT));
      // Server-log-only message; the client sees the generic 401.
      assertEquals("Refresh token reuse detected", ex.getMessage());

      verify(familyRevocationService).revokeFamilyForReuseDetection(eq(USER_ID), eq(FAMILY_ID), any());
      // No new token may be persisted on this branch.
      verify(refreshTokenRepository, never()).save(any());
      verify(securityAuditService).record(eq(SecurityAuditEventType.TOKEN_REUSE_DETECTED),
          eq(SecurityAuditOutcome.FAILURE), eq(USER_ID), isNull(), anyString());
    }

    @Test
    @DisplayName("expired token: rejects without revoking the family")
    void expiredTokenIsRejected() {
      RefreshToken expired = activeToken();
      expired.setExpiresAt(Instant.now().minusSeconds(1));
      when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.of(expired));

      assertThrows(BadCredentialsException.class,
          () -> service.rotate("raw", CLIENT_IP, USER_AGENT));
      verify(refreshTokenRepository, never()).revokeFamily(anyLong(), any(), any());
      verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    @DisplayName("unknown token: rejects without touching any other row")
    void unknownTokenIsRejected() {
      when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.empty());

      assertThrows(BadCredentialsException.class,
          () -> service.rotate("never-issued", CLIENT_IP, USER_AGENT));
      verify(refreshTokenRepository, never()).save(any());
      verify(refreshTokenRepository, never()).revokeFamily(anyLong(), any(), any());
    }

    @Test
    @DisplayName("user is no longer ACTIVE: rejects with DisabledException")
    void inactiveUserIsRejected() {
      when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.of(activeToken()));
      User suspended = activeUser();
      suspended.setStatus(UserStatus.SUSPENDED);
      when(userRepository.findById(USER_ID)).thenReturn(Optional.of(suspended));

      assertThrows(DisabledException.class,
          () -> service.rotate("raw", CLIENT_IP, USER_AGENT));
      verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    @DisplayName("user is LOCKED: rejects with LockedException (423), the same mapping as login")
    void lockedUserIsRejectedAsLocked() {
      // LOCKED has its own signal (423) at login and in the JWT filter; folding it into the
      // generic Disabled 403 would break the state→status mapping across routes.
      when(refreshTokenRepository.findByTokenHashForUpdate(any())).thenReturn(Optional.of(activeToken()));
      User locked = activeUser();
      locked.setStatus(UserStatus.LOCKED);
      when(userRepository.findById(USER_ID)).thenReturn(Optional.of(locked));

      assertThrows(LockedException.class,
          () -> service.rotate("raw", CLIENT_IP, USER_AGENT));
      verify(refreshTokenRepository, never()).save(any());
    }
  }

  // -----------------------------------------------------------------------------------------------
  // revokeFamily — idempotent
  // -----------------------------------------------------------------------------------------------

  @Nested
  @DisplayName("revokeFamily — idempotent revocation")
  class RevokeFamily {

    @Test
    @DisplayName("known token: revokes the family for that user")
    void revokesFamilyWhenTokenKnown() {
      RefreshToken known = activeToken();
      when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(known));
      // The family had live tokens: the bulk UPDATE revokes >0 rows, which is why it is audited.
      when(refreshTokenRepository.revokeFamily(eq(USER_ID), eq(FAMILY_ID), any(Instant.class)))
          .thenReturn(1);

      service.revokeFamily("the-raw-token");

      verify(refreshTokenRepository).revokeFamily(eq(USER_ID), eq(FAMILY_ID), any(Instant.class));
      verify(refreshTokenRepository, never()).save(any());
      verify(securityAuditService).record(eq(SecurityAuditEventType.LOGOUT),
          eq(SecurityAuditOutcome.SUCCESS), eq(USER_ID), isNull(), isNull());
    }

    @Test
    @DisplayName("re-presented token of an already-dead family: revokes nothing, audits nothing")
    void doesNotAuditWhenFamilyAlreadyRevoked() {
      // Re-logout with the same token: the row exists but the family is already dead, so the
      // bulk UPDATE touches nothing. With no session to end there is no LOGOUT event — retries
      // must not pile up duplicate audit rows.
      RefreshToken known = activeToken();
      when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(known));
      when(refreshTokenRepository.revokeFamily(eq(USER_ID), eq(FAMILY_ID), any(Instant.class)))
          .thenReturn(0);

      service.revokeFamily("the-raw-token");

      verify(securityAuditService, never()).record(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("unknown token: no-op, no exception")
    void noOpWhenTokenUnknown() {
      when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

      service.revokeFamily("never-issued");
      verify(refreshTokenRepository, never()).revokeFamily(anyLong(), any(), any());
    }

    @Test
    @DisplayName("null or blank token: no-op")
    void nullOrBlankIsNoOp() {
      service.revokeFamily(null);
      service.revokeFamily("");
      service.revokeFamily("   ");
      verify(refreshTokenRepository, never()).findByTokenHash(any());
      verify(refreshTokenRepository, never()).revokeFamily(anyLong(), any(), any());
    }
  }

  // -----------------------------------------------------------------------------------------------
  // revokeAllForUser — bulk revocation hook
  // -----------------------------------------------------------------------------------------------

  @Test
  @DisplayName("revokeAllForUser delegates to the repository with the current instant")
  void revokeAllForUserDelegates() {
    service.revokeAllForUser(USER_ID);
    verify(refreshTokenRepository).revokeAllByUser(eq(USER_ID), any(Instant.class));
  }

  // -----------------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------------

  /**
   * Returns a "fresh" {@link RefreshToken} as if just inserted: active, in the canonical family,
   * with a stable but plausible hash. Tests that need to mutate fields (set revokedAt, expiresAt)
   * receive their own instance via {@link #activeToken()}.
   */
  private RefreshToken activeToken() {
    return RefreshToken.builder()
        .id(100L)
        .tokenHash("a".repeat(64))
        .userId(USER_ID)
        .familyId(FAMILY_ID)
        .issuedAt(Instant.now().minusSeconds(60))
        .expiresAt(Instant.now().plus(TTL))
        .build();
  }

  private User activeUser() {
    return User.builder()
        .id(USER_ID)
        .email("u@test.com")
        .status(UserStatus.ACTIVE)
        .build();
  }

  /** Stubs {@code save()} so it stamps an id on the input — closer to JPA's real behaviour. */
  private void stubSaveReturnsAssignedId() {
    AtomicLong idCounter = new AtomicLong(1);
    when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(inv -> {
      RefreshToken arg = inv.getArgument(0);
      arg.setId(idCounter.getAndIncrement());
      return arg;
    });
  }
}
