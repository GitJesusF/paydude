package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.user.MfaRecoveryCodesResponse;
import com.jesusf.paydude.dto.user.MfaSetupResponse;
import com.jesusf.paydude.entity.MfaRecoveryCode;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.Role;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.exception.ResourceNotFoundException;
import com.jesusf.paydude.repository.MfaRecoveryCodeRepository;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.security.TotpService;
import com.jesusf.paydude.service.MfaService.MfaVerification;
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
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link MfaServiceImpl} — the TOTP enrollment lifecycle and the login-time code
 * verification primitive.
 *
 * <p>The cryptography itself is pinned by {@code TotpServiceTest} against the RFC vectors; here
 * {@code TotpService} is mocked and the contract under test is the lifecycle: the password gate
 * on setup/disable, the two-phase enrollment (a pending secret arms nothing until a code proves
 * the authenticator), the single-use guards (TOTP step + recovery code), and the audit rows for
 * the MFA_ENABLED/MFA_DISABLED transitions.
 */
@ExtendWith(MockitoExtension.class)
class MfaServiceTest {

  private static final Long USER_ID = 1L;
  private static final String RAW_PASSWORD = "S3cure!pass";
  private static final String ENCODED_PASSWORD = "encoded-bcrypt-hash";
  private static final String SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

  @Mock private UserRepository userRepository;
  @Mock private MfaRecoveryCodeRepository recoveryCodeRepository;
  @Mock private TotpService totpService;
  @Mock private PasswordEncoder passwordEncoder;
  @Mock private SecurityAuditService securityAuditService;

  private MfaServiceImpl mfaService;

  @BeforeEach
  void setUp() {
    // The fixture supplies the issuer ("PayDude") that setup() embeds in the otpauth URI.
    mfaService = new MfaServiceImpl(
        userRepository,
        recoveryCodeRepository,
        totpService,
        passwordEncoder,
        securityAuditService,
        SecurityPropertiesFixture.defaults()
    );
  }

  // MFA state varies per test: virgin (no secret), pending (secret without enabled), or
  // enrolled (both).
  private User user(boolean mfaEnabled, String mfaSecret) {
    return User.builder()
        .id(USER_ID)
        .firstName("Jesus").lastName("Dev")
        .email("jesus@test.com")
        .password(ENCODED_PASSWORD)
        .role(Role.ROLE_USER)
        .status(UserStatus.ACTIVE)
        .passwordChangedAt(Instant.now())
        .mfaEnabled(mfaEnabled)
        .mfaSecret(mfaSecret)
        .build();
  }

  @Nested
  @DisplayName("setup() — re-authentication gate and pending enrollment")
  class Setup {

    @Test
    @DisplayName("rejects a wrong password with the generic 401 and audits the attempt")
    void shouldRejectWrongPassword() {
      User user = user(false, null);
      when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
      when(passwordEncoder.matches("wrong", ENCODED_PASSWORD)).thenReturn(false);

      assertThrows(BadCredentialsException.class, () -> mfaService.setup(USER_ID, "wrong"));

      // A stolen token probing the password at the enrollment endpoint is exactly the signal the
      // audit trail must retain (the row survives the rollback via REQUIRES_NEW).
      verify(securityAuditService).record(
          SecurityAuditEventType.MFA_ENABLED, SecurityAuditOutcome.FAILURE,
          USER_ID, null, "password mismatch at setup");
      assertNull(user.getMfaSecret(), "no secret may be generated behind a failed password gate");
    }

    @Test
    @DisplayName("rejects setup while MFA is already enabled (no silent secret swap)")
    void shouldRejectWhenAlreadyEnabled() {
      when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user(true, SECRET)));
      when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);

      assertThrows(BusinessException.class, () -> mfaService.setup(USER_ID, RAW_PASSWORD));
    }

    @Test
    @DisplayName("stores the pending secret without arming MFA and returns the provisioning material")
    void shouldCreatePendingEnrollment() {
      User user = user(false, null);
      user.setMfaLastUsedStep(42L); // residue from a previous enrollment — must be cleared
      when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
      when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);
      when(totpService.generateSecret()).thenReturn(SECRET);
      when(totpService.provisioningUri("PayDude", "jesus@test.com", SECRET))
          .thenReturn("otpauth://totp/PayDude:jesus%40test.com?secret=" + SECRET);

      MfaSetupResponse response = mfaService.setup(USER_ID, RAW_PASSWORD);

      assertEquals(SECRET, response.secret());
      assertTrue(response.otpauthUri().startsWith("otpauth://totp/"));
      // Pending state: the secret persists via dirty checking, but login stays single-factor
      // until confirm() proves the authenticator produces valid codes.
      assertEquals(SECRET, user.getMfaSecret());
      assertFalse(user.isMfaEnabled(), "setup must never arm MFA by itself");
      assertNull(user.getMfaLastUsedStep(), "a new enrollment starts with a clean replay baseline");
    }
  }

  @Nested
  @DisplayName("confirm() — possession proof, activation, recovery codes")
  class Confirm {

    // confirm loads the user with findByIdForUpdate (PESSIMISTIC_WRITE): the row lock serializes
    // racing confirms so only one recovery-code batch can ever stay alive.

    @Test
    @DisplayName("rejects when there is no pending setup or MFA is already on")
    void shouldRejectWrongStates() {
      when(userRepository.findByIdForUpdate(USER_ID)).thenReturn(Optional.of(user(false, null)));
      assertThrows(BusinessException.class, () -> mfaService.confirm(USER_ID, "123456"),
          "no pending secret -> nothing to confirm");

      when(userRepository.findByIdForUpdate(USER_ID)).thenReturn(Optional.of(user(true, SECRET)));
      assertThrows(BusinessException.class, () -> mfaService.confirm(USER_ID, "123456"),
          "already enabled -> confirm is not re-runnable");
    }

    @Test
    @DisplayName("rejects an invalid code, audits the failure, and leaves MFA off")
    void shouldRejectInvalidCode() {
      User user = user(false, SECRET);
      when(userRepository.findByIdForUpdate(USER_ID)).thenReturn(Optional.of(user));
      when(totpService.findMatchingStep(SECRET, "000000")).thenReturn(OptionalLong.empty());

      assertThrows(BusinessException.class, () -> mfaService.confirm(USER_ID, "000000"));

      assertFalse(user.isMfaEnabled(), "a failed proof must never arm the second factor");
      verify(securityAuditService).record(
          SecurityAuditEventType.MFA_ENABLED, SecurityAuditOutcome.FAILURE,
          USER_ID, null, "invalid code at confirm");
      verifyNoInteractions(recoveryCodeRepository);
    }

    @Test
    @DisplayName("activates MFA, seeds the replay baseline, and issues 10 hashed recovery codes")
    void shouldActivateAndIssueRecoveryCodes() {
      User user = user(false, SECRET);
      when(userRepository.findByIdForUpdate(USER_ID)).thenReturn(Optional.of(user));
      when(totpService.findMatchingStep(SECRET, "123456")).thenReturn(OptionalLong.of(777L));

      MfaRecoveryCodesResponse response = mfaService.confirm(USER_ID, "123456");

      assertTrue(user.isMfaEnabled());
      // The replay baseline is seeded VIA THE ENTITY (not the login path's atomic UPDATE): the
      // confirmation code is burned for the first step-up without Hibernate's all-columns flush
      // clobbering the column with a stale value.
      assertEquals(777L, user.getMfaLastUsedStep(),
          "the confirmation code's step must seed the replay baseline");
      verify(userRepository, never()).markMfaStepUsed(anyLong(), anyLong());
      // 10 readable codes (unambiguous Base32 alphabet, groups of 4), shown exactly once.
      assertEquals(10, response.recoveryCodes().size());
      assertTrue(response.recoveryCodes().stream()
              .allMatch(code -> code.matches("[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}")),
          "codes must use the unambiguous Base32 alphabet in 4-char groups");
      assertEquals(10, response.recoveryCodes().stream().distinct().count(),
          "codes within a batch must be unique");

      // Hash-only persistence: 64 hex chars (SHA-256), never plaintext; and the previous batch
      // dies before the new one is seeded.
      verify(recoveryCodeRepository).deleteAllForUser(USER_ID);
      @SuppressWarnings("unchecked")
      ArgumentCaptor<List<MfaRecoveryCode>> savedCaptor = ArgumentCaptor.forClass(List.class);
      verify(recoveryCodeRepository).saveAll(savedCaptor.capture());
      assertEquals(10, savedCaptor.getValue().size());
      assertTrue(savedCaptor.getValue().stream()
              .allMatch(row -> row.getCodeHash().matches("[0-9a-f]{64}")),
          "only SHA-256 hex digests may reach the database");

      verify(securityAuditService).record(
          SecurityAuditEventType.MFA_ENABLED, SecurityAuditOutcome.SUCCESS,
          USER_ID, null, "totp second factor activated");
    }
  }

  @Nested
  @DisplayName("disable() — re-authentication gate, full cleanup, idempotency")
  class Disable {

    @Test
    @DisplayName("rejects a wrong password and audits — a bearer token alone cannot downgrade")
    void shouldRejectWrongPassword() {
      User user = user(true, SECRET);
      when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
      when(passwordEncoder.matches("wrong", ENCODED_PASSWORD)).thenReturn(false);

      assertThrows(BadCredentialsException.class, () -> mfaService.disable(USER_ID, "wrong"));

      assertTrue(user.isMfaEnabled(), "the second factor must survive a failed password gate");
      verify(securityAuditService).record(
          SecurityAuditEventType.MFA_DISABLED, SecurityAuditOutcome.FAILURE,
          USER_ID, null, "password mismatch at disable");
    }

    @Test
    @DisplayName("clears every trace of the enrollment and audits the downgrade")
    void shouldDisableCompletely() {
      User user = user(true, SECRET);
      user.setMfaLastUsedStep(777L);
      when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
      when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);

      mfaService.disable(USER_ID, RAW_PASSWORD);

      assertFalse(user.isMfaEnabled());
      assertNull(user.getMfaSecret());
      assertNull(user.getMfaLastUsedStep());
      verify(recoveryCodeRepository).deleteAllForUser(USER_ID);
      verify(securityAuditService).record(
          SecurityAuditEventType.MFA_DISABLED, SecurityAuditOutcome.SUCCESS,
          USER_ID, null, "totp second factor removed");
    }

    @Test
    @DisplayName("is idempotent: disabling a non-enrolled account returns quietly, with no audit noise")
    void shouldBeIdempotentWhenNotEnrolled() {
      when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user(false, null)));
      when(passwordEncoder.matches(RAW_PASSWORD, ENCODED_PASSWORD)).thenReturn(true);

      assertDoesNotThrow(() -> mfaService.disable(USER_ID, RAW_PASSWORD));

      // With no second factor to tear down there is no security event to record.
      verifyNoInteractions(securityAuditService);
    }
  }

  @Nested
  @DisplayName("verify() — TOTP single-use guard and recovery-code consumption")
  class Verify {

    @Test
    @DisplayName("accepts a fresh TOTP and advances the replay baseline atomically")
    void shouldAcceptFreshTotp() {
      User user = user(true, SECRET);
      when(totpService.findMatchingStep(SECRET, "123456")).thenReturn(OptionalLong.of(1000L));
      when(userRepository.markMfaStepUsed(USER_ID, 1000L)).thenReturn(1);

      assertEquals(MfaVerification.TOTP, mfaService.verify(user, "123456"));
    }

    @Test
    @DisplayName("rejects a replayed TOTP: cryptographically valid, but its step was already consumed")
    void shouldRejectReplayedTotp() {
      User user = user(true, SECRET);
      when(totpService.findMatchingStep(SECRET, "123456")).thenReturn(OptionalLong.of(1000L));
      // The UPDATE matches no row (mfa_last_used_step >= 1000). RFC 6238 §5.2: a code enters
      // once, even though the ±1 window would still accept it cryptographically.
      when(userRepository.markMfaStepUsed(USER_ID, 1000L)).thenReturn(0);

      assertEquals(MfaVerification.INVALID, mfaService.verify(user, "123456"));
    }

    @Test
    @DisplayName("rejects a wrong TOTP without touching the replay baseline")
    void shouldRejectWrongTotp() {
      User user = user(true, SECRET);
      when(totpService.findMatchingStep(SECRET, "000000")).thenReturn(OptionalLong.empty());

      assertEquals(MfaVerification.INVALID, mfaService.verify(user, "000000"));

      verify(userRepository, never()).markMfaStepUsed(anyLong(), anyLong());
    }

    @Test
    @DisplayName("redeems a recovery code once: canonical hash, atomic consume, second use fails")
    void shouldConsumeRecoveryCodeOnce() {
      User user = user(true, SECRET);
      // First redemption matches and marks the row used; the second matches 0 rows → INVALID.
      when(recoveryCodeRepository.consume(eq(USER_ID), anyString(), any(Instant.class)))
          .thenReturn(1, 0);

      assertEquals(MfaVerification.RECOVERY_CODE, mfaService.verify(user, "K7QW-2MNB-X4ZC"));
      assertEquals(MfaVerification.INVALID, mfaService.verify(user, "K7QW-2MNB-X4ZC"));

      // Canonicalization pinned without duplicating the impl's SHA-256: two spellings of the
      // same code (dashed / lowercase with spaces) must hash identically.
      ArgumentCaptor<String> hashCaptor = ArgumentCaptor.forClass(String.class);
      verify(recoveryCodeRepository, times(2)).consume(eq(USER_ID), hashCaptor.capture(), any());
      mfaService.verify(user, "k7qw 2mnb x4zc");
      verify(recoveryCodeRepository, times(3)).consume(eq(USER_ID), hashCaptor.capture(), any());
      assertEquals(hashCaptor.getAllValues().get(0), hashCaptor.getAllValues().get(2),
          "dashes, spaces and case must not change the hashed identity of a code");
      assertTrue(hashCaptor.getValue().matches("[0-9a-f]{64}"), "lookup must be by SHA-256 hex");
    }

    @Test
    @DisplayName("returns INVALID for null input or a user with no secret")
    void shouldRejectDegenerateInput() {
      assertEquals(MfaVerification.INVALID, mfaService.verify(user(true, SECRET), null));
      assertEquals(MfaVerification.INVALID, mfaService.verify(user(true, null), "123456"));
      verifyNoInteractions(totpService, recoveryCodeRepository);
    }
  }

  @Test
  @DisplayName("setup/confirm/disable surface 404 when the principal's user row no longer exists")
  void shouldRejectUnknownUser() {
    // A bearer token can outlive its deleted user; every lifecycle entry point must translate
    // the missing row into the domain 404 rather than an NPE.
    when(userRepository.findById(99L)).thenReturn(Optional.empty());
    when(userRepository.findByIdForUpdate(99L)).thenReturn(Optional.empty());

    assertThrows(ResourceNotFoundException.class, () -> mfaService.setup(99L, RAW_PASSWORD));
    assertThrows(ResourceNotFoundException.class, () -> mfaService.confirm(99L, "123456"));
    assertThrows(ResourceNotFoundException.class, () -> mfaService.disable(99L, RAW_PASSWORD));
  }
}
