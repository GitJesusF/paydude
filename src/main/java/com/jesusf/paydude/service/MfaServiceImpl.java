package com.jesusf.paydude.service;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.dto.user.MfaRecoveryCodesResponse;
import com.jesusf.paydude.dto.user.MfaSetupResponse;
import com.jesusf.paydude.entity.MfaRecoveryCode;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.exception.ResourceNotFoundException;
import com.jesusf.paydude.repository.MfaRecoveryCodeRepository;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.security.TotpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.OptionalLong;

/**
 * Default {@link MfaService} implementation.
 *
 * <p>The class is {@code @Transactional(readOnly = true)}; every operation here writes, so each
 * method overrides with a rollback-on-any-exception transaction. State changes ride on dirty
 * checking except the two single-use guards, which are atomic UPDATEs
 * ({@code UserRepository.markMfaStepUsed}, {@code MfaRecoveryCodeRepository.consume}) so
 * concurrent submissions of the same proof cannot both win.
 *
 * <p>Wrong-code semantics differ by flow on purpose. At {@link #confirm} the caller is an
 * authenticated user failing a domain precondition — {@link BusinessException} (409), the
 * breach-screening precedent. During login ({@link #verify}) a wrong code is a failed
 * authentication — but this class only reports {@code INVALID} and lets
 * {@code AuthServiceImpl.verifyMfa} own the 401, the lockout count, the metric and the audit row,
 * keeping every login-failure side-effect in one file.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MfaServiceImpl implements MfaService {

  // 10 codes of 12 chars from a 32-symbol alphabet = 60 bits of entropy each — far beyond online
  // guessing under the IP throttle + lockout, and enough that SHA-256 (not BCrypt) is the right
  // storage hash: there is nothing low-entropy to crack offline (same argument as refresh tokens).
  private static final int RECOVERY_CODE_COUNT = 10;
  private static final int RECOVERY_CODE_GROUPS = 3;
  private static final int RECOVERY_CODE_GROUP_LENGTH = 4;
  // The Base32 alphabet (RFC 4648): no 0/O, 1/l/I, 8/9 look-alikes — these codes get read off a
  // printout and typed by a stressed user who just lost their phone.
  private static final String RECOVERY_CODE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  private final UserRepository userRepository;
  private final MfaRecoveryCodeRepository recoveryCodeRepository;
  private final TotpService totpService;
  private final PasswordEncoder passwordEncoder;
  private final SecurityAuditService securityAuditService;
  private final SecurityProperties securityProperties;

  private final SecureRandom secureRandom = new SecureRandom();

  @Override
  @Transactional(rollbackFor = Exception.class)
  public MfaSetupResponse setup(Long userId, String password) {
    User user = loadUser(userId);
    requirePassword(user, password, SecurityAuditEventType.MFA_ENABLED, "password mismatch at setup");

    // Once armed, the secret can only be replaced through disable (password) + a fresh enrollment
    // (code proof). Allowing setup to overwrite an ACTIVE secret would let this endpoint silently
    // swap the second factor without ever proving possession of the old one.
    if (user.isMfaEnabled()) {
      throw new BusinessException("MFA is already enabled; disable it before re-enrolling");
    }

    String secret = totpService.generateSecret();
    // Pending state: secret present, mfaEnabled still false. Re-running setup replaces a previous
    // pending secret (the user re-scanned), and clearing the replay baseline keeps the new
    // enrollment independent of any earlier one.
    user.setMfaSecret(secret);
    user.setMfaLastUsedStep(null);

    log.info("MFA setup started for user {}", userId);
    return new MfaSetupResponse(
        secret,
        totpService.provisioningUri(securityProperties.mfa().issuer(), user.getEmail(), secret)
    );
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public MfaRecoveryCodesResponse confirm(Long userId, String code) {
    // PESSIMISTIC_WRITE: confirm is read-check-activate (pending secret -> code proof -> arm MFA
    // + replace the recovery-code batch). Without the row lock, two racing confirms both see
    // mfaEnabled=false and both persist a 10-code batch — 20 live recovery codes. The lock
    // serializes them; the loser re-reads the row already armed and gets the 409 below. Safe to
    // hold across record(...): the REQUIRES_NEW audit write touches security_audit_events only.
    User user = userRepository.findByIdForUpdate(userId)
        .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));

    if (user.isMfaEnabled()) {
      throw new BusinessException("MFA is already enabled");
    }
    if (user.getMfaSecret() == null) {
      throw new BusinessException("No pending MFA setup to confirm");
    }

    OptionalLong matchedStep = totpService.findMatchingStep(user.getMfaSecret(), code);
    if (matchedStep.isEmpty()) {
      securityAuditService.record(SecurityAuditEventType.MFA_ENABLED, SecurityAuditOutcome.FAILURE,
          userId, null, "invalid code at confirm");
      throw new BusinessException("Invalid verification code");
    }

    // The matched step seeds the replay baseline, so the very first login cannot reuse the
    // confirmation code. Set through the entity, NOT the atomic UPDATE used at login: MFA is not
    // armed yet, so there is no concurrent verification to race — and mixing a bulk UPDATE with a
    // dirty entity in the same transaction would clobber the column at flush (Hibernate writes
    // every column with the entity's stale in-memory value).
    user.setMfaEnabled(true);
    user.setMfaLastUsedStep(matchedStep.getAsLong());

    // Stale codes from any earlier enrollment die here; the fresh batch is persisted hash-only.
    recoveryCodeRepository.deleteAllForUser(userId);
    List<String> recoveryCodes = generateRecoveryCodes();
    recoveryCodeRepository.saveAll(recoveryCodes.stream()
        .map(rawCode -> MfaRecoveryCode.builder()
            .userId(userId)
            .codeHash(sha256Hex(canonicalize(rawCode)))
            .build())
        .toList());

    securityAuditService.record(SecurityAuditEventType.MFA_ENABLED, SecurityAuditOutcome.SUCCESS,
        userId, null, "totp second factor activated");
    log.info("MFA enabled for user {}", userId);
    return new MfaRecoveryCodesResponse(recoveryCodes);
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public void disable(Long userId, String password) {
    User user = loadUser(userId);
    requirePassword(user, password, SecurityAuditEventType.MFA_DISABLED, "password mismatch at disable");

    // Idempotent like logout: there is nothing useful to report about disabling an account that
    // was never enrolled, and the audit row is only written when a second factor actually fell.
    boolean wasEnrolled = user.isMfaEnabled() || user.getMfaSecret() != null;
    user.setMfaEnabled(false);
    user.setMfaSecret(null);
    user.setMfaLastUsedStep(null);
    recoveryCodeRepository.deleteAllForUser(userId);

    if (wasEnrolled) {
      securityAuditService.record(SecurityAuditEventType.MFA_DISABLED, SecurityAuditOutcome.SUCCESS,
          userId, null, "totp second factor removed");
      log.info("MFA disabled for user {}", userId);
    }
  }

  @Override
  @Transactional(rollbackFor = Exception.class, propagation = Propagation.REQUIRES_NEW)
  public MfaVerification verify(User user, String code) {
    // REQUIRES_NEW so the row lock taken by markMfaStepUsed is RELEASED here, before the caller's
    // transaction runs recordSuccess (REQUIRES_NEW on the same users row) — joined to the login
    // transaction, that inner UPDATE would block on our uncommitted one while we wait for it to
    // return: a same-thread deadlock. Side-effect, accepted and arguably correct: a verified
    // proof stays consumed even if the surrounding login later fails to mint tokens.
    if (code == null || user.getMfaSecret() == null) {
      return MfaVerification.INVALID;
    }

    String trimmed = code.trim();
    // Shape discriminates the proof kind: exactly 6 digits is a TOTP, anything else is treated as
    // a recovery code. No recovery code is 6 characters long, so the two spaces cannot collide.
    if (trimmed.length() == TotpService.CODE_DIGITS) {
      OptionalLong matchedStep = totpService.findMatchingStep(user.getMfaSecret(), trimmed);
      if (matchedStep.isEmpty()) {
        return MfaVerification.INVALID;
      }
      // RFC 6238 §5.2: a code is single-use even inside the acceptance window. Zero rows means
      // this step was already redeemed — a replay (or its concurrent race loser), not a login.
      if (userRepository.markMfaStepUsed(user.getId(), matchedStep.getAsLong()) == 0) {
        log.warn("Replayed TOTP code rejected for user {}", user.getId());
        return MfaVerification.INVALID;
      }
      return MfaVerification.TOTP;
    }

    // Recovery path: hash the canonical form and consume atomically — valid exactly once.
    int consumed = recoveryCodeRepository.consume(
        user.getId(), sha256Hex(canonicalize(trimmed)), Instant.now());
    if (consumed == 1) {
      log.info("MFA recovery code redeemed for user {}", user.getId());
      return MfaVerification.RECOVERY_CODE;
    }
    return MfaVerification.INVALID;
  }

  // -----------------------------------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------------------------------

  private User loadUser(Long userId) {
    return userRepository.findById(userId)
        .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));
  }

  /**
   * Re-authentication gate for {@code setup}/{@code disable} (OWASP ASVS v4 §2.4.5): constant-time
   * BCrypt verification, an audit row that survives this transaction's rollback (REQUIRES_NEW
   * inside {@code record}), and the same generic 401 as a failed login.
   */
  private void requirePassword(User user, String password,
                               SecurityAuditEventType auditType, String auditDetail) {
    if (!passwordEncoder.matches(password, user.getPassword())) {
      log.warn("MFA management rejected for user {} — current password mismatch", user.getId());
      securityAuditService.record(auditType, SecurityAuditOutcome.FAILURE,
          user.getId(), null, auditDetail);
      throw new BadCredentialsException("Current password does not match");
    }
  }

  /** Builds the displayed batch, e.g. {@code K7QW-2MNB-X4ZC} — groups purely for readability. */
  private List<String> generateRecoveryCodes() {
    List<String> codes = new ArrayList<>(RECOVERY_CODE_COUNT);
    for (int i = 0; i < RECOVERY_CODE_COUNT; i++) {
      StringBuilder code = new StringBuilder();
      for (int group = 0; group < RECOVERY_CODE_GROUPS; group++) {
        if (group > 0) {
          code.append('-');
        }
        for (int c = 0; c < RECOVERY_CODE_GROUP_LENGTH; c++) {
          code.append(RECOVERY_CODE_ALPHABET.charAt(secureRandom.nextInt(RECOVERY_CODE_ALPHABET.length())));
        }
      }
      codes.add(code.toString());
    }
    return codes;
  }

  /**
   * Canonical form hashed at issuance and at redemption: upper-case, separators stripped — the
   * user may type the code with or without the display dashes, in any case. {@link Locale#ROOT}
   * keeps the mapping locale-independent (a Turkish default locale maps {@code i} to {@code İ},
   * which would hash a correctly-typed code into garbage) — same rule as {@code EmailNormalizer}.
   */
  private static String canonicalize(String rawCode) {
    return rawCode.replaceAll("[\\s-]", "").toUpperCase(Locale.ROOT);
  }

  /** SHA-256 hex digest, same convention as {@code refresh_tokens.token_hash}. */
  private static String sha256Hex(String value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 not available", e);
    }
  }
}
