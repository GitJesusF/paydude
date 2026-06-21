package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.user.UserResponse;
import com.jesusf.paydude.dto.user.UserResponseV2;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.exception.ResourceNotFoundException;
import com.jesusf.paydude.mapper.UserMapper;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.security.BreachedPasswordGuard;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Default {@link UserService} implementation — profile reads and password changes.
 *
 * <p>The class is {@code @Transactional(readOnly = true)}; {@link #changePassword} overrides
 * that with a writable, rollback-on-any-exception transaction.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserServiceImpl implements UserService {

  private final UserRepository userRepository;
  private final UserMapper userMapper;
  private final PasswordEncoder passwordEncoder;
  private final RefreshTokenService refreshTokenService;
  private final BreachedPasswordGuard breachedPasswordGuard;
  // Records PASSWORD_CHANGE success/failure to the security audit log. record(...) is REQUIRES_NEW +
  // fail-safe, so the FAILURE event survives this method's rollback on a current-password mismatch.
  private final SecurityAuditService securityAuditService;

  @Override
  public UserResponse getCurrentUser(Long userId) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));

    return userMapper.toResponse(user);
  }

  @Override
  public UserResponseV2 getCurrentUserV2(Long userId) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));

    return userMapper.toResponseV2(user);
  }

  @Override
  @Transactional(rollbackFor = Exception.class)
  public void changePassword(Long userId, String currentPassword, String newPassword) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));

    // Verify with `matches` — the constant-time comparison provided by BCryptPasswordEncoder.
    // On mismatch we throw BadCredentialsException: SecurityExceptionHandler maps it to 401 with
    // the same generic ProblemDetail as a failed login — we never tell the client whether it was
    // the old password that was wrong or something else.
    if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
      log.warn("Password change rejected for user {} — current password mismatch", userId);
      // A valid access token but the wrong current password — a notable signal (e.g. a stolen token
      // being probed). Survives the rollback from the throw below thanks to REQUIRES_NEW.
      securityAuditService.record(SecurityAuditEventType.PASSWORD_CHANGE, SecurityAuditOutcome.FAILURE,
          userId, null, "current password mismatch");
      throw new BadCredentialsException("Current password does not match");
    }

    // Reject a new password already exposed in a public breach corpus (NIST SP 800-63B §5.1.1.2).
    // Deliberately checked AFTER the current-password verification so a stolen access token cannot
    // turn this endpoint into a breach oracle. Fails open if HaveIBeenPwned is down.
    breachedPasswordGuard.assertNotBreached(newPassword);

    user.setPassword(passwordEncoder.encode(newPassword));
    // passwordChangedAt is what feeds the rotation policy (SecurityUser.isCredentialsNonExpired
    // and the JWT's credentialsExpireAt claim). Without advancing this field, a freshly changed
    // password would inherit the previous expiration window.
    user.setPasswordChangedAt(Instant.now());

    // Revoke ALL of the user's refresh-token families — every device is forced to re-login. This
    // is the hook RefreshTokenService.revokeAllForUser reserved for exactly this case. The access
    // token the client just used to reach here stays valid until its natural expiry (15 min), but
    // it can no longer be refreshed.
    refreshTokenService.revokeAllForUser(userId);

    securityAuditService.record(SecurityAuditEventType.PASSWORD_CHANGE, SecurityAuditOutcome.SUCCESS,
        userId, null, "password changed; all sessions revoked");
  }
}
