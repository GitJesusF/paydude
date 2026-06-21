package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.user.UserResponse;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.Role;
import com.jesusf.paydude.enums.SecurityAuditEventType;
import com.jesusf.paydude.enums.SecurityAuditOutcome;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.exception.BusinessException;
import com.jesusf.paydude.exception.ResourceNotFoundException;
import com.jesusf.paydude.mapper.UserMapper;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.security.BreachedPasswordGuard;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UserServiceImpl}.
 *
 * <p>The service is the read-only path that backs {@code GET /v1/users/me} and any future
 * profile lookups. Two contracts are pinned: a present user must be mapped to a UserResponse
 * via the injected {@link UserMapper}, and an absent user must surface as a domain
 * {@link ResourceNotFoundException} (not a Spring {@code EmptyResultDataAccessException} or a
 * raw {@code NullPointerException}) so the global advice can render a 404 with the project's
 * standard {@code ProblemDetail} shape.
 */
@ExtendWith(MockitoExtension.class)
class UserServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private UserMapper userMapper;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private RefreshTokenService refreshTokenService;

  @Mock
  private BreachedPasswordGuard breachedPasswordGuard;

  @Mock
  private SecurityAuditService securityAuditService;

  @InjectMocks
  private UserServiceImpl userService;

  @Test
  @DisplayName("Should return current user profile when user exists")
  void shouldReturnCurrentUserProfile() {
    Long userId = 1L;
    User mockUser = User.builder()
        .id(userId)
        .firstName("Jesus")
        .lastName("Dev")
        .email("jesus@test.com")
        .role(Role.ROLE_USER)
        .status(UserStatus.ACTIVE)
        .build();

    UserResponse expectedResponse = new UserResponse(
        userId, "Jesus", "Dev", "jesus@test.com", "ROLE_USER", "ACTIVE"
    );

    when(userRepository.findById(userId)).thenReturn(Optional.of(mockUser));
    when(userMapper.toResponse(mockUser)).thenReturn(expectedResponse);

    UserResponse actual = userService.getCurrentUser(userId);

    assertNotNull(actual);
    // Reference identity: the only way to obtain this instance is delegating to the mapper —
    // a service that built its own DTO would fail here.
    assertSame(expectedResponse, actual);
    verify(userRepository).findById(userId);
  }

  @Test
  @DisplayName("Should throw ResourceNotFoundException when the principal's user record is gone")
  void shouldThrowWhenUserNotFound() {
    // The JWT filter trusts claims and never re-reads the DB per request, so a token whose user
    // has since been deleted is a plausible scenario the service must translate cleanly.
    Long userId = 99L;
    when(userRepository.findById(userId)).thenReturn(Optional.empty());

    ResourceNotFoundException exception = assertThrows(
        ResourceNotFoundException.class,
        () -> userService.getCurrentUser(userId)
    );

    // The message is client-visible contract (it becomes the ProblemDetail detail field).
    assertEquals("User not found: 99", exception.getMessage());
    verify(userMapper, never()).toResponse(any());
  }

  @Nested
  @DisplayName("changePassword flow — verify current, rotate, revoke all sessions")
  class ChangePasswordFlow {

    @Test
    @DisplayName("happy path: updates password + passwordChangedAt and revokes every refresh family")
    void shouldChangePasswordAndRevokeAllSessions() {
      Long userId = 1L;
      User stored = User.builder()
          .id(userId)
          .email("u@test.com")
          .password("encoded-old-pass")
          .role(Role.ROLE_USER)
          .status(UserStatus.ACTIVE)
          .passwordChangedAt(Instant.parse("2025-01-01T00:00:00Z"))
          .build();

      when(userRepository.findById(userId)).thenReturn(Optional.of(stored));
      when(passwordEncoder.matches("plain-old", "encoded-old-pass")).thenReturn(true);
      when(passwordEncoder.encode("plain-new-12345")).thenReturn("encoded-new-pass");

      userService.changePassword(userId, "plain-old", "plain-new-12345");

      // No explicit save(): @Transactional + JPA dirty checking persist the mutation at commit.
      assertEquals("encoded-new-pass", stored.getPassword(),
          "stored password must be the BCrypt-encoded new value");
      assertTrue(stored.getPasswordChangedAt().isAfter(Instant.parse("2025-01-01T00:00:00Z")),
          "passwordChangedAt must advance to reflect the rotation");

      // Mass revocation: every refresh family dies. The current access token stays valid until
      // its natural expiry but can no longer be refreshed — an attacker already holding a
      // refresh token is locked out.
      verify(refreshTokenService).revokeAllForUser(userId);
      verify(securityAuditService).record(eq(SecurityAuditEventType.PASSWORD_CHANGE),
          eq(SecurityAuditOutcome.SUCCESS), eq(userId), isNull(), anyString());
    }

    @Test
    @DisplayName("rejects with BadCredentialsException when the current password does not match")
    void shouldRejectWhenCurrentPasswordWrong() {
      Long userId = 1L;
      User stored = User.builder()
          .id(userId)
          .password("encoded-real-pass")
          .build();

      when(userRepository.findById(userId)).thenReturn(Optional.of(stored));
      when(passwordEncoder.matches("wrong-attempt", "encoded-real-pass")).thenReturn(false);

      assertThrows(BadCredentialsException.class,
          () -> userService.changePassword(userId, "wrong-attempt", "plain-new-12345"));

      assertEquals("encoded-real-pass", stored.getPassword(),
          "password must remain unchanged when verification fails");
      verify(passwordEncoder, never()).encode(anyString());
      verify(refreshTokenService, never()).revokeAllForUser(any());
      // The FAILURE row survives the surrounding rollback via REQUIRES_NEW.
      verify(securityAuditService).record(eq(SecurityAuditEventType.PASSWORD_CHANGE),
          eq(SecurityAuditOutcome.FAILURE), eq(userId), isNull(), anyString());
    }

    @Test
    @DisplayName("rejects with BusinessException when the new password is in a known breach corpus")
    void shouldRejectWhenNewPasswordIsBreached() {
      Long userId = 1L;
      User stored = User.builder()
          .id(userId)
          .password("encoded-old-pass")
          .passwordChangedAt(Instant.parse("2025-01-01T00:00:00Z"))
          .build();

      when(userRepository.findById(userId)).thenReturn(Optional.of(stored));
      when(passwordEncoder.matches("plain-old", "encoded-old-pass")).thenReturn(true);
      // The guard runs AFTER the current-password check — otherwise the endpoint would become
      // a breach oracle for unauthenticated guesses.
      doThrow(new BusinessException("This password has appeared in a known data breach. Please choose a different one."))
          .when(breachedPasswordGuard).assertNotBreached("plain-new-12345");

      assertThrows(BusinessException.class,
          () -> userService.changePassword(userId, "plain-old", "plain-new-12345"));

      assertEquals("encoded-old-pass", stored.getPassword(),
          "password must remain unchanged when the new password is rejected");
      verify(passwordEncoder, never()).encode(anyString());
      verify(refreshTokenService, never()).revokeAllForUser(any());
    }

    @Test
    @DisplayName("rejects with ResourceNotFoundException when the user id is unknown")
    void shouldRejectWhenUserNotFound() {
      Long userId = 999L;
      when(userRepository.findById(userId)).thenReturn(Optional.empty());

      ResourceNotFoundException ex = assertThrows(ResourceNotFoundException.class,
          () -> userService.changePassword(userId, "any", "plain-new-12345"));
      assertEquals("User not found: 999", ex.getMessage());

      verify(passwordEncoder, never()).matches(anyString(), anyString());
      verify(refreshTokenService, never()).revokeAllForUser(any());
    }
  }
}
