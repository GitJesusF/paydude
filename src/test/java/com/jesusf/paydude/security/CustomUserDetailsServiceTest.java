package com.jesusf.paydude.security;

import com.jesusf.paydude.config.properties.SecurityProperties;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.Role;
import com.jesusf.paydude.enums.UserStatus;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.support.SecurityPropertiesFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CustomUserDetailsService}.
 *
 * <p>The service is the single point where the database is consulted during the login flow:
 * {@code DaoAuthenticationProvider} invokes {@code loadUserByUsername(email)} once per login
 * to resolve the user, and the resulting {@link SecurityUser} is reused as the
 * {@code Authentication} principal for the rest of the request. Two contracts are pinned:
 * (1) a missing user surfaces as {@link UsernameNotFoundException} (Spring's expected
 * exception type for this scenario), and (2) the credentials rotation policy is applied
 * exactly once, here, when constructing the principal.
 *
 * <p>{@code SecurityProperties} is a real record built through {@link SecurityPropertiesFixture},
 * not a mock — stubbing trivial accessors would be noise.
 */
@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

  @Mock
  private UserRepository userRepository;

  private CustomUserDetailsService customUserDetailsService;

  @BeforeEach
  void setUp() {
    // Rotation policy disabled by default (NIST SP 800-63B); tests for the active branch swap
    // in SecurityPropertiesFixture.withCredentialsExpiration(90).
    customUserDetailsService = new CustomUserDetailsService(
        userRepository, SecurityPropertiesFixture.defaults()
    );
  }

  @Test
  @DisplayName("Should load user details successfully when user exists")
  void shouldLoadUserByUsernameSuccessfully() {
    // The submitted email is deliberately messy: the service must canonicalize (trim +
    // lowercase) before hitting the repository, or the stub below would not match.
    String email = "jesus@test.com";
    String submittedEmail = "  Jesus@Test.COM  ";

    User mockUser = User.builder()
        .id(1L)
        .email(email)
        .password("encodedPassword")
        .firstName("Jesus")
        .lastName("Dev")
        .role(Role.ROLE_USER)
        .build();

    when(userRepository.findByEmail(email)).thenReturn(Optional.of(mockUser));

    UserDetails result = customUserDetailsService.loadUserByUsername(submittedEmail);

    assertNotNull(result);
    assertEquals(email, result.getUsername());
    assertEquals("encodedPassword", result.getPassword());

    verify(userRepository, times(1)).findByEmail(email);
  }

  @Test
  @DisplayName("Should throw UsernameNotFoundException when user does not exist")
  void shouldThrowExceptionWhenUserNotFound() {
    // DaoAuthenticationProvider later folds this into BadCredentialsException, so a missing
    // user and a wrong password are indistinguishable on the wire (no enumeration oracle).
    String email = "ghost@test.com";
    String submittedEmail = "  GHOST@Test.COM  ";

    when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

    assertThrows(UsernameNotFoundException.class, () -> customUserDetailsService.loadUserByUsername(submittedEmail));

    verify(userRepository, times(1)).findByEmail(email);
  }

  @Test
  @DisplayName("Should propagate the configured rotation policy into the SecurityUser — when "
      + "credentialsExpirationDays > 0, credentialsExpireAt is computed as passwordChangedAt + N days")
  void shouldApplyCredentialsRotationPolicyWhenEnabled() {
    SecurityProperties withRotation = SecurityPropertiesFixture.withCredentialsExpiration(90);
    customUserDetailsService = new CustomUserDetailsService(userRepository, withRotation);

    String email = "rotating@test.com";
    Instant passwordChangedAt = Instant.parse("2026-01-01T00:00:00Z");

    User mockUser = User.builder()
        .id(1L)
        .email(email)
        .password("encodedPassword")
        .firstName("Jesus")
        .lastName("Dev")
        .role(Role.ROLE_USER)
        .status(UserStatus.ACTIVE)
        .passwordChangedAt(passwordChangedAt)
        .build();

    when(userRepository.findByEmail(email)).thenReturn(Optional.of(mockUser));

    UserDetails result = customUserDetailsService.loadUserByUsername(email);

    SecurityUser principal = (SecurityUser) result;
    Instant expected = passwordChangedAt.plus(90, ChronoUnit.DAYS);
    assertEquals(expected, principal.credentialsExpireAt(),
        "credentialsExpireAt must be derived from passwordChangedAt + the configured window");
  }
}
