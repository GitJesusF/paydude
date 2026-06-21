package com.jesusf.paydude.security;

import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.enums.Role;
import com.jesusf.paydude.enums.UserStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link SecurityUser}.
 *
 * <p>The four boolean checks ({@code isEnabled}, {@code isAccountNonLocked},
 * {@code isAccountNonExpired}, {@code isCredentialsNonExpired}) are the contract Spring Security
 * relies on to translate a {@link UserStatus} into the right exception (and therefore the right
 * HTTP status). Getting any of them wrong silently degrades the whole authentication pipeline,
 * so they deserve direct, exhaustive coverage rather than indirect coverage through filter tests.
 *
 * <p>Plain JUnit, no mocks: the record is immutable and has no collaborators, so each test builds
 * a literal instance and asserts on the result.
 */
class SecurityUserTest {

  @Nested
  @DisplayName("isEnabled() — only ACTIVE users may use the API")
  class IsEnabled {

    @Test
    @DisplayName("returns true when status is ACTIVE")
    void returnsTrueForActive() {
      assertTrue(buildUser(UserStatus.ACTIVE).isEnabled());
    }

    @Test
    @DisplayName("returns false when status is SUSPENDED — the user will receive 403 via DisabledException")
    void returnsFalseForSuspended() {
      assertFalse(buildUser(UserStatus.SUSPENDED).isEnabled());
    }

    @Test
    @DisplayName("returns false when status is CLOSED — same DisabledException path as SUSPENDED")
    void returnsFalseForClosed() {
      assertFalse(buildUser(UserStatus.CLOSED).isEnabled());
    }

    @Test
    @DisplayName("returns false when status is LOCKED — locked users also fail isEnabled, but the framework "
        + "evaluates isAccountNonLocked first so the response surfaces as 423 Locked")
    void returnsFalseForLocked() {
      assertFalse(buildUser(UserStatus.LOCKED).isEnabled());
    }
  }

  @Nested
  @DisplayName("isAccountNonLocked() — only LOCKED status triggers the lock check")
  class IsAccountNonLocked {

    @Test
    @DisplayName("returns false when status is LOCKED")
    void returnsFalseForLocked() {
      assertFalse(buildUser(UserStatus.LOCKED).isAccountNonLocked());
    }

    @Test
    @DisplayName("returns true for every non-LOCKED status (ACTIVE, SUSPENDED, CLOSED)")
    void returnsTrueForNonLockedStatuses() {
      // Exhaustive over the enum: adding a status forces an explicit decision here.
      assertTrue(buildUser(UserStatus.ACTIVE).isAccountNonLocked());
      assertTrue(buildUser(UserStatus.SUSPENDED).isAccountNonLocked());
      assertTrue(buildUser(UserStatus.CLOSED).isAccountNonLocked());
    }
  }

  @Nested
  @DisplayName("isAccountNonExpired() — null means \"never expires\", otherwise compares against the clock")
  class IsAccountNonExpired {

    @Test
    @DisplayName("returns true when accountExpiresAt is null (default for retail users)")
    void returnsTrueWhenAccountExpiresAtIsNull() {
      SecurityUser user = buildUser(UserStatus.ACTIVE, null, null);
      assertTrue(user.isAccountNonExpired());
    }

    @Test
    @DisplayName("returns true when accountExpiresAt is in the future")
    void returnsTrueWhenAccountExpiresAtIsInFuture() {
      Instant tomorrow = Instant.now().plus(1, ChronoUnit.DAYS);
      SecurityUser user = buildUser(UserStatus.ACTIVE, tomorrow, null);
      assertTrue(user.isAccountNonExpired());
    }

    @Test
    @DisplayName("returns false when accountExpiresAt is in the past — token holder will receive 401 via "
        + "AccountExpiredException, even if the JWT itself is still cryptographically valid")
    void returnsFalseWhenAccountExpiresAtIsInPast() {
      Instant yesterday = Instant.now().minus(1, ChronoUnit.DAYS);
      SecurityUser user = buildUser(UserStatus.ACTIVE, yesterday, null);
      assertFalse(user.isAccountNonExpired());
    }
  }

  @Nested
  @DisplayName("isCredentialsNonExpired() — null disables rotation policy, otherwise compares against the clock")
  class IsCredentialsNonExpired {

    @Test
    @DisplayName("returns true when credentialsExpireAt is null (rotation policy disabled, NIST default)")
    void returnsTrueWhenCredentialsExpireAtIsNull() {
      SecurityUser user = buildUser(UserStatus.ACTIVE, null, null);
      assertTrue(user.isCredentialsNonExpired());
    }

    @Test
    @DisplayName("returns true when credentialsExpireAt is in the future")
    void returnsTrueWhenCredentialsExpireAtIsInFuture() {
      Instant nextMonth = Instant.now().plus(30, ChronoUnit.DAYS);
      SecurityUser user = buildUser(UserStatus.ACTIVE, null, nextMonth);
      assertTrue(user.isCredentialsNonExpired());
    }

    @Test
    @DisplayName("returns false when credentialsExpireAt is in the past — the user must rotate the password "
        + "before logging in again")
    void returnsFalseWhenCredentialsExpireAtIsInPast() {
      Instant yesterday = Instant.now().minus(1, ChronoUnit.DAYS);
      SecurityUser user = buildUser(UserStatus.ACTIVE, null, yesterday);
      assertFalse(user.isCredentialsNonExpired());
    }
  }

  @Nested
  @DisplayName("fromEntity() factories — the only place the rotation policy is computed")
  class FromEntity {

    @Test
    @DisplayName("fromEntity(user) leaves credentialsExpireAt null — rotation policy off")
    void fromEntitySingleArgDisablesRotation() {
      User entity = sampleEntity(Instant.now());

      SecurityUser result = SecurityUser.fromEntity(entity);

      assertNull(result.credentialsExpireAt(),
          "Single-arg factory must keep rotation disabled regardless of passwordChangedAt");
    }

    @Test
    @DisplayName("fromEntity(user, 0) treats 0 as 'policy disabled' — credentialsExpireAt stays null")
    void fromEntityWithZeroDaysDisablesRotation() {
      User entity = sampleEntity(Instant.now());

      SecurityUser result = SecurityUser.fromEntity(entity, 0);

      assertNull(result.credentialsExpireAt());
    }

    @Test
    @DisplayName("fromEntity(user, 90) computes credentialsExpireAt = passwordChangedAt + 90 days")
    void fromEntityWithPositiveDaysComputesExpiry() {
      Instant changedAt = Instant.parse("2026-01-01T00:00:00Z");
      User entity = sampleEntity(changedAt);

      SecurityUser result = SecurityUser.fromEntity(entity, 90);

      Instant expected = changedAt.plus(90, ChronoUnit.DAYS);
      assertEquals(expected, result.credentialsExpireAt());
    }

    @Test
    @DisplayName("fromEntity(user, 90) keeps credentialsExpireAt null when passwordChangedAt is null — "
        + "guards against NPE for users created before the rotation column existed")
    void fromEntityHandlesMissingPasswordChangedAt() {
      User entity = sampleEntity(null);

      SecurityUser result = SecurityUser.fromEntity(entity, 90);

      assertNull(result.credentialsExpireAt());
    }

    @Test
    @DisplayName("fromEntity() copies role into a single SimpleGrantedAuthority — Spring Security's "
        + "expected shape for hasRole() / hasAuthority() checks downstream")
    void fromEntityCopiesRoleAsAuthority() {
      User entity = sampleEntity(Instant.now());

      SecurityUser result = SecurityUser.fromEntity(entity);

      assertEquals(1, result.getAuthorities().size());
      assertTrue(result.getAuthorities().contains(new SimpleGrantedAuthority(Role.ROLE_USER.name())));
    }

    @Test
    @DisplayName("fromEntity() projects identity fields straight from the entity")
    void fromEntityProjectsIdentityFields() {
      Instant changedAt = Instant.parse("2026-01-01T00:00:00Z");
      User entity = sampleEntity(changedAt);

      SecurityUser result = SecurityUser.fromEntity(entity);

      assertNotNull(result);
      assertEquals(entity.getId(), result.id());
      assertEquals(entity.getEmail(), result.getUsername());
      assertEquals(entity.getPassword(), result.getPassword());
      assertEquals(entity.getStatus(), result.status());
      assertEquals(entity.getAccountExpiresAt(), result.accountExpiresAt());
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Builders
  // ---------------------------------------------------------------------------------------------

  private static SecurityUser buildUser(UserStatus status) {
    return buildUser(status, null, null);
  }

  private static SecurityUser buildUser(UserStatus status, Instant accountExpiresAt, Instant credentialsExpireAt) {
    return new SecurityUser(
        1L,
        "user@test.com",
        "encodedPassword",
        status,
        accountExpiresAt,
        credentialsExpireAt,
        false,  // mfaEnabled — MFA is out of scope for the UserDetails contract
        List.of(new SimpleGrantedAuthority(Role.ROLE_USER.name()))
    );
  }

  private static User sampleEntity(Instant passwordChangedAt) {
    return User.builder()
        .id(1L)
        .email("user@test.com")
        .password("encodedPassword")
        .firstName("Jesus")
        .lastName("Dev")
        .role(Role.ROLE_USER)
        .status(UserStatus.ACTIVE)
        .accountExpiresAt(null)
        .passwordChangedAt(passwordChangedAt)
        .build();
  }
}
