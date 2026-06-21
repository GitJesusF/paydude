package com.jesusf.paydude.service;

import com.jesusf.paydude.dto.user.UserResponse;
import com.jesusf.paydude.dto.user.UserResponseV2;

/**
 * Business operations on the authenticated user's own profile.
 */
public interface UserService {

  /**
   * @param userId the authenticated user
   * @return the user's v1 profile
   */
  UserResponse getCurrentUser(Long userId);

  /**
   * @param userId the authenticated user
   * @return the user's v2 profile (v1 fields plus {@code createdAt})
   */
  UserResponseV2 getCurrentUserV2(Long userId);

  /**
   * Updates the user's password after verifying their current one. Side effect: every refresh
   * token belonging to this user is revoked, forcing re-login on all devices (including the one
   * making this call). Once a password rotates, every outstanding session is treated as
   * potentially compromised — this is what the OWASP ASVS v4 §2.4.5 control prescribes.
   *
   * @param userId          Authenticated user id (from the access-token principal, never from the body)
   * @param currentPassword Plaintext value the user typed; must match the stored BCrypt hash
   * @param newPassword     New plaintext; will be BCrypt-encoded before persisting
   * @throws org.springframework.security.authentication.BadCredentialsException if the current
   *         password does not match — same exception Spring Security raises for login failures,
   *         so the same 401 + {@code ProblemDetail} reaches the client
   */
  void changePassword(Long userId, String currentPassword, String newPassword);
}
