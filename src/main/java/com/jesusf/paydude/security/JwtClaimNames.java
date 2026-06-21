package com.jesusf.paydude.security;

/**
 * Centralized constant names for the application's custom JWT claims.
 *
 * <p>The token is written in one place ({@code AuthServiceImpl}) and read back in another
 * ({@code JwtService} / {@code JwtAuthenticationFilter}). Routing every claim name through these
 * constants means a typo cannot silently drop a claim on one side of that boundary.
 */
public final class JwtClaimNames {

  private JwtClaimNames() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  /** User id — stored as a number and mirrored into the JWT {@code sub} claim. */
  public static final String USER_ID = "userId";

  /** Granted authority, e.g. {@code "ROLE_USER"} — stored as a string. */
  public static final String ROLE = "role";

  /** {@code UserStatus} name, e.g. {@code "ACTIVE"} — stored as a string. */
  public static final String STATUS = "status";

  /** Account hard-expiry as epoch millis; absent from the token when the account never expires. */
  public static final String ACCOUNT_EXPIRES_AT = "accountExpiresAt";

  /** Credential expiry as epoch millis; absent from the token when the rotation policy is off. */
  public static final String CREDENTIALS_EXPIRE_AT = "credentialsExpireAt";
}
