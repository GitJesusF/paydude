package com.jesusf.paydude.enums;

/**
 * Authorization roles granted to a user.
 *
 * <p>The {@code ROLE_} prefix is intentional: Spring Security's
 * {@code hasRole("ADMIN")} expects authorities stored with that prefix, so the
 * enum name is used verbatim as the granted authority and as the {@code role}
 * claim in the JWT.
 */
public enum Role {

  /** Standard end user — access to own accounts and transactions only. */
  ROLE_USER,

  /** Administrator — additionally cleared for the admin Actuator tier. */
  ROLE_ADMIN
}