package com.jesusf.paydude.util;

/**
 * Masks account numbers for log output: only the last four characters survive, the rest collapse
 * to a fixed {@code ****} marker. The marker is fixed-width on purpose — preserving the original
 * length would leak it, and it carries no debugging value.
 *
 * <p>Account numbers are financial identifiers; they belong in the audit tables (which keep the
 * full value) and in the response to their own owner, not scattered across application logs where a
 * single log leak would expose them in bulk. Structured logs already carry the {@code traceId} and
 * the internal surrogate ids for correlation, so the last four digits are all a human needs to
 * recognize an account without exposing the whole identifier. PCI-DSS §3.4 applies the same
 * last-four convention to card numbers; an internal account number is less sensitive, but the
 * cheap, uniform masking keeps the logs clean of identifiers either way.
 */
public final class AccountNumberMasker {

  private static final int VISIBLE_SUFFIX = 4;
  private static final String MASK = "****";

  private AccountNumberMasker() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  /**
   * Returns {@code ****} followed by the last four characters of {@code accountNumber}, or
   * {@code ****} alone when the value is {@code null}, blank, or too short to reveal a tail without
   * exposing most of it.
   *
   * @param accountNumber the raw account number (may be {@code null})
   * @return the masked form, safe to log
   */
  public static String mask(String accountNumber) {
    if (accountNumber == null || accountNumber.length() <= VISIBLE_SUFFIX) {
      return MASK;
    }
    return MASK + accountNumber.substring(accountNumber.length() - VISIBLE_SUFFIX);
  }
}
