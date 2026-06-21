package com.jesusf.paydude.enums;

import com.jesusf.paydude.exception.BusinessException;
import lombok.Getter;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The currencies the platform supports.
 *
 * <p>Each constant is validated against the JDK's ISO-4217 registry at class
 * initialization, so symbol and fraction-digit metadata come from the standard
 * library rather than being hand-maintained. Currency is constrained at the
 * database level by a {@code CHECK} on the {@code accounts} table; there is no
 * FX conversion, so cross-currency transfers are rejected by the service layer.
 */
@Getter
public enum Currency {

  /** United States dollar. */
  USD("USD"),

  /** Mexican peso. */
  MXN("MXN");

  private final String code;
  private final java.util.Currency jdkCurrency;

  /**
   * @param code ISO-4217 alphabetic code; the constructor fails fast at class
   *             load time if the JDK does not recognize it, turning a typo into
   *             a startup error instead of a runtime surprise
   */
  Currency(String code) {
    this.code = code;
    try {
      this.jdkCurrency = java.util.Currency.getInstance(code);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("The currency code " + code + " is not a valid ISO-4217 standard.", e);
    }
  }

  /** @return the localized currency symbol (e.g. {@code $}), from the JDK registry */
  public String getSymbol() {
    return jdkCurrency.getSymbol();
  }

  /** @return the number of minor-unit digits ISO-4217 defines for this currency */
  public int getDefaultFractionDigits() {
    return jdkCurrency.getDefaultFractionDigits();
  }

  private static final Map<String, Currency> BY_CODE = Arrays.stream(values())
      .collect(Collectors.toUnmodifiableMap(Currency::getCode, Function.identity()));

  /**
   * Resolves a currency from its ISO-4217 code.
   *
   * @param code the alphabetic code; never {@code null} in practice — every request DTO that
   *             carries a currency validates it with {@code @NotBlank} before the value reaches
   *             the domain layer
   * @return the matching constant — never {@code null}
   * @throws NullPointerException if {@code code} is {@code null}: reachable only if a caller
   *                              bypassed the {@code @NotBlank} guard, i.e. a programming error
   *                              rather than client input — fail fast instead of returning a
   *                              null sentinel the callers would have to defend against
   * @throws BusinessException    if {@code code} is non-null but unsupported — a client-supplied
   *                              value, hence a domain error (409) rather than an
   *                              {@link IllegalArgumentException}
   */
  public static Currency fromCode(String code) {
    Objects.requireNonNull(code, "Currency code must not be null");
    Currency currency = BY_CODE.get(code);
    if (currency == null) {
      throw new BusinessException("Unsupported currency: " + code);
    }
    return currency;
  }
}
