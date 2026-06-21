package com.jesusf.paydude.entity;

import com.jesusf.paydude.exception.BusinessException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link Account}'s balance mutators.
 *
 * <p>{@code debit}/{@code credit} are the only writers of {@code balance} (there is no public
 * setter), so the non-negative invariant lives entirely in these two methods — the last line of
 * defense behind the richer service-layer validations. Every money path in the system funnels
 * through them, which makes the contract worth pinning directly rather than only through the
 * service tests that happen to traverse it.
 */
class AccountTest {

  private static Account accountWith(String balance) {
    return Account.builder().balance(new BigDecimal(balance)).build();
  }

  @Test
  @DisplayName("credit adds the amount to the balance")
  void creditAddsAmount() {
    Account account = accountWith("100.00");

    account.credit(new BigDecimal("25.50"));

    assertEquals(new BigDecimal("125.50"), account.getBalance());
  }

  @Test
  @DisplayName("debit subtracts the amount, down to exactly zero")
  void debitSubtractsAmount() {
    Account account = accountWith("100.00");

    account.debit(new BigDecimal("100.00"));

    assertEquals(0, BigDecimal.ZERO.compareTo(account.getBalance()),
        "draining the full balance is legal — only going below zero is not");
  }

  @Test
  @DisplayName("debit beyond the balance throws and leaves the balance untouched")
  void debitBeyondBalanceThrows() {
    Account account = accountWith("10.00");

    BusinessException ex = assertThrows(BusinessException.class,
        () -> account.debit(new BigDecimal("10.01")));

    assertEquals("Insufficient funds", ex.getMessage());
    assertEquals(new BigDecimal("10.00"), account.getBalance(),
        "a rejected debit must not partially mutate the balance");
  }

  @Test
  @DisplayName("debit rejects null, zero and negative amounts")
  void debitRejectsNonPositiveAmounts() {
    Account account = accountWith("100.00");

    assertThrows(BusinessException.class, () -> account.debit(null));
    assertThrows(BusinessException.class, () -> account.debit(BigDecimal.ZERO));
    // A negative debit would be a disguised credit — the signum check closes that path.
    assertThrows(BusinessException.class, () -> account.debit(new BigDecimal("-5.00")));
    assertEquals(new BigDecimal("100.00"), account.getBalance());
  }

  @Test
  @DisplayName("credit rejects null, zero and negative amounts")
  void creditRejectsNonPositiveAmounts() {
    Account account = accountWith("100.00");

    assertThrows(BusinessException.class, () -> account.credit(null));
    assertThrows(BusinessException.class, () -> account.credit(BigDecimal.ZERO));
    // A negative credit would be a disguised debit that skips the funds check.
    assertThrows(BusinessException.class, () -> account.credit(new BigDecimal("-5.00")));
    assertEquals(new BigDecimal("100.00"), account.getBalance());
  }
}
