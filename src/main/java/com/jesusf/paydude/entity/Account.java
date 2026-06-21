package com.jesusf.paydude.entity;

import com.jesusf.paydude.enums.AccountStatus;
import com.jesusf.paydude.enums.Currency;
import com.jesusf.paydude.exception.BusinessException;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.PositiveOrZero;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * A user's bank account — the holder of a balance in a single currency.
 *
 * <p>A user may own at most one account per currency (enforced by a unique
 * constraint on {@code (user_id, currency)}). Balance mutations go through
 * {@link #debit(BigDecimal)} and {@link #credit(BigDecimal)} rather than the raw
 * setter, so the non-negative-balance invariant cannot be bypassed by callers.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "accounts")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@EntityListeners(AuditingEntityListener.class)
public class Account {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(updatable = false)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  @EqualsAndHashCode.Include
  @Column(name = "account_number", length = 20, nullable = false, unique = true)
  private String accountNumber;

  // No public setter: the balance changes only through debit()/credit(), so the non-negative
  // invariant in those methods cannot be bypassed by a raw setBalance(...). Construction still
  // goes through the builder / all-args constructor; JPA hydrates the field by reflection.
  @Setter(AccessLevel.NONE)
  @Builder.Default
  @PositiveOrZero(message = "Balance cannot be negative")
  @Column(name = "balance", precision = 19, scale = 4, nullable = false)
  private BigDecimal balance = BigDecimal.ZERO;

  @Builder.Default
  @Enumerated(EnumType.STRING)
  @Column(name = "currency", length = 3, nullable = false)
  private Currency currency = Currency.USD;

  @Builder.Default
  @Enumerated(EnumType.STRING)
  @Column(name = "status", length = 20, nullable = false)
  private AccountStatus status = AccountStatus.ACTIVE;

  @CreatedDate
  @Column(name = "created_at")
  private Instant createdAt;

  @LastModifiedDate
  @Column(name = "updated_at")
  private Instant updatedAt;

  /** @return {@code true} if the account is {@code ACTIVE} and may take part in money movement. */
  public boolean isActive() {
    return this.status == AccountStatus.ACTIVE;
  }

  /**
   * Subtracts {@code amount} from the balance.
   *
   * <p>Defense-in-depth: this method makes a negative balance unreachable from
   * any caller. The service layer validates first and produces a richer,
   * context-specific error message; the checks here are the last line of defense.
   *
   * @param amount strictly positive amount to withdraw
   * @throws BusinessException if {@code amount} is null or non-positive, or if
   *                           the balance is insufficient
   */
  public void debit(BigDecimal amount) {
    if (amount == null || amount.signum() <= 0) {
      throw new BusinessException("Debit amount must be positive");
    }
    if (this.balance.compareTo(amount) < 0) {
      throw new BusinessException("Insufficient funds");
    }
    this.balance = this.balance.subtract(amount);
  }

  /**
   * Adds {@code amount} to the balance.
   *
   * @param amount strictly positive amount to deposit
   * @throws BusinessException if {@code amount} is null or non-positive
   */
  public void credit(BigDecimal amount) {
    if (amount == null || amount.signum() <= 0) {
      throw new BusinessException("Credit amount must be positive");
    }
    this.balance = this.balance.add(amount);
  }
}