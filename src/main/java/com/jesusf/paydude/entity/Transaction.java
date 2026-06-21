package com.jesusf.paydude.entity;

import com.jesusf.paydude.enums.Currency;
import com.jesusf.paydude.enums.TransactionStatus;
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
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.Instant;

/**
 * A money movement between two accounts.
 *
 * <p>{@link #sourceAccount} and {@link #targetAccount} are both nullable so the
 * schema can later model external deposits and withdrawals, where one side is
 * absent. Transfers in the current flow always set both and are persisted
 * directly as {@code COMPLETED}. {@link #idempotencyKey} records the key the
 * transfer was reserved under, for traceability.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "transactions")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@EntityListeners(AuditingEntityListener.class)
public class Transaction {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(updatable = false)
  @EqualsAndHashCode.Include
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "source_account_id")
  private Account sourceAccount;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "target_account_id")
  private Account targetAccount;

  @Positive(message = "Transaction amount must be greater than zero")
  @Column(name = "amount", precision = 19, scale = 4, nullable = false)
  private BigDecimal amount;

  @Enumerated(EnumType.STRING)
  @Column(name = "currency", length = 3, nullable = false)
  private Currency currency;

  @Builder.Default
  @Enumerated(EnumType.STRING)
  @Column(name = "status", length = 20, nullable = false)
  private TransactionStatus status = TransactionStatus.PENDING;

  @Column(name = "description", length = 255)
  private String description;

  @Column(name = "idempotency_key", length = 255)
  private String idempotencyKey;

  @CreatedDate
  @Column(name = "created_at")
  private Instant createdAt;

  @Column(name = "completed_at")
  private Instant completedAt;
}