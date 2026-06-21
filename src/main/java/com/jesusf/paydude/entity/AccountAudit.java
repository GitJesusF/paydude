package com.jesusf.paydude.entity;

import com.jesusf.paydude.enums.AuditAction;
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
 * Immutable audit record of a single balance change.
 *
 * <p>One row is written for every operation that moves money — deposits,
 * withdrawals, and both legs of a transfer — capturing the balance immediately
 * before and after. Every column is {@code updatable = false}: an audit row is
 * append-only and never edited once persisted.
 *
 * <p>{@link #transaction} is {@code null} for {@code DEPOSIT} and {@code WITHDRAW}
 * (single-account operations) and set for {@code TRANSFER_IN} / {@code TRANSFER_OUT},
 * where two rows reference the same {@link Transaction}.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "account_audits")
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@EntityListeners(AuditingEntityListener.class)
public class AccountAudit {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(updatable = false)
  @EqualsAndHashCode.Include
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "account_id", nullable = false, updatable = false)
  private Account account;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "transaction_id", updatable = false)
  private Transaction transaction;

  @Enumerated(EnumType.STRING)
  @Column(name = "action", length = 50, nullable = false, updatable = false)
  private AuditAction action;

  @Column(name = "balance_before", precision = 19, scale = 4, nullable = false, updatable = false)
  private BigDecimal balanceBefore;

  @Column(name = "balance_after", precision = 19, scale = 4, nullable = false, updatable = false)
  private BigDecimal balanceAfter;

  @Column(name = "amount", precision = 19, scale = 4, nullable = false, updatable = false)
  private BigDecimal amount;

  @CreatedDate
  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;
}