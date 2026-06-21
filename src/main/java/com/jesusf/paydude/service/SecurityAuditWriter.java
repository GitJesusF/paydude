package com.jesusf.paydude.service;

import com.jesusf.paydude.entity.SecurityAuditEvent;
import com.jesusf.paydude.repository.SecurityAuditEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Persists a single audit row in its OWN transaction.
 *
 * <p>Split out from {@link SecurityAuditServiceImpl} on purpose — the proxy boundary is the whole
 * point. Two requirements collide:
 *
 * <ul>
 *   <li><b>Durability.</b> The write must run in {@code REQUIRES_NEW} so it commits independently of
 *       the (often doomed) business transaction: a failed login rolls its transaction back, but the
 *       audit row recording that failure must survive — the same trick {@code LoginAttemptService}
 *       uses for its failure counters.</li>
 *   <li><b>Fail-safe.</b> A write that fails must never disrupt the audited operation.</li>
 * </ul>
 *
 * <p>These cannot both live in one method: a {@code REQUIRES_NEW} method commits when it returns, so
 * even if it caught the persistence exception internally, the transactional proxy's commit of the
 * now-rollback-only transaction would still throw {@code UnexpectedRollbackException} into the caller.
 * The fail-safe {@code try/catch} therefore has to sit OUTSIDE this transactional proxy — in
 * {@link SecurityAuditServiceImpl#record} — wrapping the call to this bean.
 */
@Component
@RequiredArgsConstructor
class SecurityAuditWriter {

  private final SecurityAuditEventRepository repository;

  /**
   * Inserts the row in a fresh transaction. Any failure propagates to the caller's fail-safe wrapper.
   *
   * @param event the audit row to persist
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)
  public void write(SecurityAuditEvent event) {
    repository.save(event);
  }
}
