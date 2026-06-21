package com.jesusf.paydude.service;

import com.jesusf.paydude.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Transactional boundary for refresh-token family revocation.
 *
 * <p>Reuse detection must revoke the family and then reject the request with a security
 * exception. If the bulk update runs in the same transaction as the exception, Spring rolls it
 * back and the stolen-token mitigation becomes a no-op. Keeping this method on a separate bean
 * is deliberate: Spring applies {@code REQUIRES_NEW} through the proxy, so the revocation commits
 * independently before the caller throws.
 */
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
class RefreshTokenFamilyRevocationService {

  private final RefreshTokenRepository refreshTokenRepository;

  /**
   * Revokes a token family in its own committed transaction.
   *
   * <p>{@code REQUIRES_NEW} is the whole point: the caller revokes the family and then throws a
   * security exception. In the same transaction that exception would roll the revocation back;
   * in a separate one it commits first, so the stolen-token mitigation actually sticks.
   *
   * @param userId   owner of the family
   * @param familyId the rotation chain to revoke
   * @param now      the revocation timestamp
   * @return the number of still-active tokens that were revoked
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW, rollbackFor = Exception.class)
  int revokeFamilyForReuseDetection(Long userId, UUID familyId, Instant now) {
    return refreshTokenRepository.revokeFamily(userId, familyId, now);
  }
}
