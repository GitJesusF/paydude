package com.jesusf.paydude.concurrency;

import com.jesusf.paydude.support.TestcontainersConfiguration;
import com.jesusf.paydude.dto.auth.AuthResponse;
import com.jesusf.paydude.dto.auth.RegisterRequest;
import com.jesusf.paydude.dto.idempotent.TransferRequest;
import com.jesusf.paydude.entity.Account;
import com.jesusf.paydude.entity.User;
import com.jesusf.paydude.repository.AccountAuditRepository;
import com.jesusf.paydude.repository.AccountRepository;
import com.jesusf.paydude.repository.IdempotencyKeyRepository;
import com.jesusf.paydude.repository.TransactionRepository;
import com.jesusf.paydude.repository.UserRepository;
import com.jesusf.paydude.security.ratelimit.AuthRateLimiter;
import com.jesusf.paydude.security.ratelimit.RateLimitSnapshot;
import com.jesusf.paydude.security.ratelimit.WriteRateLimiter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Concurrency integration test for the transfer flow.
 *
 * <p>Boots the full Spring context against a Testcontainers PostgreSQL instance and fires N
 * concurrent transfers from a virtual-thread executor. The test exists to verify three properties
 * that unit tests cannot:
 *
 * <ol>
 *   <li><b>The deadlock-prevention pattern actually works under contention.</b> Concurrent A&rarr;B
 *       and B&rarr;A transfers are the canonical circular-lock scenario; alphabetical ordering of
 *       {@code SELECT FOR UPDATE} acquisitions in {@code TransactionServiceImpl} forces every
 *       conflicting pair to serialise. If the ordering breaks, this test hangs (the latch never
 *       reaches zero) and surfaces the regression as a 60-second timeout.</li>
 *   <li><b>The money invariant holds.</b> Whatever interleaving the database picks, the sum of
 *       both balances must equal the pre-transfer total. A lost or duplicated transfer (e.g. a
 *       missing lock, a swallowed rollback) breaks this assertion.</li>
 *   <li><b>Virtual threads are exercised end-to-end.</b> The executor spawns one virtual thread
 *       per submitted task, and the embedded Tomcat is configured (via
 *       {@code spring.threads.virtual.enabled=true}, set globally in
 *       {@code application.properties}) to serve each request on its own virtual thread.
 *       Together they validate that the Loom + JDBC path tolerates real contention without
 *       starvation.</li>
 * </ol>
 */
@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
@TestPropertySource(properties = {
    // Raised from Spring Boot's default (10) to 100. A transfer briefly holds TWO connections:
    // the outer @Transactional takes one, and reserveKey() in REQUIRES_NEW suspends it and takes
    // a second. Under high concurrency with a small pool, every request retains its outer
    // connection while waiting for the inner one — a pool-level deadlock unrelated to DB locking.
    //
    // Loom scales request HANDLING, not downstream resources; the pool is overprovisioned here
    // so the alphabetically-ordered pessimistic locking stays the only visible bottleneck.
    // Deliberately not in application-test.properties — only this IT needs it.
    "spring.datasource.hikari.maximum-pool-size=100"
})
class VirtualThreadTransferConcurrencyIT {

  // Sized for meaningful contention without slowing the suite: 60 transfers move 30 USD each
  // way (net zero for the money invariant), and a real deadlock surfaces as the latch timeout.
  private static final BigDecimal INITIAL_BALANCE = new BigDecimal("1000.00");
  private static final BigDecimal TRANSFER_AMOUNT = new BigDecimal("1.00");
  private static final int TRANSFERS_PER_DIRECTION = 30;
  private static final int TOTAL_TRANSFERS = TRANSFERS_PER_DIRECTION * 2;
  private static final long LATCH_TIMEOUT_SECONDS = 60;

  @Autowired private TestRestTemplate restTemplate;
  @Autowired private UserRepository userRepository;
  @Autowired private AccountRepository accountRepository;
  @Autowired private TransactionRepository transactionRepository;
  @Autowired private AccountAuditRepository auditRepository;
  @Autowired private IdempotencyKeyRepository idempotencyKeyRepository;

  // The real limiters would throttle 60 burst transfers (same IP, two users) and the benchmark
  // would measure 429s instead of lock behaviour; both are mocked to admit everything.
  @MockitoBean private AuthRateLimiter authRateLimiter;
  @MockitoBean private WriteRateLimiter writeRateLimiter;

  @LocalServerPort private int port;

  private String tokenAlice;
  private String tokenBob;
  private String accountAlice;
  private String accountBob;

  @BeforeEach
  void setUp() {
    // FK-safe deletion order: audits → transactions → idempotency keys → accounts → users.
    auditRepository.deleteAll();
    transactionRepository.deleteAll();
    idempotencyKeyRepository.deleteAll();
    accountRepository.deleteAll();
    userRepository.deleteAll();

    // The per-IP methods return a RateLimitSnapshot — the mock default of null would NPE in the
    // filter — so return generous "allowed" snapshots. The boolean methods default to false (429).
    when(authRateLimiter.checkRegisterByIp(anyString())).thenReturn(new RateLimitSnapshot(true, 1000, 60, 1000, 60));
    when(authRateLimiter.checkLoginByIp(anyString())).thenReturn(new RateLimitSnapshot(true, 1000, 60, 1000, 60));
    when(authRateLimiter.tryLoginByEmail(anyString())).thenReturn(true);
    when(writeRateLimiter.tryWriteByUser(anyLong())).thenReturn(true);

    tokenAlice = registerAndCaptureToken("alice@test.com", "Alice");
    tokenBob = registerAndCaptureToken("bob@test.com", "Bob");

    accountAlice = topUpDirectly("alice@test.com", INITIAL_BALANCE);
    accountBob = topUpDirectly("bob@test.com", INITIAL_BALANCE);
  }

  @Test
  @DisplayName("100 concurrent bidirectional transfers preserve total balance and complete without deadlock")
  void concurrentBidirectionalTransfersPreserveTotalBalance() throws InterruptedException {
    CountDownLatch latch = new CountDownLatch(TOTAL_TRANSFERS);
    AtomicInteger successes = new AtomicInteger();
    AtomicInteger failures = new AtomicInteger();

    Instant start = Instant.now();
    // One virtual thread per task (JDK 21). try-with-resources waits for in-flight tasks on
    // close; the latch.await timeout below is the fail-fast guard if anything hangs.
    try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
      for (int i = 0; i < TRANSFERS_PER_DIRECTION; i++) {
        // Alternating directions is the canonical circular-lock pattern: without alphabetical
        // lock ordering, opposite transfers would deadlock A-waits-B / B-waits-A.
        executor.submit(() -> runTransfer(tokenAlice, accountAlice, accountBob, "Alice→Bob", successes, failures, latch));
        executor.submit(() -> runTransfer(tokenBob, accountBob, accountAlice, "Bob→Alice", successes, failures, latch));
      }
    }

    boolean drained = latch.await(LATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    Duration elapsed = Duration.between(start, Instant.now());

    BigDecimal balanceAlice = accountRepository.findByAccountNumber(accountAlice).orElseThrow().getBalance();
    BigDecimal balanceBob = accountRepository.findByAccountNumber(accountBob).orElseThrow().getBalance();
    BigDecimal totalAfter = balanceAlice.add(balanceBob);
    BigDecimal totalBefore = INITIAL_BALANCE.multiply(BigDecimal.valueOf(2));
    double throughput = TOTAL_TRANSFERS * 1000.0 / Math.max(elapsed.toMillis(), 1);

    log.info("");
    log.info("=== Concurrent transfer benchmark ===");
    log.info("Total transfers : {} ({} per direction)", TOTAL_TRANSFERS, TRANSFERS_PER_DIRECTION);
    log.info("Wall-clock time : {} ms", elapsed.toMillis());
    log.info("Throughput      : {} tx/sec", String.format("%.1f", throughput));
    log.info("Successes       : {}", successes.get());
    log.info("Failures        : {}", failures.get());
    log.info("Balance Alice   : {} (started at {})", balanceAlice, INITIAL_BALANCE);
    log.info("Balance Bob     : {} (started at {})", balanceBob, INITIAL_BALANCE);
    log.info("Total preserved : {} (expected {})", totalAfter, totalBefore);
    log.info("");

    assertTrue(drained, "Latch never reached zero — likely deadlock under bidirectional contention");
    assertEquals(TOTAL_TRANSFERS, successes.get(),
        "Some transfers failed; failures=" + failures.get() + ". Inspect WARN logs above.");
    // compareTo, not equals: BigDecimal.equals is scale-sensitive (100.0 != 100.00).
    assertEquals(0, totalBefore.compareTo(totalAfter),
        "Money invariant violated. Expected total: " + totalBefore + ", actual: " + totalAfter);
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  /**
   * Executes a single transfer over HTTP, classifies the response as success or failure, and
   * decrements the latch. Exceptions are caught and counted as failures so the latch always
   * decrements — without this {@code finally}, an exception in the middle of the run would
   * leave the latch undecremented and the main thread would hang until the timeout.
   */
  private void runTransfer(String token, String src, String tgt, String label,
                           AtomicInteger successes, AtomicInteger failures, CountDownLatch latch) {
    try {
      ResponseEntity<String> response = postTransfer(token, src, tgt, TRANSFER_AMOUNT);
      if (response.getStatusCode().is2xxSuccessful()) {
        successes.incrementAndGet();
      } else {
        failures.incrementAndGet();
        log.warn("{} failed status={} body={}", label, response.getStatusCode(), response.getBody());
      }
    } catch (Exception e) {
      failures.incrementAndGet();
      log.warn("{} threw {}: {}", label, e.getClass().getSimpleName(), e.getMessage());
    } finally {
      latch.countDown();
    }
  }

  private String registerAndCaptureToken(String email, String firstName) {
    RegisterRequest body = new RegisterRequest(firstName, "Test", email, "pass1234");
    ResponseEntity<AuthResponse> response = restTemplate.postForEntity(
        url("/v1/auth/register"), body, AuthResponse.class
    );
    assertTrue(response.getStatusCode().is2xxSuccessful(),
        "Register failed for " + email + ": " + response.getStatusCode());
    assertNotNull(response.getBody(), "Empty register response for " + email);
    return response.getBody().accessToken();
  }

  /**
   * Credits the starting balance straight onto the entity (the account is freshly created at
   * zero). Going through {@code POST /accounts/deposit} would also create audit rows the test
   * doesn't care about — we only want a non-zero starting balance so the transfers can debit.
   */
  private String topUpDirectly(String email, BigDecimal balance) {
    User user = userRepository.findByEmail(email).orElseThrow();
    Account account = accountRepository.findByUserId(user.getId()).orElseThrow();
    account.credit(balance);
    accountRepository.save(account);
    return account.getAccountNumber();
  }

  private ResponseEntity<String> postTransfer(String token, String src, String tgt, BigDecimal amount) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    // Fresh key per transfer: a shared key would short-circuit to the replay cache and the test
    // would pass by accidental idempotency instead of lock correctness.
    headers.set("Idempotency-Key", UUID.randomUUID().toString());
    headers.setContentType(MediaType.APPLICATION_JSON);

    TransferRequest body = new TransferRequest(src, tgt, amount, "USD", "concurrency test");
    return restTemplate.exchange(
        url("/v1/transactions/transfer"), HttpMethod.POST, new HttpEntity<>(body, headers), String.class
    );
  }

  private String url(String path) {
    return "http://localhost:" + port + path;
  }
}
