package com.jesusf.paydude.authorization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jesusf.paydude.dto.auth.RegisterRequest;
import com.jesusf.paydude.dto.idempotent.AccountOperationRequest;
import com.jesusf.paydude.dto.idempotent.TransferRequest;
import com.jesusf.paydude.support.TestcontainersConfiguration;
import com.jesusf.paydude.util.AccountNumberMasker;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.math.BigDecimal;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end authorization integration test.
 *
 * <p>Boots the full Spring context against a Testcontainers PostgreSQL instance and exercises
 * the multi-tenant boundary that unit tests cannot prove: two real users (A and B) coexist in
 * the same database and PayDude must never let one read or modify the other's data.
 *
 * <p>The single test method walks a complete scenario instead of splitting into many small
 * cases. The reasoning: authorization bugs surface as wrong-data-returned, which is easier to
 * spot when the test follows a realistic flow (register → deposit → transfer → list) than when
 * each step is isolated with hand-built fixtures. A linear narrative also keeps the test data
 * coherent — every {@code andExpect} is asserting something the previous step caused.
 *
 * <p>The contracts pinned here:
 * <ol>
 *   <li>{@code GET /v1/users/me} returns the principal's own profile, not someone else's.</li>
 *   <li>{@code GET /v1/transactions} for user A shows the transfer as {@code SENT}; the same
 *       transfer appears under user B as {@code RECEIVED}, with the matching counterparty fields.
 *       Neither user sees a transaction the other side wasn't a party to.</li>
 *   <li>{@code POST /v1/transactions/transfer} rejects a request whose {@code sourceAccountNumber}
 *       points at another user's account with HTTP 409 and the literal ownership message —
 *       this is the {@code validatePostLock} barrier under
 *       {@code TransactionServiceImpl}.</li>
 * </ol>
 *
 * <p>Everything is real here — services, repositories, security filter chain — wired to the
 * Testcontainer. {@code AuthRateLimiter} is deliberately not mocked: register does not consult
 * it today, and if throttling were ever added there a visible 429 beats a silent mock.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
@ActiveProfiles("test")
class AuthorizationIT {

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;

  @Test
  @DisplayName("Multi-tenant isolation: A and B see only their own data, and A cannot transfer from B's account")
  void shouldIsolateDataAcrossUsersAndBlockCrossUserTransfer() throws Exception {

    // Step 1 — register both users. Register returns the token pair directly; unique emails per
    // run keep reruns against a reused container clean.
    String runId = UUID.randomUUID().toString().substring(0, 8);
    String emailA = "alice-" + runId + "@test.com";
    String emailB = "bob-" + runId + "@test.com";

    String tokenA = register("Alice", "A", emailA, "password123");
    String tokenB = register("Bob", "B", emailB, "password123");

    // Step 2 — read sanity: each token resolves to its own principal. A leaked SecurityContext
    // (e.g. a badly cleaned ThreadLocal) would surface immediately here.
    mockMvc.perform(get("/v1/users/me").header("Authorization", "Bearer " + tokenA))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.email").value(emailA))
        .andExpect(jsonPath("$.firstName").value("Alice"));

    mockMvc.perform(get("/v1/users/me").header("Authorization", "Bearer " + tokenB))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.email").value(emailB))
        .andExpect(jsonPath("$.firstName").value("Bob"));

    String accountA = readAccountNumber(tokenA);
    String accountB = readAccountNumber(tokenB);
    assertNotEquals(accountA, accountB, "Each user must get their own unique account number");

    // Step 3 — A funds the account (default accounts open at 0) and transfers 50 to B.
    AccountOperationRequest deposit = new AccountOperationRequest(new BigDecimal("200.00"), "initial funding");
    mockMvc.perform(post("/v1/accounts/deposit")
            .header("Authorization", "Bearer " + tokenA)
            .header("Idempotency-Key", UUID.randomUUID().toString())
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(deposit)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.balance").value(200.00));

    TransferRequest transfer = new TransferRequest(
        accountA, accountB, new BigDecimal("50.00"), "USD", "Test rent payment"
    );
    String idempotencyKey = UUID.randomUUID().toString();
    mockMvc.perform(post("/v1/transactions/transfer")
            .header("Authorization", "Bearer " + tokenA)
            .header("Idempotency-Key", idempotencyKey)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(transfer)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value("COMPLETED"))
        .andExpect(jsonPath("$.type").value("SENT"))
        // A is the sender, not the counterparty's owner — B's number arrives masked to last-4.
        .andExpect(jsonPath("$.counterpartyAccount").value(AccountNumberMasker.mask(accountB)));

    // Step 4 — A sees the transfer as SENT. totalElements pins two distinct regressions:
    // 0 = the repo query dropped the user's own transaction; >1 = it leaked someone else's (IDOR).
    mockMvc.perform(get("/v1/transactions").header("Authorization", "Bearer " + tokenA))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.totalElements").value(1))
        .andExpect(jsonPath("$.content[0].type").value("SENT"))
        .andExpect(jsonPath("$.content[0].amount").value(50.00))
        .andExpect(jsonPath("$.content[0].counterpartyAccount").value(AccountNumberMasker.mask(accountB)))
        .andExpect(jsonPath("$.content[0].counterpartyName").value("Bob B"));

    // Step 5 — B sees the SAME transfer as RECEIVED, with the counterparty flipped to A. The
    // assembler computes direction per caller; a bug returning SENT for both sides would
    // misrepresent the receiver's history.
    mockMvc.perform(get("/v1/transactions").header("Authorization", "Bearer " + tokenB))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.totalElements").value(1))
        .andExpect(jsonPath("$.content[0].type").value("RECEIVED"))
        .andExpect(jsonPath("$.content[0].amount").value(50.00))
        .andExpect(jsonPath("$.content[0].counterpartyAccount").value(AccountNumberMasker.mask(accountA)))
        .andExpect(jsonPath("$.content[0].counterpartyName").value("Alice A"));

    // Step 6 — A attempts to drain B's account: the JWT proves A, the body names B's account as
    // source. The post-lock ownership check in TransactionServiceImpl.validatePostLock rejects
    // it with a 409 before any mutation.
    TransferRequest crossUserAttack = new TransferRequest(
        accountB,   // source: B's account — not A's
        accountA,   // target: A's own account
        new BigDecimal("10.00"),
        "USD",
        "attempted drain"
    );
    mockMvc.perform(post("/v1/transactions/transfer")
            .header("Authorization", "Bearer " + tokenA)
            .header("Idempotency-Key", UUID.randomUUID().toString())
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(crossUserAttack)))
        .andExpect(status().isConflict())
        // RFC 9457: the reason travels in "detail"; contains() lets the exact wording evolve.
        .andExpect(jsonPath("$.detail").value(
            org.hamcrest.Matchers.containsString("does not belong to the authenticated user")));

    // B only ever received 50; the rejected attack must not have moved it.
    mockMvc.perform(get("/v1/accounts/me").header("Authorization", "Bearer " + tokenB))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.balance").value(50.00));
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------------

  private String register(String firstName, String lastName, String email, String password) throws Exception {
    RegisterRequest request = new RegisterRequest(firstName, lastName, email, password);
    MvcResult result = mockMvc.perform(post("/v1/auth/register")
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(request)))
        .andExpect(status().isCreated())
        .andReturn();

    JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
    String token = body.path("accessToken").asText();
    assertTrue(token != null && !token.isBlank(), "register must return an accessToken");
    return token;
  }

  /**
   * Reads the principal's own account number via {@code GET /v1/accounts/me}. Exists because
   * the account number is generated server-side at registration time and the test cannot
   * predict it — every assertion that references {@code counterpartyAccount} has to look it
   * up dynamically.
   */
  private String readAccountNumber(String token) throws Exception {
    MvcResult result = mockMvc.perform(get("/v1/accounts/me").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andReturn();
    JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
    String accountNumber = body.path("accountNumber").asText();
    assertEquals(16, accountNumber.length(),
        "Account numbers are 16-digit Luhn-checked strings per AccountNumberGenerator");
    return accountNumber;
  }
}
