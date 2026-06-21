-- Baseline schema. Four concerns, one table each, plus the exactly-once support table:
--   users            → identity + authentication state
--   accounts         → money at rest (one balance per user and currency)
--   transactions     → money in motion between accounts
--   account_audits   → append-only evidence of every balance mutation
--   idempotency_keys → exactly-once execution for the money-moving POSTs
--
-- Conventions, stated once here, that every table below (and every later migration) follows:
--   • TIMESTAMP WITH TIME ZONE for every instant — never a naive local timestamp. created_at /
--     updated_at are written by JPA auditing (@EnableJpaAuditing); the SQL DEFAULTs only cover
--     out-of-band inserts (psql, fixtures).
--   • Money is NUMERIC(19, 4) — never binary floating point, which cannot represent decimal cents
--     exactly: a ledger that drifts by rounding is corrupt. Request DTOs mirror this precision
--     with @Digits(integer = 15, fraction = 4).
--   • Enumerations are VARCHAR + a named CHECK, not native ENUM types: the vocabulary is pinned in
--     the schema (a bad write fails loudly) while widening it stays an ordinary, reviewable
--     DROP/ADD CONSTRAINT migration instead of an ALTER TYPE with its own locking quirks.
--   • Primary keys are BIGINT GENERATED ALWAYS AS IDENTITY — ALWAYS makes it an error for the
--     application to supply its own ids.
--   • Every constraint and index is named (uc_ / chk_ / fk_ / idx_) so violation messages and
--     query plans grep straight back to this file.

-- Identity and authentication state. The four UserDetails checks (enabled, non-locked,
-- account-non-expired, credentials-non-expired) are all answered from this row.
--   email               → stored canonical (trimmed + lowercased). The CHECK turns "a code path
--                         forgot to canonicalize" into a hard failure instead of a latent
--                         duplicate-identity bug; UNIQUE then holds at the canonical form — the
--                         only form at which "same email" is meaningful.
--   password            → BCrypt modular-crypt string (60 chars today; 255 leaves room to migrate
--                         algorithms without a schema change).
--   account_expires_at  → NULL = never expires (the policy is off for this user).
--   password_changed_at → NOT NULL from the first INSERT: it anchors the credential-rotation
--                         policy (credentials expire N days after the last change) and must be
--                         updated on every password change.
CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'ROLE_USER',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    account_expires_at TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Account lockout: completes the LOCKED user state with a temporary, auto-expiring anti-bruteforce
    -- lock (OWASP ASVS V2.2 brute-force resistance / NIST SP 800-63B §5.2.2 throttling). The state
    -- machine is modelled by UserStatus.LOCKED, SecurityUser.isAccountNonLocked() and the 423 advice;
    -- these two columns supply the data the login flow needs to *enter* and *auto-leave* that state:
    --
    --   failed_login_attempts → running count of CONSECUTIVE failed logins, reset to 0 on the next
    --                           successful login. A plain counter on the user row is all the lockout
    --                           DECISION needs; a full per-attempt history belongs to the (separate)
    --                           security audit log, not here.
    --   lockout_expires_at    → when a TEMPORARY lock auto-releases. NULL is overloaded by status:
    --                             • status <> LOCKED         → not locked (the common case).
    --                             • status =  LOCKED, NULL   → PERMANENT / administrative lock; never
    --                                                          auto-releases (manual unlock only).
    --                             • status =  LOCKED, value  → TEMPORARY lock; the login flow releases
    --                                                          it once now >= lockout_expires_at.
    --
    -- Counter mutations go through atomic single-statement UPDATEs in LoginAttemptService — no
    -- read-modify-write, so concurrent failed logins cannot lose an increment or fork the decision.
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    lockout_expires_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uc_users_email UNIQUE (email),
    CONSTRAINT chk_users_role CHECK (role IN ('ROLE_USER', 'ROLE_ADMIN')),
    CONSTRAINT chk_users_status CHECK (status IN ('ACTIVE', 'LOCKED', 'SUSPENDED', 'CLOSED')),
    CONSTRAINT chk_users_email_canonical CHECK (email = lower(btrim(email))),
    -- A negative attempt count would be a logic bug; fail closed at the schema level.
    CONSTRAINT chk_users_failed_login_attempts_nonneg CHECK (failed_login_attempts >= 0)
);

-- Money at rest. UNIQUE (user_id, currency) = one account per user per currency: it makes the
-- "default USD account on register" flow deterministic and turns a double-provision race into a
-- constraint violation instead of a duplicate account.
--   account_number → application-generated: "452" + 12 SecureRandom digits + a Luhn check digit.
--                    The DB enforces only uniqueness; the format lives app-side (@AccountNumber),
--                    and the generator retries on a collision against this UNIQUE.
--   balance        → CHECK (balance >= 0) is the last line of defense against overdraft: the
--                    service validates after taking the row lock, the constraint backstops any
--                    future code path that forgets to.
--   ON DELETE CASCADE → an account is state owned by its user. Movement history is not — the
--                    transactions FKs below deliberately block such a delete once history exists.
CREATE TABLE accounts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL,
    account_number VARCHAR(20) NOT NULL UNIQUE,
    balance NUMERIC(19, 4) NOT NULL DEFAULT 0.0000,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_accounts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT uc_account_user_currency UNIQUE (user_id, currency),
    CONSTRAINT chk_accounts_status CHECK (status IN ('ACTIVE', 'PENDING', 'FROZEN', 'CLOSED')),
    CONSTRAINT chk_accounts_currency CHECK (currency IN ('USD', 'MXN')),
    CONSTRAINT chk_accounts_balance_non_negative CHECK (balance >= 0)
);

-- Money in motion between at most two internal accounts.
--   source/target_account_id → each nullable for future external rails (card top-ups, payouts):
--                     only the internal side(s) of a movement are set. chk_transactions_valid
--                     requires at least one side and forbids self-transfers via IS DISTINCT FROM,
--                     which — unlike <> — stays true when one side is NULL.
--   amount          → strictly positive; direction is carried by source/target, never by sign.
--   idempotency_key → echo of the client's Idempotency-Key, kept on the movement itself so an
--                     operator can join a stored transaction back to its idempotency_keys row.
--   FKs with no CASCADE (default NO ACTION) → history must never vanish because a parent row was
--                     deleted: an account with movements cannot be hard-deleted at all (and,
--                     through accounts' own CASCADE, neither can its owner). Closing an account
--                     is a status change, not a DELETE.
CREATE TABLE transactions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_account_id BIGINT,
    target_account_id BIGINT,
    amount NUMERIC(19, 4) NOT NULL,
    currency VARCHAR(3) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    description VARCHAR(255),
    idempotency_key VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_transactions_source_account FOREIGN KEY (source_account_id) REFERENCES accounts(id),
    CONSTRAINT fk_transactions_target_account FOREIGN KEY (target_account_id) REFERENCES accounts(id),
    CONSTRAINT chk_transactions_amount_positive CHECK (amount > 0),
    CONSTRAINT chk_transaction_status CHECK (status IN ('PENDING', 'PROCESSING', 'FROZEN', 'COMPLETED', 'FAILED', 'REVERSED')),
    CONSTRAINT chk_transactions_currency CHECK (currency IN ('USD', 'MXN')),
    CONSTRAINT chk_transactions_valid CHECK (
        (source_account_id IS NOT NULL OR target_account_id IS NOT NULL) AND
        (source_account_id IS DISTINCT FROM target_account_id)
    )
);

-- Append-only evidence: one row per balance mutation, always carrying balance_before/after so any
-- account's history can be replayed and re-checked. No updated_at — audit rows are never updated
-- (the entity maps every column updatable = false; an application-level contract, not a trigger).
-- The FKs carry no CASCADE for the same reason as transactions': evidence blocks hard deletes.
--   transaction_id → NULL for DEPOSIT/WITHDRAW (no Transaction row exists for them); a transfer
--                    writes exactly two audit rows — TRANSFER_OUT and TRANSFER_IN, one per side —
--                    referencing the SAME transaction.
CREATE TABLE account_audits (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id BIGINT NOT NULL,
    transaction_id BIGINT,
    action VARCHAR(50) NOT NULL,
    balance_before NUMERIC(19, 4) NOT NULL,
    balance_after NUMERIC(19, 4) NOT NULL,
    amount NUMERIC(19, 4) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_account_audits_account FOREIGN KEY (account_id) REFERENCES accounts(id),
    CONSTRAINT fk_account_audits_transaction FOREIGN KEY (transaction_id) REFERENCES transactions(id),
    CONSTRAINT chk_audit_action CHECK (action IN ('DEPOSIT', 'WITHDRAW', 'TRANSFER_IN', 'TRANSFER_OUT'))
);

-- Exactly-once execution for the money-moving POSTs (transfer, deposit, withdraw).
--   UNIQUE (key_value, user_id) → keys are scoped per user: clients can neither collide with nor
--                     probe each other's keys, and the reservation's SELECT ... FOR UPDATE has a
--                     natural single-row target.
--   request_hash    → SHA-256 hex (64 chars) of the canonical JSON body. The same key with a
--                     different payload is rejected — a retry must be a retry, not a new
--                     operation smuggled under an old key.
--   response_body   → the completed response, cached so a duplicate submission replays it
--                     verbatim instead of re-executing the operation.
--   expires_at      → TTL (application.idempotency.key-ttl). Expired rows are reclaimed in place
--                     on reuse and bulk-purged by ExpiredDataCleanupJob.
CREATE TABLE idempotency_keys (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key_value VARCHAR(255) NOT NULL,
    user_id BIGINT NOT NULL,
    request_hash VARCHAR(64) NOT NULL,
    response_body TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    CONSTRAINT fk_idempotency_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT uc_idempotency_key_user UNIQUE (key_value, user_id),
    CONSTRAINT chk_idempotency_status CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED'))
);

-- Read paths not already covered by a UNIQUE above (uc_users_email, accounts.account_number,
-- uc_idempotency_key_user):
--   accounts / account_audits → the "my accounts" listing and the per-account statement.
--   transactions              → per-account history is an OR over source/target, so one index per
--                               side; created_at DESC backs newest-first pagination;
--                               idempotency_key backs retry forensics.
--   idempotency_keys          → user_id supports the FK join; expires_at is the cleanup job's
--                               cutoff scan.
CREATE INDEX idx_accounts_user_id ON accounts(user_id);
CREATE INDEX idx_account_audit_account ON account_audits(account_id);
CREATE INDEX idx_transactions_source ON transactions(source_account_id);
CREATE INDEX idx_transactions_target ON transactions(target_account_id);
CREATE INDEX idx_transactions_created ON transactions(created_at DESC);
CREATE INDEX idx_transactions_idempotency ON transactions(idempotency_key);
CREATE INDEX idx_idempotency_user_id ON idempotency_keys(user_id);
CREATE INDEX idx_idempotency_expires_at ON idempotency_keys(expires_at);
