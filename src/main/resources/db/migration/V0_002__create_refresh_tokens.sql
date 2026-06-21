-- Refresh-token rotation with single-use tokens, reuse detection and family-based revocation
-- (docs/patterns.md #19). Access tokens stay stateless and verifiable offline; this table is the
-- only server-side session state — one row per issued refresh token, one family per login session.
--
-- Storage rules:
--   token_hash           → SHA-256 hex of the raw token; the raw value is never persisted. If the
--                          table leaks, nothing in it authenticates anybody — the same principle
--                          as password storage. Its UNIQUE constraint doubles as the lookup index
--                          for /refresh, which finds tokens by hash.
--   family_id            → UUID shared by every rotation of one session. Revoking a session —
--                          logout, reuse detection, password change — is one UPDATE over the
--                          family, never a walk of the rotation chain.
--   revoked_at           → NULL = active; any non-null value disables the token. Set on
--                          (a) successful rotation (the previous link in the chain),
--                          (b) family-wide revocation, (c) logout. Presenting a revoked token is
--                          the reuse-detection trigger: the whole family is revoked in response.
--   replaced_by_token_id → forward pointer in the rotation chain; pure audit, never consulted at
--                          runtime. Invaluable for forensic walk-backs ("which token replaced
--                          which, and where was the chain broken").
--   created_from_ip      → VARCHAR(45) fits the longest textual IPv6 form (including IPv4-mapped).
--                          With user_agent: a best-effort session fingerprint for forensics,
--                          never an authentication input.
--
-- ON DELETE CASCADE on user_id: tokens are operational session state owned by the user row —
-- removing a user wipes their token history, leaving no orphans. These rows are session plumbing,
-- not audit evidence.

CREATE TABLE refresh_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL,
    user_id BIGINT NOT NULL,
    family_id UUID NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    replaced_by_token_id BIGINT,
    created_from_ip VARCHAR(45),
    user_agent VARCHAR(255),

    CONSTRAINT uc_refresh_tokens_hash UNIQUE (token_hash),
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_refresh_tokens_replaced_by FOREIGN KEY (replaced_by_token_id) REFERENCES refresh_tokens(id),
    CONSTRAINT chk_refresh_tokens_expires_after_issued CHECK (expires_at > issued_at)
);

-- Family-wide revocation path (logout, reuse detection, password change): one UPDATE over
-- (user_id, family_id).
CREATE INDEX idx_refresh_tokens_user_family ON refresh_tokens(user_id, family_id);

-- Cutoff scan for ExpiredDataCleanupJob's bulk purge of expired rows (same pattern as
-- idempotency_keys.expires_at). Only expired rows are purged: revoked-but-unexpired rows are kept
-- on purpose — they are the evidence reuse detection needs and the session's audit window.
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
