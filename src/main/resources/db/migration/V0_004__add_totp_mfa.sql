-- TOTP second factor (RFC 6238), opt-in per user (docs/patterns.md #24). Three pieces:
--   1. users gains the per-user MFA state: the enabled flag, the shared secret (Base32 text;
--      VARCHAR(64) is headroom over today's 32 chars for a 160-bit secret), and the last time
--      step that verified successfully — the RFC 6238 §5.2 replay guard, making a code one-shot
--      even inside the ±1-step acceptance window.
--   2. mfa_recovery_codes — single-use backup codes for the lost-device path. Only the SHA-256
--      hex of each code is stored (the refresh_tokens.token_hash convention): the codes are
--      high-entropy random values, so a deliberately-slow password hash buys nothing and a plain
--      digest keeps the redemption lookup O(1) on the unique index.
--   3. security_audit_events.event_type widens to admit the three MFA events (the CHECK pins the
--      enum, so adding values requires a migration — by design of V0_003, which created it).
--
-- mfa_secret is stored as it must be USED: TOTP verification recomputes an HMAC from the raw
-- shared secret on every check, so unlike a password it cannot be hashed. Encrypting it at rest
-- is a KMS/key-management exercise deliberately out of scope here and documented as the
-- production hardening step (docs/patterns.md #24). A pending enrollment is `mfa_secret IS NOT
-- NULL AND mfa_enabled = FALSE` — created by /setup, harmless until /confirm proves the
-- authenticator works.

ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(64);
ALTER TABLE users ADD COLUMN mfa_last_used_step BIGINT;

-- One row per issued recovery code; used_at NULL = still redeemable. Consumption is a single
-- atomic UPDATE guarded by `used_at IS NULL` (the lockout-counter pattern), so two concurrent
-- redemptions of the same code cannot both win. FK with ON DELETE CASCADE: unlike the audit
-- trail, recovery codes are operational state owned by the user row, not evidence that must
-- outlive it.
CREATE TABLE mfa_recovery_codes (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL,
    code_hash VARCHAR(64) NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_mfa_recovery_codes_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT uc_mfa_recovery_codes_hash UNIQUE (code_hash)
);

-- user_id → list/replace all of one user's codes on enroll/disable; the UNIQUE above already
-- indexes code_hash for the redemption lookup.
CREATE INDEX idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id);

-- New audit vocabulary: MFA_CHALLENGE (password verified, second factor pending — a challenge
-- with no later LOGIN SUCCESS is the "compromised password stopped by the second factor" forensic
-- signal), MFA_ENABLED, MFA_DISABLED. Postgres DDL is transactional: the DROP/ADD pair commits
-- atomically with the rest of this migration, so there is no window with the vocabulary unpinned.
ALTER TABLE security_audit_events DROP CONSTRAINT chk_security_audit_event_type;
ALTER TABLE security_audit_events ADD CONSTRAINT chk_security_audit_event_type CHECK (event_type IN
    ('LOGIN', 'LOGOUT', 'REGISTER', 'PASSWORD_CHANGE', 'ACCOUNT_LOCKED', 'TOKEN_REUSE_DETECTED',
     'MFA_CHALLENGE', 'MFA_ENABLED', 'MFA_DISABLED'));
