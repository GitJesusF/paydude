-- Security audit log — the detection/forensics counterpart to the prevention controls (layered
-- rate limiting, account lockout, breach screening, refresh-token rotation); completes OWASP ASVS
-- V7 security logging (docs/patterns.md #23). V0_001's lockout comment already pointed here: "a
-- full per-attempt history belongs to the (separate) security audit log, not here."
--
-- One INSERT-only row per audited event (login, logout, register, password change, account
-- lockout, refresh-token reuse). Each row pairs an event_type with an outcome (SUCCESS/FAILURE) —
-- mirroring the paydude.auth.login{outcome} metric — plus the request context (ip, user agent,
-- W3C trace id) needed to investigate an incident and to pivot from an audit row back into the
-- request's logs. No updated_at, no UPDATE path: evidence is never edited (the same contract as
-- account_audits). Rows older than application.security.audit.retention are purged by
-- ExpiredDataCleanupJob.
--
-- Two deliberate design choices:
--   user_id has NO foreign key → the trail must OUTLIVE its subject: a closed or deleted user
--           must never cascade away the evidence of what was done to — or by — that account. The
--           column is NULL when the actor is unknown (a failed login for an unrecognised email);
--           `principal` then carries the attempted identity, the forensic crux of "which account
--           was targeted".
--   principal may hold an email → the table is admin-only (GET /v1/admin/audit-events), so
--           recording the attempted identity is acceptable and necessary. Passwords, raw or
--           hashed tokens and full account numbers are NEVER stored here — a threat model
--           distinct from the application logs, which are scrubbed of identifiers altogether.
--
-- The CHECK pins the event vocabulary: admitting a new event type takes a DROP/ADD CONSTRAINT
-- migration, so changes to what the trail can record remain reviewable schema history.

CREATE TABLE security_audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    outcome VARCHAR(20) NOT NULL,
    user_id BIGINT,
    principal VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    trace_id VARCHAR(64),
    detail VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_security_audit_event_type CHECK (event_type IN
        ('LOGIN', 'LOGOUT', 'REGISTER', 'PASSWORD_CHANGE', 'ACCOUNT_LOCKED', 'TOKEN_REUSE_DETECTED')),
    CONSTRAINT chk_security_audit_outcome CHECK (outcome IN ('SUCCESS', 'FAILURE'))
);

-- user_id → forensic walk-back of every event touching one account. event_type → dashboards and
-- sweeps ("all lockouts this week"). created_at DESC → backs both the default newest-first
-- listing and the retention-purge cutoff scan.
CREATE INDEX idx_security_audit_user_id ON security_audit_events(user_id);
CREATE INDEX idx_security_audit_event_type ON security_audit_events(event_type);
CREATE INDEX idx_security_audit_created_at ON security_audit_events(created_at DESC);
