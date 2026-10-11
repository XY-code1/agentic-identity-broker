# ADR 038: Refresh Token Rotation Grace Period

**Status**: Proposed
**Date**: 2026-10-11
**Feature**: 033-offline-access-refresh — User Story 1, Scenarios 3 to 5

---

## Supersedes

This decision amends only the strict single-use rule for broker-issued refresh tokens in Feature 033 (FR-004 and User Story 1, Scenario 3). Feature 033 remains authoritative for refresh-token issuance, client eligibility, lifetime and metadata advertisement.

## Context

Local and hybrid mode rotate a broker refresh token on every use. The fosite refresh handler treats any presentation of an already rotated token as theft. It revokes every refresh token in the request chain, so the agent and every process sharing that chain must send the user through authorization again.

Legitimate clients present a rotated token in two common situations:

- A client times out or loses the token response after the broker committed the rotation, then retries with the token it still holds.
- Two processes of one MCP host share a refresh token and refresh at the same moment. One wins the row update; the other is told to retry and, on retry, triggers reuse detection, which also revokes the winner's new token.

Both cases looked like random logouts to users. Strict rotation offers no extra protection in the first seconds after a rotation: a client that just rotated cannot distinguish its own retry from an attacker's replay either.

## Decision

A rotated refresh token remains redeemable by the same client for a grace period after its rotation. The period defaults to 60 seconds and is configured with `oauth2_authorization_server.local.refresh_token_grace_period` (1 second to 5 minutes).

- `refresh_token_sessions.revoked_at` separates revocation from rotation. Rotation sets `used_at`; revocation by reuse detection, by request chain or by explicit deletion sets `revoked_at` as well.
- A token is redeemable when it is unrevoked and either unused or rotated within the grace period. Redeeming it in the grace period mints a new pair in the same request chain and is logged as `oauth2server.refresh.grace_replay`.
- Rotating a token that was already rotated inside the grace period succeeds instead of failing the request, so the loser of a concurrent refresh receives a usable pair.
- After the grace period, or for any revoked token, fosite's reuse detection applies unchanged: the request fails with `invalid_grant` and the whole chain is revoked.
- fosite's own checks remain: the client presenting the token must be the client it was issued to, and refresh-token expiry still applies.

## Consequences

- Lost-response retries and concurrent refreshes no longer revoke a user's agent sessions.
- A refresh token stolen and replayed within the grace period yields a valid token pair instead of triggering revocation. The window is short, bounded by configuration, limited to the original authenticated client, and every use is audited. After the window the replay still revokes the chain.
- Within the grace period one rotated token can fork the chain into several valid refresh tokens. They share the request ID, so a later reuse detection or explicit revocation still revokes all of them.
- Migration 037 adds the nullable `revoked_at` column. Existing used tokens have no `revoked_at`, but their `used_at` is older than any grace period, so they stay inactive.

## References

- `specs/033-offline-access-refresh/spec.md` FR-004, FR-018, User Story 1 Scenarios 3–5
- RFC 6819 §5.2.2.3 (refresh token rotation)
- OAuth 2.0 Security Best Current Practice §4.14.2 (refresh token rotation and replay)
- `internal/domain/oauth2server/fosite_storage.go`
