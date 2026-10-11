---
title: Third-party session troubleshooting
description: How to diagnose third-party session logouts, refresh failures and confusing grant state from broker logs and metrics.
---

# Third-Party Session Troubleshooting

Use this runbook when users report being logged out of a connected service, agents ask for re-authentication, or the consent and sessions pages disagree about a connection.

## How a session stays alive

- The broker refreshes a stored access token `third_party_oauth2.refresh_leeway` (default 30 seconds) before it expires. If that early refresh fails, the still-valid stored token is returned.
- Refresh retries provider 5xx, 429 and connection failures up to three attempts. It never retries timeouts or 4xx answers.
- A re-connect keeps the stored refresh token when the provider omits `refresh_token`, which Google, Microsoft and Okta do on repeat consent.
- A session is **usable** while its refresh token has not expired and it has either a valid access token or a refresh token. The sessions page, consent page, grant submission and authorization flow all use this definition. An expired access token alone is normal and is not shown as a problem.
- Broker-issued refresh tokens (local and hybrid mode) may be presented again for `oauth2_authorization_server.local.refresh_token_grace_period` (default 60 seconds) after rotation. Later reuse revokes the token chain.

## Symptom to cause

| What the user sees | Diagnostic detail | Cause | Action |
|---|---|---|---|
| Agent asks to log in; sessions page shows **Expired** | `refresh_rejected` | The provider rejected the stored refresh token (`invalid_grant` or a provider-specific code such as `invalid_token`). The user revoked access, the provider rotated or expired the token, or a password change invalidated it. | The user logs in to the service again. If many users of one service are affected at once, check the provider's client configuration and token lifetime policy. |
| Same as above | `refresh_token_expired` | The provider advertised a refresh-token lifetime that has passed. | The user logs in again. Consider the provider's offline-access or session-length settings. |
| Same as above | `access_token_expired` or `refresh_unavailable` | The provider never issued a refresh token. | Configure the provider to issue one, for example Google's `access_type=offline` and `prompt=consent` in the service's authorization parameters. |
| Agent fails with `server_error`; sessions page shows **Active** | `provider_unavailable` | The provider stayed unavailable through all refresh retries. | Check provider status and `oauth2_session_refresh_retries_total`. No user action is needed once the provider recovers. |
| Agent fails with `server_error` for every user of one service | `provider_client_rejected` | The provider rejected the broker's client credentials. | Fix the service's client ID, secret or CIMD key; no user re-authentication helps. |
| Agent asks to log in right after a successful connect | `session_scope_insufficient` | The provider granted fewer scopes than the agent's permission sets require, or reports them under names the service does not configure. | Compare the session's scopes with the permission set. Add the provider's names as scope `aliases` on the service if they differ. |
| Consent page reappears with a "Connection expired" or "More permissions needed" banner | consent `reason` `session_expired` or `scope_mismatch` | The authorization flow found a connection that cannot deliver tokens or lacks required scopes. | The user follows the banner's login button. |
| Agent is logged out of a broker-issued session | `invalid_grant` on `/oauth2/token` refresh | A rotated refresh token was reused after the grace period, which revokes its chain. | Check that the client stores the newest refresh token and that processes sharing one token are not offline for longer than the grace period. |
| Grant appears to expire at the wrong time | — | Fixed by migration 036; grant expiry is now stored as a UTC instant. | Ensure migrations are current. |

Diagnostic details appear as `token_exchange.failure_detail` on token-exchange logs and spans, and as `oauth2_session.failure_detail` on broker session logs.

## Metrics

| Metric | Attributes | Use |
|---|---|---|
| `oauth2_session_refreshes_total` | `service_id`, `outcome` (`success`, `rejected`, `unavailable`, `error`) | Refresh health per provider. A rising `rejected` share means users must log in again. |
| `oauth2_session_refresh_retries_total` | `service_id` | Transient provider failures absorbed by retries. |
| `oauth2_session_reauth_required_total` | `service_id`, `failure_detail` | Token requests that need the user to log in again, by cause. |
| `oauth2_session_proactive_refresh_fallbacks_total` | `service_id` | Early refreshes that failed while the stored token was still valid. A sustained rate predicts upcoming re-authentication. |
| `oauth2_session_refresh_token_preserved_total` | `service_id` | Re-connects where the provider omitted `refresh_token` and the stored one was kept. |
| `oauth2_refresh_grace_replays_total` | `agent_id` | Broker refresh tokens redeemed again within the rotation grace period. Occasional values are normal retries; a high rate for one agent suggests shared or leaked tokens. |

Suggested alerts:

- `rejected` refreshes above 5% of all refreshes for one `service_id` over 15 minutes.
- `unavailable` refreshes for one `service_id` for more than 10 minutes.
- Any sustained `oauth2_refresh_grace_replays_total` growth for a single `agent_id`.

## Audit events

| Event | Meaning |
|---|---|
| `session.oauth2.refresh_retry` | A refresh attempt failed transiently and will be retried. |
| `session.oauth2.refresh_failed` | A refresh failed after all attempts. |
| `session.oauth2.proactive_refresh_failed` | An early refresh failed; the stored token was returned. |
| `session.oauth2.refresh_token_preserved` | A re-connect kept the stored refresh token. |
| `oauth2server.refresh.grace_replay` | A broker refresh token was redeemed within the grace period. |
