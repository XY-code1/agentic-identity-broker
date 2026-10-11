/**
 * SessionCard status regression tests.
 *
 * specs/008-thirdparty-oauth2-sessions/spec.md
 * - US1-S6: expired session shows "Expired" and a Login button instead of Terminate
 * - US1-S7: expired access token with a usable refresh token is still "Active";
 *           expired access token without a refresh token requires re-authentication
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SessionCard } from './SessionCard';
import type { SessionSummary } from '@services/api/sessions';

const session = (overrides?: Partial<SessionSummary>): SessionSummary => ({
  id: 'session-1',
  service_id: 'github',
  service_display_name: 'GitHub',
  token_type: 'Bearer',
  scope: ['repo'],
  initiated_at: new Date('2026-10-01T12:00:00Z').toISOString(),
  is_expired: false,
  access_token_expired: false,
  has_refresh_token: true,
  reauth_required: false,
  dependent_agent_count: 1,
  is_encrypted: true,
  ...overrides,
});

describe('SessionCard status semantics', () => {
  // US1-S7 (first clause)
  it('keeps an auto-refreshable session "Active" when only the access token has expired', () => {
    render(
      <SessionCard
        session={session({ access_token_expired: true, has_refresh_token: true })}
        onTerminate={vi.fn()}
      />,
    );

    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.queryByText(/Access Token Expired/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Re-authenticat/i)).not.toBeInTheDocument();
  });

  // US1-S7 (second clause)
  it('asks for re-authentication when the access token expired and no refresh token exists', () => {
    const onLogin = vi.fn();
    render(
      <SessionCard
        session={session({
          access_token_expired: true,
          has_refresh_token: false,
          reauth_required: true,
        })}
        onTerminate={vi.fn()}
        onLogin={onLogin}
      />,
    );

    expect(screen.getByText(/Re-authenticat/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /log ?in/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /terminate/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /refresh/i })).not.toBeInTheDocument();
  });

  // US1-S6
  it('offers a Login button instead of Terminate for an expired session', async () => {
    const onLogin = vi.fn();
    render(
      <SessionCard
        session={session({ is_expired: true, reauth_required: true })}
        onTerminate={vi.fn()}
        onLogin={onLogin}
      />,
    );

    expect(screen.getByText('Expired')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /log ?in/i }));
    expect(onLogin).toHaveBeenCalledWith('github');
    expect(screen.queryByRole('button', { name: /terminate/i })).not.toBeInTheDocument();
  });
});
