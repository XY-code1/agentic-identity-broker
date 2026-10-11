/**
 * ThirdPartySessionsPage re-authentication tests.
 *
 * specs/008-thirdparty-oauth2-sessions/spec.md
 * - US1-S6: an expired session offers Login, which starts the service's authorization flow
 * - US3-S6: a provider rejection of the stored refresh token asks the user to log in again
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { ThirdPartySessionsPage } from './ThirdPartySessionsPage';
import { sessionsApi } from '@services/api/sessions';
import type { SessionSummary } from '@services/api/sessions';

vi.mock('@services/api/sessions', () => ({
  sessionsApi: {
    listSessions: vi.fn(),
    refreshSession: vi.fn(),
    getSessionDetails: vi.fn(),
    terminateSession: vi.fn(),
  },
}));

const session = (overrides?: Partial<SessionSummary>): SessionSummary => ({
  id: 'session-1',
  service_id: 'svc-github',
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

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={['/sessions']}>
      <ThirdPartySessionsPage />
    </MemoryRouter>,
  );

describe('ThirdPartySessionsPage re-authentication', () => {
  const originalLocation = window.location;

  beforeEach(() => {
    vi.clearAllMocks();
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...originalLocation, origin: 'https://broker.example.com', href: '' },
    });
  });

  afterEach(() => {
    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
  });

  // US1-S6
  it('starts the service authorization flow when Login is clicked on an expired session', async () => {
    vi.mocked(sessionsApi.listSessions).mockResolvedValue([
      session({ is_expired: true, reauth_required: true }),
    ]);
    renderPage();

    await userEvent.click(await screen.findByRole('button', { name: /log ?in/i }));

    expect(window.location.href).toBe(
      '/api/third-party/svc-github/oauth2/authorize?redirect_uri=' +
        encodeURIComponent('https://broker.example.com/sessions'),
    );
  });

  // US3-S6
  it('marks the session for re-authentication when the provider rejects the refresh token', async () => {
    vi.mocked(sessionsApi.listSessions).mockResolvedValue([session()]);
    vi.mocked(sessionsApi.refreshSession).mockRejectedValue({
      status: 409,
      code: 'CONFLICT',
      message: 'the stored refresh token is no longer accepted; log in to the service again',
    });
    renderPage();

    await userEvent.click(await screen.findByRole('button', { name: /refresh/i }));

    expect(
      await screen.findByText(/GitHub no longer accepts the stored sign-in/i),
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /log ?in/i })).toBeInTheDocument();
    });
    expect(screen.queryByRole('button', { name: /terminate/i })).not.toBeInTheDocument();
  });

  // US3-S6: a provider outage is not a rejection
  it('keeps the session active when the provider is unavailable', async () => {
    vi.mocked(sessionsApi.listSessions).mockResolvedValue([session()]);
    vi.mocked(sessionsApi.refreshSession).mockRejectedValue({
      status: 502,
      code: 'SERVER_ERROR',
      message: 'Service temporarily unavailable. Please try again later.',
    });
    renderPage();

    await userEvent.click(await screen.findByRole('button', { name: /refresh/i }));

    expect(await screen.findByText(/could not be reached/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /terminate/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /log ?in/i })).not.toBeInTheDocument();
  });
});
