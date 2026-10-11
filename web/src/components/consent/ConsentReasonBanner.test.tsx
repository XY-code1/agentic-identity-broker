/**
 * ConsentReasonBanner tests — specs/011-agent-permission-requirements/spec.md US3-S8
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ConsentReasonBanner, parseConsentReason } from './ConsentReasonBanner';

describe('ConsentReasonBanner', () => {
  it.each([
    ['session_required', /needs a connection to GitHub/],
    ['session_expired', /connection to GitHub has expired/],
    ['scope_mismatch', /does not include all permissions/],
  ] as const)('explains %s and names the service', (reason, text) => {
    render(
      <ConsentReasonBanner reason={reason} serviceId="svc-1" serviceName="GitHub" onLogin={vi.fn()} />,
    );
    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it('starts the login for the named service', async () => {
    const onLogin = vi.fn();
    render(
      <ConsentReasonBanner reason="session_expired" serviceId="svc-1" serviceName="GitHub" onLogin={onLogin} />,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Log in to GitHub' }));
    expect(onLogin).toHaveBeenCalledWith('svc-1');
  });

  it('accepts only reasons the broker sends', () => {
    expect(parseConsentReason('session_expired')).toBe('session_expired');
    expect(parseConsentReason('<script>')).toBeUndefined();
    expect(parseConsentReason(null)).toBeUndefined();
  });
});
