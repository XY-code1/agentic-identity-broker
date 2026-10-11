/**
 * ConsentReasonBanner explains why an authorization request was sent back to the consent page
 * because of a service connection, and offers to log in to that service.
 *
 * specs/011-agent-permission-requirements/spec.md US3-S8
 */

import React from 'react';
import { Alert } from '@design-system/components/feedback/Alert';

export type ConsentReason = 'session_required' | 'session_expired' | 'scope_mismatch';

const CONSENT_REASONS: readonly ConsentReason[] = [
  'session_required',
  'session_expired',
  'scope_mismatch',
];

/** Returns the reason when the value is one the broker sends, otherwise undefined. */
export function parseConsentReason(value: string | null): ConsentReason | undefined {
  return CONSENT_REASONS.find((reason) => reason === value);
}

const MESSAGES: Record<ConsentReason, { title: string; body: (service: string) => string }> = {
  session_required: {
    title: 'Connection required',
    body: (service) => `This agent needs a connection to ${service}. Log in to continue.`,
  },
  session_expired: {
    title: 'Connection expired',
    body: (service) =>
      `Your connection to ${service} has expired and agents can no longer use it. Log in again to continue.`,
  },
  scope_mismatch: {
    title: 'More permissions needed',
    body: (service) =>
      `Your connection to ${service} does not include all permissions this agent requires. Log in again to grant them.`,
  },
};

export interface ConsentReasonBannerProps {
  reason: ConsentReason;
  serviceId: string;
  serviceName?: string;
  onLogin: (serviceId: string) => void;
}

export const ConsentReasonBanner: React.FC<ConsentReasonBannerProps> = ({
  reason,
  serviceId,
  serviceName,
  onLogin,
}) => {
  const service = serviceName || 'a required service';
  const message = MESSAGES[reason];
  return (
    <Alert
      variant="warning"
      title={message.title}
      role="status"
      action={{
        label: serviceName ? `Log in to ${serviceName}` : 'Log in',
        onClick: () => onLogin(serviceId),
      }}
    >
      {message.body(service)}
    </Alert>
  );
};

export default ConsentReasonBanner;
