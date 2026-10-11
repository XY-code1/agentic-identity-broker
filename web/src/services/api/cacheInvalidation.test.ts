/**
 * Cross-resource cache invalidation: session and grant changes must not leave the other side
 * of the sessions/consent pages showing stale connection state or dependent-agent counts.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('./client', () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  },
}));

import { apiClient } from './client';
import { apiCache } from './cache';
import { sessionsApi } from './sessions';
import { consentApi } from './consent';

describe('cache invalidation across sessions and consent', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiCache.clear();
  });

  it('terminating a session drops cached agent connection status', async () => {
    apiCache.set('/consent/agents/agent-1', { services: [] }, 60_000);
    apiCache.set('/consent/agents', [], 60_000);
    apiCache.set('/third-party/sessions', [], 60_000);
    vi.mocked(apiClient.delete).mockResolvedValue({ data: {} });

    await sessionsApi.terminateSession('svc-1');

    expect(apiCache.get('/consent/agents/agent-1')).toBeNull();
    expect(apiCache.get('/consent/agents')).toBeNull();
    expect(apiCache.get('/third-party/sessions')).toBeNull();
  });

  it('changing a grant drops cached session dependent-agent counts', async () => {
    apiCache.set('/third-party/sessions', [], 60_000);
    apiCache.set('/third-party/svc-1/session', {}, 60_000);
    vi.mocked(apiClient.post).mockResolvedValue({ status: 201, data: { data: {} } });

    await consentApi.createOrUpdateGrant('agent-1', { granted_permission_sets: {} });

    expect(apiCache.get('/third-party/sessions')).toBeNull();
    expect(apiCache.get('/third-party/svc-1/session')).toBeNull();
  });

  it('revoking a grant drops cached session dependent-agent counts', async () => {
    apiCache.set('/third-party/sessions', [], 60_000);
    vi.mocked(apiClient.delete).mockResolvedValue({ status: 204, data: {} });

    await consentApi.deleteGrant('agent-1');

    expect(apiCache.get('/third-party/sessions')).toBeNull();
  });
});
