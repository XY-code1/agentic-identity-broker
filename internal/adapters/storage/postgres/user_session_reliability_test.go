//go:build integration
// +build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression: WithLockedSession only writes the two token columns and access_token_expires_at.
// Refresh-token expiry advertised by the provider and a scope narrowed on refresh are set on the
// in-memory session by the domain but silently dropped on commit, so the sessions page and the
// consent gate keep evaluating stale metadata. Edge case "Expired access token with valid refresh
// token" in specs/008-thirdparty-oauth2-sessions/spec.md.
func TestUserSessionRefreshPersistsRefreshExpiryAndScope(t *testing.T) {
	adapter, cleanup := setupUserSessionTestDB(t)
	defer cleanup()
	repo := NewUserSessionRepository(adapter)
	ctx := context.Background()

	serviceID := id.NewServiceID()
	insertTestService(t, adapter, serviceID)
	principal := id.Principal("refresh-metadata@example.com")
	expired := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, repo.Create(ctx, &storage.UserSession{
		ID: id.NewSessionID(), Principal: principal, ServiceID: serviceID,
		EncryptedAccessToken: []byte("old-access"), EncryptedRefreshToken: []byte("old-refresh"),
		TokenType: "Bearer", AccessTokenExpiresAt: &expired, Scope: []string{"repo", "user"},
		EncryptionContext: storage.EncryptionContext{ServiceID: serviceID},
		InitiatedAt:       time.Now().UTC(), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}))

	newAccessExpiry := time.Now().UTC().Add(time.Hour).Round(time.Millisecond)
	newRefreshExpiry := time.Now().UTC().Add(14 * 24 * time.Hour).Round(time.Millisecond)
	_, err := repo.WithLockedSession(ctx, principal, serviceID, func(_ context.Context, session *storage.UserSession) (bool, error) {
		session.EncryptedAccessToken = []byte("new-access")
		session.EncryptedRefreshToken = []byte("new-refresh")
		session.AccessTokenExpiresAt = &newAccessExpiry
		session.RefreshTokenExpiresAt = &newRefreshExpiry
		session.Scope = []string{"repo"}
		session.UpdatedAt = time.Now().UTC()
		return true, nil
	})
	require.NoError(t, err)

	persisted, err := repo.FindByPrincipalAndService(ctx, principal, serviceID)
	require.NoError(t, err)
	require.NotNil(t, persisted)
	assert.Equal(t, []byte("new-refresh"), persisted.EncryptedRefreshToken)
	require.NotNil(t, persisted.RefreshTokenExpiresAt, "refresh_token_expires_at must be committed by the refresh transaction")
	assert.WithinDuration(t, newRefreshExpiry, *persisted.RefreshTokenExpiresAt, time.Second)
	assert.Equal(t, []string{"repo"}, persisted.Scope, "scope narrowed on refresh must be committed")
}

// Regression: the SQL active filter only checks refresh_token_expires_at, which most providers
// never populate. A session with an expired access token and no refresh token therefore passes
// the consent submission gate (FR-020) although no agent can obtain a token from it.
func TestUserSessionListActiveExcludesSessionsThatCannotDeliverTokens(t *testing.T) {
	adapter, cleanup := setupUserSessionTestDB(t)
	defer cleanup()
	repo := NewUserSessionRepository(adapter)
	ctx := context.Background()
	principal := id.Principal("active-filter@example.com")
	expired := time.Now().UTC().Add(-time.Hour)
	valid := time.Now().UTC().Add(time.Hour)

	usable, refreshable, dead, refreshExpired := id.NewServiceID(), id.NewServiceID(), id.NewServiceID(), id.NewServiceID()
	for _, serviceID := range []id.ServiceID{usable, refreshable, dead, refreshExpired} {
		insertTestService(t, adapter, serviceID)
	}
	base := func(serviceID id.ServiceID) *storage.UserSession {
		return &storage.UserSession{
			ID: id.NewSessionID(), Principal: principal, ServiceID: serviceID,
			EncryptedAccessToken: []byte("access"), TokenType: "Bearer", Scope: []string{"repo"},
			EncryptionContext: storage.EncryptionContext{ServiceID: serviceID},
			InitiatedAt:       time.Now().UTC(), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}
	}
	s1 := base(usable)
	s1.AccessTokenExpiresAt = &valid
	s2 := base(refreshable)
	s2.AccessTokenExpiresAt = &expired
	s2.EncryptedRefreshToken = []byte("refresh")
	s3 := base(dead)
	s3.AccessTokenExpiresAt = &expired
	s4 := base(refreshExpired)
	s4.AccessTokenExpiresAt = &expired
	s4.EncryptedRefreshToken = []byte("refresh")
	s4.RefreshTokenExpiresAt = &expired
	for _, session := range []*storage.UserSession{s1, s2, s3, s4} {
		require.NoError(t, repo.Create(ctx, session))
	}

	active, err := repo.ListActiveByPrincipal(ctx, principal)
	require.NoError(t, err)
	activeIDs := make([]id.ServiceID, 0, len(active))
	for _, session := range active {
		activeIDs = append(activeIDs, session.ServiceID)
	}
	assert.ElementsMatch(t, []id.ServiceID{usable, refreshable}, activeIDs)
}
