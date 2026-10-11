package memory

import (
	"context"
	"testing"
	"time"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression: ListActiveByPrincipal feeds the consent submission gate (FR-020) and the consent
// detail screen. A session whose access token expired without a refresh token cannot deliver a
// token to any agent, so it must not count as active. Today only refresh_token_expires_at is
// consulted, which is nil for most providers, so such sessions are reported as active forever.
func TestListActiveByPrincipalExcludesSessionsThatCannotDeliverTokens(t *testing.T) {
	ctx := context.Background()
	repo := NewInMemoryUserSessionRepository()
	principal := id.Principal("user@example.com")
	expired := time.Now().Add(-time.Hour)
	valid := time.Now().Add(time.Hour)

	usable := id.NewServiceID()
	refreshable := id.NewServiceID()
	dead := id.NewServiceID()
	refreshExpired := id.NewServiceID()

	for _, session := range []*storage.UserSession{
		{ID: id.NewSessionID(), Principal: principal, ServiceID: usable, EncryptedAccessToken: []byte("a"), TokenType: "Bearer", AccessTokenExpiresAt: &valid},
		{ID: id.NewSessionID(), Principal: principal, ServiceID: refreshable, EncryptedAccessToken: []byte("a"), EncryptedRefreshToken: []byte("r"), TokenType: "Bearer", AccessTokenExpiresAt: &expired},
		{ID: id.NewSessionID(), Principal: principal, ServiceID: dead, EncryptedAccessToken: []byte("a"), TokenType: "Bearer", AccessTokenExpiresAt: &expired},
		{ID: id.NewSessionID(), Principal: principal, ServiceID: refreshExpired, EncryptedAccessToken: []byte("a"), EncryptedRefreshToken: []byte("r"), TokenType: "Bearer", AccessTokenExpiresAt: &expired, RefreshTokenExpiresAt: &expired},
	} {
		require.NoError(t, repo.Create(ctx, session))
	}

	active, err := repo.ListActiveByPrincipal(ctx, principal)
	require.NoError(t, err)
	activeIDs := make([]id.ServiceID, 0, len(active))
	for _, session := range active {
		activeIDs = append(activeIDs, session.ServiceID)
	}
	assert.ElementsMatch(t, []id.ServiceID{usable, refreshable}, activeIDs,
		"only sessions with a valid access token or a usable refresh token are active")
}
