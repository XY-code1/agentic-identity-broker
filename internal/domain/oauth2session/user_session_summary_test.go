package oauth2session_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
)

func TestNewUserSessionSummary(t *testing.T) {
	now := time.Now()
	refreshExp := now.Add(24 * time.Hour)

	session := &storage.UserSession{
		ID:                    id.NewSessionID(),
		ServiceID:             id.NewServiceID(),
		TokenType:             "Bearer",
		Scope:                 []string{"repo", "user"},
		InitiatedAt:           now.Add(-1 * time.Hour),
		RefreshTokenExpiresAt: &refreshExp,
	}

	summary := storage.NewUserSessionSummary(session, "GitHub", 3)

	assert.Equal(t, session.ID, summary.ID)
	assert.Equal(t, session.ServiceID, summary.ServiceID)
	assert.Equal(t, "GitHub", summary.ServiceDisplayName)
	assert.Equal(t, "Bearer", summary.TokenType)
	assert.Equal(t, []string{"repo", "user"}, summary.Scope)
	assert.Equal(t, 3, summary.DependentAgentCount)
	assert.True(t, summary.IsEncrypted)
	assert.False(t, summary.IsExpired)
}

func TestUserSessionSummary_WithExpiredSession(t *testing.T) {
	now := time.Now()
	refreshExp := now.Add(-1 * time.Hour) // Expired

	session := &storage.UserSession{
		ID:                    id.NewSessionID(),
		ServiceID:             id.NewServiceID(),
		RefreshTokenExpiresAt: &refreshExp,
		AccessTokenExpiresAt:  &refreshExp,
	}

	summary := storage.NewUserSessionSummary(session, "GitHub", 0)

	assert.True(t, summary.IsExpired)
}

func TestUserSessionSummary_WithExpiredAccessToken(t *testing.T) {
	now := time.Now()
	accessExp := now.Add(-1 * time.Hour)  // Expired access token
	refreshExp := now.Add(24 * time.Hour) // Valid refresh token

	session := &storage.UserSession{
		ID:                    id.NewSessionID(),
		ServiceID:             id.NewServiceID(),
		AccessTokenExpiresAt:  &accessExp,
		RefreshTokenExpiresAt: &refreshExp,
		EncryptedRefreshToken: []byte("refresh"),
	}

	summary := storage.NewUserSessionSummary(session, "GitHub", 2)

	assert.True(t, summary.AccessTokenExpired)
	assert.False(t, summary.IsExpired) // Session not expired if refresh token valid
}

func TestUserSessionSummary_HasRefreshToken(t *testing.T) {
	t.Run("has_refresh_token is true when EncryptedRefreshToken is set", func(t *testing.T) {
		session := &storage.UserSession{
			ID:                    id.NewSessionID(),
			ServiceID:             id.NewServiceID(),
			EncryptedRefreshToken: []byte("encrypted-refresh-token"),
		}
		summary := storage.NewUserSessionSummary(session, "GitHub", 0)
		assert.True(t, summary.HasRefreshToken)
	})

	t.Run("has_refresh_token is false when EncryptedRefreshToken is empty", func(t *testing.T) {
		session := &storage.UserSession{
			ID:                    id.NewSessionID(),
			ServiceID:             id.NewServiceID(),
			EncryptedRefreshToken: nil,
		}
		summary := storage.NewUserSessionSummary(session, "GitHub", 0)
		assert.False(t, summary.HasRefreshToken)
	})
}
