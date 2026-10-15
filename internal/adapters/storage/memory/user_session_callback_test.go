package memory

import (
	"context"
	"testing"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateIfAbsentKeepsConcurrentCallbackWinner(t *testing.T) {
	repo := NewInMemoryUserSessionRepository()
	ctx := context.Background()
	principal, serviceID := id.Principal("callbacks@example.com"), id.NewServiceID()
	type result struct {
		session *storage.UserSession
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, token := range []string{"first-account", "second-account"} {
		candidate := refreshTestSession(principal, serviceID)
		candidate.EncryptedAccessToken = []byte(token)
		candidate.CallbackID = token
		go func() {
			<-start
			session, err := repo.CreateIfAbsent(ctx, candidate)
			results <- result{session, err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	require.NoError(t, first.err)
	require.NoError(t, second.err)
	require.NotNil(t, first.session)
	require.NotNil(t, second.session)
	assert.Equal(t, first.session.ID, second.session.ID)
	assert.Equal(t, first.session.EncryptedAccessToken, second.session.EncryptedAccessToken)
	persisted, err := repo.FindByPrincipalAndService(ctx, principal, serviceID)
	require.NoError(t, err)
	assert.Equal(t, first.session.CallbackID, persisted.CallbackID)
	assert.Equal(t, first.session.EncryptedAccessToken, persisted.EncryptedAccessToken)
}
