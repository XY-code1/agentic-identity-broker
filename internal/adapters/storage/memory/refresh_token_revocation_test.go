package memory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
)

func TestRefreshTokenSessionStoreRevocation(t *testing.T) {
	ctx := context.Background()
	store := NewRefreshTokenSessionStore()
	create := func(signature, requestID string) {
		require.NoError(t, store.Create(ctx, &storage.RefreshTokenSession{
			Signature: signature, RequestID: requestID, AgentID: id.NewAgentID(),
			ClientID: id.NewClientID("client"), Principal: id.NewPrincipal("user@example.com"),
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}))
	}

	create("sig-1", "req-1")
	require.NoError(t, store.MarkUsed(ctx, "sig-1"))
	rotated, err := store.FindBySignature(ctx, "sig-1")
	require.NoError(t, err)
	require.Nil(t, rotated.RevokedAt)
	require.NoError(t, store.MarkRevoked(ctx, "sig-1"))
	require.NoError(t, store.MarkRevoked(ctx, "sig-1"))
	revoked, err := store.FindBySignature(ctx, "sig-1")
	require.NoError(t, err)
	require.NotNil(t, revoked.RevokedAt)
	assert.Equal(t, *rotated.UsedAt, *revoked.UsedAt)

	var storageErr *storage.StorageError
	require.ErrorAs(t, store.MarkRevoked(ctx, "unknown"), &storageErr)
	assert.Equal(t, storage.ErrorKindNotFound, storageErr.Kind)

	create("chain-1", "chain")
	create("chain-2", "chain")
	require.NoError(t, store.MarkUsed(ctx, "chain-1"))
	require.NoError(t, store.RevokeByRequestID(ctx, "chain"))
	for _, signature := range []string{"chain-1", "chain-2"} {
		session, err := store.FindBySignature(ctx, signature)
		require.NoError(t, err)
		assert.NotNil(t, session.UsedAt, signature)
		assert.NotNil(t, session.RevokedAt, signature)
	}
}
