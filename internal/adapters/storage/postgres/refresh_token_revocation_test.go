//go:build integration
// +build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
)

func TestRefreshTokenSessionRepoRevocation(t *testing.T) {
	adapter, cleanup := setupRefreshTokenSessionTestDB(t)
	defer cleanup()
	repo := NewRefreshTokenSessionRepo(adapter)
	ctx := context.Background()

	create := func(t *testing.T, signature, requestID string) {
		t.Helper()
		agent := createTestAgent(t, adapter)
		require.NoError(t, repo.Create(ctx, &storage.RefreshTokenSession{
			Signature: signature, RequestID: requestID, AgentID: agent.ID,
			ClientID: id.NewClientID("client-" + signature), Principal: id.NewPrincipal("user@example.com"),
			Scope: "offline_access", ExpiresAt: time.Now().Add(time.Hour).UTC(), CreatedAt: time.Now().UTC(),
		}))
	}

	t.Run("revoking a rotated token keeps its rotation time", func(t *testing.T) {
		create(t, "rev-sig-1", "rev-req-1")
		require.NoError(t, repo.MarkUsed(ctx, "rev-sig-1"))
		rotated, err := repo.FindBySignature(ctx, "rev-sig-1")
		require.NoError(t, err)
		require.Nil(t, rotated.RevokedAt)

		require.NoError(t, repo.MarkRevoked(ctx, "rev-sig-1"))
		require.NoError(t, repo.MarkRevoked(ctx, "rev-sig-1"), "revocation is idempotent")
		revoked, err := repo.FindBySignature(ctx, "rev-sig-1")
		require.NoError(t, err)
		require.NotNil(t, revoked.RevokedAt)
		assert.WithinDuration(t, *rotated.UsedAt, *revoked.UsedAt, time.Millisecond)
	})

	t.Run("revoking an unknown token reports not found", func(t *testing.T) {
		err := repo.MarkRevoked(ctx, "rev-unknown")
		var storageErr *storage.StorageError
		require.ErrorAs(t, err, &storageErr)
		assert.Equal(t, storage.ErrorKindNotFound, storageErr.Kind)
	})

	t.Run("revoking a chain revokes rotated and active tokens", func(t *testing.T) {
		create(t, "rev-chain-1", "rev-chain")
		create(t, "rev-chain-2", "rev-chain")
		require.NoError(t, repo.MarkUsed(ctx, "rev-chain-1"))
		require.NoError(t, repo.RevokeByRequestID(ctx, "rev-chain"))
		for _, signature := range []string{"rev-chain-1", "rev-chain-2"} {
			session, err := repo.FindBySignature(ctx, signature)
			require.NoError(t, err)
			assert.NotNil(t, session.UsedAt, signature)
			assert.NotNil(t, session.RevokedAt, signature)
		}
	})
}
