package oauth2server

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
)

// Regression suite for broker-issued refresh tokens (local and hybrid mode agents).
// Scenario references: specs/033-offline-access-refresh/spec.md US1-S4 and US1-S5.
//
// fosite's refresh handler revokes the entire request chain on any re-presentation of a
// rotated token. Real clients retry after a lost response and MCP hosts frequently run two
// processes with one refresh token, so strict single-use rotation without a reuse grace
// window logs the user out of every agent in the chain.

func establishOfflineSession(t *testing.T) (*Provider, string, string, string) {
	t.Helper()
	provider, agentRepo, _ := newTestProvider(t)
	agent, _, plaintext := setupTestCredentials(t, provider, agentRepo)
	agent.RedirectURIs = []string{"http://localhost:8080/callback"}
	require.NoError(t, agentRepo.Update(context.Background(), agent))

	verifier := "rotation-regression-verifier-12345678901234567890"
	challenge := generateS256Challenge(verifier)
	code, err := provider.HandleAuthorize(
		context.Background(),
		agent.ID.String(),
		"http://localhost:8080/callback",
		"code",
		"read offline_access",
		"state",
		challenge,
		"S256",
		id.NewPrincipal("user@example.com"),
	)
	require.NoError(t, err)

	resp, err := provider.HandleAuthorizationCodeExchange(
		context.Background(),
		agent.ID.String(),
		plaintext,
		code,
		"http://localhost:8080/callback",
		verifier,
	)
	require.NoError(t, err)
	require.NotEmpty(t, resp.RefreshToken)
	return provider, agent.ID.String(), plaintext, resp.RefreshToken
}

// US1-S4: a client that lost the response to a successful refresh retries with the token it
// still holds. Within the reuse grace window the broker must answer with a usable token pair
// instead of revoking the chain.
func TestProvider_RefreshTokens_ReplayWithinGraceWindowDoesNotRevokeChain(t *testing.T) {
	provider, clientID, secret, initialRefresh := establishOfflineSession(t)
	ctx := context.Background()

	first, err := provider.HandleRefreshToken(ctx, clientID, secret, initialRefresh, "")
	require.NoError(t, err)
	require.NotEmpty(t, first.RefreshToken)

	replay, err := provider.HandleRefreshToken(ctx, clientID, secret, initialRefresh, "")
	require.NoError(t, err, "an immediate replay of the rotated token must be treated as a lost-response retry, not as theft")
	assert.NotEmpty(t, replay.AccessToken)
	assert.NotEmpty(t, replay.RefreshToken)

	latest := first.RefreshToken
	if replay.RefreshToken != "" {
		latest = replay.RefreshToken
	}
	next, err := provider.HandleRefreshToken(ctx, clientID, secret, latest, "")
	require.NoError(t, err, "the newest refresh token must still be valid after a grace-window replay")
	assert.NotEmpty(t, next.AccessToken)
}

// US1-S5: two processes sharing one refresh token race the token endpoint. One request may be
// told to retry, but the winner's new refresh token must survive the loser's retry.
func TestProvider_RefreshTokens_ConcurrentPresentationsDoNotRevokeWinner(t *testing.T) {
	provider, clientID, secret, initialRefresh := establishOfflineSession(t)
	ctx := context.Background()

	type outcome struct {
		refreshToken string
		err          error
	}
	outcomes := make([]outcome, 2)
	var wg sync.WaitGroup
	for i := range outcomes {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			resp, err := provider.HandleRefreshToken(ctx, clientID, secret, initialRefresh, "")
			if err != nil {
				outcomes[slot] = outcome{err: err}
				return
			}
			outcomes[slot] = outcome{refreshToken: resp.RefreshToken}
		}(i)
	}
	wg.Wait()

	var winner string
	for _, o := range outcomes {
		if o.err == nil && o.refreshToken != "" {
			winner = o.refreshToken
		}
	}
	require.NotEmpty(t, winner, "at least one concurrent refresh must succeed")

	// The losing process retries with the token it still holds, exactly like a real client.
	_, _ = provider.HandleRefreshToken(ctx, clientID, secret, initialRefresh, "")

	next, err := provider.HandleRefreshToken(ctx, clientID, secret, winner, "")
	require.NoError(t, err, "the winner's refresh token must survive the loser's retry")
	assert.NotEmpty(t, next.AccessToken)
}
