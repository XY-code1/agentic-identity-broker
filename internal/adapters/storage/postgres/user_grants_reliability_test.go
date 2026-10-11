//go:build integration
// +build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression: user_grants.valid_until is TIMESTAMP (without time zone) while every other
// lifecycle column is TIMESTAMPTZ. pgx discards the zone of a non-UTC time.Time when encoding
// a TIMESTAMP parameter, so a grant expiry supplied with an offset is stored shifted by that
// offset and the SQL filter in ListByPrincipal disagrees with UserGrant.IsActive. FR-016 in
// specs/006-domain-model-apis/spec.md requires the stored expiry to be the instant the user chose.
func TestUserGrantValidUntilRoundTripsAsTheSameInstant(t *testing.T) {
	adapter, agentRepo, grantRepo, cleanup := setupUserGrantTestDB(t)
	defer cleanup()
	ctx := context.Background()

	agent := createUserGrantTestAgent(t, agentRepo, "tz")
	principal := id.Principal("tz-user@example.com")
	berlin := time.FixedZone("Europe/Berlin", 2*60*60)
	chosen := time.Now().In(berlin).Add(90 * time.Minute).Round(time.Second)

	grant := newUserGrant(principal, agent.ID, newGrantedPermissionSetEntry(t, adapter))
	grant.ValidUntil = &chosen
	require.NoError(t, grantRepo.Create(ctx, grant))

	stored, err := grantRepo.FindByPrincipalAndAgent(ctx, principal, agent.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.ValidUntil)
	assert.True(t, chosen.Equal(*stored.ValidUntil), "stored valid_until %s must be the chosen instant %s", stored.ValidUntil, chosen)

	active, err := grantRepo.ListByPrincipal(ctx, principal)
	require.NoError(t, err)
	require.Len(t, active, 1)
	assert.True(t, chosen.Equal(*active[0].ValidUntil))
}
