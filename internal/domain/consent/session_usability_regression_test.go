package consent

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/model"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/ptr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression: the consent screen reports "Active Session" for any session whose refresh token
// has not passed a recorded expiry, even when the access token is expired and no refresh token
// exists. Token exchange for such a session fails with access_token_expired, so the user sees a
// connected service that agents cannot use. Scenario US3-S7 in specs/011-agent-permission-requirements/spec.md.
func TestService_GetAgentConsentDetail_ReportsSessionWithoutUsableTokensAsNotConnected(t *testing.T) {
	ctx := context.Background()
	principal := id.Principal("user@example.com")
	serviceID := id.NewServiceID()
	agentID := id.NewAgentID()
	permissionSetID := id.NewPermissionSetID()

	permissionSetService := &mockPermissionSetService{permissionSets: map[id.PermissionSetID]*storage.PermissionSet{
		permissionSetID: {
			ID:   permissionSetID,
			Name: "GitHub",
			ServiceScopes: []storage.ServiceScope{
				{ServiceID: serviceID, Scopes: []string{"repo"}, RequirementType: storage.RequirementTypeMandatory},
			},
		},
	}}
	agent := &storage.Agent{
		ID:          agentID,
		ClientID:    ptr.To(id.ClientID("agent-client")),
		DisplayName: "Agent",
		ServiceRequirements: []storage.ServiceRequirement{
			{ServiceID: serviceID, RequirementType: storage.RequirementTypeMandatory, RequiredScopes: []string{"repo"}},
		},
		PermissionSets: []storage.AgentPermissionSetEntry{{PermissionSetID: permissionSetID, RequirementType: storage.RequirementTypeMandatory}},
	}
	github := &model.ThirdpartyOAuth2ProviderEntity{
		ID:          serviceID,
		DisplayName: "GitHub",
		Scopes:      []model.OAuthScope{{ScopeValue: "repo", Description: "Repos"}},
		Secret:      model.NewEncryptedSecret([]byte("cipher")),
	}

	for _, tc := range []struct {
		name          string
		session       func() *storage.UserSession
		wantConnected bool
	}{
		{
			name: "expired access token without refresh token is not connected",
			session: func() *storage.UserSession {
				expired := time.Now().Add(-time.Hour)
				return &storage.UserSession{ID: id.NewSessionID(), ServiceID: serviceID, EncryptedAccessToken: []byte("x"), AccessTokenExpiresAt: &expired}
			},
			wantConnected: false,
		},
		{
			name: "expired access token with refresh token is connected",
			session: func() *storage.UserSession {
				expired := time.Now().Add(-time.Hour)
				return &storage.UserSession{ID: id.NewSessionID(), ServiceID: serviceID, EncryptedAccessToken: []byte("x"), EncryptedRefreshToken: []byte("r"), AccessTokenExpiresAt: &expired}
			},
			wantConnected: true,
		},
		{
			name: "expired refresh token is not connected",
			session: func() *storage.UserSession {
				expired := time.Now().Add(-time.Hour)
				return &storage.UserSession{ID: id.NewSessionID(), ServiceID: serviceID, EncryptedAccessToken: []byte("x"), EncryptedRefreshToken: []byte("r"), AccessTokenExpiresAt: &expired, RefreshTokenExpiresAt: &expired}
			},
			wantConnected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService(
				&mockAgentRepo{agents: map[id.AgentID]*storage.Agent{agentID: agent}},
				newTestProviderService(&mockServiceRepo{services: map[id.ServiceID]*model.ThirdpartyOAuth2ProviderEntity{serviceID: github}}),
				&mockGrantRepo{grants: map[id.GrantID]*storage.UserGrant{}},
				&mockSessionRepo{findFunc: func(_ context.Context, _ id.Principal, _ id.ServiceID) (*storage.UserSession, error) {
					return tc.session(), nil
				}},
				permissionSetService,
				slog.Default(),
			)
			detail, err := svc.GetAgentConsentDetail(ctx, agentID, principal)
			require.NoError(t, err)
			require.Len(t, detail.ServiceRequirements, 1)
			assert.Equal(t, tc.wantConnected, detail.ServiceRequirements[0].IsConnected)
		})
	}
}

func TestUTCTimeNormalizesOffsetsToTheSameInstant(t *testing.T) {
	berlin := time.FixedZone("Europe/Berlin", 2*60*60)
	local := time.Date(2030, 1, 1, 18, 0, 0, 0, berlin)
	got := utcTime(&local)
	require.NotNil(t, got)
	assert.Equal(t, time.UTC, got.Location())
	assert.True(t, local.Equal(*got))
	assert.Nil(t, utcTime(nil))
}
