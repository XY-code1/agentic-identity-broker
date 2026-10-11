package oauth2

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/ports"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/ptr"
)

// US3-S8 from specs/011-agent-permission-requirements/spec.md: a consent redirect caused by a
// service connection names the service and the reason.
func TestService_HandleAuthorization_ConsentRedirectCarriesReason(t *testing.T) {
	principal := id.Principal("user@example.com")
	agentID := id.NewAgentID()
	serviceID := id.NewServiceID()
	permissionSetID := id.NewPermissionSetID()
	expired := time.Now().Add(-time.Hour)

	cfg := &OAuth2Config{
		UpstreamAuthorizeEndpoint: "https://auth.example.com/authorize",
		PublicURL:                 "https://broker.example.com",
		ModeStrategy:              NewProxyModeStrategy(),
	}
	authReq := &ports.AuthorizationRequest{
		ClientID:     id.ClientID(agentID.String()),
		RedirectURI:  "https://client.example.com/callback",
		ResponseType: "code",
		OriginalURL:  "https://broker.example.com/oauth2/authorize?client_id=" + agentID.String(),
	}

	for _, tc := range []struct {
		name         string
		requirements []storage.ServiceRequirement
		session      *storage.UserSession
		wantReason   ConsentReason
	}{
		{
			name:       "delegated session cannot deliver tokens",
			session:    &storage.UserSession{ID: id.NewSessionID(), Principal: principal, ServiceID: serviceID, TokenType: "Bearer", AccessTokenExpiresAt: &expired},
			wantReason: ConsentReasonSessionExpired,
		},
		{
			name:         "mandatory service has no session",
			requirements: []storage.ServiceRequirement{{ServiceID: serviceID, RequirementType: storage.RequirementTypeMandatory}},
			wantReason:   ConsentReasonSessionRequired,
		},
		{
			name:         "mandatory service session lacks required scopes",
			requirements: []storage.ServiceRequirement{{ServiceID: serviceID, RequirementType: storage.RequirementTypeMandatory, RequiredScopes: []string{"repo"}}},
			session:      &storage.UserSession{ID: id.NewSessionID(), Principal: principal, ServiceID: serviceID, TokenType: "Bearer", Scope: []string{"user"}},
			wantReason:   ConsentReasonScopeMismatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agentRepo := NewMockAgentRepository()
			grantRepo := NewMockGrantRepository()
			sessionRepo := NewMockSessionRepository()
			require.NoError(t, agentRepo.Create(context.Background(), &storage.Agent{
				ID:                  agentID,
				ClientID:            ptr.To(id.ClientID("client-1")),
				DisplayName:         "Test Client",
				RedirectURIs:        []string{"https://client.example.com/callback"},
				PermissionSets:      []storage.AgentPermissionSetEntry{{PermissionSetID: permissionSetID}},
				ServiceRequirements: tc.requirements,
			}))
			require.NoError(t, grantRepo.Create(context.Background(), &storage.UserGrant{
				ID:                    id.NewGrantID(),
				Principal:             principal,
				AgentID:               agentID,
				GrantedPermissionSets: []storage.GrantedPermissionSetEntry{{PermissionSetID: permissionSetID, IncludedServiceIDs: []id.ServiceID{serviceID}}},
			}))
			sessionRepo.findFunc = func(context.Context, id.Principal, id.ServiceID) (*storage.UserSession, error) {
				return tc.session, nil
			}

			decision, err := newTestAuthorizationServiceWithSessions(agentRepo, grantRepo, sessionRepo, cfg).
				HandleAuthorization(context.Background(), authReq, principal)
			require.NoError(t, err)
			require.Equal(t, "redirect_to_consent", decision.Action)
			redirect, err := url.Parse(decision.RedirectURL)
			require.NoError(t, err)
			assert.Equal(t, "/agents/"+agentID.String(), redirect.Path)
			assert.NotEmpty(t, redirect.Query().Get("session_token"))
			assert.Equal(t, string(tc.wantReason), redirect.Query().Get("reason"))
			assert.Equal(t, serviceID.String(), redirect.Query().Get("service_id"))
		})
	}
}

func TestService_HandleAuthorization_ConsentRedirectWithoutGrantHasNoReason(t *testing.T) {
	agentID := id.NewAgentID()
	agentRepo := NewMockAgentRepository()
	require.NoError(t, agentRepo.Create(context.Background(), &storage.Agent{
		ID:           agentID,
		ClientID:     ptr.To(id.ClientID("client-1")),
		DisplayName:  "Test Client",
		RedirectURIs: []string{"https://client.example.com/callback"},
	}))
	cfg := &OAuth2Config{
		UpstreamAuthorizeEndpoint: "https://auth.example.com/authorize",
		PublicURL:                 "https://broker.example.com",
		ModeStrategy:              NewProxyModeStrategy(),
	}
	decision, err := newTestAuthorizationServiceWithSessions(agentRepo, NewMockGrantRepository(), NewMockSessionRepository(), cfg).
		HandleAuthorization(context.Background(), &ports.AuthorizationRequest{
			ClientID:     id.ClientID(agentID.String()),
			RedirectURI:  "https://client.example.com/callback",
			ResponseType: "code",
			OriginalURL:  "https://broker.example.com/oauth2/authorize",
		}, id.Principal("user@example.com"))
	require.NoError(t, err)
	require.Equal(t, "redirect_to_consent", decision.Action)
	redirect, err := url.Parse(decision.RedirectURL)
	require.NoError(t, err)
	assert.Empty(t, redirect.Query().Get("reason"))
	assert.Empty(t, redirect.Query().Get("service_id"))
}
