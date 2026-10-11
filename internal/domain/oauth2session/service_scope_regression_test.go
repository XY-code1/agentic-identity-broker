package oauth2session_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/model"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/oauth2session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 013 US1-S9 (RFC 6749 §6): a refresh response may narrow the granted scope. The session must reflect it so
// token exchange and consent evaluate the real scope instead of the scope from first connect.
func TestGetValidAccessToken_UpdatesSessionScopeWhenProviderNarrowsScopeOnRefresh(t *testing.T) {
	ctx := context.Background()
	service, _, sessions, _, _, providers := setupServiceWithConfig(t, nil)
	serviceID := id.NewServiceID()
	principal := id.Principal("user@example.com")

	upstream, _ := jsonTokenEndpoint(func(_ map[string]string, _ int32) (int, string) {
		return http.StatusOK, `{"access_token":"narrowed-access","token_type":"Bearer","expires_in":3600,"refresh_token":"next-refresh","scope":"repo"}`
	})
	defer upstream.Close()
	provider := createTestService(serviceID)
	provider.Endpoints.TokenEndpoint = upstream.URL
	require.NoError(t, providers.Create(ctx, provider))

	seedExpiringSession(t, sessions, principal, serviceID, time.Now().Add(-time.Hour), "stored-refresh", []string{"repo", "user"})

	session, _, err := service.GetValidAccessToken(ctx, principal, serviceID)
	require.NoError(t, err)
	assert.Equal(t, []string{"repo"}, session.Scope, "narrowed scope from the refresh response must replace the stored scope")
	persisted, err := sessions.FindByPrincipalAndService(ctx, principal, serviceID)
	require.NoError(t, err)
	assert.Equal(t, []string{"repo"}, persisted.Scope)
}

// 008 US2-S12: Google returns canonical scope URIs (https://www.googleapis.com/auth/userinfo.email) for the
// short aliases (email) an administrator configures. Without normalization every exchange fails
// scope validation with "re-authentication required" although the user just connected.
func TestHandleCallback_NormalizesProviderScopeAliasesToConfiguredScopes(t *testing.T) {
	ctx := context.Background()
	service, _, _, _, _, providers := setupServiceWithConfig(t, nil)
	serviceID := id.NewServiceID()
	principal := id.Principal("user@example.com")

	upstream, _ := jsonTokenEndpoint(func(_ map[string]string, _ int32) (int, string) {
		return http.StatusOK, `{"access_token":"google-access","token_type":"Bearer","expires_in":3599,"refresh_token":"google-refresh","scope":"openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"}`
	})
	defer upstream.Close()
	provider := createTestService(serviceID)
	provider.DisplayName = "Google"
	provider.IssuerURI = "https://accounts.google.com"
	provider.Endpoints.AuthorizeEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	provider.Endpoints.TokenEndpoint = upstream.URL
	provider.Scopes = []model.OAuthScope{
		{ScopeValue: "openid", Description: "OpenID"},
		{ScopeValue: "email", Description: "Email"},
		{ScopeValue: "profile", Description: "Profile"},
	}
	require.NoError(t, providers.Create(ctx, provider))

	flow, err := service.InitiateOAuth2Flow(ctx, principal, serviceID, "https://example.com/sessions")
	require.NoError(t, err)
	result, err := service.HandleCallback(ctx, principal, &oauth2session.HandleCallbackRequest{ServiceID: serviceID, Code: "code", State: flow.StateToken})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"openid", "email", "profile"}, result.Session.Scope,
		"provider scope aliases must be recorded under the configured scope values so grants and exchanges match")
}
