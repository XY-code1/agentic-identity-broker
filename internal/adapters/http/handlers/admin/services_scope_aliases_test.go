package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/model"
)

func scopeAliasServiceRequest(scopes []OAuthScopeRequest) []byte {
	body, _ := json.Marshal(ServiceRequest{
		DisplayName:  "Identity Provider",
		ClientID:     "idp-client",
		ClientSecret: "idp-secret",
		IssuerURI:    "https://idp.example.com",
		Discovery:    DiscoveryConfigRequest{EnableDiscovery: false},
		Endpoints:    &OAuth2EndpointsRequest{TokenEndpoint: "https://idp.example.com/token", AuthorizeEndpoint: "https://idp.example.com/authorize"},
		Scopes:       scopes,
	})
	return body
}

func TestServicesHandler_CreateServiceStoresAndReturnsScopeAliases(t *testing.T) {
	mockRepo := new(MockProviderRepository)
	handler := setupHandler(t, mockRepo)
	mockRepo.On("Create", mock.Anything, mock.MatchedBy(func(entity *model.ThirdpartyOAuth2ProviderEntity) bool {
		return len(entity.Scopes) == 1 && assert.ObjectsAreEqual([]string{"https://idp.example.com/scopes/files.read"}, entity.Scopes[0].Aliases)
	})).Return(nil)

	w := httptest.NewRecorder()
	handler.CreateService(w, httptest.NewRequest(http.MethodPost, "/api/services", bytes.NewReader(scopeAliasServiceRequest([]OAuthScopeRequest{
		{ScopeValue: "files.read", Description: "Read files", Aliases: []string{"https://idp.example.com/scopes/files.read"}},
	}))))

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var response ServiceResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	require.Len(t, response.Scopes, 1)
	assert.Equal(t, []string{"https://idp.example.com/scopes/files.read"}, response.Scopes[0].Aliases)
	mockRepo.AssertExpectations(t)
}

func TestServicesHandler_CreateServiceRejectsAmbiguousScopeAliases(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scopes []OAuthScopeRequest
	}{
		{name: "alias shared by two scopes", scopes: []OAuthScopeRequest{
			{ScopeValue: "a", Description: "A", Aliases: []string{"x"}},
			{ScopeValue: "b", Description: "B", Aliases: []string{"x"}},
		}},
		{name: "alias equals another scope value", scopes: []OAuthScopeRequest{
			{ScopeValue: "a", Description: "A", Aliases: []string{"b"}},
			{ScopeValue: "b", Description: "B"},
		}},
		{name: "alias with whitespace", scopes: []OAuthScopeRequest{
			{ScopeValue: "a", Description: "A", Aliases: []string{"x y"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockRepo := new(MockProviderRepository)
			handler := setupHandler(t, mockRepo)
			w := httptest.NewRecorder()
			handler.CreateService(w, httptest.NewRequest(http.MethodPost, "/api/services", bytes.NewReader(scopeAliasServiceRequest(tc.scopes))))
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			mockRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
		})
	}
}
