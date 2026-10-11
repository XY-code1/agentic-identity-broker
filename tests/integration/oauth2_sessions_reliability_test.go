package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/adapters/http/oauth2_sessions"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/adapters/storage/memory"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/model"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/oauth2session"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
)

// Regression: POST /session/refresh collapses every provider failure into 502 refresh_failed.
// A provider that rejects the stored refresh token (invalid_grant) is not an outage: the token
// is dead and the user must re-connect. The UI needs a distinct code to say so instead of
// "please try again". Scenario US3-S5 in specs/008-thirdparty-oauth2-sessions/spec.md.
func TestRefreshSession_DistinguishesProviderRejectionFromProviderOutage(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		wantStatus int
		wantCode   string
	}{
		{name: "provider rejects refresh token", status: http.StatusBadRequest, body: `{"error":"invalid_grant"}`, wantStatus: http.StatusConflict, wantCode: "refresh_rejected"},
		{name: "provider outage", status: http.StatusServiceUnavailable, body: `{"error":"temporarily_unavailable"}`, wantStatus: http.StatusBadGateway, wantCode: "refresh_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			sessionRepo := memory.NewInMemoryUserSessionRepository()
			serviceRepo := memory.NewInMemoryThirdpartyOAuth2ProviderRepository()
			grantRepo := memory.NewUserGrantRepository()
			principal := "user@example.com"
			serviceUUID := id.NewServiceID()

			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer mockServer.Close()

			require.NoError(t, serviceRepo.Create(ctx, &model.ThirdpartyOAuth2ProviderEntity{
				ID:          serviceUUID,
				DisplayName: "GitHub",
				ClientID:    id.NewClientID("test-client-id"),
				Secret:      model.NewEncryptedSecret(encryptSecretForTest(t, serviceUUID.String(), "test-secret")),
				IssuerURI:   "https://github.com",
				Endpoints: model.OAuth2Endpoints{
					AuthorizeEndpoint: "https://github.com/login/oauth/authorize",
					TokenEndpoint:     mockServer.URL,
				},
				Scopes:    []model.OAuthScope{{ScopeValue: "repo", Description: "Repository access"}},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}))

			expiry := time.Now().Add(time.Hour)
			require.NoError(t, sessionRepo.Create(ctx, &storage.UserSession{
				ID:                    id.NewSessionID(),
				Principal:             id.Principal(principal),
				ServiceID:             serviceUUID,
				EncryptedAccessToken:  encryptSecretForTest(t, serviceUUID.String(), "old-access-token"),
				EncryptedRefreshToken: encryptSecretForTest(t, serviceUUID.String(), "old-refresh-token"),
				TokenType:             "Bearer",
				Scope:                 []string{"repo"},
				InitiatedAt:           time.Now(),
				CreatedAt:             time.Now(),
				AccessTokenExpiresAt:  &expiry,
			}))

			cfg := oauth2session.DefaultConfig()
			cfg.RetryBaseDelay = 5 * time.Millisecond
			service := createOAuth2SessionService(t, serviceRepo, sessionRepo, grantRepo, nil, createTestJWEKey(t), cfg)
			handler := oauth2_sessions.NewHandler(service)
			router := setupTestRouter(handler)

			req := httptest.NewRequest(http.MethodPost, "/api/third-party/"+serviceUUID.String()+"/session/refresh", nil)
			req.Header.Set("X-Remote-User", principal)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.Equal(t, tc.wantStatus, w.Code, w.Body.String())
			var body map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, tc.wantCode, body["error"])
		})
	}
}
