package oauth2session_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/oauth2session"
)

func withMetricReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(previous)
		_ = provider.Shutdown(context.Background())
	})
	return reader
}

// counterValue sums the data points of a counter whose attributes include every wanted pair.
func counterValue(t *testing.T, reader *sdkmetric.ManualReader, name string, want ...attribute.KeyValue) int64 {
	t.Helper()
	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &collected))
	var total int64
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			require.True(t, ok, "%s must be an Int64 counter", name)
			for _, point := range sum.DataPoints {
				matches := true
				for _, kv := range want {
					if value, found := point.Attributes.Value(kv.Key); !found || value != kv.Value {
						matches = false
					}
				}
				if matches {
					total += point.Value
				}
			}
		}
	}
	return total
}

func TestSessionMetrics_RefreshRetryAndOutcome(t *testing.T) {
	reader := withMetricReader(t)
	ctx := context.Background()
	service, _, sessions, _, _, providers := setupServiceWithConfig(t, nil)
	serviceID := id.NewServiceID()
	principal := id.Principal("metrics@example.com")
	upstream, _ := jsonTokenEndpoint(func(_ map[string]string, call int32) (int, string) {
		if call == 1 {
			return http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`
		}
		return http.StatusOK, `{"access_token":"new","token_type":"Bearer","expires_in":3600}`
	})
	defer upstream.Close()
	provider := createTestService(serviceID)
	provider.Endpoints.TokenEndpoint = upstream.URL
	require.NoError(t, providers.Create(ctx, provider))
	seedExpiringSession(t, sessions, principal, serviceID, time.Now().Add(-time.Hour), "stored-refresh", []string{"repo"})

	_, _, err := service.GetValidAccessToken(ctx, principal, serviceID)
	require.NoError(t, err)

	serviceAttr := attribute.String("service_id", serviceID.String())
	assert.EqualValues(t, 1, counterValue(t, reader, "oauth2_session_refresh_retries_total", serviceAttr))
	assert.EqualValues(t, 1, counterValue(t, reader, "oauth2_session_refreshes_total", serviceAttr, attribute.String("outcome", "success")))
}

func TestSessionMetrics_ReauthRequiredAndRejection(t *testing.T) {
	reader := withMetricReader(t)
	ctx := context.Background()
	service, _, sessions, _, _, providers := setupServiceWithConfig(t, nil)
	serviceID := id.NewServiceID()
	principal := id.Principal("metrics@example.com")
	upstream, _ := jsonTokenEndpoint(func(_ map[string]string, _ int32) (int, string) {
		return http.StatusBadRequest, `{"error":"invalid_grant"}`
	})
	defer upstream.Close()
	provider := createTestService(serviceID)
	provider.Endpoints.TokenEndpoint = upstream.URL
	require.NoError(t, providers.Create(ctx, provider))
	seedExpiringSession(t, sessions, principal, serviceID, time.Now().Add(-time.Hour), "stored-refresh", []string{"repo"})

	_, _, err := service.GetValidAccessToken(ctx, principal, serviceID)
	require.Error(t, err)

	serviceAttr := attribute.String("service_id", serviceID.String())
	assert.EqualValues(t, 1, counterValue(t, reader, "oauth2_session_refreshes_total", serviceAttr, attribute.String("outcome", "rejected")))
	assert.EqualValues(t, 1, counterValue(t, reader, "oauth2_session_reauth_required_total", serviceAttr, attribute.String("failure_detail", "refresh_rejected")))
}

func TestSessionMetrics_ProactiveFallbackAndPreservedRefreshToken(t *testing.T) {
	reader := withMetricReader(t)
	ctx := context.Background()
	service, _, sessions, _, _, providers := setupServiceWithConfig(t, nil)
	serviceID := id.NewServiceID()
	principal := id.Principal("metrics@example.com")
	upstream, _ := jsonTokenEndpoint(func(form map[string]string, _ int32) (int, string) {
		if form["grant_type"] == "refresh_token" {
			return http.StatusBadRequest, `{"error":"invalid_grant"}`
		}
		return http.StatusOK, `{"access_token":"reconnected","token_type":"Bearer","expires_in":3600}`
	})
	defer upstream.Close()
	provider := createTestService(serviceID)
	provider.Endpoints.TokenEndpoint = upstream.URL
	require.NoError(t, providers.Create(ctx, provider))
	seedExpiringSession(t, sessions, principal, serviceID, time.Now().Add(10*time.Second), "stored-refresh", []string{"repo"})

	_, _, err := service.GetValidAccessToken(ctx, principal, serviceID)
	require.NoError(t, err)
	reconnect(t, service, principal, serviceID)

	serviceAttr := attribute.String("service_id", serviceID.String())
	assert.EqualValues(t, 1, counterValue(t, reader, "oauth2_session_proactive_refresh_fallbacks_total", serviceAttr))
	assert.EqualValues(t, 1, counterValue(t, reader, "oauth2_session_refresh_token_preserved_total", serviceAttr))
}

func reconnect(t *testing.T, service *oauth2session.OAuth2SessionService, principal id.Principal, serviceID id.ServiceID) {
	t.Helper()
	ctx := context.Background()
	flow, err := service.InitiateOAuth2Flow(ctx, principal, serviceID, "https://example.com/sessions")
	require.NoError(t, err)
	_, err = service.HandleCallback(ctx, principal, &oauth2session.HandleCallbackRequest{ServiceID: serviceID, Code: "code", State: flow.StateToken})
	require.NoError(t, err)
}
