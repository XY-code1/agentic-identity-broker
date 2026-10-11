package oauth2session

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
)

// Refresh outcomes recorded on oauth2_session_refreshes_total.
const (
	refreshOutcomeSuccess     = "success"
	refreshOutcomeRejected    = "rejected"
	refreshOutcomeUnavailable = "unavailable"
	refreshOutcomeError       = "error"
)

// sessionMetrics records token-lifecycle counters with bounded attributes: the service ID and
// fixed outcome or failure-detail values. Tokens and provider text are never recorded.
type sessionMetrics struct {
	refreshes          metric.Int64Counter
	refreshRetries     metric.Int64Counter
	preserved          metric.Int64Counter
	proactiveFallbacks metric.Int64Counter
	reauthRequired     metric.Int64Counter
}

func newSessionMetrics() *sessionMetrics {
	meter := otel.Meter("oauth2session")
	refreshes, _ := meter.Int64Counter("oauth2_session_refreshes_total",
		metric.WithDescription("Third-party token refreshes by final outcome"),
		metric.WithUnit("{refresh}"))
	refreshRetries, _ := meter.Int64Counter("oauth2_session_refresh_retries_total",
		metric.WithDescription("Third-party token refresh attempts repeated after a transient failure"),
		metric.WithUnit("{retry}"))
	preserved, _ := meter.Int64Counter("oauth2_session_refresh_token_preserved_total",
		metric.WithDescription("Re-connects that kept the stored refresh token because the provider omitted one"),
		metric.WithUnit("{session}"))
	proactiveFallbacks, _ := meter.Int64Counter("oauth2_session_proactive_refresh_fallbacks_total",
		metric.WithDescription("Failed early refreshes answered with the still-valid stored access token"),
		metric.WithUnit("{token}"))
	reauthRequired, _ := meter.Int64Counter("oauth2_session_reauth_required_total",
		metric.WithDescription("Token requests that require the user to log in to the service again"),
		metric.WithUnit("{request}"))
	return &sessionMetrics{
		refreshes:          refreshes,
		refreshRetries:     refreshRetries,
		preserved:          preserved,
		proactiveFallbacks: proactiveFallbacks,
		reauthRequired:     reauthRequired,
	}
}

func serviceAttribute(serviceID id.ServiceID) attribute.KeyValue {
	return attribute.String("service_id", serviceID.String())
}

func (m *sessionMetrics) recordRefresh(ctx context.Context, serviceID id.ServiceID, err error) {
	if m == nil || m.refreshes == nil {
		return
	}
	outcome := refreshOutcomeSuccess
	if err != nil {
		switch sessionFailureMetadata(err).Detail() {
		case DetailRefreshRejected:
			outcome = refreshOutcomeRejected
		case DetailProviderUnavailable:
			outcome = refreshOutcomeUnavailable
		default:
			outcome = refreshOutcomeError
		}
	}
	m.refreshes.Add(ctx, 1, metric.WithAttributes(serviceAttribute(serviceID), attribute.String("outcome", outcome)))
}

func (m *sessionMetrics) recordRetry(ctx context.Context, serviceID id.ServiceID) {
	if m == nil || m.refreshRetries == nil {
		return
	}
	m.refreshRetries.Add(ctx, 1, metric.WithAttributes(serviceAttribute(serviceID)))
}

func (m *sessionMetrics) recordPreserved(ctx context.Context, serviceID id.ServiceID) {
	if m == nil || m.preserved == nil {
		return
	}
	m.preserved.Add(ctx, 1, metric.WithAttributes(serviceAttribute(serviceID)))
}

func (m *sessionMetrics) recordProactiveFallback(ctx context.Context, serviceID id.ServiceID) {
	if m == nil || m.proactiveFallbacks == nil {
		return
	}
	m.proactiveFallbacks.Add(ctx, 1, metric.WithAttributes(serviceAttribute(serviceID)))
}

// recordReauthRequired counts a token request that failed because the user must log in again.
func (m *sessionMetrics) recordReauthRequired(ctx context.Context, serviceID id.ServiceID, err error) {
	if m == nil || m.reauthRequired == nil {
		return
	}
	detail := sessionFailureMetadata(err).Detail()
	switch detail {
	case DetailSessionMissing, DetailAccessTokenExpired, DetailRefreshTokenExpired, DetailRefreshUnavailable, DetailRefreshRejected:
		m.reauthRequired.Add(ctx, 1, metric.WithAttributes(serviceAttribute(serviceID), attribute.String("failure_detail", string(detail))))
	}
}
