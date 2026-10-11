package oauth2

import (
	"fmt"
	"net/url"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
)

// ConsentReason explains why an authorization request was sent to the consent screen.
type ConsentReason string

const (
	// ConsentReasonSessionRequired means a required service has no session.
	ConsentReasonSessionRequired ConsentReason = "session_required"
	// ConsentReasonSessionExpired means a session exists but can no longer deliver tokens.
	ConsentReasonSessionExpired ConsentReason = "session_expired"
	// ConsentReasonScopeMismatch means a session lacks scopes the agent requires.
	ConsentReasonScopeMismatch ConsentReason = "scope_mismatch"
)

// ConsentRedirectReason names the service whose session state sent the user to the consent
// screen. It is returned as the error of a failed service-requirement check.
type ConsentRedirectReason struct {
	Reason    ConsentReason
	ServiceID id.ServiceID
}

func (r *ConsentRedirectReason) Error() string {
	return fmt.Sprintf("%s: service %s", r.Reason, r.ServiceID)
}

// withConsentReason adds the reason and service ID to a consent URL so the consent screen can
// tell the user which connection needs attention.
func withConsentReason(consentURL string, reason *ConsentRedirectReason) (string, error) {
	if reason == nil {
		return consentURL, nil
	}
	u, err := url.Parse(consentURL)
	if err != nil {
		return "", fmt.Errorf("invalid consent URL: %w", err)
	}
	query := u.Query()
	query.Set("reason", string(reason.Reason))
	query.Set("service_id", reason.ServiceID.String())
	u.RawQuery = query.Encode()
	return u.String(), nil
}
