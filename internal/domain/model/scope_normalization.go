package model

import (
	"net/url"
	"strings"
)

// googleScopeAliases maps the canonical scope URIs Google reports in token responses to the
// OpenID Connect short names administrators usually configure.
var googleScopeAliases = map[string]string{
	"https://www.googleapis.com/auth/userinfo.email":   "email",
	"https://www.googleapis.com/auth/userinfo.profile": "profile",
}

var googleHosts = map[string]struct{}{
	"accounts.google.com":   {},
	"oauth2.googleapis.com": {},
}

// isGoogleProvider reports whether the provider is Google, by flavor or by its well-known hosts.
func (e *ThirdpartyOAuth2ProviderEntity) isGoogleProvider() bool {
	if e.Flavor == OAuth2FlavorGoogle {
		return true
	}
	for _, raw := range []string{e.IssuerURI, e.Endpoints.TokenEndpoint, e.Endpoints.AuthorizeEndpoint} {
		if parsed, err := url.Parse(raw); err == nil {
			if _, ok := googleHosts[strings.ToLower(parsed.Hostname())]; ok {
				return true
			}
		}
	}
	return false
}

// NormalizeGrantedScopes maps scope names reported by the provider to the configured scope
// values, using configured aliases first and well-known provider aliases second. Unknown
// scopes are kept unchanged, duplicates are removed, and the provider's order is preserved.
func (e *ThirdpartyOAuth2ProviderEntity) NormalizeGrantedScopes(granted []string) []string {
	configured := make(map[string]string, len(e.Scopes))
	for _, scope := range e.Scopes {
		configured[scope.ScopeValue] = scope.ScopeValue
	}
	if e.isGoogleProvider() {
		for alias, value := range googleScopeAliases {
			if _, ok := configured[value]; ok {
				configured[alias] = value
			}
		}
	}
	for _, scope := range e.Scopes {
		for _, alias := range scope.Aliases {
			configured[alias] = scope.ScopeValue
		}
	}

	normalized := make([]string, 0, len(granted))
	seen := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		if value, ok := configured[scope]; ok {
			scope = value
		}
		if _, dup := seen[scope]; dup {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	return normalized
}
