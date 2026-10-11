package model

import (
	"errors"
	"fmt"
	"strings"
)

// OAuthScope represents a permission scope within a third-party OAuth2 service.
// Scopes define what resources and actions an agent can access.
//
// Aliases lists other names under which the provider may report this scope in a token
// response, for example the canonical URI a provider returns for a short scope name. Granted
// scopes are normalized to ScopeValue before they are stored on a session.
type OAuthScope struct {
	ScopeValue  string
	Description string
	Aliases     []string
}

// Validate performs validation on the OAuthScope.
func (s *OAuthScope) Validate() error {
	if s.ScopeValue == "" {
		return errors.New("scope_value is required")
	}
	if s.Description == "" {
		return errors.New("description is required")
	}
	for i, alias := range s.Aliases {
		if alias == "" || strings.ContainsAny(alias, " \t\r\n") {
			return fmt.Errorf("aliases[%d] must be a non-empty scope token without whitespace", i)
		}
		if alias == s.ScopeValue {
			return fmt.Errorf("aliases[%d] must differ from scope_value", i)
		}
	}
	return nil
}

// Copy creates a deep copy of the OAuthScope.
func (s *OAuthScope) Copy() OAuthScope {
	return OAuthScope{
		ScopeValue:  s.ScopeValue,
		Description: s.Description,
		Aliases:     append([]string(nil), s.Aliases...),
	}
}

// validateScopeAliases rejects a scope set in which one reported name could normalize to two
// different configured scopes.
func validateScopeAliases(scopes []OAuthScope) error {
	owner := make(map[string]string, len(scopes))
	for _, scope := range scopes {
		owner[scope.ScopeValue] = scope.ScopeValue
	}
	for _, scope := range scopes {
		for _, alias := range scope.Aliases {
			if existing, ok := owner[alias]; ok && existing != scope.ScopeValue {
				return fmt.Errorf("scope alias %q is already used by scope %q", alias, existing)
			}
			owner[alias] = scope.ScopeValue
		}
	}
	return nil
}
