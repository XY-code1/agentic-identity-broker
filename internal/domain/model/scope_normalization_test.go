package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeGrantedScopes(t *testing.T) {
	google := &ThirdpartyOAuth2ProviderEntity{
		IssuerURI: "https://accounts.google.com",
		Scopes: []OAuthScope{
			{ScopeValue: "openid", Description: "OpenID"},
			{ScopeValue: "email", Description: "Email"},
			{ScopeValue: "profile", Description: "Profile"},
		},
	}
	custom := &ThirdpartyOAuth2ProviderEntity{
		IssuerURI: "https://login.example.com",
		Scopes: []OAuthScope{
			{ScopeValue: "files.read", Description: "Read files", Aliases: []string{"https://graph.example.com/Files.Read"}},
			{ScopeValue: "email", Description: "Email"},
		},
	}

	for _, tc := range []struct {
		name     string
		provider *ThirdpartyOAuth2ProviderEntity
		granted  []string
		want     []string
	}{
		{
			name:     "google canonical URIs map to configured short names",
			provider: google,
			granted:  []string{"openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
			want:     []string{"openid", "email", "profile"},
		},
		{
			name:     "well-known google aliases do not apply to other providers",
			provider: custom,
			granted:  []string{"https://www.googleapis.com/auth/userinfo.email"},
			want:     []string{"https://www.googleapis.com/auth/userinfo.email"},
		},
		{
			name:     "configured alias maps to scope value",
			provider: custom,
			granted:  []string{"https://graph.example.com/Files.Read", "email"},
			want:     []string{"files.read", "email"},
		},
		{
			name:     "unknown scopes are kept and duplicates removed",
			provider: google,
			granted:  []string{"email", "https://www.googleapis.com/auth/userinfo.email", "drive"},
			want:     []string{"email", "drive"},
		},
		{
			name:     "google alias only applies when the short name is configured",
			provider: &ThirdpartyOAuth2ProviderEntity{Flavor: OAuth2FlavorGoogle, Scopes: []OAuthScope{{ScopeValue: "openid", Description: "OpenID"}}},
			granted:  []string{"https://www.googleapis.com/auth/userinfo.email"},
			want:     []string{"https://www.googleapis.com/auth/userinfo.email"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.provider.NormalizeGrantedScopes(tc.granted))
		})
	}
}

func TestOAuthScopeAliasValidation(t *testing.T) {
	assert.NoError(t, (&OAuthScope{ScopeValue: "email", Description: "Email", Aliases: []string{"https://x/userinfo.email"}}).Validate())
	assert.Error(t, (&OAuthScope{ScopeValue: "email", Description: "Email", Aliases: []string{""}}).Validate())
	assert.Error(t, (&OAuthScope{ScopeValue: "email", Description: "Email", Aliases: []string{"a b"}}).Validate())
	assert.Error(t, (&OAuthScope{ScopeValue: "email", Description: "Email", Aliases: []string{"email"}}).Validate())

	assert.NoError(t, validateScopeAliases([]OAuthScope{{ScopeValue: "a", Aliases: []string{"x"}}, {ScopeValue: "b", Aliases: []string{"y"}}}))
	assert.ErrorContains(t, validateScopeAliases([]OAuthScope{{ScopeValue: "a", Aliases: []string{"x"}}, {ScopeValue: "b", Aliases: []string{"x"}}}), `"x"`)
	assert.ErrorContains(t, validateScopeAliases([]OAuthScope{{ScopeValue: "a", Aliases: []string{"b"}}, {ScopeValue: "b"}}), `"b"`)
}

func TestOAuthScopeCopyIsDeep(t *testing.T) {
	original := OAuthScope{ScopeValue: "email", Description: "Email", Aliases: []string{"alias"}}
	copied := original.Copy()
	original.Aliases[0] = "mutated"
	assert.Equal(t, []string{"alias"}, copied.Aliases)
}
