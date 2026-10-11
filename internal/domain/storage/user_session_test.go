package storage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUserSession_HasAccessTokenValidFor(t *testing.T) {
	inFiveSeconds := time.Now().Add(5 * time.Second)
	inOneHour := time.Now().Add(time.Hour)
	expired := time.Now().Add(-time.Second)

	for _, tc := range []struct {
		name      string
		expiresAt *time.Time
		window    time.Duration
		want      bool
	}{
		{name: "no recorded expiry never expires", window: time.Hour, want: true},
		{name: "valid beyond window", expiresAt: &inOneHour, window: 30 * time.Second, want: true},
		{name: "expires inside window", expiresAt: &inFiveSeconds, window: 30 * time.Second, want: false},
		{name: "still valid without window", expiresAt: &inFiveSeconds, want: true},
		{name: "already expired", expiresAt: &expired, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := &UserSession{AccessTokenExpiresAt: tc.expiresAt}
			assert.Equal(t, tc.want, session.HasAccessTokenValidFor(tc.window))
		})
	}
}

func TestUserSession_IsUsable(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		name    string
		session UserSession
		want    bool
	}{
		{name: "valid access token", session: UserSession{AccessTokenExpiresAt: &future}, want: true},
		{name: "no recorded expiry", session: UserSession{}, want: true},
		{name: "expired access token with refresh token", session: UserSession{AccessTokenExpiresAt: &past, EncryptedRefreshToken: []byte("r")}, want: true},
		{name: "expired access token without refresh token", session: UserSession{AccessTokenExpiresAt: &past}, want: false},
		{name: "expired refresh token", session: UserSession{AccessTokenExpiresAt: &past, EncryptedRefreshToken: []byte("r"), RefreshTokenExpiresAt: &past}, want: false},
		{name: "expired refresh token with valid access token is expired per FR-002", session: UserSession{AccessTokenExpiresAt: &future, EncryptedRefreshToken: []byte("r"), RefreshTokenExpiresAt: &past}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.session.IsUsable())
		})
	}
}
