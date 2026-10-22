package storage

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUserSession_Usability(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		past, future := now.Add(-time.Second), now.Add(time.Second)
		for _, tc := range []struct {
			name          string
			accessExpiry  *time.Time
			refreshExpiry *time.Time
			refresh       []byte
			wantExpired   bool
		}{
			{name: "access-only valid", accessExpiry: &future},
			{name: "access-only spent", accessExpiry: &past, wantExpired: true},
			{name: "access expires now", accessExpiry: &now, wantExpired: true},
			{name: "unknown access expiry"},
			{name: "unknown refresh expiry", accessExpiry: &past, refresh: []byte("refresh")},
			{name: "refreshable", accessExpiry: &past, refreshExpiry: &future, refresh: []byte("refresh")},
			{name: "both spent", accessExpiry: &past, refreshExpiry: &past, refresh: []byte("refresh"), wantExpired: true},
			{name: "refresh expires now", accessExpiry: &past, refreshExpiry: &now, refresh: []byte("refresh"), wantExpired: true},
			{name: "valid access despite spent refresh", accessExpiry: &future, refreshExpiry: &past, refresh: []byte("refresh")},
		} {
			session := &UserSession{AccessTokenExpiresAt: tc.accessExpiry, RefreshTokenExpiresAt: tc.refreshExpiry, EncryptedRefreshToken: tc.refresh}
			assert.Equal(t, tc.wantExpired, session.IsExpired(), tc.name)
			assert.Equal(t, tc.wantExpired, NewUserSessionSummary(session, "provider", 0).IsExpired, tc.name)
		}
	})
}
