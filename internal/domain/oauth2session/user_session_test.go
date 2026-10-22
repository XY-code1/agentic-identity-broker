package oauth2session_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
)

func TestUserSession_Validate(t *testing.T) {
	tests := []struct {
		name    string
		session *storage.UserSession
		wantErr bool
	}{
		{
			name: "valid session",
			session: &storage.UserSession{
				ID:                   id.NewSessionID(),
				Principal:            id.Principal("user@example.com"),
				ServiceID:            id.NewServiceID(),
				EncryptedAccessToken: []byte("encrypted-token"),
				TokenType:            "Bearer",
			},
			wantErr: false,
		},
		{
			name: "empty ID",
			session: &storage.UserSession{
				Principal:            id.Principal("user@example.com"),
				ServiceID:            id.NewServiceID(),
				EncryptedAccessToken: []byte("token"),
				TokenType:            "Bearer",
			},
			wantErr: true,
		},
		{
			name: "empty principal",
			session: &storage.UserSession{
				ID:                   id.NewSessionID(),
				ServiceID:            id.NewServiceID(),
				EncryptedAccessToken: []byte("token"),
				TokenType:            "Bearer",
			},
			wantErr: true,
		},
		{
			name: "principal exceeds 200 chars",
			session: &storage.UserSession{
				ID:                   id.NewSessionID(),
				Principal:            id.Principal(string(make([]byte, 201))),
				ServiceID:            id.NewServiceID(),
				EncryptedAccessToken: []byte("token"),
				TokenType:            "Bearer",
			},
			wantErr: true,
		},
		{
			name: "empty service ID",
			session: &storage.UserSession{
				ID:                   id.NewSessionID(),
				Principal:            id.Principal("user@example.com"),
				EncryptedAccessToken: []byte("token"),
				TokenType:            "Bearer",
			},
			wantErr: true,
		},
		{
			name: "empty encrypted token",
			session: &storage.UserSession{
				ID:        id.NewSessionID(),
				Principal: id.Principal("user@example.com"),
				ServiceID: id.NewServiceID(),
				TokenType: "Bearer",
			},
			wantErr: true,
		},
		{
			name: "empty token type",
			session: &storage.UserSession{
				ID:                   id.NewSessionID(),
				Principal:            id.Principal("user@example.com"),
				ServiceID:            id.NewServiceID(),
				EncryptedAccessToken: []byte("token"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.session.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserSession_HasValidAccessToken(t *testing.T) {
	tests := []struct {
		name    string
		session *storage.UserSession
		want    bool
	}{
		{
			name: "no expiration",
			session: &storage.UserSession{
				AccessTokenExpiresAt: nil,
			},
			want: true,
		},
		{
			name: "valid",
			session: &storage.UserSession{
				AccessTokenExpiresAt: ptrTime(time.Now().Add(1 * time.Hour)),
			},
			want: true,
		},
		{
			name: "expired",
			session: &storage.UserSession{
				AccessTokenExpiresAt: ptrTime(time.Now().Add(-1 * time.Hour)),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.session.HasValidAccessToken())
		})
	}
}

// Helper function
func ptrTime(t time.Time) *time.Time {
	return &t
}
