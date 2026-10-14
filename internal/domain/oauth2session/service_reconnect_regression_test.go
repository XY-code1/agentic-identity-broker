package oauth2session

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/id"
	"github.com/agentic-identity-broker/agentic-identity-broker/internal/domain/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestReconnectWithoutRefreshTokenReplacesConcurrentRotationUnderLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		service, provider, stored := newOperationTestService(t, io.Discard)
		ctx := context.Background()
		refreshStarted := make(chan struct{})
		releaseRefresh := make(chan struct{})
		service.httpClient.Transport = operationTransport(func(*http.Request) (*http.Response, error) {
			close(refreshStarted)
			<-releaseRefresh
			return operationTokenResponse(http.StatusOK, `{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600}`), nil
		})
		var lock sync.Mutex
		var lockCalls atomic.Int32
		reconnectWaiting := make(chan struct{})
		service.refreshRepo = operationRefreshRepository(func(ctx context.Context, _ id.Principal, _ id.ServiceID, update func(context.Context, *storage.UserSession) (bool, error)) (*storage.UserSession, error) {
			if lockCalls.Add(1) == 2 {
				close(reconnectWaiting)
			}
			lock.Lock()
			defer lock.Unlock()
			current := *stored
			changed, err := update(ctx, &current)
			if changed && err == nil {
				*stored = current
			}
			return &current, err
		})
		refreshed := make(chan error, 1)
		go func() {
			_, _, _, err := service.refreshDueSession(ctx, stored.Principal, provider.ID, time.Now, RefreshTriggerOnDemand)
			refreshed <- err
		}()
		<-refreshStarted
		reconnected := make(chan error, 1)
		go func() {
			_, err := service.createSession(ctx, stored.Principal, provider.ID, &oauth2.Token{AccessToken: "other-account-access", Expiry: time.Now().Add(time.Hour)}, []string{"other-scope"})
			reconnected <- err
		}()
		<-reconnectWaiting
		select {
		case err := <-reconnected:
			t.Fatalf("reconnect completed while refresh held the session lock: %v", err)
		default:
		}
		close(releaseRefresh)
		require.NoError(t, <-refreshed)
		require.NoError(t, <-reconnected)
		assert.Equal(t, "other-account-access", string(stored.EncryptedAccessToken))
		assert.Empty(t, stored.EncryptedRefreshToken)
		assert.Nil(t, stored.RefreshTokenExpiresAt)
		require.NotNil(t, stored.AccessTokenExpiresAt)
		assert.Equal(t, time.Now().Add(time.Hour), *stored.AccessTokenExpiresAt)
		assert.Equal(t, []string{"other-scope"}, stored.Scope)
	})
}
