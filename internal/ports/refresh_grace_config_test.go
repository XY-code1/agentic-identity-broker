package ports

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuth2AuthServerConfig_RefreshTokenGracePeriod(t *testing.T) {
	t.Run("defaults to 60 seconds and resolves into local mode", func(t *testing.T) {
		cfg := validLocalOAuth2Config()
		require.NoError(t, cfg.Validate())
		assert.Equal(t, DefaultRefreshTokenGracePeriod, cfg.Local.RefreshTokenGracePeriod)

		resolved, err := cfg.Resolve()
		require.NoError(t, err)
		local, ok := resolved.(*LocalOAuth2Config)
		require.True(t, ok)
		assert.Equal(t, DefaultRefreshTokenGracePeriod, local.RefreshGracePeriod)
	})

	for _, tc := range []struct {
		name    string
		grace   time.Duration
		wantErr bool
	}{
		{name: "minimum", grace: time.Second},
		{name: "maximum", grace: 5 * time.Minute},
		{name: "negative", grace: -time.Second, wantErr: true},
		{name: "below minimum", grace: 100 * time.Millisecond, wantErr: true},
		{name: "above maximum", grace: 10 * time.Minute, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validLocalOAuth2Config()
			cfg.Local.RefreshTokenGracePeriod = tc.grace
			err := cfg.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "local.refresh_token_grace_period")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.grace, cfg.Local.RefreshTokenGracePeriod)
		})
	}
}
