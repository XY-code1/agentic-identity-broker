package oauth2session

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLifetimeSeconds_DecodesNumbersAndNumericStrings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		seconds int64
	}{
		{name: "integer", body: `{"v":3600}`, seconds: 3600},
		{name: "numeric string", body: `{"v":"3600"}`, seconds: 3600},
		{name: "float", body: `{"v":3599.9}`, seconds: 3599},
		{name: "exponent", body: `{"v":3.6e3}`, seconds: 3600},
		{name: "whole second", body: `{"v":1.0}`, seconds: 1},
		{name: "largest duration", body: `{"v":9223372036}`, seconds: 9223372036},
		{name: "largest duration as float", body: `{"v":9223372036.0}`, seconds: 9223372036},
		{name: "zero", body: `{"v":0}`, seconds: 0},
		{name: "zero with exponent", body: `{"v":0e10}`, seconds: 0},
		{name: "negative clamps to zero", body: `{"v":-5}`, seconds: 0},
		{name: "null", body: `{"v":null}`},
		{name: "absent", body: `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var decoded struct {
				V lifetimeSeconds `json:"v"`
			}
			require.NoError(t, json.Unmarshal([]byte(tc.body), &decoded))
			assert.Equal(t, tc.seconds, int64(decoded.V))
		})
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, 2*time.Second, retryAfter("2", now))
	assert.Equal(t, 5*time.Second, retryAfter(now.Add(5*time.Second).Format(http.TimeFormat), now))
	assert.Zero(t, retryAfter("", now))
	assert.Zero(t, retryAfter("-3", now))
	assert.Zero(t, retryAfter("soon", now))
	assert.Zero(t, retryAfter(now.Add(-time.Minute).Format(http.TimeFormat), now))
}
