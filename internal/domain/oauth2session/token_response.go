package oauth2session

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// lifetimeSeconds decodes a token-endpoint lifetime sent as a JSON number or numeric string.
// A value it cannot interpret is treated as absent so that a malformed lifetime never discards
// an otherwise valid token.
type lifetimeSeconds int64

func (l *lifetimeSeconds) UnmarshalJSON(data []byte) error {
	var number json.Number
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || json.Unmarshal(data, &number) != nil {
		return nil
	}
	if seconds, ok := numberSeconds(number.String()); ok {
		*l = lifetimeSeconds(seconds)
	}
	return nil
}

func numberSeconds(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return max(seconds, 0), true
	}
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds > math.MaxInt32 {
		return 0, false
	}
	return int64(max(seconds, 0)), true
}

const maxRetryAfter = 10 * time.Second

// retryAfter parses a Retry-After header given in seconds or as an HTTP date.
func retryAfter(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		return time.Duration(max(seconds, 0)) * time.Second
	}
	if at, err := http.ParseTime(header); err == nil {
		return max(at.Sub(now), 0)
	}
	return 0
}
