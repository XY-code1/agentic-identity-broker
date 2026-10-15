package oauth2session

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// lifetimeSeconds decodes a token-endpoint lifetime sent as a JSON number or numeric string.
type lifetimeSeconds int64

func (l *lifetimeSeconds) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return errors.New("invalid expires_in lifetime")
	}
	seconds, ok := numberSeconds(number.String())
	if !ok {
		return errors.New("invalid expires_in lifetime")
	}
	*l = lifetimeSeconds(seconds)
	return nil
}

const maxLifetimeSeconds = int64(math.MaxInt64) / int64(time.Second)

func numberSeconds(value string) (int64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return max(seconds, 0), seconds <= maxLifetimeSeconds
	} else if errors.Is(err, strconv.ErrRange) {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds > float64(maxLifetimeSeconds) || seconds < math.MinInt64 {
		return 0, false
	}
	if seconds >= 0 && seconds < 1 {
		// ParseFloat can underflow a positive lifetime to zero without an error.
		mantissa, _, _ := strings.Cut(value, "e")
		mantissa, _, _ = strings.Cut(mantissa, "E")
		if strings.ContainsAny(mantissa, "123456789") {
			return 0, false
		}
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
	if seconds, err := strconv.ParseInt(header, 10, 64); err == nil || errors.Is(err, strconv.ErrRange) {
		if seconds > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter + time.Second
		}
		return time.Duration(max(seconds, 0)) * time.Second
	}
	if at, err := http.ParseTime(header); err == nil {
		return max(at.Sub(now), 0)
	}
	return 0
}
