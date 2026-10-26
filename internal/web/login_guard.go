package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
)

const (
	// loginIPMaxFailures caps failed password/TOTP attempts per client network.
	loginIPMaxFailures = 5
	// loginAccountMaxFailures caps failed password attempts per account across
	// all client addresses, so a distributed attacker cannot reset the budget by
	// rotating IPs.
	loginAccountMaxFailures = 10
	// totpAccountMaxFailures caps failed second-factor attempts per account.
	totpAccountMaxFailures = 5
	loginFailureWindow     = 15 * time.Minute
	// preAuthMaxAttempts bounds TOTP guesses within one pre-auth session; once
	// exceeded the user has to re-enter the password.
	preAuthMaxAttempts = 5
	// regMaxAttempts bounds registration POSTs per client network per hour,
	// counting failed captcha/validation attempts as well as successes.
	regMaxAttempts = 10
	// frontendErrorSentryPerMinute caps unauthenticated /api/errors reports
	// forwarded to Sentry across all clients.
	frontendErrorSentryPerMinute = 30
)

// errAuthStoreUnavailable is returned when the Redis-backed brute-force
// counters cannot be read. Auth endpoints fail closed in that case.
var errAuthStoreUnavailable = errors.New("authentication temporarily unavailable")

// rateLimitSubject normalizes a client IP for rate-limit keys. IPv6 clients are
// keyed by their /64 so one end-user allocation cannot mint a fresh budget per
// address; IPv4 (and unparseable values) are returned unchanged.
func rateLimitSubject(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return prefix.String()
}

func loginIPFailureKey(clientIP string) string {
	return "login_failures:" + rateLimitSubject(clientIP)
}

// loginAccountFailureKey is derived from the submitted email (not the user ID)
// so unknown and known accounts behave identically and cannot be enumerated.
func loginAccountFailureKey(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return "login_failures_acct:" + hex.EncodeToString(sum[:])
}

func totpAccountFailureKey(userID int) string {
	return fmt.Sprintf("totp_failures:%d", userID)
}

// failureCount reads a failure counter. A missing key counts as zero; any other
// Redis error is reported as errAuthStoreUnavailable so callers fail closed.
func (a *App) failureCount(ctx context.Context, key string) (int, error) {
	if a.Redis == nil {
		return 0, nil
	}
	count, err := a.Redis.Get(ctx, key).Int()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		log.Printf("Redis error reading %s: %v", key, err) // #nosec G706 -- key is built from hashed/normalized values
		return 0, errAuthStoreUnavailable
	}
	return count, nil
}

// limitReached reports whether any of the given counters is at or above its
// limit. limits[i] applies to keys[i].
func (a *App) limitReached(ctx context.Context, keys []string, limits []int) (bool, error) {
	for i, key := range keys {
		count, err := a.failureCount(ctx, key)
		if err != nil {
			return true, err
		}
		if count >= limits[i] {
			return true, nil
		}
	}
	return false, nil
}

func (a *App) recordFailures(ctx context.Context, window time.Duration, keys ...string) {
	if a.Redis == nil {
		return
	}
	pipe := a.Redis.Pipeline()
	for _, key := range keys {
		pipe.Incr(ctx, key)
		pipe.Expire(ctx, key, window)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		log.Printf("Redis pipeline error recording failures: %v", err)
	}
}

func (a *App) clearFailures(ctx context.Context, keys ...string) {
	if a.Redis == nil {
		return
	}
	a.Redis.Del(ctx, keys...)
}

// totpReplayScript atomically accepts a TOTP time step only if it is strictly
// greater than the last accepted step for the user.
var totpReplayScript = redis.NewScript(`
local last = tonumber(redis.call('GET', KEYS[1]) or '-1')
if tonumber(ARGV[1]) <= last then
	return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 1
`)

const totpPeriod = 30

var totpValidateOpts = totp.ValidateOpts{Period: totpPeriod, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// matchTOTPCounter returns the time step a code is valid for, honoring the
// usual +/-1 step skew, or false when the code does not match.
func matchTOTPCounter(code, secret string, now time.Time) (int64, bool) {
	period := int64(totpPeriod)
	current := now.Unix() / period
	matched := int64(-1)
	for skew := int64(-1); skew <= 1; skew++ {
		counter := current + skew
		expected, err := totp.GenerateCodeCustom(secret, time.Unix(counter*period, 0).UTC(), totpValidateOpts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			matched = counter
		}
	}
	return matched, matched >= 0
}

// consumeTOTP validates a TOTP code and marks its time step as used, so the same
// (or an older) code cannot be replayed for another login.
func (a *App) consumeTOTP(ctx context.Context, userID int, code, secret string) (bool, error) {
	counter, ok := matchTOTPCounter(code, secret, a.Now())
	if !ok {
		return false, nil
	}
	if a.Redis == nil {
		return true, nil
	}
	key := fmt.Sprintf("totp_last_step:%d", userID)
	res, err := totpReplayScript.Run(ctx, a.Redis, []string{key}, counter, int((5 * time.Minute).Seconds())).Int()
	if err != nil {
		log.Printf("Redis error recording TOTP step: %v", err)
		return false, errAuthStoreUnavailable
	}
	return res == 1, nil
}
