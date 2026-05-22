package web

import (
	"net/http"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	limiter_redis "github.com/ulule/limiter/v3/drivers/store/redis"
)

func (a *App) getLimiter() *limiter.Limiter {
	a.rateLimiterMu.Lock()
	defer a.rateLimiterMu.Unlock()

	if a.rateLimiter != nil {
		return a.rateLimiter
	}

	// Define rate: 10 requests per second
	// (this matches the burst of 10 requests that TestRateLimitMiddleware expects)
	rate := limiter.Rate{
		Period: 1 * time.Second,
		Limit:  10,
	}

	var store limiter.Store
	var err error

	if a.Redis != nil {
		if client, ok := a.Redis.(*goredis.Client); ok {
			store, err = limiter_redis.NewStoreWithOptions(client, limiter.StoreOptions{
				Prefix: "vulfixx_rate_limit:",
			})
			if err != nil {
				store = memory.NewStore()
			}
		} else {
			store = memory.NewStore()
		}
	} else {
		store = memory.NewStore()
	}

	a.rateLimiter = limiter.New(store, rate)
	return a.rateLimiter
}

func (a *App) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := a.GetClientIP(r)
		l := a.getLimiter()

		limitCtx, err := l.Get(r.Context(), ip)
		if err != nil {
			// Fallback to next handler if rate limiting fails to prevent blocking user traffic
			next.ServeHTTP(w, r)
			return
		}

		if limitCtx.Reached {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

