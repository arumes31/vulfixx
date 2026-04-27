package web

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var visitors = make(map[string]*visitor)
var mtx sync.Mutex

func init() {
	go cleanupVisitors()
}

func cleanupVisitors() {
	for {
		time.Sleep(1 * time.Minute)
		mtx.Lock()
		for ip, v := range visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(visitors, ip)
			}
		}
		mtx.Unlock()
	}
}

func getVisitor(ip string) *rate.Limiter {
	mtx.Lock()
	defer mtx.Unlock()

	v, exists := visitors[ip]
	if !exists {
		// Allow 5 requests per second, burst of 10
		limiter := rate.NewLimiter(5, 10)
		visitors[ip] = &visitor{limiter, time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func (a *App) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, ok := r.Context().Value(clientIPKey).(string)
		if !ok {
			ip = r.RemoteAddr
		}

		limiter := getVisitor(ip)
		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
