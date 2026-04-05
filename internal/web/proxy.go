package web

import (
	"sync"
	"log"
	"net/netip"
	"net"
	"context"
	"net/http"
	"os"
	"strings"
)

type contextKey string

const clientIPKey contextKey = "ClientIP"

var (
	trustedProxiesLogged bool
	trustedProxiesMutex  sync.Mutex
)

func isTrustedProxy(ip string) bool {
	trustedProxiesEnv := os.Getenv("TRUSTED_PROXIES")

	trustedProxiesMutex.Lock()
	if !trustedProxiesLogged {
		if trustedProxiesEnv == "" {
			log.Println("WARNING: TRUSTED_PROXIES is not set. Defaulting to trusting only loopback addresses (127.0.0.1, ::1). If you are behind a reverse proxy, you MUST set TRUSTED_PROXIES to avoid rate-limiting all users based on the proxy IP.")
		}
		trustedProxiesLogged = true
	}
	trustedProxiesMutex.Unlock()

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	if trustedProxiesEnv == "" {
		return addr.IsLoopback()
	}

	proxies := strings.Split(trustedProxiesEnv, ",")

	for _, proxyStr := range proxies {
		proxyStr = strings.TrimSpace(proxyStr)
		if proxyStr == "" {
			continue
		}
		if strings.Contains(proxyStr, "/") {
			prefix, err := netip.ParsePrefix(proxyStr)
			if err == nil && prefix.Contains(addr) {
				return true
			}
		} else {
			pAddr, err := netip.ParseAddr(proxyStr)
			if err == nil && pAddr == addr {
				return true
			}
		}
	}
	return false
}

func ProxyMiddleware(next http.Handler) http.Handler {
	enableCF := os.Getenv("ENABLE_CLOUDFLARE_PROXY") == "true"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		clientIP := host

		if enableCF {
			if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
				clientIP = cfIP
			}
		}

		// Only parse X-Forwarded-For / X-Real-IP if not using CF header and is trusted proxy
		if clientIP == host && isTrustedProxy(host) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				ips := strings.Split(xff, ",")
				if len(ips) > 0 {
					clientIP = strings.TrimSpace(ips[0])
				}
			} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
				clientIP = xri
			}
		}

		ctx := context.WithValue(r.Context(), clientIPKey, clientIP)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
