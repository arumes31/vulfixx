package web

import (
	"net/netip"
	"net"
	"context"
	"net/http"
	"os"
	"strings"
)

type contextKey string

const clientIPKey contextKey = "ClientIP"

func isTrustedProxy(ip string) bool {
	trustedProxiesEnv := os.Getenv("TRUSTED_PROXIES")
	if trustedProxiesEnv == "" {
		return false
	}
	proxies := strings.Split(trustedProxiesEnv, ",")

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

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
