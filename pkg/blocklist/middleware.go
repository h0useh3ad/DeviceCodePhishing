package blocklist

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// Middleware returns an HTTP middleware that checks the blocklist
func Middleware(b *Blocklist) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the real client IP, considering proxy headers
			clientIP := GetClientIP(r)

			if b.IsBlocked(clientIP) {
				// Multiple log levels to make blocked requests more visible
				slog.Warn("🚫 BLOCKED REQUEST",
					"ip", clientIP,
					"path", r.URL.Path,
					"method", r.Method,
					"user_agent", r.UserAgent(),
					"reason", "IP in blocklist")

				// Also log to stdout for immediate visibility
				fmt.Printf("\n🚫 BLOCKED: IP %s tried to access %s\n", clientIP, r.URL.Path)

				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP attempts to get the real client IP address
func GetClientIP(r *http.Request) string {
	// Check for proxy headers
	clientIP := r.Header.Get("CF-Connecting-IP") // Cloudflare
	if clientIP != "" {
		return clientIP
	}

	clientIP = r.Header.Get("True-Client-IP") // Some proxies
	if clientIP != "" {
		return clientIP
	}

	clientIP = r.Header.Get("X-Real-IP") // Nginx proxy/FastCGI
	if clientIP != "" {
		return clientIP
	}

	clientIP = r.Header.Get("X-Forwarded-For") // Most proxies/load balancers
	if clientIP != "" {
		// X-Forwarded-For can contain multiple IPs (comma-separated)
		// The first one is the original client IP
		ips := r.Header.Get("X-Forwarded-For")
		if idx := strings.Index(ips, ","); idx != -1 {
			clientIP = ips[:idx]
		}
		return clientIP
	}

	// Fall back to RemoteAddr
	clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	return clientIP
}
