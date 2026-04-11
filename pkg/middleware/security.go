package middleware

import (
	"net/http"
)

// SecurityHeadersMiddleware adds standard security headers to all responses.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Prevent Clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// 2. Prevent MIME Sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// 3. Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// 4. Content Security Policy (CSP)
		// Note: 'unsafe-inline' is used here because the internal templates currently use inline styles/scripts.
		// In a production environment, it is recommended to use nonces or hash-based CSP.
		csp := "default-src 'self'; " +
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
			"script-src 'self' 'unsafe-inline'; " +
			"font-src 'self' https://fonts.gstatic.com; " +
			"img-src 'self' data:; " +
			"frame-ancestors 'none';"
		w.Header().Set("Content-Security-Policy", csp)

		// 5. XSS Protection (Legacy but still useful for some browsers)
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		next.ServeHTTP(w, r)
	})
}
