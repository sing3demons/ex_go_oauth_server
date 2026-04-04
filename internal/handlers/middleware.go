package handlers

import (
	"crypto/subtle"
	"net/http"
)

// BasicAuthMiddleware ปกป้อง Endpoint ด้วย HTTP Basic Authentication
func BasicAuthMiddleware(expectedUsername, expectedPassword string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()

			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// ใช้ subtle.ConstantTimeCompare ป้องกัน Timing Attacks
			usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(expectedUsername)) == 1
			passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword)) == 1

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)
			} else {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
		}
	}
}
