package handlers

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"time"

	"github.com/sing3demons/oauth_server/pkg/kp"
	"github.com/sing3demons/oauth_server/pkg/response"
)

// BasicAuthMiddleware ปกป้อง Endpoint ด้วย HTTP Basic Authentication
func BasicAuthMiddleware(expectedUsername, expectedPassword string) kp.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		})
	}
}

// CORSMiddleware อนุญาตให้ SPA หรือต่าง Origin สามารถเรียกใช้งาน OIDC APIs ได้
func CORSMiddleware() kp.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*") // ควรปรับเป็น Domain ที่อนุญาตใน Production
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (h *OAuthHandler) RateLimit(ctx *kp.Ctx, limit int, window time.Duration) *response.Error {
	// ดึง IP Address ของผู้ขอใช้ (พื้นฐาน)
	ip := ctx.IP()

	key := fmt.Sprintf("ratelimit:login:%s", ip)
	count, err := h.rateLimitStore.Increment(ctx, key, window)
	if err != nil {
		// หาก Redis มีปัญหา ให้ปล่อยผ่านก่อนเพื่อไม่ให้ระบบล่ม (Fail Open)
		return nil
	}

	if count > limit {
		return &response.Error{
			Err:     fmt.Errorf("too many requests: %d/%d", count, limit),
			Message: response.TooManyRequest,
		}
	}
	return nil
}
