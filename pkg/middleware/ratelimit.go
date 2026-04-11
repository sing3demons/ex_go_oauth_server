package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sing3demons/oauth_server/pkg/kp"
)

type RateLimitStore interface {
	Increment(ctx context.Context, key string, expiration time.Duration) (int, error)
}

func RateLimitMiddleware(store RateLimitStore, limit int, window time.Duration) kp.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ดึง IP Address ของผู้ขอใช้ (พื้นฐาน)
			ip := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ip = forwarded
			}

			key := fmt.Sprintf("ratelimit:login:%s", ip)
			count, err := store.Increment(r.Context(), key, window)
			if err != nil {
				// หาก Redis มีปัญหา ให้ปล่อยผ่านก่อนเพื่อไม่ให้ระบบล่ม (Fail Open)
				next.ServeHTTP(w, r)
				return
			}

			if count > limit {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"too_many_requests", "message":"Please try again later"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
