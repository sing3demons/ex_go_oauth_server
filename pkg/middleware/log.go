package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/pkg/logger"
)

type contextKey string

const (
	DetailLoggerKey  contextKey = "detail_logger"
	SummaryLoggerKey contextKey = "summary_logger"
)

type ResponseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func LoggerMiddleware(next http.Handler, cfg *config.Config, detailSlogAdapter *logger.SlogAdapter, summarySlogAdapter *logger.SlogAdapter, maskingSvc logger.MaskingService) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		beginTime := time.Now()

		sessionID := r.Header.Get("X-Session-ID")
		if sessionID == "" {
			if (r.URL.Query().Get("sid")) != "" {
				sessionID = r.URL.Query().Get("sid")
			} else {
				sessionID = ""
			}
		}
		transactionID := r.Header.Get("X-Transaction-ID")
		if transactionID == "" {
			if (r.URL.Query().Get("tid")) != "" {
				transactionID = r.URL.Query().Get("tid")
			} else {
				transactionID = ""
			}
		}

		// สร้าง Base DTO (จำลองค่าพื้นฐานที่ดึงจาก Config)
		baseDto := logger.LogDto{
			AppName:          cfg.ServiceName,
			ComponentName:    cfg.ComponentName,
			ComponentVersion: cfg.Version,
			SessionId:        sessionID,
			TransactionId:    transactionID,
			Channel:          "web",
			Agent:            r.Header.Get("User-Agent"),
		}

		// สร้าง Detail Logger สำหรับ Request นี้
		detailLogger := logger.NewCustomLogger(detailSlogAdapter, maskingSvc, baseDto)

		// สร้าง Summary Logger สำหรับ Request นี้
		util := &logger.DefaultLoggerUtil{BeginTime: beginTime}
		summaryLogger := logger.NewSummaryLogger(summarySlogAdapter, detailLogger, util)

		// ฝัง Loggers ไว้ใน Context
		ctx := context.WithValue(r.Context(), DetailLoggerKey, detailLogger)
		ctx = context.WithValue(ctx, SummaryLoggerKey, summaryLogger)

		rw := &ResponseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		// 2. เรียกให้ Handler ทำงาน
		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}
