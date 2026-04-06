package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/utils"

	"github.com/mssola/user_agent"
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

type ClientInfo struct {
	Type    string
	Browser string
	OS      string
	IsBot   bool
	raw     string
}

func parseUA(uaStr string) string {
	ua := user_agent.New(uaStr)

	name, version := ua.Browser()

	clientInfo := ClientInfo{
		Type: func() string {
			if ua.Bot() {
				return "bot"
			}
			if ua.Mobile() {
				return "mobile"
			}
			return "browser"
		}(),
		Browser: name + "_" + version,
		OS: func() string {
			if ua.OS() == "" {
				return "unknown"
			}
			return ua.OS()
		}(),
		IsBot: ua.Bot(),
		raw:   uaStr,
	}
	if clientInfo.IsBot {
		return fmt.Sprintf("%s(bot)|%s|%s|%s", clientInfo.Type, clientInfo.Browser, clientInfo.OS, clientInfo.raw)

	}
	return fmt.Sprintf("%s|%s|%s|%s", clientInfo.Type, clientInfo.Browser, clientInfo.OS, clientInfo.raw)
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
			Channel:          "none",
			Agent:            utils.ParseUA(r.UserAgent()),
			RecordType:       "detail",
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
