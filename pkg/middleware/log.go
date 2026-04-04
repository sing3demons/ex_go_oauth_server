package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/sing3demons/tr_02_oauth/pkg/logger"
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

// Setup Singleton-like Slog engine once
var slogHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		// Slog injects its own "msg", we remove it since our LogDto handles Message
		if a.Key == slog.MessageKey {
			return slog.Attr{}
		}
		return a
	},
})
var slogAdapter = logger.NewSlogAdapter(slog.New(slogHandler))
var maskingSvc = &logger.DefaultMaskingService{}

func LoggerMiddleware(next http.Handler) http.Handler {

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
			AppName:          "MyRestAPI",
			ComponentName:    "UserManagement",
			ComponentVersion: "1.0.0",
			SessionId:        sessionID,
			TransactionId:    transactionID,
			RecordName:       r.URL.Path, // e.g. /api/users
			Channel:          "web",
		}

		// สร้าง Detail Logger สำหรับ Request นี้
		detailLogger := logger.NewCustomLogger(slogAdapter, maskingSvc, baseDto)

		// สร้าง Summary Logger สำหรับ Request นี้
		util := &logger.DefaultLoggerUtil{BeginTime: beginTime}
		summaryLogger := logger.NewSummaryLogger(slogAdapter, detailLogger, util)

		// ฝัง Loggers ไว้ใน Context
		ctx := context.WithValue(r.Context(), DetailLoggerKey, detailLogger)
		ctx = context.WithValue(ctx, SummaryLoggerKey, summaryLogger)

		rw := &ResponseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}

		// 2. เรียกให้ Handler ทำงาน
		next.ServeHTTP(rw, r.WithContext(ctx))

		// 3. เมื่อ Handler ทำงานเสร็จ สั่ง Flush Summary Log ออกมา
		// ดึงค่า status code จาก Wrapper ไปใส่ใน summary
		dto := detailLogger.GetLogDto()
		dto.AppResultHttpStatus = fmt.Sprintf("%d", rw.statusCode)

		if rw.statusCode >= 400 {
			dto.AppResultType = "Error"
			dto.Severity = "Critical"
			dto.AppResultCode = "50000"
			detailLogger.SetDependencyMetadata(logger.LogDependencyMetadata{}) // Reset detail fields
			summaryLogger.FlushError(map[string]any{"message": "API Failed"}, "stacktrace-goes-here")
		} else {
			dto.AppResultType = "Healthy"
			dto.Severity = "Normal"
			dto.AppResultCode = "20000"
			summaryLogger.Flush()
		}
	})
}
