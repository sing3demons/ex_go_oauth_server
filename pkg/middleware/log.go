package middleware

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/sing3demons/tr_02_oauth/pkg/logger"
	"gopkg.in/natefinch/lumberjack.v2"
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

var detailSlogAdapter *logger.SlogAdapter
var summarySlogAdapter *logger.SlogAdapter
var maskingSvc = &logger.DefaultMaskingService{}

func init() {
	// Create logs folder
	os.MkdirAll("logs/detail", 0755)
	os.MkdirAll("logs/summary", 0755)

	dateStr := time.Now().Format("2006-01-02")

	// 1. Setup Detail Logger with Rotation
	detailRotateLogger := &lumberjack.Logger{
		Filename:   fmt.Sprintf("logs/detail/detail-%s.log", dateStr),
		MaxSize:    10, // megabytes
		MaxBackups: 14,
		MaxAge:     28,   // days
		Compress:   true, // disabled by default
	}
	detailWriter := io.MultiWriter(os.Stdout, detailRotateLogger)
	
	detailHandler := slog.NewJSONHandler(detailWriter, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey {
				return slog.Attr{}
			}
			return a
		},
	})
	detailSlogAdapter = logger.NewSlogAdapter(slog.New(detailHandler))

	// 2. Setup Summary Logger with Rotation
	summaryRotateLogger := &lumberjack.Logger{
		Filename:   fmt.Sprintf("logs/summary/summary-%s.log", dateStr),
		MaxSize:    10, // megabytes
		MaxBackups: 14,
		MaxAge:     28,   // days
		Compress:   true, // disabled by default
	}
	summaryWriter := io.MultiWriter(os.Stdout, summaryRotateLogger)
	
	summaryHandler := slog.NewJSONHandler(summaryWriter, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey {
				return slog.Attr{}
			}
			return a
		},
	})
	summarySlogAdapter = logger.NewSlogAdapter(slog.New(summaryHandler))
}

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
