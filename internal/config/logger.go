package config

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/sing3demons/oauth_server/pkg/logger"
	"gopkg.in/natefinch/lumberjack.v2"
)

func buildLogFilename(props LogFileProperties) string {
	datePattern := props.DatePattern
	datePattern = strings.ReplaceAll(datePattern, "YYYY", "2006")
	datePattern = strings.ReplaceAll(datePattern, "MM", "01")
	datePattern = strings.ReplaceAll(datePattern, "DD", "02")
	datePattern = strings.ReplaceAll(datePattern, "HH", "15")

	dateStr := time.Now().Format(datePattern)

	filename := props.Filename
	if strings.Contains(filename, "%DATE%") {
		filename = strings.ReplaceAll(filename, "%DATE%", dateStr)
	}

	return fmt.Sprintf("%s/%s%s", props.Dirname, filename, props.Extension)
}

func NewLogger(cfg *Config) (*logger.SlogAdapter, *logger.SlogAdapter, *logger.DefaultMaskingService) {
	var maskingSvc = &logger.DefaultMaskingService{}

	// 1. Setup Detail Logger
	detailWriter := io.MultiWriter(os.Stdout)
	if cfg.LoggerConfig.Detail.EnableFileLogging {
		os.MkdirAll(cfg.LoggerConfig.Detail.LogFileProperties.Dirname, 0755)
		path := buildLogFilename(cfg.LoggerConfig.Detail.LogFileProperties)

		detailRotateLogger := &lumberjack.Logger{
			Filename:   path,
			MaxSize:    cfg.LoggerConfig.Detail.Rotation.MaxSize / (1024 * 1024), // converting bytes to megabytes
			MaxBackups: cfg.LoggerConfig.Detail.Rotation.MaxBackups,
			MaxAge:     cfg.LoggerConfig.Detail.Rotation.MaxAge,
			Compress:   cfg.LoggerConfig.Detail.Rotation.Compress,
		}
		writers := []io.Writer{detailRotateLogger}
		if cfg.LoggerConfig.Detail.Console {
			writers = append(writers, os.Stdout)
		}
		detailWriter = io.MultiWriter(writers...)
	}

	// 2. Setup Summary Logger
	summaryWriter := io.MultiWriter(os.Stdout)
	if cfg.LoggerConfig.Summary.EnableFileLogging {
		os.MkdirAll(cfg.LoggerConfig.Summary.LogFileProperties.Dirname, 0755)
		path := buildLogFilename(cfg.LoggerConfig.Summary.LogFileProperties)

		summaryRotateLogger := &lumberjack.Logger{
			Filename:   path,
			MaxSize:    cfg.LoggerConfig.Summary.Rotation.MaxSize / (1024 * 1024), // converting bytes to megabytes
			MaxBackups: cfg.LoggerConfig.Summary.Rotation.MaxBackups,
			MaxAge:     cfg.LoggerConfig.Summary.Rotation.MaxAge,
			Compress:   cfg.LoggerConfig.Summary.Rotation.Compress,
		}
		writers := []io.Writer{summaryRotateLogger}
		if cfg.LoggerConfig.Summary.Console {
			writers = append(writers, os.Stdout)
		}
		summaryWriter = io.MultiWriter(writers...)
	}

	detailHandler := slog.NewJSONHandler(detailWriter, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey {
				return slog.Attr{}
			}
			return a
		},
	})
	detailSlogAdapter := logger.NewSlogAdapter(slog.New(detailHandler))

	summaryHandler := slog.NewJSONHandler(summaryWriter, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.MessageKey {
				return slog.Attr{}
			}
			return a
		},
	})
	summarySlogAdapter := logger.NewSlogAdapter(slog.New(summaryHandler))
	return detailSlogAdapter, summarySlogAdapter, maskingSvc
}
