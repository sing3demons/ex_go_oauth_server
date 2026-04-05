package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sing3demons/oauth_server/internal/adapters/mongo_store"
	"github.com/sing3demons/oauth_server/internal/adapters/redis_store"
	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/internal/core/services"
	"github.com/sing3demons/oauth_server/internal/handlers"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/middleware"
	"gopkg.in/natefinch/lumberjack.v2"
)

func buildLogFilename(props config.LogFileProperties) string {
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

func NewLogger(cfg *config.Config) (*logger.SlogAdapter, *logger.SlogAdapter, *logger.DefaultMaskingService) {
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

func main() {
	cfg := config.LoadConfig()
	detailSlogAdapter, summarySlogAdapter, maskingSvc := NewLogger(cfg)

	// Init MongoDB
	mongoClient, err := mongo_store.NewMongoClient(cfg.MongoURI)
	if err != nil {
		log.Fatalf("MongoDB connection failed: %v", err)
	}
	db := mongoClient.Database(cfg.MongoDBName)

	// Init Redis
	redisClient, err := redis_store.NewRedisClient(cfg.RedisURI)
	if err != nil {
		log.Fatalf("Redis connection failed: %v", err)
	}

	// Init Adapters for JWKS
	keyRepo := mongo_store.NewKeyRepository(db, cfg.KeyGracePeriod)
	keyCache := redis_store.NewKeyCache(redisClient)

	// Init Adapters for OAuth entities
	userRepo := mongo_store.NewUserRepository(db)
	clientRepo := mongo_store.NewClientRepository(db)
	authCodeCache := redis_store.NewAuthCodeCache(redisClient)
	sessionCache := redis_store.NewSessionCache(redisClient)
	transactionCache := redis_store.NewTransactionCache(redisClient)

	// Init Core Key Service
	rtRepo := mongo_store.NewRefreshTokenRepository(db)
	keyService := services.NewKeyService(keyRepo, keyCache, cfg.KeyRotationDuration, cfg.KeyMaxRetentionCount)
	oauthService := services.NewOAuthService(clientRepo, authCodeCache, rtRepo, keyService, userRepo, cfg)

	// Start Key generation or fetching
	ctx := context.Background()
	if _, err := keyService.GetActiveKeyManager(ctx); err != nil {
		log.Fatalf("Failed to initialize RSA keys from Mongo/Redis: %v", err)
	}
	log.Println("JWKS Key Management Service Initialized Successfully")

	// HTTP Routing Setup
	mux := http.NewServeMux()

	discoveryHandler := handlers.NewDiscoveryHandler(cfg, keyService)
	mux.HandleFunc("GET /.well-known/openid-configuration", discoveryHandler.OpenIDConfiguration)
	mux.HandleFunc("GET /jwks.json", discoveryHandler.JWKS)

	oauthHandler := handlers.NewOAuthHandler(oauthService, userRepo, clientRepo, sessionCache, transactionCache)
	mux.HandleFunc("GET /authorize", oauthHandler.Authorize)
	mux.HandleFunc("POST /login", oauthHandler.LoginSubmit)
	mux.HandleFunc("POST /register", oauthHandler.RegisterSubmit)
	mux.HandleFunc("GET /consent", oauthHandler.ConsentUI)
	mux.HandleFunc("POST /consent", oauthHandler.ConsentSubmit)
	mux.HandleFunc("POST /token", oauthHandler.Token)
	mux.HandleFunc("GET /userinfo", oauthHandler.UserInfo)
	mux.HandleFunc("POST /userinfo", oauthHandler.UserInfo)

	// Session Management & Token Management
	mux.HandleFunc("GET /logout", oauthHandler.Logout)
	mux.HandleFunc("POST /revoke", oauthHandler.Revoke)
	mux.HandleFunc("POST /introspect", oauthHandler.Introspect)

	adminHandler := handlers.NewAdminHandler(userRepo, clientRepo)

	// API Endpoints
	mux.HandleFunc("POST /admin/users", handlers.BasicAuthMiddleware(cfg.AdminUsername, cfg.AdminPassword)(adminHandler.CreateUser))
	mux.HandleFunc("POST /admin/clients", handlers.BasicAuthMiddleware(cfg.AdminUsername, cfg.AdminPassword)(adminHandler.CreateClient))

	// UI Endpoints
	mux.HandleFunc("GET /admin/dashboard", handlers.BasicAuthMiddleware(cfg.AdminUsername, cfg.AdminPassword)(adminHandler.DashboardUI))
	mux.HandleFunc("POST /admin/clients/ui", handlers.BasicAuthMiddleware(cfg.AdminUsername, cfg.AdminPassword)(adminHandler.CreateClientUI))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Printf("Starting OIDC Server on port %s", cfg.Port)

	// ใช้ LoggerMiddleware หุ้ม Router ทั้งหมดก่อน Listen
	loggedMux := middleware.LoggerMiddleware(mux, cfg, detailSlogAdapter, summarySlogAdapter, maskingSvc)

	if err := http.ListenAndServe(fmt.Sprintf(":%s", cfg.Port), loggedMux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
