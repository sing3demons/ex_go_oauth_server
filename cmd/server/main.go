package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/sing3demons/oauth_server/internal/adapters/mongo_store"
	"github.com/sing3demons/oauth_server/internal/adapters/redis_store"
	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/internal/core/services"
	"github.com/sing3demons/oauth_server/internal/handlers"
	"github.com/sing3demons/oauth_server/pkg/kp"
	"github.com/sing3demons/oauth_server/pkg/middleware"
	"github.com/sing3demons/oauth_server/pkg/response"
)

func main() {
	cfg := config.LoadConfig()
	detailSlogAdapter, summarySlogAdapter, maskingSvc := config.NewLogger(cfg)

	// Init MongoDB
	mongoClient, err := mongo_store.NewMongoClient(cfg.MongoURI)
	if err != nil {
		log.Fatalf("MongoDB connection failed: %v", err)
	}
	db := mongoClient.Database(cfg.MongoDBName)

	// 🔥 Ensure DB Indexes
	mongo_store.EnsureIndexes(mongoClient, cfg.MongoDBName)

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
	clientRepo := mongo_store.NewClientRepository(db, redisClient)
	authCodeCache := redis_store.NewAuthCodeCache(redisClient)
	profileRepo := mongo_store.NewUserProfileRepository(db)
	rateLimitCache := redis_store.NewRateLimitCache(redisClient)
	auditRepo := mongo_store.NewAuditRepository(db)
	sessionCache := redis_store.NewSessionCache(redisClient)
	credentialRepo := mongo_store.NewUserCredentialRepository(db)
	transactionCache := redis_store.NewTransactionCache(redisClient)

	// Init Core Key Service
	rtRepo := mongo_store.NewRefreshTokenRepository(db)
	supportedAlgs := cfg.GetArray("oidc.id_token_signing_alg_values_supported")
	keyService := services.NewKeyService(keyRepo, keyCache, cfg.KeyRotationDuration, cfg.KeyMaxRetentionCount, supportedAlgs)
	oauthService := services.NewOAuthService(cfg, clientRepo, authCodeCache, rtRepo, keyService, userRepo, profileRepo)

	// Start Key generation or fetching
	ctx := context.Background()
	if _, err := keyService.GetJWKS(ctx); err != nil {
		log.Fatalf("Failed to initialize cryptographic keys from Mongo/Redis: %v", err)
	}
	log.Println("JWKS Key Management Service Initialized Successfully")

	// HTTP Routing Setup
	app := kp.NewApplication(cfg, detailSlogAdapter, summarySlogAdapter)

	discoveryHandler := handlers.NewDiscoveryHandler(cfg, keyService)
	app.GET("/.well-known/openid-configuration", discoveryHandler.OpenIDConfiguration)
	app.GET("/jwks.json", discoveryHandler.JWKS)

	oauthHandler := handlers.NewOAuthHandler(cfg, clientRepo, userRepo, authCodeCache, oauthService, credentialRepo, sessionCache, transactionCache, auditRepo)
	accountHandler := handlers.NewAccountHandler(sessionCache, auditRepo)

	app.GET("/authorize", oauthHandler.Authorize)
	app.POST("/login", oauthHandler.LoginSubmit, middleware.RateLimitMiddleware(rateLimitCache, 5, 1*time.Minute))
	app.POST("/register", oauthHandler.RegisterSubmit)
	app.GET("/consent", oauthHandler.ConsentUI)
	app.POST("/consent", oauthHandler.ConsentSubmit)
	app.GET("/account/sessions", accountHandler.SessionsUI)
	app.POST("/account/sessions/revoke", accountHandler.RevokeSession)
	app.GET("/account/history", accountHandler.HistoryUI)
	app.POST("/token", oauthHandler.Token)
	app.GET("/userinfo", oauthHandler.UserInfo)
	app.POST("/userinfo", oauthHandler.UserInfo)

	// Session Management & Token Management
	app.GET("/logout", oauthHandler.Logout)
	app.POST("/revoke", oauthHandler.Revoke)
	app.POST("/introspect", oauthHandler.Introspect)

	adminHandler := handlers.NewAdminHandler(cfg, userRepo, clientRepo, credentialRepo, profileRepo)
	basicAuth := handlers.BasicAuthMiddleware(cfg.AdminUsername, cfg.AdminPassword)

	// API Endpoints
	app.POST("/admin/users", adminHandler.CreateUser, basicAuth)
	app.POST("/admin/clients", adminHandler.CreateClient, basicAuth)

	// UI Endpoints
	app.GET("/admin/dashboard", adminHandler.DashboardUI, basicAuth)
	app.POST("/admin/clients/ui", adminHandler.CreateClientUI, basicAuth)

	app.GET("/health", func(ctx *kp.Ctx) {
		ctx.JSON(http.StatusOK, "OK")
	})

	// *
	app.Any("/", func(ctx *kp.Ctx) {
		ctx.Log("unknown")
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("unknown endpoint"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
	})

	log.Printf("Starting OIDC Server on port %s", cfg.Port)

	// ใช้ LoggerMiddleware หุ้ม Router ทั้งหมดก่อน Listen
	// loggedMux := middleware.LoggerMiddleware(mux, cfg, detailSlogAdapter, summarySlogAdapter, maskingSvc)

	// if err := http.ListenAndServe(fmt.Sprintf(":%s", cfg.Port), loggedMux); err != nil {
	// 	log.Fatalf("Server failed: %v", err)
	// }

	app.Use(middleware.GzipMiddleware)
	app.Use(middleware.SecurityHeadersMiddleware)
	app.Use(func(next http.Handler) http.Handler {
		return middleware.LoggerMiddleware(next, cfg, detailSlogAdapter, summarySlogAdapter, maskingSvc)
	})
	app.Use(handlers.CORSMiddleware())
	app.Start()

	// หลังจาก app.Start() (ซึ่งจะรอสัญญาณ Interrupt คืนมา)
	log.Println("Closing database connections...")
	mongoClient.Disconnect(context.Background())
	redisClient.Close()
	log.Println("Cleanup complete.")
}
