package main

import (
	"context"
	"log"
	"net/http"

	"github.com/sing3demons/oauth_server/internal/adapters/mongo_store"
	"github.com/sing3demons/oauth_server/internal/adapters/redis_store"
	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/internal/core/services"
	"github.com/sing3demons/oauth_server/internal/handlers"
	"github.com/sing3demons/oauth_server/pkg/kp"
	"github.com/sing3demons/oauth_server/pkg/middleware"
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
	app := kp.NewApplication(cfg, detailSlogAdapter, summarySlogAdapter)

	discoveryHandler := handlers.NewDiscoveryHandler(cfg, keyService)
	app.GET("/.well-known/openid-configuration", discoveryHandler.OpenIDConfiguration)
	app.GET("/jwks.json", discoveryHandler.JWKS)

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
	// loggedMux := middleware.LoggerMiddleware(mux, cfg, detailSlogAdapter, summarySlogAdapter, maskingSvc)

	// if err := http.ListenAndServe(fmt.Sprintf(":%s", cfg.Port), loggedMux); err != nil {
	// 	log.Fatalf("Server failed: %v", err)
	// }

	app.Use(func(next http.Handler) http.Handler {
		return middleware.LoggerMiddleware(next, cfg, detailSlogAdapter, summarySlogAdapter, maskingSvc)
	})
	app.Start()
}
