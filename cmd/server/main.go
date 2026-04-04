package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/sing3demons/tr_02_oauth/internal/adapters/mongo_store"
	"github.com/sing3demons/tr_02_oauth/internal/adapters/redis_store"
	"github.com/sing3demons/tr_02_oauth/internal/config"
	"github.com/sing3demons/tr_02_oauth/internal/core/services"
	"github.com/sing3demons/tr_02_oauth/internal/handlers"
)

func main() {
	cfg := config.LoadConfig()

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

	oauthHandler := handlers.NewOAuthHandler(oauthService, userRepo, sessionCache, transactionCache)
	mux.HandleFunc("GET /authorize", oauthHandler.Authorize)
	mux.HandleFunc("POST /login", oauthHandler.LoginSubmit)
	mux.HandleFunc("POST /register", oauthHandler.RegisterSubmit)
	mux.HandleFunc("POST /token", oauthHandler.Token)
	mux.HandleFunc("GET /userinfo", oauthHandler.UserInfo)
	mux.HandleFunc("POST /userinfo", oauthHandler.UserInfo)

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
	if err := http.ListenAndServe(fmt.Sprintf(":%s", cfg.Port), mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
