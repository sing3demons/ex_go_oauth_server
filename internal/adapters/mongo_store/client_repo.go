package mongo_store

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/pkg/logAction"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/mlog"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type clientCacheEntry struct {
	client    *models.Client
	expiresAt time.Time
}

type ClientRepository struct {
	col     *mongo.Collection
	redis   *redis.Client
	l1Cache map[string]clientCacheEntry
	mu      sync.RWMutex
}

func NewClientRepository(db *mongo.Database, redisClient *redis.Client) *ClientRepository {
	return &ClientRepository{
		col:     db.Collection("clients"),
		redis:   redisClient,
		l1Cache: make(map[string]clientCacheEntry),
	}
}

func (r *ClientRepository) Create(ctx context.Context, client *models.Client) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), map[string]any{
		"document": client,
	})

	result, err := r.col.InsertOne(ctx, client)
	end := time.Since(start).Microseconds()
	if err != nil {
		resultCode, resultDesc := classifyMongoError(err)
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   resultCode,
		}).Info(logAction.DB_RESPONSE(logAction.DB_CREATE, "mongo -> app"), resultDesc)
		return err
	}
	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.col.Name(),
		ResponseTime: end,
		ResultCode:   "20000",
	}).Info(logAction.DB_RESPONSE(logAction.DB_CREATE, "mongo -> app"), map[string]any{
		"result": result,
	})
	return nil
}

func (r *ClientRepository) FindByID(ctx context.Context, clientID string) (*models.Client, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), "clients.findOne({_id: "+clientID+"})")

	var client models.Client
	err := r.col.FindOne(ctx, bson.M{"_id": clientID}).Decode(&client)
	end := time.Since(start).Microseconds()
	if err != nil {
		resultCode, resultDesc := classifyMongoError(err)

		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   resultCode,
		}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), resultDesc)
		return nil, err
	}
	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.col.Name(),
		ResponseTime: end,
		ResultCode:   "20000",
	}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), map[string]any{
		"result": client,
	})
	return &client, nil
}

func (r *ClientRepository) FindAll(ctx context.Context) ([]*models.Client, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), "clients.find({})")
	cursor, err := r.col.Find(ctx, bson.M{})
	end := time.Since(start).Microseconds()
	if err != nil {
		resultCode, resultDesc := classifyMongoError(err)
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   resultCode,
		}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), resultDesc)
		return nil, err
	}
	defer cursor.Close(ctx)

	var clients []*models.Client
	if err := cursor.All(ctx, &clients); err != nil {
		resultCode, resultDesc := classifyMongoError(err)
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   resultCode,
		}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), resultDesc)
		return nil, err
	}
	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.col.Name(),
		ResponseTime: end,
		ResultCode:   "20000",
	}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), map[string]any{
		"result": clients,
	})

	return clients, nil
}

func (r *ClientRepository) FindByIDWithCache(ctx context.Context, clientID string) (*models.Client, error) {
	// ⚡ 1. Try L1 Cache (In-Memory)
	r.mu.RLock()
	entry, ok := r.l1Cache[clientID]
	r.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.client, nil
	}

	cacheKey := "client:" + clientID
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: "redis",
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> redis"), map[string]any{"key": cacheKey})

	val, err := r.redis.Get(ctx, cacheKey).Result()
	end := time.Since(start).Microseconds()
	if err == nil {
		var client models.Client
		if err := json.Unmarshal([]byte(val), &client); err == nil {
			_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
				Dependency:   "redis",
				ResponseTime: end,
				ResultCode:   "20000",
			}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "redis -> app"), map[string]any{"key": cacheKey, "result": "hit"})
			return &client, nil
		}
	}

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   "redis",
		ResponseTime: end,
		ResultCode:   "40400",
	}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "redis -> app"), map[string]any{"key": cacheKey, "result": "miss", "error": err.Error()})

	client, err := r.FindByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	cacheData, err := json.Marshal(client)
	if err == nil {
		_start := time.Now()
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency: "redis",
		}).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> redis"), map[string]any{"key": cacheKey, "action": "set"})
		statusCmd := r.redis.Set(ctx, cacheKey, cacheData, 1*time.Hour)
		_end := time.Since(_start).Microseconds()
		if err := statusCmd.Err(); err != nil {
			_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
				Dependency:   "redis",
				ResponseTime: _end,
				ResultCode:   "50000",
			}).Info(logAction.DB_RESPONSE(logAction.DB_CREATE, "redis -> app"), map[string]any{"key": cacheKey, "action": "set", "error": err.Error()})
		} else {
			_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
				Dependency:   "redis",
				ResponseTime: _end,
				ResultCode:   "20000",
			}).Info(logAction.DB_RESPONSE(logAction.DB_CREATE, "redis -> app"), map[string]any{"key": cacheKey, "action": "set", "result": "success"})
		}
	}

	// ⚡ 4. Store in L1 Cache (30s TTL)
	r.mu.Lock()
	r.l1Cache[clientID] = clientCacheEntry{
		client:    client,
		expiresAt: time.Now().Add(30 * time.Second),
	}
	r.mu.Unlock()

	return client, nil
}
