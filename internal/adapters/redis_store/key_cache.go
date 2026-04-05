package redis_store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/pkg/logAction"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/mlog"
)

type KeyCache struct {
	client *redis.Client
}

func NewKeyCache(client *redis.Client) *KeyCache {
	return &KeyCache{client: client}
}

func (c *KeyCache) GetRaw(ctx context.Context) (*models.KeyRecord, error) {
	key_cache := "jwks:current"
	start := time.Now()
	_log := mlog.L(ctx)
	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: "redis",
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, key_cache), map[string]any{"key": key_cache})
	val, err := c.client.Get(ctx, key_cache).Result()
	if err != nil {
		resultCode := "50000"
		if err == redis.Nil {
			resultCode = "40400"
		}
		_log.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   "redis",
			ResponseTime: time.Since(start).Microseconds(),
			ResultCode:   resultCode,
		}).Debug(logAction.DB_REQUEST(logAction.DB_READ, key_cache), map[string]any{"key": key_cache, "error": err})
		return nil, err // Returns redis.Nil if not found
	}

	var key models.KeyRecord
	if err := json.Unmarshal([]byte(val), &key); err != nil {
		_log.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   "redis",
			ResponseTime: time.Since(start).Microseconds(),
			ResultCode:   "50000",
		}).Debug(logAction.DB_REQUEST(logAction.DB_READ, key_cache), map[string]any{"key": key_cache, "error": err})
		return nil, err
	}

	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   "redis",
		ResponseTime: time.Since(start).Microseconds(),
		ResultCode:   "20000",
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, key_cache), map[string]any{"key": key_cache, "result": "hit"})

	return &key, nil
}

func (c *KeyCache) SetRaw(ctx context.Context, key *models.KeyRecord) error {
	start := time.Now()
	key_cache := "jwks:current"
	_log := mlog.L(ctx)

	data, err := json.Marshal(key)
	if err != nil {
		return err
	}

	// Set TTL so redis auto evicts when token rotates
	ttl := time.Until(key.ExpiresAt)
	if ttl <= 0 {
		return nil
	}

	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: "redis",
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, key_cache), map[string]any{"key": key_cache, "ttl": ttl})

	statusCmd := c.client.Set(ctx, key_cache, data, ttl).Err()

	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   "redis",
		ResponseTime: time.Since(start).Microseconds(),
		ResultCode:   "20000",
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, key_cache), map[string]any{"key": key_cache, "ttl": ttl, "error": statusCmd})
	return statusCmd
}
