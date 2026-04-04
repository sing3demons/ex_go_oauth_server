package redis_store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sing3demons/tr_02_oauth/internal/core/models"
)

type KeyCache struct {
	client *redis.Client
}

func NewKeyCache(client *redis.Client) *KeyCache {
	return &KeyCache{client: client}
}

func (c *KeyCache) GetRaw(ctx context.Context) (*models.KeyRecord, error) {
	val, err := c.client.Get(ctx, "jwks:current").Result()
	if err != nil {
		return nil, err // Returns redis.Nil if not found
	}

	var key models.KeyRecord
	if err := json.Unmarshal([]byte(val), &key); err != nil {
		return nil, err
	}
	
	return &key, nil
}

func (c *KeyCache) SetRaw(ctx context.Context, key *models.KeyRecord) error {
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}

	// Set TTL so redis auto evicts when token rotates
	ttl := time.Until(key.ExpiresAt)
	if ttl <= 0 {
		return nil
	}

	return c.client.Set(ctx, "jwks:current", data, ttl).Err()
}
