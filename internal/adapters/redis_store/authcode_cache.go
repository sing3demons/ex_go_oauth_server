package redis_store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sing3demons/tr_02_oauth/internal/core/models"
)

type AuthCodeCache struct {
	client *redis.Client
}

func NewAuthCodeCache(client *redis.Client) *AuthCodeCache {
	return &AuthCodeCache{client: client}
}

func (c *AuthCodeCache) SetCode(ctx context.Context, code string, info *models.AuthCodeInfo, ttl time.Duration) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, "authcode:"+code, data, ttl).Err()
}

func (c *AuthCodeCache) GetCode(ctx context.Context, code string) (*models.AuthCodeInfo, error) {
	val, err := c.client.Get(ctx, "authcode:"+code).Result()
	if err != nil {
		return nil, err // Returns redis.Nil if not found
	}

	var info models.AuthCodeInfo
	if err := json.Unmarshal([]byte(val), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *AuthCodeCache) DeleteCode(ctx context.Context, code string) error {
	return c.client.Del(ctx, "authcode:"+code).Err()
}
