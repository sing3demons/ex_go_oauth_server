package redis_store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sing3demons/tr_02_oauth/internal/core/models"
)

type SessionCache struct {
	client *redis.Client
}

func NewSessionCache(client *redis.Client) *SessionCache {
	return &SessionCache{client: client}
}

func (c *SessionCache) SetSession(ctx context.Context, sessionID string, info *models.SessionInfo, ttl time.Duration) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, "session:"+sessionID, data, ttl).Err()
}

func (c *SessionCache) GetSession(ctx context.Context, sessionID string) (*models.SessionInfo, error) {
	val, err := c.client.Get(ctx, "session:"+sessionID).Result()
	if err != nil {
		return nil, err 
	}

	var info models.SessionInfo
	if err := json.Unmarshal([]byte(val), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *SessionCache) DeleteSession(ctx context.Context, sessionID string) error {
	return c.client.Del(ctx, "session:"+sessionID).Err()
}
