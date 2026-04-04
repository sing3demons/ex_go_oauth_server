package redis_store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sing3demons/tr_02_oauth/internal/core/models"
)

type TransactionCache struct {
	client *redis.Client
}

func NewTransactionCache(client *redis.Client) *TransactionCache {
	return &TransactionCache{client: client}
}

func (c *TransactionCache) SetTransaction(ctx context.Context, txID string, info *models.AuthTransaction, ttl time.Duration) error {
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, "tx:"+txID, b, ttl).Err()
}

func (c *TransactionCache) GetTransaction(ctx context.Context, txID string) (*models.AuthTransaction, error) {
	val, err := c.client.Get(ctx, "tx:"+txID).Result()
	if err != nil {
		return nil, err
	}
	var info models.AuthTransaction
	if err := json.Unmarshal([]byte(val), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *TransactionCache) DeleteTransaction(ctx context.Context, txID string) error {
	return c.client.Del(ctx, "tx:"+txID).Err()
}
