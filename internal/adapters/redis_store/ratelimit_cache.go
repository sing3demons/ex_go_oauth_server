package redis_store

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RateLimitCache struct {
	client *redis.Client
}

func NewRateLimitCache(client *redis.Client) *RateLimitCache {
	return &RateLimitCache{client: client}
}
// Increment(ctx any, key string, expiration time.Duration) (int, error)
func (c *RateLimitCache) Increment(ctx context.Context, key string, expiration time.Duration) (int, error) {
	pipe := c.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, expiration)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return int(incr.Val()), nil
}
