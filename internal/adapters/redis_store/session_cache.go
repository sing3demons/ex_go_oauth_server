package redis_store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/pkg/errors"
	"github.com/sing3demons/oauth_server/pkg/logAction"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/mlog"
)

type SessionCache struct {
	client *redis.Client
}

func NewSessionCache(client *redis.Client) *SessionCache {
	return &SessionCache{client: client}
}

func (c *SessionCache) SetSession(ctx context.Context, sessionID string, info *models.SessionInfo, ttl time.Duration) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	key := "session:" + sessionID

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: "redis",
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> redis"), map[string]any{
		"key": key,
	})
	data, err := json.Marshal(info)
	if err != nil {
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency: "redis",
			ResultCode: "50000",
		}).Debug(logAction.EXCEPTION("redis -> app"), map[string]any{
			"error": err.Error(),
		})
		return err
	}

	// 1. Store the session data
	result := c.client.Set(ctx, key, data, ttl).Err()
	if result != nil {
		end := time.Since(start).Microseconds()
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   "redis",
			ResponseTime: end,
			ResultCode:   "50000",
		}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, "redis -> app"), map[string]any{
			"error": result.Error(),
		})
		return result
	}

	// 2. Add to User Session Index (Set)
	userSessionsKey := "user:sessions:" + info.UserID
	c.client.SAdd(ctx, userSessionsKey, sessionID)
	c.client.Expire(ctx, userSessionsKey, ttl) // Keep index alive as long as potential sessions

	end := time.Since(start).Microseconds()
	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   "redis",
		ResponseTime: end,
		ResultCode:   "20000",
	}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, "redis -> app"), map[string]any{
		"result": "set",
	})
	return result
}

func (c *SessionCache) GetSession(ctx context.Context, sessionID string) (*models.SessionInfo, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	key := "session:" + sessionID

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: "redis",
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, "app -> redis"), map[string]any{
		"key": key,
	})
	val, err := c.client.Get(ctx, key).Result()
	end := time.Since(start).Microseconds()
	if err != nil {
		if err == redis.Nil {
			_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
				Dependency:   "redis",
				ResponseTime: end,
				ResultCode:   "40400",
			}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "redis -> app"), map[string]any{
				"result": "not found",
			})
			return nil, errors.ErrNotFound
		}
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   "redis",
			ResponseTime: end,
			ResultCode:   "50000",
		}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "redis -> app"), map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}
	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   "redis",
		ResponseTime: end,
		ResultCode:   "20000",
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "redis -> app"), map[string]any{
		"result": val,
	})

	var info models.SessionInfo
	if err := json.Unmarshal([]byte(val), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (c *SessionCache) DeleteSession(ctx context.Context, sessionID string) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	key := "session:" + sessionID

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: "redis",
	}).Debug(logAction.DB_REQUEST(logAction.DB_DELETE, "app -> redis"), map[string]any{
		"key": key,
	})

	// 1. Get session info to find UserID first (if we don't have it)
	val, err := c.client.Get(ctx, key).Result()
	if err == nil {
		var info models.SessionInfo
		if json.Unmarshal([]byte(val), &info) == nil {
			// 2. Remove from User Session Index
			userSessionsKey := "user:sessions:" + info.UserID
			c.client.SRem(ctx, userSessionsKey, sessionID)
		}
	}

	// 3. Delete the session key
	err = c.client.Del(ctx, key).Err()
	end := time.Since(start).Microseconds()
	if err != nil {
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   "redis",
			ResponseTime: end,
			ResultCode:   "50000",
		}).Debug(logAction.DB_RESPONSE(logAction.DB_DELETE, "redis -> app"), map[string]any{
			"error": err.Error(),
		})
		return err
	}
	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   "redis",
		ResponseTime: end,
		ResultCode:   "20000",
	}).Debug(logAction.DB_RESPONSE(logAction.DB_DELETE, "redis -> app"), map[string]any{
		"result": "deleted",
	})
	return nil
}

func (c *SessionCache) GetUserSessions(ctx context.Context, userID string) ([]*models.SessionInfo, error) {
	userSessionsKey := "user:sessions:" + userID
	sids, err := c.client.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return nil, err
	}

	var sessions []*models.SessionInfo
	for _, sid := range sids {
		session, err := c.GetSession(ctx, sid)
		if err == nil && session != nil {
			sessions = append(sessions, session)
		} else {
			// Cleanup stale indices if session is gone
			c.client.SRem(ctx, userSessionsKey, sid)
		}
	}
	return sessions, nil
}
