package mongo_store

import (
	"context"
	"time"

	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/pkg/logAction"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/mlog"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type RefreshTokenRepository struct {
	col *mongo.Collection
}

func NewRefreshTokenRepository(db *mongo.Database) *RefreshTokenRepository {
	return &RefreshTokenRepository{
		col: db.Collection("refresh_tokens"),
	}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, rt *models.RefreshToken) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), map[string]any{
		"document": rt,
	})

	result, err := r.col.InsertOne(ctx, rt)
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

func (r *RefreshTokenRepository) FindByToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), "refresh_tokens.findOne({_id: "+token+"})")

	var rt models.RefreshToken
	err := r.col.FindOne(ctx, bson.M{"_id": token}).Decode(&rt)
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
		"result": rt,
	})
	return &rt, nil
}

func (r *RefreshTokenRepository) Delete(ctx context.Context, token string) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_DELETE, "app -> mongo"), "refresh_tokens.deleteOne({_id: "+token+"})")
	result, err := r.col.DeleteOne(ctx, bson.M{"_id": token})
	end := time.Since(start).Microseconds()
	if err != nil {
		resultCode, resultDesc := classifyMongoError(err)
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   resultCode,
		}).Info(logAction.DB_RESPONSE(logAction.DB_DELETE, "mongo -> app"), resultDesc)
		return err
	}
	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.col.Name(),
		ResponseTime: end,
		ResultCode:   "20000",
	}).Info(logAction.DB_RESPONSE(logAction.DB_DELETE, "mongo -> app"), map[string]any{
		"result": result,
	})
	return nil
}

func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_DELETE, "app -> mongo"), "refresh_tokens.deleteMany({expires_at: {$lt: "+time.Now().String()+"}})")
	result, err := r.col.DeleteMany(ctx, bson.M{"expires_at": bson.M{"$lt": time.Now()}})
	end := time.Since(start).Microseconds()
	if err != nil {
		resultCode, resultDesc := classifyMongoError(err)
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   resultCode,
		}).Info(logAction.DB_RESPONSE(logAction.DB_DELETE, "mongo -> app"), resultDesc)
		return err
	}
	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.col.Name(),
		ResponseTime: end,
		ResultCode:   "20000",
	}).Info(logAction.DB_RESPONSE(logAction.DB_DELETE, "mongo -> app"), map[string]any{
		"result": result,
	})
	return nil
}
