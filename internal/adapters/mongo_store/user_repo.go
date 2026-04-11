package mongo_store

import (
	"context"
	"fmt"
	"time"

	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/pkg/logAction"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/mlog"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type UserRepository struct {
	col *mongo.Collection
}

func NewUserRepository(db *mongo.Database) *UserRepository {
	col := db.Collection("users")

	// Ensure unique index for username
	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	indexModelEmail := mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	// context.Background is usually fine here because it runs on startup
	_, _ = col.Indexes().CreateMany(context.Background(), []mongo.IndexModel{indexModel, indexModelEmail})

	return &UserRepository{
		col: col,
	}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), map[string]any{
		"document": user,
	})
	_, err := r.col.InsertOne(ctx, user)
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
		"result": user,
	})
	return nil
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), "users.findOne({username: "+username+"})")

	var user models.User
	err := r.col.FindOne(ctx, bson.M{"username": username}).Decode(&user)
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
		"result": user,
	})
	return &user, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), "users.findOne({_id: "+id+"})")

	var user models.User
	err := r.col.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
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
		"result": user,
	})
	return &user, nil
}

func (r *UserRepository) UpdateMFAEnabled(ctx context.Context, userID string, enabled bool) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_UPDATE, "app -> mongo"), "users.updateOne({_id: "+userID+"}, {$set: {mfa_enabled: "+fmt.Sprintf("%v", enabled)+"}})")

	_, err := r.col.UpdateOne(ctx, bson.M{"_id": userID}, bson.M{"$set": bson.M{"mfa_enabled": enabled}})
	end := time.Since(start).Microseconds()
	if err != nil {
		resultCode, resultDesc := classifyMongoError(err)
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   resultCode,
		}).Info(logAction.DB_RESPONSE(logAction.DB_UPDATE, "mongo -> app"), resultDesc)
		return err
	}
	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.col.Name(),
		ResponseTime: end,
		ResultCode:   "20000",
	}).Info(logAction.DB_RESPONSE(logAction.DB_UPDATE, "mongo -> app"), "success")
	return nil
}
