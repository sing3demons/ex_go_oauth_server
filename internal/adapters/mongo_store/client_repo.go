package mongo_store

import (
	"context"
	"errors"
	"time"

	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/pkg/logAction"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/mlog"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type ClientRepository struct {
	col *mongo.Collection
}

func NewClientRepository(db *mongo.Database) *ClientRepository {
	return &ClientRepository{
		col: db.Collection("clients"),
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
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   "50000",
		}).Info(logAction.DB_RESPONSE(logAction.DB_CREATE, "mongo -> app"), map[string]any{
			"error": err.Error(),
		})
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
		msgErr := err
		resultCode := "50000"
		resultErr := err.Error()

		if errors.Is(err, mongo.ErrNoDocuments) {
			msgErr = nil
			resultCode = "40400"
		}

		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   resultCode,
		}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), map[string]any{
			"error": resultErr,
		})
		return nil, msgErr
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
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   "50000",
		}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}
	defer cursor.Close(ctx)

	var clients []*models.Client
	if err := cursor.All(ctx, &clients); err != nil {
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   "50000",
		}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), map[string]any{
			"error": err.Error(),
		})
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
