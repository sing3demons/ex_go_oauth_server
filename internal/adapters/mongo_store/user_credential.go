package mongo_store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/pkg/logAction"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/mlog"
	"github.com/sing3demons/oauth_server/pkg/utils"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type UserCredentialRepository struct {
	col *mongo.Collection
}

func NewUserCredentialRepository(db *mongo.Database) *UserCredentialRepository {
	col := db.Collection("user_credentials")

	createUserCredentialIndexes(context.Background(), col)
	return &UserCredentialRepository{
		col: col,
	}
}

func createUserCredentialIndexes(ctx context.Context, col *mongo.Collection) error {
	indexes := []mongo.IndexModel{

		// 🔑 1. Login index (สำคัญสุด)
		{
			Keys: bson.D{
				bson.E{Key: "type", Value: 1},
				bson.E{Key: "identifier", Value: 1},
			},
			Options: options.Index().
				SetName("idx_type_identifier_unique").
				SetUnique(true).
				SetPartialFilterExpression(bson.M{
					"revoked":    false,
					"identifier": bson.M{"$exists": true},
				}),
		},

		// 🔍 2. Query credential ของ user
		{
			Keys: bson.D{
				bson.E{Key: "user_id", Value: 1},
				bson.E{Key: "type", Value: 1},
			},
			Options: options.Index().
				SetName("idx_user_type"),
		},

		// ⏳ 3. TTL index (OTP / temporary credential)
		{
			Keys: bson.D{
				bson.E{Key: "expires_at", Value: 1},
			},
			Options: options.Index().
				SetName("idx_expires_at_ttl").
				SetExpireAfterSeconds(0),
		},

		// ⚡ 4. Optimize login query (include revoked)
		{
			Keys: bson.D{
				bson.E{Key: "type", Value: 1},
				bson.E{Key: "identifier", Value: 1},
				bson.E{Key: "revoked", Value: 1},
			},
			Options: options.Index().
				SetName("idx_login_compound"),
		},
	}

	_, err := col.Indexes().CreateMany(ctx, indexes)
	return err
}

func (r *UserCredentialRepository) Create(ctx context.Context, credential *models.UserCredential) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	rules := map[string]func(string) string{
		"secret": utils.MaskPassword,
	}
	result := utils.MaskRecursive(credential, rules)
	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), fmt.Sprintf("users.insertOne(%v)", result))
	// _logger.SetDependencyMetadata(logger.LogDependencyMetadata{
	// 	Dependency: r.col.Name(),
	// }).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), map[string]any{
	// 	"document": credential,
	// }, logger.MaskingOption{
	// 	MaskingField: "secret",
	// 	MaskingType:  logger.MaskAll,
	// })
	_, err := r.col.InsertOne(ctx, credential)
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
		"result": credential,
	})
	return nil
}

// CreateMany
func (r *UserCredentialRepository) CreateMany(ctx context.Context, credentials []models.UserCredential) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	rules := map[string]func(string) string{
		"secret": utils.MaskPassword,
	}
	result := utils.MaskRecursive(credentials, rules)
	jsonResult, _ := json.Marshal(result)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), fmt.Sprintf("users.insertMany(%v)", string(jsonResult)))

	var docs []any
	for _, c := range credentials {
		docs = append(docs, c)
	}

	results, err := r.col.InsertMany(ctx, docs)
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
		"result": results,
	})
	return nil
}
func (r *UserCredentialRepository) FindByUsernamePassword(ctx context.Context, username string) (*models.UserCredential, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), "users.findOne({username: "+username+", type: password})")

	var credential models.UserCredential
	err := r.col.FindOne(ctx, bson.M{"identifier": username, "type": "password"}).Decode(&credential)
	end := time.Since(start).Microseconds()
	resultCode, resultDesc := classifyMongoError(err)
	if err != nil {
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
		ResultCode:   resultCode,
	}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), map[string]any{
		"result": credential,
	})
	return &credential, nil
}
func (r *UserCredentialRepository) FindByEmailPassword(ctx context.Context, email string) (*models.UserCredential, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), "users.findOne({email: "+email+", type: password})")

	var credential models.UserCredential
	err := r.col.FindOne(ctx, bson.M{"identifier": email, "type": "password"}).Decode(&credential)
	end := time.Since(start).Microseconds()
	resultCode, resultDesc := classifyMongoError(err)
	if err != nil {
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
		ResultCode:   resultCode,
	}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), map[string]any{
		"result": credential,
	}, logger.MaskingOption{
		MaskingField: "result.secret",
		MaskingType:  logger.MaskAll,
	})
	return &credential, nil
}

func (r *UserCredentialRepository) FindByID(ctx context.Context, id string) (*models.UserCredential, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), "users.findOne({_id: "+id+"})")

	var credential models.UserCredential
	err := r.col.FindOne(ctx, bson.M{"_id": id}).Decode(&credential)
	end := time.Since(start).Microseconds()
	resultCode, resultDesc := classifyMongoError(err)
	if err != nil {
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
		ResultCode:   resultCode,
	}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), map[string]any{
		"result": credential,
	})
	return &credential, nil
}

func (r *UserCredentialRepository) FindByUserIDAndType(ctx context.Context, userID, credentialType string) (*models.UserCredential, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), fmt.Sprintf("users.findOne({user_id: %s, type: %s, revoked: false})", userID, credentialType))

	filter := bson.M{
		"user_id": userID,
		"type":    credentialType,
		"revoked": false,
	}

	var credential models.UserCredential
	err := r.col.FindOne(ctx, filter).Decode(&credential)

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

	// ⏳ ตรวจสอบวันหมดอายุ (ถ้ามี)
	if credential.ExpiresAt != nil && time.Now().After(*credential.ExpiresAt) {
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   "40001",
		}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), "credential expired")
		return nil, mongo.ErrNoDocuments
	}

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.col.Name(),
		ResponseTime: end,
		ResultCode:   "20000",
	}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), map[string]any{
		"result": credential,
	})
	return &credential, nil
}

func (r *UserCredentialRepository) FindAllByUserIDAndType(ctx context.Context, userID, credentialType string) ([]*models.UserCredential, error) {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), fmt.Sprintf("users.find({user_id: %s, type: %s, revoked: false})", userID, credentialType))

	filter := bson.M{
		"user_id": userID,
		"type":    credentialType,
		"revoked": false,
	}

	cursor, err := r.col.Find(ctx, filter)
	end := time.Since(start).Microseconds()
	resultCode, resultDesc := classifyMongoError(err)
	if err != nil {
		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   resultCode,
		}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), resultDesc)
		return nil, err
	}
	defer cursor.Close(ctx)

	var credentials []*models.UserCredential
	if err := cursor.All(ctx, &credentials); err != nil {
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
		ResultCode:   resultCode,
	}).Info(logAction.DB_RESPONSE(logAction.DB_READ, "mongo -> app"), map[string]any{
		"count": len(credentials),
	})
	return credentials, nil
}

func (r *UserCredentialRepository) DeleteByID(ctx context.Context, id string) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_DELETE, "app -> mongo"), fmt.Sprintf("user_credentials.deleteOne({_id: %s})", id))

	result, err := r.col.DeleteOne(ctx, bson.M{"_id": id})
	end := time.Since(start).Microseconds()
	resultCode, resultDesc := classifyMongoError(err)
	if err != nil {

		_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.col.Name(),
			ResponseTime: end,
			ResultCode:   resultCode,
		}).Info(logAction.DB_RESPONSE(logAction.DB_DELETE, "mongo -> app"), resultDesc)
		return err
	}

	if result.DeletedCount == 0 {
		return mongo.ErrNoDocuments
	}

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.col.Name(),
		ResponseTime: end,
		ResultCode:   resultCode,
	}).Info(logAction.DB_RESPONSE(logAction.DB_DELETE, "mongo -> app"), "deleted credential successfully")

	return nil
}

func (r *UserCredentialRepository) DeleteAllByUserIDAndType(ctx context.Context, userID, credentialType string) error {
	start := time.Now()
	_logger := mlog.L(ctx)

	filter := bson.M{"user_id": userID, "type": credentialType}

	_logger.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.col.Name(),
	}).Info(logAction.DB_REQUEST(logAction.DB_DELETE, "app -> mongo"), fmt.Sprintf("user_credentials.deleteMany({user_id: %s, type: %s})", userID, credentialType))

	result, err := r.col.DeleteMany(ctx, filter)
	end := time.Since(start).Microseconds()
	resultCode, resultDesc := classifyMongoError(err)
	if err != nil {
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
		ResultCode:   resultCode,
	}).Info(logAction.DB_RESPONSE(logAction.DB_DELETE, "mongo -> app"), map[string]any{
		"result": result,
	})
	return nil
}
