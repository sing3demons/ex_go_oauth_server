package mongo_store

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/sing3demons/tr_02_oauth/internal/core/models"
	"github.com/sing3demons/tr_02_oauth/pkg/logAction"
	"github.com/sing3demons/tr_02_oauth/pkg/logger"
	"github.com/sing3demons/tr_02_oauth/pkg/mlog"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type KeyRepository struct {
	col         *mongo.Collection
	gracePeriod time.Duration
	colName     string
}

func NewKeyRepository(db *mongo.Database, gracePeriod time.Duration) *KeyRepository {
	colName := "keys"
	col := db.Collection(colName)

	// Set up TTL index to auto-delete documents
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	indexModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().SetExpireAfterSeconds(int32(gracePeriod.Seconds())),
	}

	if _, err := col.Indexes().CreateOne(ctx, indexModel); err != nil {
		log.Printf("Warning: failed to create TTL index on keys collection: %v", err)
	}

	return &KeyRepository{
		col:         col,
		gracePeriod: gracePeriod,
	}
}

func (r *KeyRepository) Insert(ctx context.Context, key *models.KeyRecord) error {
	start := time.Now()
	_log := mlog.L(ctx)
	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.colName,
	}).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), key)

	result, err := r.col.InsertOne(ctx, key)

	if err != nil {
		_log.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.colName,
			ResponseTime: time.Since(start).Microseconds(),
			ResultCode:   "50000",
		}).Error(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), map[string]any{"error": err}, err.Error())
		return err
	} else {
		_log.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.colName,
			ResponseTime: time.Since(start).Microseconds(),
			ResultCode:   "20000",
		}).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), map[string]any{"result": result})
	}

	return err
}

func (r *KeyRepository) FindLatest(ctx context.Context) (*models.KeyRecord, error) {
	start := time.Now()
	_log := mlog.L(ctx)
	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.colName,
	}).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), "keys.findOne({}, sort={created_at: -1})")

	opts := options.FindOne().SetSort(bson.D{{Key: "created_at", Value: -1}})
	var key models.KeyRecord

	err := r.col.FindOne(ctx, bson.M{}, opts).Decode(&key)

	if err != nil {
		_log.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.colName,
			ResponseTime: time.Since(start).Microseconds(),
			ResultCode:   "50000",
		}).Error(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), map[string]any{"error": err}, err.Error())
		return nil, err
	}
	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.colName,
		ResponseTime: time.Since(start).Microseconds(),
		ResultCode:   "20000",
	}).Info(logAction.DB_REQUEST(logAction.DB_CREATE, "app -> mongo"), map[string]any{"result": key})

	return &key, nil
}

func (r *KeyRepository) FindAll(ctx context.Context) ([]*models.KeyRecord, error) {
	start := time.Now()
	_log := mlog.L(ctx)
	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.colName,
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), "keys.find({expires_at: {$gt: now() - gracePeriod}})")
	// ดึงคีย์ทั้งหมดที่ยังไม่หมดตาม Grace period
	graceLimit := time.Now().Add(-r.gracePeriod)

	cursor, err := r.col.Find(ctx, bson.M{"expires_at": bson.M{"$gt": graceLimit}})
	if err != nil {
		_log.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.colName,
			ResponseTime: time.Since(start).Microseconds(),
			ResultCode:   "50000",
		}).Error(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), map[string]any{"error": err}, err.Error())
		return nil, err
	}

	var keys []*models.KeyRecord
	if err := cursor.All(ctx, &keys); err != nil {
		_log.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.colName,
			ResponseTime: time.Since(start).Microseconds(),
			ResultCode:   "50000",
		}).Error(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), map[string]any{"error": err}, err.Error())
		return nil, err
	}

	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.colName,
		ResponseTime: time.Since(start).Microseconds(),
		ResultCode:   "20000",
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), map[string]any{"result_count": len(keys)})
	return keys, nil
}

func (r *KeyRepository) DeleteOldKeys(ctx context.Context, retainCount int) error {
	start := time.Now()
	_log := mlog.L(ctx)
	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.colName,
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), fmt.Sprintf("keys.find({}, sort={created_at: -1}, limit=%d)", retainCount))

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(int64(retainCount))
	cursor, err := r.col.Find(ctx, bson.M{}, opts)
	if err != nil {
		_log.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.colName,
			ResponseTime: time.Since(start).Microseconds(),
			ResultCode:   "50000",
		}).Error(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), map[string]any{"error": err}, err.Error())
		return err
	}

	var keys []models.KeyRecord
	if err := cursor.All(ctx, &keys); err != nil {
		_log.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.colName,
			ResponseTime: time.Since(start).Microseconds(),
			ResultCode:   "50000",
		}).Error(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), map[string]any{"error": err}, err.Error())
		return err
	}

	if len(keys) == 0 {
		_log.SetDependencyMetadata(logger.LogDependencyMetadata{
			Dependency:   r.colName,
			ResponseTime: time.Since(start).Microseconds(),
			ResultCode:   "40401",
		}).Info(logAction.DB_REQUEST(logAction.DB_DELETE, "app -> mongo"), "no old keys to delete")
		return nil
	}
	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.colName,
		ResponseTime: time.Since(start).Microseconds(),
		ResultCode:   "20000",
	}).Info(logAction.DB_REQUEST(logAction.DB_READ, "app -> mongo"), keys)

	var ids []string
	for _, k := range keys {
		ids = append(ids, k.Kid)
	}

	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency: r.colName,
	}).Info(logAction.DB_REQUEST(logAction.DB_DELETE, "app -> mongo"), fmt.Sprintf("keys.deleteMany({ _id: { $nin: %v } })", ids))

	_, err = r.col.DeleteMany(ctx, bson.M{
		"_id": bson.M{"$nin": ids},
	})

	_log.SetDependencyMetadata(logger.LogDependencyMetadata{
		Dependency:   r.colName,
		ResponseTime: time.Since(start).Microseconds(),
		ResultCode:   "20000",
	}).Info(logAction.DB_REQUEST(logAction.DB_DELETE, "app -> mongo"), map[string]any{"deleted_count": len(ids)})

	return err
}
