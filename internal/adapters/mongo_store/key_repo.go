package mongo_store

import (
	"context"
	"log"
	"time"

	"github.com/sing3demons/tr_02_oauth/internal/core/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type KeyRepository struct {
	col         *mongo.Collection
	gracePeriod time.Duration
}

func NewKeyRepository(db *mongo.Database, gracePeriod time.Duration) *KeyRepository {
	col := db.Collection("keys")

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
	_, err := r.col.InsertOne(ctx, key)
	return err
}

func (r *KeyRepository) FindLatest(ctx context.Context) (*models.KeyRecord, error) {
	opts := options.FindOne().SetSort(bson.D{{Key: "created_at", Value: -1}})
	var key models.KeyRecord
	
	err := r.col.FindOne(ctx, bson.M{}, opts).Decode(&key)
	if err != nil {
		return nil, err
	}
	
	return &key, nil
}

func (r *KeyRepository) FindAll(ctx context.Context) ([]*models.KeyRecord, error) {
	// ดึงคีย์ทั้งหมดที่ยังไม่หมดตาม Grace period
	graceLimit := time.Now().Add(-r.gracePeriod)
	
	cursor, err := r.col.Find(ctx, bson.M{"expires_at": bson.M{"$gt": graceLimit}})
	if err != nil {
		return nil, err
	}
	
	var keys []*models.KeyRecord
	if err := cursor.All(ctx, &keys); err != nil {
		return nil, err
	}
	
	return keys, nil
}

func (r *KeyRepository) DeleteOldKeys(ctx context.Context, retainCount int) error {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(int64(retainCount))
	cursor, err := r.col.Find(ctx, bson.M{}, opts)
	if err != nil {
		return err
	}
	
	var keys []models.KeyRecord
	if err := cursor.All(ctx, &keys); err != nil {
		return err
	}

	if len(keys) == 0 {
		return nil
	}

	var ids []string
	for _, k := range keys {
		ids = append(ids, k.Kid)
	}

	_, err = r.col.DeleteMany(ctx, bson.M{
		"_id": bson.M{"$nin": ids},
	})
	
	return err
}
