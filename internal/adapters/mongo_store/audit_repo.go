package mongo_store

import (
	"context"
	"log"
	"time"

	"github.com/sing3demons/oauth_server/internal/core/models"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type AuditRepository struct {
	col *mongo.Collection
}

func NewAuditRepository(db *mongo.Database) *AuditRepository {
	repo := &AuditRepository{
		col: db.Collection("audit_logs"),
	}

	// Create index for performance
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		repo.col.Indexes().CreateMany(ctx, []mongo.IndexModel{
			{
				Keys: map[string]interface{}{"user_id": 1},
			},
			{
				Keys: map[string]interface{}{"created_at": -1},
			},
		})
	}()

	return repo
}

func (r *AuditRepository) Save(ctx context.Context, audit *models.AuditLog) error {
	if audit.CreatedAt.IsZero() {
		audit.CreatedAt = time.Now()
	}

	// Use background context for saves if we want asynchronicity, 
	// but usually handler passes its context.
	_, err := r.col.InsertOne(ctx, audit)
	if err != nil {
		log.Printf("failed to save audit log: %v", err)
	}
	return err
}

func (r *AuditRepository) FindByUserID(ctx context.Context, userID string, limit, skip int64) ([]*models.AuditLog, error) {
	opts := options.Find().SetSort(map[string]interface{}{"created_at": -1}).SetLimit(limit).SetSkip(skip)
	cursor, err := r.col.Find(ctx, map[string]interface{}{"user_id": userID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []*models.AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	return logs, nil
}

func (r *AuditRepository) CountByUserID(ctx context.Context, userID string) (int64, error) {
	return r.col.CountDocuments(ctx, map[string]interface{}{"user_id": userID})
}
