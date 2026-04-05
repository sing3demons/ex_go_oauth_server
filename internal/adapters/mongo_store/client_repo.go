package mongo_store

import (
	"context"
	"errors"

	"github.com/sing3demons/oauth_server/internal/core/models"
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
	_, err := r.col.InsertOne(ctx, client)
	return err
}

func (r *ClientRepository) FindByID(ctx context.Context, clientID string) (*models.Client, error) {
	var client models.Client
	err := r.col.FindOne(ctx, bson.M{"_id": clientID}).Decode(&client)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, err
	}
	return &client, nil
}

func (r *ClientRepository) FindAll(ctx context.Context) ([]*models.Client, error) {
	cursor, err := r.col.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var clients []*models.Client
	if err := cursor.All(ctx, &clients); err != nil {
		return nil, err
	}
	return clients, nil
}
