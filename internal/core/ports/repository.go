package ports

import (
	"context"

	"github.com/sing3demons/tr_02_oauth/internal/core/models"
)

type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	FindByUsername(ctx context.Context, username string) (*models.User, error)
	FindByID(ctx context.Context, id string) (*models.User, error)
}

type ClientRepository interface {
	FindByID(ctx context.Context, clientID string) (*models.Client, error)
	Create(ctx context.Context, client *models.Client) error
}

type KeyRepository interface {
	Insert(ctx context.Context, key *models.KeyRecord) error
	FindLatest(ctx context.Context) (*models.KeyRecord, error)
	FindAll(ctx context.Context) ([]*models.KeyRecord, error)
	DeleteOldKeys(ctx context.Context, retainCount int) error
}

type KeyCache interface {
	GetRaw(ctx context.Context) (*models.KeyRecord, error)
	SetRaw(ctx context.Context, key *models.KeyRecord) error
}
