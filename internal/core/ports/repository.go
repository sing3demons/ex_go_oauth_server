package ports

import (
	"context"
	"time"

	"github.com/sing3demons/oauth_server/internal/core/models"
)

type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	FindByUsername(ctx context.Context, username string) (*models.User, error)
	FindByID(ctx context.Context, id string) (*models.User, error)
}

type ClientRepository interface {
	FindByID(ctx context.Context, clientID string) (*models.Client, error)
	FindByIDWithCache(ctx context.Context, clientID string) (*models.Client, error)
	FindAll(ctx context.Context) ([]*models.Client, error)
	Create(ctx context.Context, client *models.Client) error
}

type KeyRepository interface {
	Insert(ctx context.Context, key *models.KeyRecord) error
	FindLatest(ctx context.Context, alg string) (*models.KeyRecord, error)
	FindAll(ctx context.Context) ([]*models.KeyRecord, error)
	DeleteOldKeys(ctx context.Context, alg string, retainCount int) error
}

type KeyCache interface {
	GetRaw(ctx context.Context, alg string) (*models.KeyRecord, error)
	SetRaw(ctx context.Context, alg string, key *models.KeyRecord) error
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, rt *models.RefreshToken) error
	FindByToken(ctx context.Context, token string) (*models.RefreshToken, error)
	Delete(ctx context.Context, token string) error
	DeleteExpired(ctx context.Context) error
}

type AuthCodeCache interface {
	SetCode(ctx context.Context, code string, info *models.AuthCodeInfo, ttl time.Duration) error
	GetCode(ctx context.Context, code string) (*models.AuthCodeInfo, error)
	DeleteCode(ctx context.Context, code string) error
}

type SessionCache interface {
	SetSession(ctx context.Context, sessionID string, info *models.SessionInfo, ttl time.Duration) error
	GetSession(ctx context.Context, sessionID string) (*models.SessionInfo, error)
	DeleteSession(ctx context.Context, sessionID string) error
}

type TransactionCache interface {
	SetTransaction(ctx context.Context, txID string, info *models.AuthTransaction, ttl time.Duration) error
	GetTransaction(ctx context.Context, txID string) (*models.AuthTransaction, error)
	DeleteTransaction(ctx context.Context, txID string) error
}
