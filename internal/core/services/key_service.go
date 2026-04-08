package services

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/internal/core/ports"
	"github.com/sing3demons/oauth_server/pkg/crypto"
)

type KeyService struct {
	keyRepo           ports.KeyRepository
	keyCache          ports.KeyCache
	rotationTime      time.Duration
	maxRetentionCount int
	supportedAlgs     []string
}

func NewKeyService(keyRepo ports.KeyRepository, keyCache ports.KeyCache, rotationTime time.Duration, maxRetentionCount int, supportedAlgs []string) *KeyService {
	if len(supportedAlgs) == 0 {
		supportedAlgs = []string{"RS256"}
	}
	return &KeyService{
		keyRepo:           keyRepo,
		keyCache:          keyCache,
		rotationTime:      rotationTime,
		maxRetentionCount: maxRetentionCount,
		supportedAlgs:     supportedAlgs,
	}
}

// GetActiveKeyManager มองหากุญแจที่ยังใช้งานได้อยู่จาก Redis หรือ Mongo
func (s *KeyService) GetActiveKeyManager(ctx context.Context, alg string) (*crypto.CryptoManager, error) {
	if alg == "" {
		alg = "RS256"
	}
	
	// 1. Check in Redis
	keyRecord, err := s.keyCache.GetRaw(ctx, alg)
	if err == nil && keyRecord != nil {
		// Found in Redis
		return crypto.ParseFromPEM(keyRecord.PrivateKeyPEM, keyRecord.Kid, keyRecord.Kty, keyRecord.Alg)
	}

	// 2. Not in Redis, Check Mongo for the latest
	latestKey, err := s.keyRepo.FindLatest(ctx, alg)
	if err == nil && latestKey != nil && latestKey.ExpiresAt.After(time.Now()) {
		// Found active key in Mongo, restore to Redis cache
		s.keyCache.SetRaw(ctx, alg, latestKey)
		return crypto.ParseFromPEM(latestKey.PrivateKeyPEM, latestKey.Kid, latestKey.Kty, latestKey.Alg)
	}

	// 3. Not found or expired, Generate a new Key
	log.Printf("Generating a new %s Key Pair for JWT...\n", alg)
	kid := uuid.New().String()
	newCryptoMgr, err := crypto.GenerateKeyPair(kid, alg)
	if err != nil {
		return nil, err
	}

	// 4. Save the new key to Mongo and Redis
	now := time.Now()
	expiresAt := now.Add(s.rotationTime)

	newKeyRecord := &models.KeyRecord{
		Kid:           kid,
		Kty:           newCryptoMgr.Kty,
		Alg:           newCryptoMgr.Alg,
		PrivateKeyPEM: newCryptoMgr.PrivateKeyPEM(),
		PublicKeyPEM:  newCryptoMgr.PublicKeyPEM(),
		CreatedAt:     now,
		ExpiresAt:     expiresAt,
	}

	if err := s.keyRepo.Insert(ctx, newKeyRecord); err != nil {
		return nil, err
	}

	// ลบกุญแจเก่าที่เกินโควต้าทิ้ง (รักษาไว้แค่ maxRetentionCount อ้างอิงเวลาสร้างล่าสุด)
	if err := s.keyRepo.DeleteOldKeys(ctx, alg, s.maxRetentionCount); err != nil {
		log.Printf("Warning: failed to prune old keys for %s: %v", alg, err)
	}

	s.keyCache.SetRaw(ctx, alg, newKeyRecord)

	return newCryptoMgr, nil
}

// GetJWKS ดึงกุญแจทั้งหมดในระบบมาแพ็ครวมส่งให้ Endpoint JWKS
func (s *KeyService) GetJWKS(ctx context.Context) (crypto.JWKS, error) {
	// Trigger get or create active key for all supported algorithms
	for _, alg := range s.supportedAlgs {
		if _, err := s.GetActiveKeyManager(ctx, alg); err != nil {
			log.Printf("Failed to init key for %s: %v", alg, err)
		}
	}

	// FindAll returns active keys + gracefully expired ones
	records, err := s.keyRepo.FindAll(ctx, map[string]any{"alg": s.supportedAlgs})
	if err != nil {
		return crypto.JWKS{}, err
	}

	var jwks crypto.JWKS
	for _, rec := range records {
		mgr, err := crypto.ParseFromPEM(rec.PrivateKeyPEM, rec.Kid, rec.Kty, rec.Alg)
		if err == nil {
			jwks.Keys = append(jwks.Keys, mgr.GetJWK())
		}
	}
	return jwks, nil
}
