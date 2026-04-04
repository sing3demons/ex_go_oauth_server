package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sing3demons/tr_02_oauth/internal/config"
	"github.com/sing3demons/tr_02_oauth/internal/core/models"
	"github.com/sing3demons/tr_02_oauth/internal/core/ports"
	"golang.org/x/crypto/bcrypt"
)

type OAuthService struct {
	clientRepo ports.ClientRepository
	authCache  ports.AuthCodeCache
	keyService *KeyService
	userRepo   ports.UserRepository
	cfg        *config.Config
}

func NewOAuthService(
	clientRepo ports.ClientRepository,
	authCache ports.AuthCodeCache,
	keyService *KeyService,
	userRepo ports.UserRepository,
	cfg *config.Config,
) *OAuthService {
	return &OAuthService{
		clientRepo: clientRepo,
		authCache:  authCache,
		keyService: keyService,
		userRepo:   userRepo,
		cfg:        cfg,
	}
}

func (s *OAuthService) GenerateAuthCode(ctx context.Context, clientID, userID, redirectURI, nonce string, scopes []string, codeChallenge, codeChallengeMethod string) (string, error) {
	// 1. ตรวจสอบความมีอยู่จริงของ Client ในระบบ (MongoDB)
	client, err := s.clientRepo.FindByID(ctx, clientID)
	if err != nil || client == nil {
		return "", errors.New("invalid_client")
	}

	if client.RequirePKCE && codeChallenge == "" {
		return "", errors.New("invalid_request_pkce_required_for_this_client")
	}

	// 2. Validate Redirect URI
	validURI := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validURI = true
			break
		}
	}
	if !validURI {
		return "", errors.New("invalid_redirect_uri")
	}

	// 2.5 Scope Validation (Filtering)
	allowedMap := make(map[string]bool)
	for _, s := range client.AllowedScopes {
		allowedMap[s] = true
	}
	var finalScopes []string
	for _, s := range scopes {
		if allowedMap[s] {
			finalScopes = append(finalScopes, s)
		}
	}
	scopes = finalScopes

	// 3. ปั๊มรหัส Authorization Code สุ่มขึ้นมา
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)

	// 4. บันทึก Code ลงใน Redis พร้อมตั้งทำลายตัวเองเมื่อครบ 10 นาที
	ttl := 10 * time.Minute
	info := &models.AuthCodeInfo{
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(ttl),
	}
	if err := s.authCache.SetCode(ctx, code, info, ttl); err != nil {
		return "", err
	}

	return code, nil
}

func (s *OAuthService) ExchangeToken(ctx context.Context, code, clientID, clientSecret, redirectURI, codeVerifier string) (map[string]interface{}, error) {
	// 1. ค้นหา Auth Code จาก Redis
	info, err := s.authCache.GetCode(ctx, code)
	if err != nil || info == nil {
		return nil, errors.New("invalid_grant")
	}
	
	// 2. ลบรหัสทิ้งทันที เพื่อป้องกันการใช้งานซ้ำซ้อน (Replay Attack)
	defer s.authCache.DeleteCode(ctx, code)

	// 3. ตรวจสอบความถูกต้องของคำขอ
	if info.ClientID != clientID {
		return nil, errors.New("invalid_client")
	}
	if info.RedirectURI != redirectURI {
		return nil, errors.New("invalid_grant")
	}
	if time.Now().After(info.ExpiresAt) {
		return nil, errors.New("invalid_grant_expired")
	}

	// 3.1 ตรวจสอบ Confidential Client
	client, err := s.clientRepo.FindByID(ctx, clientID)
	if err != nil || client == nil {
		return nil, errors.New("invalid_client")
	}
	if client.ClientType == "confidential" {
		if clientSecret == "" {
			return nil, errors.New("invalid_client_secret: confidential clients must provide a secret")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)); err != nil {
			return nil, errors.New("invalid_client_secret: secret mismatch")
		}
	}

	// 3.5 PKCE Verification
	if info.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, errors.New("invalid_request_missing_code_verifier")
		}
		if info.CodeChallengeMethod == "S256" {
			h := sha256.New()
			h.Write([]byte(codeVerifier))
			hash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
			if hash != info.CodeChallenge {
				return nil, errors.New("invalid_grant_pkce_mismatch")
			}
		} else { // default to plain
			if codeVerifier != info.CodeChallenge {
				return nil, errors.New("invalid_grant_pkce_mismatch")
			}
		}
	}

	// 4. ไปคว้ากุญแจ Signature (RSA) จาก KeyService (Redis/Mongo)
	keyMgr, err := s.keyService.GetActiveKeyManager(ctx)
	if err != nil {
		return nil, errors.New("internal_server_error_keys")
	}

	// 5. ปั้น Access Token (JWT)
	now := time.Now()
	atClaims := jwt.MapClaims{
		"iss":    s.cfg.Issuer,
		"sub":    info.UserID,
		"aud":    clientID,
		"exp":    now.Add(1 * time.Hour).Unix(),
		"iat":    now.Unix(),
		"scopes": info.Scopes,
	}
	atToken := jwt.NewWithClaims(jwt.SigningMethodRS256, atClaims)
	atToken.Header["kid"] = keyMgr.KeyID

	accessToken, err := atToken.SignedString(keyMgr.PrivateKey)
	if err != nil {
		return nil, err
	}

	// 6. เตรียมส่งกลับ
	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	// 7. จัดให้มี OIDC (ID Token) ด้วยมั้ย
	hasOpenID := false
	hasEmail := false
	hasProfile := false

	for _, scope := range info.Scopes {
		if scope == "openid" { hasOpenID = true }
		if scope == "email" { hasEmail = true }
		if scope == "profile" { hasProfile = true }
	}

	if hasOpenID {
		idClaims := jwt.MapClaims{
			"iss":   s.cfg.Issuer,
			"sub":   info.UserID,
			"aud":   clientID,
			"exp":   now.Add(1 * time.Hour).Unix(),
			"iat":   now.Unix(),
		}
		// ป้อน Nonce คืนเข้าไปเพื่อปิดกั้น CSRF Attack
		if info.Nonce != "" {
			idClaims["nonce"] = info.Nonce
		}

		// เติมข้อมูลตาม OIDC Standard Scopes
		if hasEmail || hasProfile {
			user, _ := s.userRepo.FindByID(ctx, info.UserID)
			if user != nil {
				if hasEmail {
					idClaims["email"] = user.Email
					idClaims["email_verified"] = true
				}
				if hasProfile {
					idClaims["preferred_username"] = user.Username
					idClaims["name"] = user.Username // mock using username as default name
				}
			}
		}

		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
		idToken.Header["kid"] = keyMgr.KeyID

		idTokenStr, err := idToken.SignedString(keyMgr.PrivateKey)
		if err == nil {
			response["id_token"] = idTokenStr
		}
	}

	return response, nil
}
