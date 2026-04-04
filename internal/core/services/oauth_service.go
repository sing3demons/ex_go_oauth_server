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
	rtRepo     ports.RefreshTokenRepository
	keyService *KeyService
	userRepo   ports.UserRepository
	cfg        *config.Config
}

func NewOAuthService(
	clientRepo ports.ClientRepository,
	authCache ports.AuthCodeCache,
	rtRepo ports.RefreshTokenRepository,
	keyService *KeyService,
	userRepo ports.UserRepository,
	cfg *config.Config,
) *OAuthService {
	return &OAuthService{
		clientRepo: clientRepo,
		authCache:  authCache,
		rtRepo:     rtRepo,
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

	// 5.5 Generate Refresh Token
	rtBytes := make([]byte, 32)
	rand.Read(rtBytes)
	refreshTokenStr := base64.URLEncoding.EncodeToString(rtBytes)
	rt := &models.RefreshToken{
		Token:     refreshTokenStr,
		ClientID:  clientID,
		UserID:    info.UserID,
		Scopes:    info.Scopes,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days
	}
	s.rtRepo.Create(ctx, rt)

	// 6. เตรียมส่งกลับ
	response := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshTokenStr,
		"token_type":    "Bearer",
		"expires_in":    3600,
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
// RefreshToken exchanges a valid refresh token for a new set of access/id tokens and optionally a new refresh token.
func (s *OAuthService) RefreshToken(ctx context.Context, refreshTokenStr string, clientID string, clientSecret string) (map[string]interface{}, error) {
	// 1. Validate Client
	client, err := s.clientRepo.FindByID(ctx, clientID)
	if err != nil || client == nil {
		return nil, errors.New("invalid_client")
	}

	if client.ClientType == "confidential" {
		if clientSecret == "" {
			return nil, errors.New("invalid_client_secret: confidential clients must provide a secret")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)); err != nil {
			return nil, errors.New("invalid_client_secret")
		}
	}

	// 2. Lookup Refresh Token
	rt, err := s.rtRepo.FindByToken(ctx, refreshTokenStr)
	if err != nil || rt == nil {
		return nil, errors.New("invalid_grant")
	}

	// 3. Check token validity
	if rt.Revoked || time.Now().After(rt.ExpiresAt) {
		s.rtRepo.Delete(ctx, refreshTokenStr) // clear it
		return nil, errors.New("invalid_grant_expired")
	}
	if rt.ClientID != clientID {
		return nil, errors.New("invalid_grant_client_mismatch")
	}

	// 4. Issue new tokens (Access + ID + new Refresh Token potentially)
	// Optionally revoke the old one, but for resilience, some keep it. Let's rotate it:
	s.rtRepo.Delete(ctx, refreshTokenStr)

	keyMgr, err := s.keyService.GetActiveKeyManager(ctx)
	if err != nil {
		return nil, errors.New("internal_server_error_keys")
	}

	now := time.Now()
	atClaims := jwt.MapClaims{
		"iss":    s.cfg.Issuer,
		"sub":    rt.UserID,
		"aud":    clientID,
		"exp":    now.Add(1 * time.Hour).Unix(),
		"iat":    now.Unix(),
		"scopes": rt.Scopes,
	}
	atToken := jwt.NewWithClaims(jwt.SigningMethodRS256, atClaims)
	atToken.Header["kid"] = keyMgr.KeyID

	accessToken, err := atToken.SignedString(keyMgr.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Rotate refresh token
	newRtBytes := make([]byte, 32)
	rand.Read(newRtBytes)
	newRefreshTokenStr := base64.URLEncoding.EncodeToString(newRtBytes)
	newRt := &models.RefreshToken{
		Token:     newRefreshTokenStr,
		ClientID:  clientID,
		UserID:    rt.UserID,
		Scopes:    rt.Scopes,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // Reset window
	}
	s.rtRepo.Create(ctx, newRt)

	response := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": newRefreshTokenStr,
		"token_type":    "Bearer",
		"expires_in":    3600,
	}

	// ID Token
	hasOpenID := false
	for _, scope := range rt.Scopes {
		if scope == "openid" {
			hasOpenID = true
		}
	}
	if hasOpenID {
		idClaims := jwt.MapClaims{
			"iss": s.cfg.Issuer,
			"sub": rt.UserID,
			"aud": clientID,
			"exp": now.Add(1 * time.Hour).Unix(),
			"iat": now.Unix(),
		}
		user, _ := s.userRepo.FindByID(ctx, rt.UserID)
		if user != nil {
			for _, s := range rt.Scopes {
				if s == "email" {
					idClaims["email"] = user.Email
					idClaims["email_verified"] = true
				}
				if s == "profile" {
					idClaims["preferred_username"] = user.Username
					idClaims["name"] = user.Username
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

// ValidateAccessToken parses and verifies an access token.
func (s *OAuthService) ValidateAccessToken(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	records, err := s.keyService.keyRepo.FindAll(ctx)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		kidRaw, ok := t.Header["kid"]
		if !ok {
			return nil, errors.New("missing kid header")
		}
		kid := kidRaw.(string)

		// ค้นหา Public Key ที่ตรงกับ kid ใน JWT Header
		for _, rec := range records {
			if rec.Kid == kid {
				return jwt.ParseRSAPublicKeyFromPEM([]byte(rec.PublicKeyPEM))
			}
		}
		return nil, errors.New("key not found")
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid_token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid_token_claims")
	}

	return claims, nil
}
