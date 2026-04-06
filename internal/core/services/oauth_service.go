package services

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/internal/core/ports"
	"github.com/sing3demons/oauth_server/pkg/jwks"
	"golang.org/x/crypto/bcrypt"
)

type OAuthService struct {
	clientRepo ports.ClientRepository
	authCache  ports.AuthCodeCache
	rtRepo     ports.RefreshTokenRepository
	keyService *KeyService
	userRepo    ports.UserRepository
	cfg         *config.Config
	jwksFetcher *jwks.ExternalJWKSFetcher
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
		userRepo:    userRepo,
		cfg:         cfg,
		jwksFetcher: jwks.NewExternalJWKSFetcher(),
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

	// Validate code_challenge_method against server's supported list
	if codeChallengeMethod != "" {
		supported := false
		for _, m := range s.cfg.Oidc.CodeChallengeMethods {
			if m == codeChallengeMethod {
				supported = true
				break
			}
		}
		if !supported {
			return "", errors.New("invalid_request: unsupported code_challenge_method")
		}
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

func (s *OAuthService) ExchangeToken(ctx context.Context, code, clientID, clientSecret, redirectURI, codeVerifier, usedAuthMethod string) (map[string]interface{}, error) {
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
	if err := s.validateClientAuth(client, usedAuthMethod, clientSecret); err != nil {
		return nil, err
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
		} else if info.CodeChallengeMethod == "plain" || info.CodeChallengeMethod == "" {
			if codeVerifier != info.CodeChallenge {
				return nil, errors.New("invalid_grant_pkce_mismatch")
			}
		} else {
			return nil, errors.New("invalid_request: unsupported code_challenge_method")
		}
	}

	alg := client.IDTokenSignedResponseAlg
	if alg == "" {
		alg = "RS256"
	}
	
	// 4. ไปคว้ากุญแจ Signature จาก KeyService (Redis/Mongo)
	keyMgr, err := s.keyService.GetActiveKeyManager(ctx, alg)
	if err != nil {
		return nil, errors.New("internal_server_error_keys")
	}

	signingMethod := s.getSigningMethod(alg)

	// 5. ปั้น Access Token (JWT)
	now := time.Now()
	atClaims := jwt.MapClaims{
		"iss":    s.cfg.Issuer,
		"sub":    s.deriveSub(client, info.UserID),
		"aud":    clientID,
		"exp":    now.Add(1 * time.Hour).Unix(),
		"iat":    now.Unix(),
		"scopes": info.Scopes,
	}
	atToken := jwt.NewWithClaims(signingMethod, atClaims)
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
	response := map[string]any{
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
		if scope == "openid" {
			hasOpenID = true
		}
		if scope == "email" {
			hasEmail = true
		}
		if scope == "profile" {
			hasProfile = true
		}
	}

	if hasOpenID {
		idClaims := jwt.MapClaims{
			"iss": s.cfg.Issuer,
			"sub": s.deriveSub(client, info.UserID),
			"aud": clientID,
			"exp": now.Add(1 * time.Hour).Unix(),
			"iat": now.Unix(),
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

		idToken := jwt.NewWithClaims(signingMethod, idClaims)
		idToken.Header["kid"] = keyMgr.KeyID

		idTokenStr, err := idToken.SignedString(keyMgr.PrivateKey)
		if err == nil {
			response["id_token"] = idTokenStr
		}
	}

	return response, nil
}

// RefreshToken exchanges a valid refresh token for a new set of access/id tokens and optionally a new refresh token.
func (s *OAuthService) RefreshToken(ctx context.Context, refreshTokenStr string, clientID string, clientSecret string, usedAuthMethod string) (map[string]interface{}, error) {
	// 1. Validate Client
	client, err := s.clientRepo.FindByID(ctx, clientID)
	if err != nil || client == nil {
		return nil, errors.New("invalid_client")
	}

	if err := s.validateClientAuth(client, usedAuthMethod, clientSecret); err != nil {
		return nil, err
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

	alg := client.IDTokenSignedResponseAlg
	if alg == "" {
		alg = "RS256"
	}

	keyMgr, err := s.keyService.GetActiveKeyManager(ctx, alg)
	if err != nil {
		return nil, errors.New("internal_server_error_keys")
	}

	signingMethod := s.getSigningMethod(alg)

	now := time.Now()
	atClaims := jwt.MapClaims{
		"iss":    s.cfg.Issuer,
		"sub":    s.deriveSub(client, rt.UserID),
		"aud":    clientID,
		"exp":    now.Add(1 * time.Hour).Unix(),
		"iat":    now.Unix(),
		"scopes": rt.Scopes,
	}
	atToken := jwt.NewWithClaims(signingMethod, atClaims)
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

	response := map[string]any{
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
			"sub": s.deriveSub(client, rt.UserID),
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

// ClientCredentials handles the client_credentials grant type (M2M flows).
// ไม่ต้องการ User — Client ยืนยันตัวเองด้วย client_id + client_secret
func (s *OAuthService) ClientCredentials(ctx context.Context, clientID, clientSecret string, scopes []string, usedAuthMethod string) (map[string]interface{}, error) {
	// 1. ค้นหาและยืนยัน Client
	client, err := s.clientRepo.FindByID(ctx, clientID)
	if err != nil || client == nil {
		return nil, errors.New("invalid_client")
	}

	// 2. Client ต้องเป็น confidential เท่านั้น (public client ไม่มี secret)
	if client.ClientType != "confidential" {
		return nil, errors.New("unauthorized_client: client_credentials requires a confidential client")
	}

	// 3. Validate auth method
	if err := s.validateClientAuth(client, usedAuthMethod, clientSecret); err != nil {
		return nil, err
	}

	// 4. ตรวจสอบว่า Client รองรับ grant_type นี้
	hasGrant := false
	for _, g := range client.GrantTypes {
		if g == "client_credentials" {
			hasGrant = true
			break
		}
	}
	if !hasGrant {
		return nil, errors.New("unauthorized_client: client_credentials not allowed for this client")
	}

	// 5. Scope Validation — กรองตาม server -> client สองชั้น
	// server-level: เฉพาะ scope ที่ server รองรับ
	serverScopesSet := make(map[string]bool, len(s.cfg.Oidc.SupportedScopes))
	for _, sc := range s.cfg.Oidc.SupportedScopes {
		serverScopesSet[sc] = true
	}
	// client-level: กรองจาก client.AllowedScopes
	allowedMap := make(map[string]bool, len(client.AllowedScopes))
	for _, sc := range client.AllowedScopes {
		if serverScopesSet[sc] {
			allowedMap[sc] = true
		}
	}
	var finalScopes []string
	for _, sc := range scopes {
		if serverScopesSet[sc] && allowedMap[sc] {
			finalScopes = append(finalScopes, sc)
		}
	}
	if len(finalScopes) == 0 {
		// fallback: ใช้ทุก scope ที่ client มี และ server รองรับ
		for _, sc := range client.AllowedScopes {
			if serverScopesSet[sc] {
				finalScopes = append(finalScopes, sc)
			}
		}
	}

	// 6. ดึง Signing Key
	alg := client.IDTokenSignedResponseAlg
	if alg == "" {
		alg = "RS256"
	}
	keyMgr, err := s.keyService.GetActiveKeyManager(ctx, alg)
	if err != nil {
		return nil, errors.New("internal_server_error_keys")
	}

	signingMethod := s.getSigningMethod(alg)

	// 7. สร้าง Access Token (ไม่มี sub เพราะไม่มี User)
	now := time.Now()
	atClaims := jwt.MapClaims{
		"iss":    s.cfg.Issuer,
		"sub":    clientID, // M2M: sub = client_id
		"aud":    clientID,
		"exp":    now.Add(1 * time.Hour).Unix(),
		"iat":    now.Unix(),
		"scopes": finalScopes,
		"client_credentials": true, // บอก downstream ว่า flow นี้ไม่ใช่ user
	}
	atToken := jwt.NewWithClaims(signingMethod, atClaims)
	atToken.Header["kid"] = keyMgr.KeyID

	accessToken, err := atToken.SignedString(keyMgr.PrivateKey)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(finalScopes, " "),
	}, nil
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

// RevokeToken invalidates a refresh token
func (s *OAuthService) RevokeToken(ctx context.Context, tokenStr string, clientID string, clientSecret string, usedAuthMethod string) error {
	client, err := s.clientRepo.FindByID(ctx, clientID)
	if err != nil || client == nil {
		return errors.New("invalid_client")
	}

	if err := s.validateClientAuth(client, usedAuthMethod, clientSecret); err != nil {
		return err
	}

	// ลบออกไป (ถ้าไม่มีในระบบ ก็ให้ถือว่าสำเร็จ 200 OK ตาม RFC)
	s.rtRepo.Delete(ctx, tokenStr)
	return nil
}

// TokenExchange handles the RFC 8693 token exchange.
func (s *OAuthService) TokenExchange(
	ctx context.Context, subjectToken, subjectTokenType, clientID, clientSecret string,
	requestedScopes []string, audience string, usedAuthMethod string,
) (map[string]interface{}, error) {
	// 1. Validate Client
	client, err := s.clientRepo.FindByID(ctx, clientID)
	if err != nil || client == nil {
		return nil, errors.New("invalid_client")
	}
	if err := s.validateClientAuth(client, usedAuthMethod, clientSecret); err != nil {
		return nil, err
	}

	hasGrant := false
	for _, g := range client.GrantTypes {
		if g == "urn:ietf:params:oauth:grant-type:token-exchange" {
			hasGrant = true
			break
		}
	}
	if !hasGrant {
		return nil, errors.New("unauthorized_client: token-exchange not allowed")
	}

	// 2. Decode original token (without full verification at first)
	token, _, err := new(jwt.Parser).ParseUnverified(subjectToken, jwt.MapClaims{})
	if err != nil {
		return nil, errors.New("invalid_request: unable to parse subject_token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid_request: unable to parse claims")
	}

	originalIss, _ := claims["iss"].(string)

	var subject string
	var grantedScopes []string

	// 3. Verify based on Internal vs External
	if originalIss == s.cfg.Issuer {
		// --- INTERNAL TOKEN EXCHANGE ---
		_, err := s.ValidateAccessToken(ctx, subjectToken)
		if err != nil {
			return nil, errors.New("invalid_token: " + err.Error())
		}
		
		sub, ok := claims["sub"].(string)
		if !ok {
			return nil, errors.New("invalid_token: missing sub")
		}
		subject = sub

		// Read scopes
		switch scopesVal := claims["scopes"].(type) {
		case []interface{}:
			for _, v := range scopesVal {
				if sStr, ok := v.(string); ok {
					grantedScopes = append(grantedScopes, sStr)
				}
			}
		}

	} else {
		// --- EXTERNAL FEDERATION ---
		// Find in config
		var trusted *config.TrustedIssuer
		for _, t := range s.cfg.TrustedIssuers {
			if t.Issuer == originalIss {
				trusted = &t
				break
			}
		}
		if trusted == nil {
			return nil, errors.New("invalid_request: untrusted issuer")
		}

		// Validate token with external jwks
		keyFunc := func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("missing kid")
			}
			return s.jwksFetcher.GetPublicKey(trusted.Issuer, kid)
		}

		parsed, err := jwt.Parse(subjectToken, keyFunc)
		if err != nil || !parsed.Valid {
			return nil, errors.New("invalid_token: signature verification failed")
		}

		// Extract subject
		extSub, _ := claims["sub"].(string)
		subject = trusted.Name + "|" + extSub
		
		// External tokens might use 'scope' (string) instead of 'scopes' (array)
		if scopeStr, ok := claims["scope"].(string); ok {
			grantedScopes = strings.Fields(scopeStr)
		}
	}

	// 4. Downscope / Intersection logic (server -> client -> original token)
	// server-level
	serverScopesSet := make(map[string]bool, len(s.cfg.Oidc.SupportedScopes))
	for _, sc := range s.cfg.Oidc.SupportedScopes {
		serverScopesSet[sc] = true
	}
	// client-level
	allowedMap := make(map[string]bool, len(client.AllowedScopes))
	for _, sc := range client.AllowedScopes {
		if serverScopesSet[sc] {
			allowedMap[sc] = true
		}
	}
	// original token scopes
	grantedMap := make(map[string]bool, len(grantedScopes))
	for _, sc := range grantedScopes {
		grantedMap[sc] = true
	}

	var finalScopes []string
	if len(requestedScopes) > 0 {
		// requested must exist in server + client + original token
		for _, sc := range requestedScopes {
			if serverScopesSet[sc] && allowedMap[sc] && grantedMap[sc] {
				finalScopes = append(finalScopes, sc)
			}
		}
	} else {
		// default: intersection of original token ∩ client allowed ∩ server
		for sc := range grantedMap {
			if allowedMap[sc] {
				finalScopes = append(finalScopes, sc)
			}
		}
	}

	// 5. Generate New Token
	alg := client.IDTokenSignedResponseAlg
	if alg == "" {
		alg = "RS256"
	}
	keyMgr, err := s.keyService.GetActiveKeyManager(ctx, alg)
	if err != nil {
		return nil, errors.New("internal_server_error_keys")
	}
	
	signingMethod := s.getSigningMethod(alg)

	now := time.Now()
	newClaims := jwt.MapClaims{
		"iss":    s.cfg.Issuer,
		"sub":    subject,
		"exp":    now.Add(1 * time.Hour).Unix(),
		"iat":    now.Unix(),
		"scopes": finalScopes,
		"act": map[string]string{
			"sub": clientID, // Token Exchange indicates who the actor is
		},
	}
	if audience != "" {
		newClaims["aud"] = audience
	}

	atToken := jwt.NewWithClaims(signingMethod, newClaims)
	atToken.Header["kid"] = keyMgr.KeyID

	accessToken, err := atToken.SignedString(keyMgr.PrivateKey)
	if err != nil {
		return nil, err
	}

	// 6. Return response according to RFC 8693
	return map[string]interface{}{
		"access_token": accessToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(finalScopes, " "),
	}, nil
}

func (s *OAuthService) getSigningMethod(alg string) jwt.SigningMethod {
	switch alg {
	case "ES256":
		return jwt.SigningMethodES256
	case "EdDSA":
		return jwt.SigningMethodEdDSA
	case "RS256":
		return jwt.SigningMethodRS256
	default:
		return jwt.SigningMethodRS256
	}
}

// deriveSub returns pairwise or public subject identifier based on client config.
// Pairwise: HMAC-SHA256(salt, clientID+"|"+userID) → base64url
// Public:   raw userID
func (s *OAuthService) deriveSub(client *models.Client, userID string) string {
	if client == nil || client.SubjectType != "pairwise" {
		return userID
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.PairwiseSalt))
	mac.Write([]byte(client.ClientID + "|" + userID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// validateClientAuth enforces the registered token_endpoint_auth_method for a client.
// usedMethod: how credentials were actually sent ("client_secret_basic", "client_secret_post", "none")
func (s *OAuthService) validateClientAuth(client *models.Client, usedMethod, secret string) error {
	expected := client.TokenEndpointAuthMethod
	if expected == "" {
		// Legacy fallback: infer from client type
		if client.ClientType == "confidential" {
			expected = usedMethod // accept whatever method was used
			if expected == "none" || expected == "" {
				expected = "client_secret_post" // require some secret
			}
		} else {
			expected = "none"
		}
	}

	switch expected {
	case "none":
		// Public client — no secret required or accepted
		if secret != "" {
			return errors.New("invalid_client: this client does not accept credentials")
		}
		return nil
	case "client_secret_basic", "client_secret_post":
		if client.ClientType != "confidential" {
			return errors.New("invalid_client: public clients cannot use secret-based auth")
		}
		if secret == "" {
			return errors.New("invalid_client: client_secret is required")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(secret)); err != nil {
			return errors.New("invalid_client: secret mismatch")
		}
		// Enforce the registered method if it was explicitly set and method is known
		if usedMethod != "" && usedMethod != expected {
			return errors.New("invalid_client: wrong auth method, expected " + expected)
		}
		return nil
	default:
		return errors.New("invalid_client: unsupported auth method")
	}
}
