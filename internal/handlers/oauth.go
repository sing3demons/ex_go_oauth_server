package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/internal/core/ports"
	"github.com/sing3demons/oauth_server/internal/core/services"
	pkgErrors "github.com/sing3demons/oauth_server/pkg/errors"
	"github.com/sing3demons/oauth_server/pkg/kp"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/response"
	"github.com/sing3demons/oauth_server/pkg/utils"
	"golang.org/x/crypto/bcrypt"
)

type OAuthHandler struct {
	oauthService     *services.OAuthService
	userRepo         ports.UserRepository
	clientRepo       ports.ClientRepository
	sessionCache     ports.SessionCache
	transactionCache ports.TransactionCache
	cfg              *config.Config
}

func NewOAuthHandler(oauthService *services.OAuthService, userRepo ports.UserRepository, clientRepo ports.ClientRepository, sessionCache ports.SessionCache, transactionCache ports.TransactionCache, cfg *config.Config) *OAuthHandler {
	return &OAuthHandler{
		oauthService:     oauthService,
		userRepo:         userRepo,
		clientRepo:       clientRepo,
		sessionCache:     sessionCache,
		transactionCache: transactionCache,
		cfg:              cfg,
	}
}

func (h *OAuthHandler) insertTransaction(ctx *kp.Ctx, query url.Values, tid string) (response.MessageError, *response.Error) {
	responseType := query.Get("response_type")
	// Validate response_type against server's supported list from config
	responseTypeAllowed := false
	for _, rt := range h.cfg.Oidc.SupportedResponseTypes {
		if rt == responseType {
			responseTypeAllowed = true
			break
		}
	}
	if !responseTypeAllowed {
		return response.UnsupportedResponseType, &response.Error{
			Err:     fmt.Errorf("unsupported response_type: %s", responseType),
			Message: response.UnsupportedResponseType,
		}
	}

	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	// Validate client exists and redirect_uri is registered
	client, err := h.clientRepo.FindByIDWithCache(ctx, clientID)
	if err != nil || client == nil {
		return response.InvalidClient, &response.Error{
			Err:     fmt.Errorf("client not found: %s", clientID),
			Message: response.InvalidClient,
		}
	}

	validURI := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validURI = true
			break
		}
	}
	if !validURI {
		return response.InvalidGrant, &response.Error{
			Err:     fmt.Errorf("redirect_uri not registered: %s", redirectURI),
			Message: response.InvalidGrant,
		}
	}

	// Scope Validation
	requestedScopes := strings.Fields(query.Get("scope"))

	// 1. openid scope บังคับใน OIDC (RFC)
	hasOpenID := false
	for _, s := range requestedScopes {
		if s == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return response.InvalidScope, &response.Error{
			Err:     fmt.Errorf("scope 'openid' is required"),
			Message: "scope 'openid' is required for OIDC requests",
		}
	}

	// 2. กรอง scope ที่ server รองรับก่อน (server-level)
	serverScopesSet := make(map[string]struct{}, len(h.cfg.Oidc.SupportedScopes))
	for _, s := range h.cfg.Oidc.SupportedScopes {
		serverScopesSet[s] = struct{}{}
	}
	var serverFilteredScopes []string
	for _, s := range requestedScopes {
		if _, ok := serverScopesSet[s]; ok {
			serverFilteredScopes = append(serverFilteredScopes, s)
		}
	}
	requestedScopes = serverFilteredScopes

	// 3. ตรวจว่า Client อนุญาต Scopes ที่ขอไหม (client-level)
	allowedSet := make(map[string]struct{}, len(client.AllowedScopes))
	for _, s := range client.AllowedScopes {
		allowedSet[s] = struct{}{}
	}
	for _, s := range requestedScopes {
		if _, ok := allowedSet[s]; !ok {
			return response.InvalidScope, &response.Error{
				Err:     fmt.Errorf("scope '%s' is not allowed for this client", s),
				Message: response.InvalidScope,
			}
		}
	}

	tx := &models.AuthTransaction{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              requestedScopes,
		State:               query.Get("state"),
		Nonce:               query.Get("nonce"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		ExpiresAt:           time.Now().Add(15 * time.Minute),
	}

	if err := h.transactionCache.SetTransaction(ctx, tid, tx, 15*time.Minute); err != nil {
		return response.SystemError, &response.Error{
			Err:     err,
			Message: response.SystemError,
		}
	}
	return response.Success, nil
}

func (h *OAuthHandler) Authorize(ctx *kp.Ctx) {
	ctx.Log("authorize")

	query := ctx.Req.URL.Query()
	sid := ctx.SessionId() // cookie override จัดการใน ensureRequestMetadata แล้ว
	tid := ctx.TransactionId()
	errMsg := query.Get("error")

	if query.Get("client_id") == "" || query.Get("redirect_uri") == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing required parameters"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	queryTid := query.Get("tid")
	// 1. ถ้าไม่มี tid แสดงว่าเป็นการเริ่ม OAuth Flow ใหม่
	if queryTid == "" {
		body, err := h.insertTransaction(ctx, query, tid)
		if err != nil {
			ctx.JsonError(err, body.Error())
			return
		}
	} else {
		// 2. ถ้ามี tid อยู่แล้ว เช็คว่าความจำนี้หมดอายุหรือยัง
		_, err := h.transactionCache.GetTransaction(ctx, tid)
		if err != nil {
			if errors.Is(err, pkgErrors.ErrNotFound) {
				body, err := h.insertTransaction(ctx, query, tid)
				if err != nil {
					ctx.JsonError(err, body.Error())
					return
				}
			} else {
				ctx.JsonError(&response.Error{
					Err:     err,
					Message: "Session or Transaction expired. Please return to your app and try again.",
				}, map[string]string{"error": "transaction_expired"})
				return
			}
		}
	}

	// 2.5 ตรวจสอบว่ามี sid อยู่ในระบบ (Log in ค้างไว้) หรือไม่
	session, _ := h.sessionCache.GetSession(ctx, sid)
	if session != nil {
		// ถ้าเคย Login แล้ว พาไปหน้า Consent ทันที
		ctx.Redirect("/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		return
	}

	// 3. Render Unified Auth Page
	type AuthPageData struct {
		SID   string
		TID   string
		Error string
	}
	data := AuthPageData{
		SID:   sid,
		TID:   tid,
		Error: errMsg,
	}

	ctx.RenderTemplate("templates/auth.html", data)
}

func (h *OAuthHandler) LoginSubmit(ctx *kp.Ctx) {
	ctx.Log("login", logger.MaskingOption{
		MaskingField: "body.password",
		MaskingType:  logger.MaskCustom,
		Callback:     utils.MaskPassword,
	}, logger.MaskingOption{
		MaskingField: "body.username",
		MaskingType:  logger.MaskCustom,
		Callback:     utils.MaskUsernameOrEmail,
	})

	sid := ctx.Req.URL.Query().Get("sid")
	tid := ctx.Req.URL.Query().Get("tid")

	if sid == "" || tid == "" {
		// http.Error(w, "Missing session or transaction ID", http.StatusBadRequest)
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing session or transaction ID"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	username := ctx.Req.FormValue("username")
	password := ctx.Req.FormValue("password")

	user, err := h.userRepo.FindByUsername(ctx, username)
	if err != nil || user == nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Invalid+credentials", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=invalid_credentials", http.StatusFound)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Invalid+credentials", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=invalid_credentials", http.StatusFound)
		return
	}

	sessionInfo := &models.SessionInfo{
		UserID:     user.ID,
		LoggedInAt: time.Now(),
	}
	h.sessionCache.SetSession(ctx, sid, sessionInfo, 24*time.Hour)

	// ฝัง Cookie เพื่อทำ SSO ทะลุ Flow
	http.SetCookie(ctx.Res, &http.Cookie{
		Name:     "oidc_session",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,                 // ← เพิ่ม: HTTPS only
		SameSite: http.SameSiteLaxMode, // ← เพิ่ม: ป้องกัน CSRF
		MaxAge:   86400,
	})

	// http.Redirect(w, r, "/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
	ctx.Redirect("/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
}

func (h *OAuthHandler) RegisterSubmit(ctx *kp.Ctx) {
	maskRegister := []logger.MaskingOption{
		{
			MaskingField: "body.password",
			MaskingType:  logger.MaskCustom,
			Callback:     utils.MaskPassword,
		}, {
			MaskingField: "body.username",
			MaskingType:  logger.MaskCustom,
			Callback:     utils.MaskUsername,
		}, {
			MaskingField: "body.email",
			MaskingType:  logger.MaskCustom,
			Callback:     utils.MaskEmail,
		},
	}
	ctx.Log("register", maskRegister...)

	sid := ctx.Req.URL.Query().Get("sid")
	tid := ctx.Req.URL.Query().Get("tid")

	if sid == "" || tid == "" {
		// http.Error(w, "Missing session or transaction ID", http.StatusBadRequest)
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing session or transaction ID"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())

		return
	}

	username := ctx.Req.FormValue("username")
	password := ctx.Req.FormValue("password")
	email := ctx.Req.FormValue("email")

	// validate input
	if username == "" || password == "" || email == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing required fields"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	if len(password) < 6 {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("password too short"),
			Message: "Password must be at least 6 characters",
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	if !strings.Contains(email, "@") {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("invalid email format"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	existing, _ := h.userRepo.FindByUsername(ctx, username)
	if existing != nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Username+already+taken#register", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=username_already_taken#register", http.StatusFound)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Server+Error#register", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=server_error#register", http.StatusFound)
		return
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		CreatedAt:    time.Now(),
	}

	if err := h.userRepo.Create(ctx, user); err != nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Database+Error#register", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=database_error#register", http.StatusFound)
		return
	}

	// สร้างสำเร็จ ก็ให้ Login ผ่านต่อเลย
	sessionInfo := &models.SessionInfo{
		UserID:     user.ID,
		LoggedInAt: time.Now(),
	}
	h.sessionCache.SetSession(ctx, sid, sessionInfo, 24*time.Hour)

	// ฝัง Cookie เพื่อทำ SSO ทะลุ Flow
	http.SetCookie(ctx.Res, &http.Cookie{
		Name:     "oidc_session",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
	})

	ctx.Redirect("/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
}

func (h *OAuthHandler) completeAuth(ctx *kp.Ctx, sid, tid, userID string) {

	// 2. ดึง Transaction ก้อนเดิมออกมา
	tx, err := h.transactionCache.GetTransaction(ctx.Context(), tid)
	if err != nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Transaction expired"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// 3. ปล่อย AuthCode ตามระบบ OAuth2
	code, err := h.oauthService.GenerateAuthCode(ctx.Context(), tx.ClientID, userID, tx.RedirectURI, tx.Nonce, tx.Scopes, tx.CodeChallenge, tx.CodeChallengeMethod)
	if err != nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Failed to authorize: %s", err.Error()),
			Message: response.ServerError,
		}, response.ServerError.Error())
		return
	}

	// 4. ลบ Transaction ทิ้งเมื่อใช้งานเสร็จ
	h.transactionCache.DeleteTransaction(ctx.Context(), tid)

	// 5. บินกลับไปเวป Client หรือส่ง JSON ถ่าไม่มี Redirect URI
	if tx.RedirectURI == "" {
		ctx.Json(http.StatusOK, map[string]string{
			"code":  code,
			"state": tx.State,
		})
		return
	}

	redirectURL, err := url.Parse(tx.RedirectURI)
	if err != nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Invalid redirect_uri"),
			Message: response.InvalidGrant,
		}, response.InvalidGrant.Error())
		return
	}

	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", tx.State)
	redirectURL.RawQuery = q.Encode()

	ctx.Redirect(redirectURL.String(), http.StatusFound)
}

func (h *OAuthHandler) ConsentUI(ctx *kp.Ctx) {
	ctx.Log("consent_ui")

	sid := ctx.Req.URL.Query().Get("sid")
	tid := ctx.Req.URL.Query().Get("tid")

	if sid == "" || tid == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Missing session or transaction"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	session, err := h.sessionCache.GetSession(ctx, sid)
	if err != nil || session == nil {
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		return
	}

	tx, err := h.transactionCache.GetTransaction(ctx, tid)
	if err != nil || tx == nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Transaction expired"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	client, err := h.clientRepo.FindByIDWithCache(ctx, tx.ClientID)
	if err != nil || client == nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Invalid Client"),
			Message: response.InvalidClient,
		}, response.InvalidClient.Error())
		return
	}

	type ConsentPageData struct {
		SID        string
		TID        string
		ClientName string
		Scopes     []string
	}

	data := ConsentPageData{
		SID:        sid,
		TID:        tid,
		ClientName: client.ClientName,
		Scopes:     tx.Scopes,
	}

	ctx.RenderTemplate("templates/consent.html", data)
}

func (h *OAuthHandler) ConsentSubmit(ctx *kp.Ctx) {
	ctx.Log("consent_submit")

	sid := ctx.Req.FormValue("sid")
	tid := ctx.Req.FormValue("tid")
	action := ctx.Req.FormValue("action")

	if sid == "" || tid == "" {
		// http.Error(w, "Missing mapping", http.StatusBadRequest)
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Missing session or transaction ID"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	session, err := h.sessionCache.GetSession(ctx, sid)
	if err != nil || session == nil {
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		return
	}

	tx, err := h.transactionCache.GetTransaction(ctx, tid)
	if err != nil || tx == nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Transaction expired"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	if action == "deny" {
		h.transactionCache.DeleteTransaction(ctx, tid)
		if tx.RedirectURI == "" {
			// w.Header().Set("Content-Type", "application/json")
			// json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
			// ctx.Json(http.StatusUnauthorized, map[string]string{"error": "access_denied"})
			ctx.JsonError(&response.Error{
				Err:     fmt.Errorf("access denied by user"),
				Message: response.AccessDenied,
			}, response.AccessDenied.Error())
			return
		}

		redirectURL, _ := url.Parse(tx.RedirectURI)
		q := redirectURL.Query()
		q.Set("error", "access_denied")
		if tx.State != "" {
			q.Set("state", tx.State)
		}
		redirectURL.RawQuery = q.Encode()
		ctx.Redirect(redirectURL.String(), http.StatusFound)
		return
	}

	// ถ้ากด Allow อนุญาตให้ดำเนินการสร้าง Authorization Code
	h.completeAuth(ctx, sid, tid, session.UserID)
}

// Token (POST /token) เปิดรับให้ Backend เอารหัสมาแลกเป็นตัว JWT
func (h *OAuthHandler) Token(ctx *kp.Ctx) {

	if err := ctx.Req.ParseForm(); err != nil {
		ctx.Log("token")
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Invalid form data: %s", err.Error()),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	grantType := ctx.Req.FormValue("grant_type")

	// Validate grant_type against server-supported list from config
	supportedGrants := h.cfg.Oidc.SupportedGrantTypes
	grantAllowed := false
	for _, g := range supportedGrants {
		if g == grantType {
			grantAllowed = true
			break
		}
	}
	if !grantAllowed {
		ctx.Log("token")
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Unsupported grant type: %s", grantType),
			Message: response.UnsupportedResponseType,
		}, response.UnsupportedResponseType.Error())
		return
	}

	ctx.Log("token_" + grantType)

	code := ctx.Req.FormValue("code")
	clientID := ctx.Req.FormValue("client_id")
	clientSecret := ctx.Req.FormValue("client_secret")

	// Postman บางทีส่ง client_id มาใน Body แต่ส่ง Secret ไปใน Basic Auth
	basicID, basicSecret, ok := ctx.Req.BasicAuth()
	if ok {
		if clientID == "" {
			clientID = basicID
		}
		if clientSecret == "" {
			clientSecret = basicSecret
		}
	}

	var resp map[string]interface{}
	var err error

	switch grantType {
	case "authorization_code":
		redirectURI := ctx.Req.FormValue("redirect_uri")
		codeVerifier := ctx.Req.FormValue("code_verifier")
		resp, err = h.oauthService.ExchangeToken(ctx, code, clientID, clientSecret, redirectURI, codeVerifier)
	case "refresh_token":
		refreshToken := ctx.Req.FormValue("refresh_token")
		resp, err = h.oauthService.RefreshToken(ctx, refreshToken, clientID, clientSecret)
	case "client_credentials":
		scopes := strings.Fields(ctx.Req.FormValue("scope"))
		resp, err = h.oauthService.ClientCredentials(ctx, clientID, clientSecret, scopes)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		subjectToken := ctx.Req.FormValue("subject_token")
		subjectTokenType := ctx.Req.FormValue("subject_token_type")
		audience := ctx.Req.FormValue("audience")
		scopes := strings.Fields(ctx.Req.FormValue("scope"))
		resp, err = h.oauthService.TokenExchange(ctx, subjectToken, subjectTokenType, clientID, clientSecret, scopes, audience)
	}

	if err != nil {
		// w.Header().Set("Content-Type", "application/json")
		// w.WriteHeader(http.StatusBadRequest)
		// json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	ctx.Json(http.StatusOK, resp)
}

// UserInfo (GET /userinfo) เปิดรับให้ Web/Mobile ตรวจข้อมูลส่วนตัว
func (h *OAuthHandler) UserInfo(ctx *kp.Ctx) {
	ctx.Log("userinfo")
	authHeader := ctx.Req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Missing or invalid Bearer token"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// 1. ตรวจสอบความถูกต้องของ JWT
	claims, err := h.oauthService.ValidateAccessToken(ctx, tokenStr)
	if err != nil {
		// http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// 2. ควัก ID ผู้ใช้จาก 'sub'
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Invalid token claims"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// 3. ดึงข้อมูล User จาก DB
	user, err := h.userRepo.FindByID(ctx, sub)
	if err != nil || user == nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("User not found"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// 4. ประกอบร่าง JSON ตามมาตรฐาน OIDC
	userInfo := map[string]any{
		"sub": user.ID,
	}

	// ตรวจสอบ Scopes ที่พ่วงมากว่าได้รับอนุญาตให้ดูอะไรบ้าง
	if scopesRaw, ok := claims["scopes"].([]any); ok {
		for _, sRaw := range scopesRaw {
			if s, ok := sRaw.(string); ok {
				if s == "profile" {
					userInfo["name"] = user.Username
					userInfo["preferred_username"] = user.Username
				}
				if s == "email" {
					userInfo["email"] = user.Email
					userInfo["email_verified"] = true
				}
			}
		}
	}

	ctx.Json(http.StatusOK, userInfo)
}

// Logout (GET /logout) เปิดรับให้ยุติ Session และลบ Cookie
func (h *OAuthHandler) Logout(ctx *kp.Ctx) {
	ctx.Log("logout")
	redirectURI := ctx.Req.URL.Query().Get("post_logout_redirect_uri")
	if redirectURI == "" {
		redirectURI = "/authorize?error=Logged+out+successfully"
	}

	if _, err := url.ParseRequestURI(redirectURI); err != nil {
		redirectURI = "/authorize?error=Logged+out+successfully"
	}

	if cookie, err := ctx.Req.Cookie("oidc_session"); err == nil {
		sid := cookie.Value
		if sid != "" {
			h.sessionCache.DeleteSession(ctx, sid)
		}
	}

	http.SetCookie(ctx.Res, &http.Cookie{
		Name:     "oidc_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	ctx.Redirect(redirectURI, http.StatusFound)
}

// Revoke (POST /revoke) เคลียร์ Token ตาม RFC 7009
func (h *OAuthHandler) Revoke(ctx *kp.Ctx) {
	ctx.Log("revoke")

	if err := ctx.Req.ParseForm(); err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	token := ctx.Req.FormValue("token")
	clientID := ctx.Req.FormValue("client_id")
	clientSecret := ctx.Req.FormValue("client_secret")

	// รองรับ Basic Auth
	basicID, basicSecret, ok := ctx.Req.BasicAuth()
	if ok {
		if clientID == "" {
			clientID = basicID
		}
		if clientSecret == "" {
			clientSecret = basicSecret
		}
	}

	if token == "" || clientID == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing token or client ID"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	err := h.oauthService.RevokeToken(ctx, token, clientID, clientSecret)
	if err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// w.WriteHeader(http.StatusOK)
	ctx.Json(http.StatusOK, map[string]string{"result": "success"})
}

// Introspect (POST /introspect) ตรวจสอบสถานะของ Token ควบคู่ตาม RFC 7662
func (h *OAuthHandler) Introspect(ctx *kp.Ctx) {
	ctx.Log("introspect")
	if err := ctx.Req.ParseForm(); err != nil {
		// http.Error(w, "Invalid request", http.StatusBadRequest)
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	token := ctx.Req.FormValue("token")
	if token == "" {
		// http.Error(w, "missing_token", http.StatusBadRequest)
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing token"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// รันผ่านระบบ Validate
	claims, err := h.oauthService.ValidateAccessToken(ctx, token)
	if err != nil {
		// RFC กำหนดไว้ว่าถ้า Token ผิด ให้ตอบแค่ active: false
		ctx.Json(http.StatusOK, map[string]bool{"active": false})
		return
	}

	// ถ้าถูกต้อง นำข้อมูลกลับมาแพคตามมาตรฐาน
	resp := map[string]interface{}{
		"active": true,
		"iss":    claims["iss"],
		"sub":    claims["sub"],
		"aud":    claims["aud"],
		"exp":    claims["exp"],
		"iat":    claims["iat"],
	}

	// แปลง Array Scopes กลับเป็นวรรค (Space-separated)
	if scopesRaw, ok := claims["scopes"].([]interface{}); ok {
		var scopes []string
		for _, s := range scopesRaw {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
		resp["scope"] = strings.Join(scopes, " ")
	}

	if clientID, ok := claims["client_id"].(string); ok {
		resp["client_id"] = clientID
	}

	ctx.Json(http.StatusOK, resp)
}
