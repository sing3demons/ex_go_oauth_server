package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
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
}

func NewOAuthHandler(oauthService *services.OAuthService, userRepo ports.UserRepository, clientRepo ports.ClientRepository, sessionCache ports.SessionCache, transactionCache ports.TransactionCache) *OAuthHandler {
	return &OAuthHandler{
		oauthService:     oauthService,
		userRepo:         userRepo,
		clientRepo:       clientRepo,
		sessionCache:     sessionCache,
		transactionCache: transactionCache,
	}
}

type ResponseMessageError struct {
	Message string `json:"error"`
}

func (h *OAuthHandler) insertTransaction(ctx *kp.Ctx, query url.Values, tid string) (response.MessageError, *pkgErrors.Error) {
	responseError := &ResponseMessageError{}

	responseType := query.Get("response_type")
	if responseType != "code" {
		// http.Error(w, "Unsupported response_type. Expected 'code'", http.StatusBadRequest)
		responseError.Message = "unsupported_response_type"
		return response.UnsupportedResponseType, &pkgErrors.Error{
			Err:           fmt.Errorf("unsupported response_type: %s", responseType),
			Message:       fmt.Sprintf("Unsupported response_type: %s. Expected 'code'", responseType),
			AppResultCode: response.UnsupportedResponseType.ResultCode(),
		}
	}

	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	// Validate client exists and redirect_uri is registered
	client, err := h.clientRepo.FindByID(ctx, clientID)
	if err != nil || client == nil {
		responseError.Message = "invalid_client"
		return response.InvalidClient, &pkgErrors.Error{
			Err:           fmt.Errorf("client not found: %s", clientID),
			Message:       "Invalid client_id",
			AppResultCode: response.InvalidClient.ResultCode(),
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
		responseError.Message = "invalid_redirect_uri"
		return response.InvalidGrant, &pkgErrors.Error{
			Err:           fmt.Errorf("redirect_uri not registered: %s", redirectURI),
			Message:       "redirect_uri is not registered for this client",
			AppResultCode: response.InvalidGrant.ResultCode(),
		}
	}

	tx := &models.AuthTransaction{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              strings.Split(query.Get("scope"), " "),
		State:               query.Get("state"),
		Nonce:               query.Get("nonce"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		ExpiresAt:           time.Now().Add(15 * time.Minute),
	}

	if err := h.transactionCache.SetTransaction(ctx, tid, tx, 15*time.Minute); err != nil {
		// http.Error(w, "Server Error", http.StatusInternalServerError)
		responseError.Message = "system_error"
		return response.SystemError, &pkgErrors.Error{
			Err:           err,
			Message:       "Failed to set transaction",
			AppResultCode: response.SystemError.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("missing required parameters"),
			Message:       "client_id and redirect_uri are required",
			AppResultCode: "40000",
		}, map[string]string{"error": "invalid_request"})
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
				ctx.JsonError(&pkgErrors.Error{
					Err:           err,
					Message:       "Session or Transaction expired. Please return to your app and try again.",
					AppResultCode: response.InvalidGrant.ResultCode(),
				},
					map[string]string{"error": "transaction_expired"})
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("missing session or transaction ID"),
			Message:       "Missing session or transaction ID",
			AppResultCode: response.MissingOrInvalidParameter.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("missing session or transaction ID"),
			Message:       "Missing session or transaction ID",
			AppResultCode: response.MissingOrInvalidParameter.ResultCode(),
		}, response.MissingOrInvalidParameter.Error())

		return
	}

	username := ctx.Req.FormValue("username")
	password := ctx.Req.FormValue("password")
	email := ctx.Req.FormValue("email")

	// validate input
	if username == "" || password == "" || email == "" {
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("missing required fields"),
			Message:       "Missing required fields",
			AppResultCode: "40000",
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	if len(password) < 6 {
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("password too short"),
			Message:       "Password must be at least 6 characters",
			AppResultCode: response.MissingOrInvalidParameter.ResultCode(),
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	if !strings.Contains(email, "@") {
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("invalid email format"),
			Message:       "Invalid email format",
			AppResultCode: response.MissingOrInvalidParameter.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Transaction expired"),
			Message:       "Transaction expired",
			AppResultCode: response.InvalidRequest.ResultCode(),
		}, response.InvalidRequest.Error())
		return
	}

	// 3. ปล่อย AuthCode ตามระบบ OAuth2
	code, err := h.oauthService.GenerateAuthCode(ctx.Context(), tx.ClientID, userID, tx.RedirectURI, tx.Nonce, tx.Scopes, tx.CodeChallenge, tx.CodeChallengeMethod)
	if err != nil {
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Failed to authorize: %s", err.Error()),
			Message:       "Failed to authorize",
			AppResultCode: response.ServerError.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Invalid redirect_uri"),
			Message:       "Invalid redirect_uri",
			AppResultCode: response.InvalidGrant.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Missing session or transaction"),
			Message:       "Missing session or transaction",
			AppResultCode: response.MissingOrInvalidParameter.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Transaction expired"),
			Message:       "Transaction expired",
			AppResultCode: response.InvalidRequest.ResultCode(),
		}, response.InvalidRequest.Error())
		return
	}

	client, err := h.clientRepo.FindByID(ctx, tx.ClientID)
	if err != nil || client == nil {
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Invalid Client"),
			Message:       "Invalid Client",
			AppResultCode: response.InvalidClient.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Missing session or transaction ID"),
			Message:       "Missing session or transaction ID",
			AppResultCode: response.MissingOrInvalidParameter.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Transaction expired"),
			Message:       "Transaction expired",
			AppResultCode: response.InvalidRequest.ResultCode(),
		}, response.InvalidRequest.Error())
		return
	}

	if action == "deny" {
		h.transactionCache.DeleteTransaction(ctx, tid)
		if tx.RedirectURI == "" {
			// w.Header().Set("Content-Type", "application/json")
			// json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
			// ctx.Json(http.StatusUnauthorized, map[string]string{"error": "access_denied"})
			ctx.JsonError(&pkgErrors.Error{
				Err:           fmt.Errorf("access denied by user"),
				Message:       "Access denied by user",
				AppResultCode: response.AccessDenied.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Invalid form data: %s", err.Error()),
			Message:       "Invalid form data",
			AppResultCode: "40000",
		}, map[string]string{"error": "invalid_form_data"})
		return
	}

	grantType := ctx.Req.FormValue("grant_type")
	if grantType != "authorization_code" && grantType != "refresh_token" {
		ctx.Log("token")
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Unsupported grant type: %s", grantType),
			Message:       "Unsupported grant type",
			AppResultCode: "40003",
		}, map[string]string{"error": "unsupported_grant_type"})
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
	}

	if err != nil {
		// w.Header().Set("Content-Type", "application/json")
		// w.WriteHeader(http.StatusBadRequest)
		// json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		ctx.JsonError(&pkgErrors.Error{
			Err:           err,
			Message:       "Failed to exchange token: " + err.Error(),
			AppResultCode: response.InvalidRequest.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Missing or invalid Bearer token"),
			Message:       "Missing or invalid Bearer token",
			AppResultCode: "40100",
		}, map[string]string{"error": "invalid_token"})
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// 1. ตรวจสอบความถูกต้องของ JWT
	claims, err := h.oauthService.ValidateAccessToken(ctx, tokenStr)
	if err != nil {
		// http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		ctx.JsonError(&pkgErrors.Error{
			Err:           err,
			Message:       "Invalid token: " + err.Error(),
			AppResultCode: "40100",
		}, map[string]string{"error": "invalid_token"})
		return
	}

	// 2. ควัก ID ผู้ใช้จาก 'sub'
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("Invalid token claims"),
			Message:       "Invalid token claims",
			AppResultCode: "40101",
		}, map[string]string{"error": "invalid_token"})
		return
	}

	// 3. ดึงข้อมูล User จาก DB
	user, err := h.userRepo.FindByID(ctx, sub)
	if err != nil || user == nil {
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("User not found"),
			Message:       "User not found",
			AppResultCode: "40401",
		}, map[string]string{"error": "user_not_found"})
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           err,
			Message:       "Invalid request",
			AppResultCode: "40000",
		}, map[string]string{"error": "invalid_request"})
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("missing token or client ID"),
			Message:       "Missing token or client ID",
			AppResultCode: response.InvalidRequest.ResultCode(),
		}, response.InvalidRequest.Error())
		return
	}

	err := h.oauthService.RevokeToken(ctx, token, clientID, clientSecret)
	if err != nil {
		ctx.JsonError(&pkgErrors.Error{
			Err:           err,
			Message:       "Failed to revoke token",
			AppResultCode: response.InvalidRequest.ResultCode(),
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
		ctx.JsonError(&pkgErrors.Error{
			Err:           err,
			Message:       "Invalid request",
			AppResultCode: "40000",
		}, map[string]string{"error": "invalid_request"})
		return
	}

	token := ctx.Req.FormValue("token")
	if token == "" {
		// http.Error(w, "missing_token", http.StatusBadRequest)
		ctx.JsonError(&pkgErrors.Error{
			Err:           fmt.Errorf("missing token"),
			Message:       "Missing token",
			AppResultCode: "40000",
		}, map[string]string{"error": "missing_token"})
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
