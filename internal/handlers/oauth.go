package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/internal/core/ports"
	"github.com/sing3demons/oauth_server/internal/core/services"
	"github.com/sing3demons/oauth_server/pkg/errors"
	"github.com/sing3demons/oauth_server/pkg/kp"
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

func (h *OAuthHandler) Authorize(ctx *kp.Ctx) {
	query := ctx.Req.URL.Query()
	sid := query.Get("sid")
	tid := query.Get("tid")
	errMsg := query.Get("error")

	// ดึง sid จาก Cookie ถ้าหาไม่เจอใน URL
	if sid == "" {
		if cookie, err := ctx.Req.Cookie("oidc_session"); err == nil {
			sid = cookie.Value
		}
	}

	if sid == "" {
		sid = uuid.New().String()
	}
	if tid == "" {
		tid = uuid.New().String()
	}

	requestLog := ctx.Log("authorize")
	requestLog.Update("SessionId", sid)
	requestLog.Update("TransactionId", tid)

	// 1. ถ้าไม่มี tid แสดงว่าเป็นการเริ่ม OAuth Flow ใหม่
	if query.Get("tid") == "" {
		responseType := query.Get("response_type")
		if responseType != "code" {
			// http.Error(w, "Unsupported response_type. Expected 'code'", http.StatusBadRequest)
			ctx.JsonError(&errors.Error{
				Err:           fmt.Errorf("unsupported response_type: %s", responseType),
				Message:       fmt.Sprintf("Unsupported response_type: %s. Expected 'code'", responseType),
				AppResultCode: "40000",
			}, map[string]string{"error": "unsupported_response_type"})
			return
		}

		tx := &models.AuthTransaction{
			ClientID:            query.Get("client_id"),
			RedirectURI:         query.Get("redirect_uri"),
			Scopes:              strings.Split(query.Get("scope"), " "),
			State:               query.Get("state"),
			Nonce:               query.Get("nonce"),
			CodeChallenge:       query.Get("code_challenge"),
			CodeChallengeMethod: query.Get("code_challenge_method"),
			ExpiresAt:           time.Now().Add(15 * time.Minute),
		}

		if err := h.transactionCache.SetTransaction(ctx, tid, tx, 15*time.Minute); err != nil {
			// http.Error(w, "Server Error", http.StatusInternalServerError)
			ctx.JsonError(&errors.Error{
				Err:           err,
				Message:       "Failed to set transaction",
				AppResultCode: "50000",
			}, map[string]string{"error": "system_error"})
			return
		}
	} else {
		// 2. ถ้ามี tid อยู่แล้ว เช็คว่าความจำนี้หมดอายุหรือยัง
		_, err := h.transactionCache.GetTransaction(ctx, tid)
		if err != nil {
			ctx.JsonError(&errors.Error{
				Err:           err,
				Message:       "Session or Transaction expired. Please return to your app and try again.",
				AppResultCode: "40000",
			}, map[string]string{"error": "transaction_expired"})
			return
		}
	}

	// 2.5 ตรวจสอบว่ามี sid อยู่ในระบบ (Log in ค้างไว้) หรือไม่
	session, _ := h.sessionCache.GetSession(ctx, sid)
	if session != nil {
		// ถ้าเคย Login แล้ว พาไปหน้า Consent ทันที
		// http.Redirect(w, r, "/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		ctx.Redirect("/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		return
	}

	// 3. Render Unified Auth Page
	data := struct {
		SID   string
		TID   string
		Error string
	}{
		SID:   sid,
		TID:   tid,
		Error: errMsg,
	}

	ctx.RenderTemplate("templates/auth.html", data)
}

func (h *OAuthHandler) LoginSubmit(ctx *kp.Ctx) {
	ctx.Log("login")

	sid := ctx.Req.URL.Query().Get("sid")
	tid := ctx.Req.URL.Query().Get("tid")

	if sid == "" || tid == "" {
		// http.Error(w, "Missing session or transaction ID", http.StatusBadRequest)
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("missing session or transaction ID"),
			Message:       "Missing session or transaction ID",
			AppResultCode: "40000",
		}, map[string]string{"error": "missing_session_or_transaction_id"})
		return
	}

	username := ctx.Req.FormValue("username")
	password := ctx.Req.FormValue("password")

	user, err := h.userRepo.FindByUsername(ctx, username)
	if err != nil || user == nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Invalid+credentials", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Invalid+credentials", http.StatusFound)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Invalid+credentials", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Invalid+credentials", http.StatusFound)
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
		MaxAge:   86400,
	})

	// http.Redirect(w, r, "/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
	ctx.Redirect("/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
}

func (h *OAuthHandler) RegisterSubmit(ctx *kp.Ctx) {
	ctx.Log("register")

	sid := ctx.Req.URL.Query().Get("sid")
	tid := ctx.Req.URL.Query().Get("tid")

	if sid == "" || tid == "" {
		// http.Error(w, "Missing session or transaction ID", http.StatusBadRequest)
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("missing session or transaction ID"),
			Message:       "Missing session or transaction ID",
			AppResultCode: "40000",
		}, map[string]string{"error": "missing_session_or_transaction_id"})

		return
	}

	username := ctx.Req.FormValue("username")
	password := ctx.Req.FormValue("password")
	email := ctx.Req.FormValue("email")

	existing, _ := h.userRepo.FindByUsername(ctx, username)
	if existing != nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Username+already+taken#register", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Username+already+taken#register", http.StatusFound)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Server+Error#register", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Server+Error#register", http.StatusFound)
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
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Database+Error#register", http.StatusFound)
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
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("Transaction expired"),
			Message:       "Transaction expired",
			AppResultCode: "40000",
		}, map[string]string{"error": "transaction_expired"})
		return
	}

	// 3. ปล่อย AuthCode ตามระบบ OAuth2
	code, err := h.oauthService.GenerateAuthCode(ctx.Context(), tx.ClientID, userID, tx.RedirectURI, tx.Nonce, tx.Scopes, tx.CodeChallenge, tx.CodeChallengeMethod)
	if err != nil {
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("Failed to authorize: %s", err.Error()),
			Message:       "Failed to authorize",
			AppResultCode: "50000",
		}, map[string]string{"error": "failed_to_authorize"})
		return
	}

	// 4. ลบ Transaction ทิ้งเมื่อใช้งานเสร็จ
	h.transactionCache.DeleteTransaction(ctx.Context(), tid)

	// 5. บินกลับไปเวป Client หรือส่ง JSON ถ่าไม่มี Redirect URI
	if tx.RedirectURI == "" {
		// w.Header().Set("Content-Type", "application/json")
		// json.NewEncoder(w).Encode(map[string]string{
		// 	"code":  code,
		// 	"state": tx.State,
		// })
		ctx.Json(http.StatusOK, map[string]string{
			"code":  code,
			"state": tx.State,
		})
		return
	}

	redirectURL, err := url.Parse(tx.RedirectURI)
	if err != nil {
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("Invalid redirect_uri"),
			Message:       "Invalid redirect_uri",
			AppResultCode: "40002",
		}, map[string]string{"error": "invalid_redirect_uri"})
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
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("Missing session or transaction"),
			Message:       "Missing session or transaction",
			AppResultCode: "40000",
		}, map[string]string{"error": "missing_session_or_transaction"})
		return
	}

	session, err := h.sessionCache.GetSession(ctx, sid)
	if err != nil || session == nil {
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		return
	}

	tx, err := h.transactionCache.GetTransaction(ctx, tid)
	if err != nil || tx == nil {
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("Transaction expired"),
			Message:       "Transaction expired",
			AppResultCode: "40001",
		}, map[string]string{"error": "transaction_expired"})
		return
	}

	client, err := h.clientRepo.FindByID(ctx, tx.ClientID)
	if err != nil || client == nil {
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("Invalid Client"),
			Message:       "Invalid Client",
			AppResultCode: "40002",
		}, map[string]string{"error": "invalid_client"})
		return
	}

	data := struct {
		SID        string
		TID        string
		ClientName string
		Scopes     []string
	}{
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
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("Missing session or transaction ID"),
			Message:       "Missing session or transaction ID",
			AppResultCode: "40000",
		}, map[string]string{"error": "missing_session_or_transaction_id"})
		return
	}

	session, err := h.sessionCache.GetSession(ctx, sid)
	if err != nil || session == nil {
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		return
	}

	tx, err := h.transactionCache.GetTransaction(ctx, tid)
	if err != nil || tx == nil {
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("Transaction expired"),
			Message:       "Transaction expired",
			AppResultCode: "40001",
		}, map[string]string{"error": "transaction_expired"})
		return
	}

	if action == "deny" {
		h.transactionCache.DeleteTransaction(ctx, tid)
		if tx.RedirectURI == "" {
			// w.Header().Set("Content-Type", "application/json")
			// json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
			// ctx.Json(http.StatusUnauthorized, map[string]string{"error": "access_denied"})
			ctx.JsonError(&errors.Error{
				Err:           fmt.Errorf("access denied by user"),
				Message:       "Access denied by user",
				AppResultCode: "40101",
			}, map[string]string{"error": "access_denied"})
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
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("Invalid form data: %s", err.Error()),
			Message:       "Invalid form data",
			AppResultCode: "40000",
		}, map[string]string{"error": "invalid_form_data"})
		return
	}

	grantType := ctx.Req.FormValue("grant_type")
	if grantType != "authorization_code" && grantType != "refresh_token" {
		ctx.Log("token")
		ctx.JsonError(&errors.Error{
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

	var response map[string]interface{}
	var err error

	switch grantType {
	case "authorization_code":
		redirectURI := ctx.Req.FormValue("redirect_uri")
		codeVerifier := ctx.Req.FormValue("code_verifier")
		response, err = h.oauthService.ExchangeToken(ctx, code, clientID, clientSecret, redirectURI, codeVerifier)
	case "refresh_token":
		refreshToken := ctx.Req.FormValue("refresh_token")
		response, err = h.oauthService.RefreshToken(ctx, refreshToken, clientID, clientSecret)
	}

	if err != nil {
		// w.Header().Set("Content-Type", "application/json")
		// w.WriteHeader(http.StatusBadRequest)
		// json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		ctx.JsonError(&errors.Error{
			Err:           err,
			Message:       "Failed to exchange token: " + err.Error(),
			AppResultCode: "40001",
		}, map[string]string{"error": err.Error()})
		return
	}

	ctx.Json(http.StatusOK, response)
}

// UserInfo (GET /userinfo) เปิดรับให้ Web/Mobile ตรวจข้อมูลส่วนตัว
func (h *OAuthHandler) UserInfo(ctx *kp.Ctx) {
	authHeader := ctx.Req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		ctx.JsonError(&errors.Error{
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
		ctx.JsonError(&errors.Error{
			Err:           err,
			Message:       "Invalid token: " + err.Error(),
			AppResultCode: "40100",
		}, map[string]string{"error": "invalid_token"})
		return
	}

	// 2. ควัก ID ผู้ใช้จาก 'sub'
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("Invalid token claims"),
			Message:       "Invalid token claims",
			AppResultCode: "40101",
		}, map[string]string{"error": "invalid_token"})
		return
	}

	// 3. ดึงข้อมูล User จาก DB
	user, err := h.userRepo.FindByID(ctx, sub)
	if err != nil || user == nil {
		ctx.JsonError(&errors.Error{
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
		ctx.JsonError(&errors.Error{
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
		ctx.JsonError(&errors.Error{
			Err:           fmt.Errorf("missing token or client ID"),
			Message:       "Missing token or client ID",
			AppResultCode: "40000",
		}, map[string]string{"error": "missing_token_or_client"})
		return
	}

	err := h.oauthService.RevokeToken(ctx, token, clientID, clientSecret)
	if err != nil {
		ctx.JsonError(&errors.Error{
			Err:           err,
			Message:       "Failed to revoke token",
			AppResultCode: "40001",
		}, map[string]string{"error": "invalid_request"})
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
		ctx.JsonError(&errors.Error{
			Err:           err,
			Message:       "Invalid request",
			AppResultCode: "40000",
		}, map[string]string{"error": "invalid_request"})
		return
	}

	token := ctx.Req.FormValue("token")
	if token == "" {
		// http.Error(w, "missing_token", http.StatusBadRequest)
		ctx.JsonError(&errors.Error{
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
