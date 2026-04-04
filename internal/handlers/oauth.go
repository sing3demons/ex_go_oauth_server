package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/tr_02_oauth/internal/core/models"
	"github.com/sing3demons/tr_02_oauth/internal/core/ports"
	"github.com/sing3demons/tr_02_oauth/internal/core/services"
	"golang.org/x/crypto/bcrypt"
)

type OAuthHandler struct {
	oauthService     *services.OAuthService
	userRepo         ports.UserRepository
	sessionCache     ports.SessionCache
	transactionCache ports.TransactionCache
}

func NewOAuthHandler(oauthService *services.OAuthService, userRepo ports.UserRepository, sessionCache ports.SessionCache, transactionCache ports.TransactionCache) *OAuthHandler {
	return &OAuthHandler{
		oauthService:     oauthService,
		userRepo:         userRepo,
		sessionCache:     sessionCache,
		transactionCache: transactionCache,
	}
}

func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	sid := query.Get("sid")
	tid := query.Get("tid")
	errMsg := query.Get("error")

	// 1. ถ้าไม่มี sid หรือ tid พ่วงมา แปลว่าเป็นคำขอรอบแรกจาก Client App
	if sid == "" || tid == "" {
		responseType := query.Get("response_type")
		if responseType != "code" {
			http.Error(w, "Unsupported response_type. Expected 'code'", http.StatusBadRequest)
			return
		}

		sid = uuid.New().String()
		tid = uuid.New().String()

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

		if err := h.transactionCache.SetTransaction(r.Context(), tid, tx, 15*time.Minute); err != nil {
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		// 2. ถ้ามี tid อยู่แล้ว เช็คว่าความจำนี้หมดอายุหรือยัง
		_, err := h.transactionCache.GetTransaction(r.Context(), tid)
		if err != nil {
			http.Error(w, "Session or Transaction expired. Please return to your app and try again.", http.StatusBadRequest)
			return
		}
	}

	// 3. Render Unified Auth Page 
	tmpl, err := template.ParseFiles("templates/auth.html")
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}

	data := struct {
		SID   string
		TID   string
		Error string
	}{
		SID:   sid,
		TID:   tid,
		Error: errMsg,
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, data)
}

func (h *OAuthHandler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	tid := r.URL.Query().Get("tid")

	if sid == "" || tid == "" {
		http.Error(w, "Missing session or transaction ID", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := h.userRepo.FindByUsername(r.Context(), username)
	if err != nil || user == nil {
		http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Invalid+credentials", http.StatusFound)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Invalid+credentials", http.StatusFound)
		return
	}

	h.completeAuth(w, r, sid, tid, user.ID)
}

func (h *OAuthHandler) RegisterSubmit(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	tid := r.URL.Query().Get("tid")

	if sid == "" || tid == "" {
		http.Error(w, "Missing session or transaction ID", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")

	existing, _ := h.userRepo.FindByUsername(r.Context(), username)
	if existing != nil {
		http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Username+already+taken#register", http.StatusFound)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Server+Error#register", http.StatusFound)
		return
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		CreatedAt:    time.Now(),
	}

	if err := h.userRepo.Create(r.Context(), user); err != nil {
		http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Database+Error#register", http.StatusFound)
		return
	}

	// สร้างสำเร็จ ก็ให้ Login ผ่านต่อเลย
	h.completeAuth(w, r, sid, tid, user.ID)
}

func (h *OAuthHandler) completeAuth(w http.ResponseWriter, r *http.Request, sid, tid, userID string) {
	// 1. ลงทะเบียนว่า SessionID นี้มีคนล็อกอินแล้ว 
	sessionInfo := &models.SessionInfo{
		UserID:     userID,
		LoggedInAt: time.Now(),
	}
	h.sessionCache.SetSession(r.Context(), sid, sessionInfo, 24*time.Hour)

	// 2. ดึง Transaction ก้อนเดิมออกมา
	tx, err := h.transactionCache.GetTransaction(r.Context(), tid)
	if err != nil {
		http.Error(w, "Transaction expired", http.StatusBadRequest)
		return
	}

	// 3. ปล่อย AuthCode ตามระบบ OAuth2
	code, err := h.oauthService.GenerateAuthCode(r.Context(), tx.ClientID, userID, tx.RedirectURI, tx.Nonce, tx.Scopes, tx.CodeChallenge, tx.CodeChallengeMethod)
	if err != nil {
		http.Error(w, "Failed to authorize: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 4. ลบ Transaction ทิ้งเมื่อใช้งานเสร็จ
	h.transactionCache.DeleteTransaction(r.Context(), tid)

	// 5. บินกลับไปเวป Client หรือส่ง JSON ถ่าไม่มี Redirect URI
	if tx.RedirectURI == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"code":  code,
			"state": tx.State,
		})
		return
	}

	redirectURL, err := url.Parse(tx.RedirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", tx.State)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// Token (POST /token) เปิดรับให้ Backend เอารหัสมาแลกเป็นตัว JWT
func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" && grantType != "refresh_token" {
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	if clientID == "" {
		clientID, clientSecret, _ = r.BasicAuth()
	}

	var response map[string]interface{}
	var err error

	if grantType == "authorization_code" {
		redirectURI := r.FormValue("redirect_uri")
		codeVerifier := r.FormValue("code_verifier")
		response, err = h.oauthService.ExchangeToken(r.Context(), code, clientID, clientSecret, redirectURI, codeVerifier)
	} else if grantType == "refresh_token" {
		refreshToken := r.FormValue("refresh_token")
		response, err = h.oauthService.RefreshToken(r.Context(), refreshToken, clientID, clientSecret)
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// UserInfo (GET /userinfo) เปิดรับให้ Web/Mobile ตรวจข้อมูลส่วนตัว
func (h *OAuthHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid Bearer token", http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// 1. ตรวจสอบความถูกต้องของ JWT
	claims, err := h.oauthService.ValidateAccessToken(r.Context(), tokenStr)
	if err != nil {
		http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// 2. ควัก ID ผู้ใช้จาก 'sub'
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// 3. ดึงข้อมูล User จาก DB
	user, err := h.userRepo.FindByID(r.Context(), sub)
	if err != nil || user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 4. ประกอบร่าง JSON ตามมาตรฐาน OIDC
	userInfo := map[string]interface{}{
		"sub": user.ID,
	}

	// ตรวจสอบ Scopes ที่พ่วงมากว่าได้รับอนุญาตให้ดูอะไรบ้าง
	if scopesRaw, ok := claims["scopes"].([]interface{}); ok {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}
