package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/tr_02_oauth/internal/core/models"
	"github.com/sing3demons/tr_02_oauth/internal/core/ports"
	"github.com/sing3demons/tr_02_oauth/internal/core/services"
)

type OAuthHandler struct {
	oauthService *services.OAuthService
	userRepo     ports.UserRepository
	sessionCache ports.SessionCache
}

func NewOAuthHandler(oauthService *services.OAuthService, userRepo ports.UserRepository, sessionCache ports.SessionCache) *OAuthHandler {
	return &OAuthHandler{
		oauthService: oauthService,
		userRepo:     userRepo,
		sessionCache: sessionCache,
	}
}

// Authorize (GET /authorize) จุดเชื่อมต่อแรกสำหรับการล็อคอิน
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	responseType := query.Get("response_type")
	scopeStr := query.Get("scope")
	state := query.Get("state")
	nonce := query.Get("nonce")

	if responseType != "code" {
		http.Error(w, "Unsupported response_type. Expected 'code'", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" {
		// ผู้ใช้ยังไม่มี Session ในตัว, บังคับเบี่ยงเข็มไปยังหน้าจอ Login
		loginURL := "/login?" + query.Encode()
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	session, err := h.sessionCache.GetSession(r.Context(), cookie.Value)
	if err != nil || session == nil {
		// Session ไม่ปรากฎใน Redis (อาจจะหมดอายุ), ไปล็อกอินใหม่
		loginURL := "/login?" + query.Encode()
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// ถ้าพก Session มาครบถ้วนตามกฎหมาย ให้ออก Auth Code ได้เลย!
	scopes := strings.Split(scopeStr, " ")
	code, err := h.oauthService.GenerateAuthCode(r.Context(), clientID, session.UserID, redirectURI, nonce, scopes)
	if err != nil {
		http.Error(w, "Failed to authorize: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ดีดโค้ดส่งกลับไปยังแอปปลายทางพร้อมรหัส
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// LoginPage (GET /login) คืนค่าหน้า HTML แบบฝัง
func (h *OAuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OIDC Secure Login</title>
    <style>
        body { font-family: -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f7f9fc; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); width: 320px; }
        input { width: 100%; padding: 12px; margin: 10px 0 20px 0; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: 600; }
        button:hover { background: #0056b3; }
        .logo { text-align: center; font-size: 24px; font-weight: bold; margin-bottom: 20px; color: #333; }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">OIDC Login</div>
        <form method="POST" action="/login?` + r.URL.Query().Encode() + `">
            <label>Username</label>
            <input type="text" name="username" placeholder="your username" required />
            <label>Password</label>
            <input type="password" name="password" placeholder="••••••••" required />
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// LoginSubmit (POST /login) ค้นหารายชื่อจากฐานและสร้าง Session Cookie
func (h *OAuthHandler) LoginSubmit(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := h.userRepo.FindByUsername(r.Context(), username)
	if err != nil || user == nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// NOTE: ระบบ Production ต้องเข้ารหัสแบบ Bcrypt ตลอดเสมอ (เอาออกเพื่อเดโม่ง่ายๆ ก่อน)
	if user.PasswordHash != password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// ผลิต Session ใหม่ (สุ่ม uuid ชนิดหายาก)
	sessionID := uuid.New().String()
	sessionInfo := &models.SessionInfo{
		UserID:     user.ID,
		LoggedInAt: time.Now(),
	}
	
	if err := h.sessionCache.SetSession(r.Context(), sessionID, sessionInfo, 24*time.Hour); err != nil {
		http.Error(w, "Failed to create session in cache", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	// หมุนรถกลับไปด่านหน้า (/authorize)
	authURL := "/authorize?" + r.URL.Query().Encode()
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Token (POST /token) เปิดรับให้ Backend เอารหัสมาแลกเป็นตัว JWT
func (h *OAuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")

	// สั่ง Oauth เดินเรื่องแจกแหวน 
	response, err := h.oauthService.ExchangeToken(r.Context(), code, clientID, redirectURI)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest) // ตามหลักต้องเป็น 400 เสมอ
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
