package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
)

const (
	clientID     = "88dbd8da-a052-4680-8731-c3401483937f"         // เปลี่ยนเป็น ClientID ของคุณจาก DB
	clientSecret = "asDONXL7xP4qGv1PT1b69RgRrySDaLO-XHR70Gc4opA=" // เปลี่ยนเป็น Secret ของคุณ
	redirectURI  = "http://localhost:3000/callback"
	authURL      = "http://localhost:8080/authorize"
	tokenURL     = "http://localhost:8080/token"
	userInfoURL  = "http://localhost:8080/userinfo"
	logoutURL    = "http://localhost:8080/logout"
)

// ข้อมูลจำลองฐานข้อมูลในฝั่ง Client
var sessionStore = make(map[string]map[string]any)

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/dashboard", handleDashboard)
	http.HandleFunc("/logout", handleLogout)

	fmt.Println("🚀 Client App running on http://localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("client_session"); err == nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	tmpl := template.Must(template.ParseFiles("templates/client/index.html"))
	tmpl.Execute(w, nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// สร้างตัวแปร PKCE
	verifier := generateRandomString(43)
	challenge := generateCodeChallenge(verifier)
	state := generateRandomString(32)

	// เก็บค่าลับลง Cookie เพื่อไปดึงตอน /callback
	http.SetCookie(w, &http.Cookie{Name: "code_verifier", Value: verifier, Path: "/", HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: state, Path: "/", HttpOnly: true})

	// สร้าง URL พร้อมพารามิเตอร์ส่งไป OIDC Server
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", clientID)
	params.Add("redirect_uri", redirectURI)
	params.Add("scope", "openid profile email offline_access")
	params.Add("state", state)
	params.Add("code_challenge", challenge)
	params.Add("code_challenge_method", "S256")

	redirect := authURL + "?" + params.Encode()
	http.Redirect(w, r, redirect, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errQuery := r.URL.Query().Get("error")

	if errQuery != "" {
		http.Error(w, "Auth Error: "+errQuery, http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != state {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	verifierCookie, err := r.Cookie("code_verifier")
	if err != nil {
		http.Error(w, "Missing code verifier", http.StatusBadRequest)
		return
	}

	// แลก Token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("code_verifier", verifierCookie.Value)

	req, _ := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to call token endpoint", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		http.Error(w, "Token exchange failed: "+string(body), http.StatusBadRequest)
		return
	}

	var tokenResponse map[string]any
	json.NewDecoder(resp.Body).Decode(&tokenResponse)
	accessToken := tokenResponse["access_token"].(string)

	// เรียกข้อมูลส่วนตัว (UserInfo)
	userInfoReq, _ := http.NewRequest("GET", userInfoURL, nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+accessToken)

	userInfoResp, err := client.Do(userInfoReq)
	if err != nil || userInfoResp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer userInfoResp.Body.Close()

	var userInfo map[string]any
	json.NewDecoder(userInfoResp.Body).Decode(&userInfo)

	// สร้าง Session สำหรับ Client App
	sessionID := generateRandomString(32)
	sessionStore[sessionID] = map[string]any{
		"user":   userInfo,
		"tokens": tokenResponse,
	}

	http.SetCookie(w, &http.Cookie{Name: "client_session", Value: sessionID, Path: "/", HttpOnly: true})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("client_session")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	data, exists := sessionStore[cookie.Value]
	if !exists {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	tmpl := template.New("dashboard.html").Funcs(template.FuncMap{
		"json": func(v any) string {
			b, _ := json.MarshalIndent(v, "", "  ")
			return string(b)
		},
	})
	tmpl = template.Must(tmpl.ParseFiles("templates/client/dashboard.html"))
	tmpl.Execute(w, data)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("client_session"); err == nil {
		delete(sessionStore, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{Name: "client_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "code_verifier", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})

	// เตะกลับไปที่ OIDC Server ให้เคลียร์ Session ฝั่งโน้นด้วย
	redirect := logoutURL + "?post_logout_redirect_uri=" + url.QueryEscape("http://localhost:3000/")
	http.Redirect(w, r, redirect, http.StatusFound)
}

// Helpers ---------------------------
func generateRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
