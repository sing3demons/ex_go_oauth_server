package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/tr_02_oauth/internal/core/models"
	"github.com/sing3demons/tr_02_oauth/internal/core/ports"
	"golang.org/x/crypto/bcrypt"
)

type RegisterHandler struct {
	userRepo ports.UserRepository
}

func NewRegisterHandler(userRepo ports.UserRepository) *RegisterHandler {
	return &RegisterHandler{
		userRepo: userRepo,
	}
}

func (h *RegisterHandler) RegisterPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign Up to OIDC System</title>
    <style>
        body { font-family: -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f7f9fc; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); width: 320px; }
        input { width: 100%; padding: 12px; margin: 10px 0 20px 0; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #28a745; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: 600; }
        button:hover { background: #218838; }
        .logo { text-align: center; font-size: 24px; font-weight: bold; margin-bottom: 20px; color: #333; }
        .footer { text-align: center; margin-top: 15px; font-size: 14px;}
        .footer a { color: #007bff; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">Create Account</div>
        <form method="POST" action="/register">
            <label>Username</label>
            <input type="text" name="username" required />
            <label>Email</label>
            <input type="email" name="email" required />
            <label>Password</label>
            <input type="password" name="password" required />
            <button type="submit">Sign Up</button>
        </form>
        <div class="footer"><a href="/login">Already have an account? Log in</a></div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (h *RegisterHandler) RegisterSubmit(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")

	existing, _ := h.userRepo.FindByUsername(r.Context(), username)
	if existing != nil {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
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
		log.Println("Error creating user:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}
