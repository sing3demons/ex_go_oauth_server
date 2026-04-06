package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/internal/core/ports"
	"golang.org/x/crypto/bcrypt"
)

type AdminHandler struct {
	userRepo   ports.UserRepository
	clientRepo ports.ClientRepository
}

func NewAdminHandler(userRepo ports.UserRepository, clientRepo ports.ClientRepository) *AdminHandler {
	return &AdminHandler{
		userRepo:   userRepo,
		clientRepo: clientRepo,
	}
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid input JSON", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
		CreatedAt:    time.Now(),
	}

	if err := h.userRepo.Create(r.Context(), user); err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully", "id": user.ID})
}

type CreateClientRequest struct {
	ClientName    string   `json:"client_name"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
}

func (h *AdminHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	var req CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid input JSON", http.StatusBadRequest)
		return
	}

	clientID := uuid.New().String()

	client := &models.Client{
		ClientID:      clientID,
		ClientName:    req.ClientName,
		RedirectURIs:  req.RedirectURIs,
		GrantTypes:    []string{"authorization_code"},
		AllowedScopes: req.AllowedScopes,
	}

	if err := h.clientRepo.Create(r.Context(), client); err != nil {
		http.Error(w, "Failed to create client", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Client created successfully",
		"client_id": client.ClientID,
	})
}

// -----------------------------------------------------
// Admin UI Handlers
// -----------------------------------------------------

func (h *AdminHandler) DashboardUI(w http.ResponseWriter, r *http.Request) {
	clients, err := h.clientRepo.FindAll(r.Context())
	if err != nil {
		http.Error(w, "Failed to fetch clients", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/admin_dashboard.html")
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}

	data := struct {
		Clients []*models.Client
	}{
		Clients: clients,
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, data)
}

func (h *AdminHandler) CreateClientUI(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}

	clientName := r.FormValue("client_name")
	redirectURIsRaw := r.FormValue("redirect_uris")
	requirePKCE := r.FormValue("require_pkce") == "true"

	// รับ Checkbox ที่ชื่อเดียวกันมาเป็น slice ของ string
	r.ParseForm() // already parsed actually, but let's be safe
	scopes := r.Form["scopes"]
	if len(scopes) == 0 {
		scopes = []string{}
	}
	
	// รับ grant_types จาก Form (checkbox)
	// Grant types ที่รองรับ: "authorization_code", "refresh_token"
	allowedGrantTypes := map[string]bool{
		"authorization_code": true,
		"refresh_token":      true,
	}
	grantTypes := r.Form["grant_types"]
	if len(grantTypes) == 0 {
		// Default: authorization_code เสมอ
		grantTypes = []string{"authorization_code"}
	} else {
		// Whitelist validation
		var validGrants []string
		for _, gt := range grantTypes {
			if allowedGrantTypes[gt] {
				validGrants = append(validGrants, gt)
			}
		}
		if len(validGrants) == 0 {
			validGrants = []string{"authorization_code"}
		}
		grantTypes = validGrants
	}

	// Clean up Redirect URIs (comma separated)
	var redirectURIs []string
	for _, uri := range strings.Split(redirectURIsRaw, ",") {
		cleanURI := strings.TrimSpace(uri)
		if cleanURI != "" {
			redirectURIs = append(redirectURIs, cleanURI)
		}
	}

	clientType := r.FormValue("client_type")
	if clientType == "" {
		clientType = "public"
	}

	clientID := uuid.New().String()
	var plainSecret string
	var secretHash string

	if clientType == "confidential" {
		// Generate 32 bytes of random data for the secret
		secretBytes := make([]byte, 32)
		rand.Read(secretBytes)
		plainSecret = base64.URLEncoding.EncodeToString(secretBytes)

		hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
		if err == nil {
			secretHash = string(hash)
		}
	}

	client := &models.Client{
		ClientID:         clientID,
		ClientSecretHash: secretHash,
		ClientType:       clientType,
		ClientName:       clientName,
		RedirectURIs:     redirectURIs,
		GrantTypes:       grantTypes,
		AllowedScopes:    scopes,
		RequirePKCE:      requirePKCE,
	}

	if err := h.clientRepo.Create(r.Context(), client); err != nil {
		http.Error(w, "Failed to create client", http.StatusInternalServerError)
		return
	}

	if clientType == "confidential" {
		tmpl, err := template.ParseFiles("templates/client_success.html")
		if err != nil {
			http.Error(w, "Failed to load success template", http.StatusInternalServerError)
			return
		}
		data := struct {
			ClientID     string
			ClientName   string
			ClientType   string
			ClientSecret string
		}{
			ClientID:     clientID,
			ClientName:   clientName,
			ClientType:   clientType,
			ClientSecret: plainSecret,
		}
		w.Header().Set("Content-Type", "text/html")
		tmpl.Execute(w, data)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}
