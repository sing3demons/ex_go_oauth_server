package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/tr_02_oauth/internal/core/models"
	"github.com/sing3demons/tr_02_oauth/internal/core/ports"
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
