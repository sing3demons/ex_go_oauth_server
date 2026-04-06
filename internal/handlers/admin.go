package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/internal/core/ports"
	"github.com/sing3demons/oauth_server/pkg/kp"
	"github.com/sing3demons/oauth_server/pkg/response"
	"golang.org/x/crypto/bcrypt"
)

type AdminHandler struct {
	cfg        *config.Config
	userRepo   ports.UserRepository
	clientRepo ports.ClientRepository
}

func NewAdminHandler(cfg *config.Config, userRepo ports.UserRepository, clientRepo ports.ClientRepository) *AdminHandler {
	return &AdminHandler{
		cfg:        cfg,
		userRepo:   userRepo,
		clientRepo: clientRepo,
	}
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func (h *AdminHandler) CreateUser(ctx *kp.Ctx) {
	ctx.Log("create_user")
	var req CreateUserRequest

	if err := ctx.Bind(&req); err != nil {
		// http.Error(w, "Invalid input JSON", http.StatusBadRequest)
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.ServerError,
		}, response.ServerError.Error())
		return
	}

	user := &models.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
		CreatedAt:    time.Now(),
	}

	if err := h.userRepo.Create(ctx, user); err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.ServerError,
		}, response.ServerError.Error())
		return
	}

	ctx.Json(http.StatusCreated, map[string]string{"message": "User created successfully", "id": user.ID})
}

type CreateClientRequest struct {
	ClientName    string   `json:"client_name"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
}

func (h *AdminHandler) CreateClient(ctx *kp.Ctx) {
	ctx.Log("create_client")
	var req CreateClientRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
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

	if err := h.clientRepo.Create(ctx, client); err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.ServerError,
		}, response.ServerError.Error())
		return
	}

	ctx.Json(http.StatusCreated, map[string]interface{}{
		"message":   "Client created successfully",
		"client_id": client.ClientID,
	})
}

// -----------------------------------------------------
// Admin UI Handlers
// -----------------------------------------------------

func (h *AdminHandler) DashboardUI(ctx *kp.Ctx) {
	ctx.Log("admin_dashboard")
	clients, err := h.clientRepo.FindAll(ctx)
	if err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.ServerError,
		}, response.ServerError.Error())
		return
	}

	// tmpl, err := template.ParseFiles("templates/admin_dashboard.html")
	// if err != nil {
	// 	ctx.JsonError(&errors.Error{
	// 		Err:           err,
	// 		Message:       "Failed to load template",
	// 		AppResultCode: response.ServerError.ResultCode(),
	// 	}, response.ServerError.Error())
	// 	return
	// }

	data := struct {
		Clients         []*models.Client
		ScopesSupported []string
		GrantTypes      []string
	}{
		Clients:         clients,
		ScopesSupported: h.cfg.GetArray("oidc.scopes_supported"),
		GrantTypes:      h.cfg.GetArray("oidc.grant_types_supported"),
	}

	// w.Header().Set("Content-Type", "text/html")
	// tmpl.Execute(w, data)
	ctx.RenderTemplate("templates/admin_dashboard.html", data)
}

func (h *AdminHandler) CreateClientUI(ctx *kp.Ctx) {
	ctx.Log("create_client_ui")
	if err := ctx.Req.ParseForm(); err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	clientName := ctx.Req.FormValue("client_name")
	redirectURIsRaw := ctx.Req.FormValue("redirect_uris")
	requirePKCE := ctx.Req.FormValue("require_pkce") == "true"

	// รับ Checkbox ที่ชื่อเดียวกันมาเป็น slice ของ string
	ctx.Req.ParseForm() // already parsed actually, but let's be safe

	// validate scopes กับค่าใน config
	allowedScopes := make(map[string]bool)
	for _, s := range h.cfg.GetArray("oidc.scopes_supported") {
		allowedScopes[s] = true
	}
	var scopes []string
	for _, s := range ctx.Req.Form["scopes"] {
		if allowedScopes[s] {
			scopes = append(scopes, s)
		}
	}
	// openid บังคับเสมอ
	hasOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		scopes = append([]string{"openid"}, scopes...)
	}

	// รับ grant_types จาก Form (checkbox) และ validate กับค่าใน config
	allowedGrantTypes := make(map[string]bool)
	for _, gt := range h.cfg.GetArray("oidc.grant_types_supported") {
		allowedGrantTypes[gt] = true
	}
	grantTypes := ctx.Req.Form["grant_types"]
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

	clientType := ctx.Req.FormValue("client_type")
	if clientType == "" {
		clientType = "public"
	}

	idTokenAlg := ctx.Req.FormValue("id_token_signed_response_alg")
	if idTokenAlg == "" {
		idTokenAlg = "RS256"
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
		IDTokenSignedResponseAlg: idTokenAlg,
	}

	if err := h.clientRepo.Create(ctx.Req.Context(), client); err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.ServerError,
		}, response.ServerError.Error())
		return
	}

	if clientType == "confidential" {
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
		// w.Header().Set("Content-Type", "text/html")
		// tmpl.Execute(w, data)
		ctx.RenderTemplate("templates/client_success.html", data)
		return
	}

	ctx.Redirect("/admin/dashboard", http.StatusFound)
}
