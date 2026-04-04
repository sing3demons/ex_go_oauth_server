package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/sing3demons/tr_02_oauth/internal/config"
	"github.com/sing3demons/tr_02_oauth/internal/core/services"
	"github.com/sing3demons/tr_02_oauth/pkg/errors"
	"github.com/sing3demons/tr_02_oauth/pkg/kp"
)

type DiscoveryHandler struct {
	cfg *config.Config
	ks  *services.KeyService
}

func NewDiscoveryHandler(cfg *config.Config, ks *services.KeyService) *DiscoveryHandler {
	return &DiscoveryHandler{cfg: cfg, ks: ks}
}

func (h *DiscoveryHandler) OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	
	discovery := map[string]interface{}{
		"issuer":                                h.cfg.Issuer,
		"authorization_endpoint":                h.cfg.Issuer + "/authorize",
		"token_endpoint":                        h.cfg.Issuer + "/token",
		"userinfo_endpoint":                     h.cfg.Issuer + "/userinfo",
		"jwks_uri":                              h.cfg.Issuer + "/jwks.json",
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "email"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

func (h *DiscoveryHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	ctx := kp.NewCtx(r, w)
	ctx.Log("get_jwks")

	jwks, err := h.ks.GetJWKS(ctx)
	if err != nil {
		// http.Error(w, "Failed to get JWKS", http.StatusInternalServerError)
		ctx.JsonError(&errors.Error{
			Err: err,
			Message:  "Failed to get JWKS",
			AppResultCode: "50000",
		})
		return
	}

	ctx.Json(http.StatusOK, jwks)
}
