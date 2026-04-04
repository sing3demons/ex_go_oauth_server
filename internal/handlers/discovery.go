package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/sing3demons/tr_02_oauth/internal/config"
	"github.com/sing3demons/tr_02_oauth/internal/core/services"
	"github.com/sing3demons/tr_02_oauth/pkg/logAction"
	"github.com/sing3demons/tr_02_oauth/pkg/mlog"
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
	ctx := r.Context()
	_log := mlog.L(ctx)
	incoming := map[string]any{
		"method":  r.Method,
		"url":     r.URL.String(),
		"headers": r.Header,
		"query":   r.URL.Query(),
		"body":    r.Body,
	}
	_log.Info(logAction.INBOUND("GetJWKS"), incoming)
	jwks, err := h.ks.GetJWKS(ctx)
	if err != nil {
		http.Error(w, "Failed to get JWKS", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)

	outgoing := map[string]any{
		"status": http.StatusOK,
		"body":   jwks,
		"header": w.Header(),
	}
	_log.Info(logAction.OUTBOUND("GetJWKS"), outgoing)
}
