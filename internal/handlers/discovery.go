package handlers

import (
	"net/http"

	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/internal/core/services"
	"github.com/sing3demons/oauth_server/pkg/kp"
	"github.com/sing3demons/oauth_server/pkg/response"
)

type DiscoveryHandler struct {
	cfg *config.Config
	ks  *services.KeyService
}

func NewDiscoveryHandler(cfg *config.Config, ks *services.KeyService) *DiscoveryHandler {
	return &DiscoveryHandler{cfg: cfg, ks: ks}
}

func (h *DiscoveryHandler) OpenIDConfiguration(ctx *kp.Ctx) {
	discovery := map[string]any{
		"issuer":                                h.cfg.Issuer,
		"authorization_endpoint":                h.cfg.Issuer + "/authorize",
		"token_endpoint":                        h.cfg.Issuer + "/token",
		"userinfo_endpoint":                     h.cfg.Issuer + "/userinfo",
		"jwks_uri":                              h.cfg.Issuer + "/jwks.json",
		"revocation_endpoint":                   h.cfg.Issuer + "/revoke",
		"introspection_endpoint":                h.cfg.Issuer + "/introspect",
		"end_session_endpoint":                  h.cfg.Issuer + "/logout",
		"scopes_supported":                      h.cfg.GetArray("oidc.scopes_supported"),
		"response_types_supported":              h.cfg.GetArray("oidc.response_types_supported"),
		"grant_types_supported":                 h.cfg.GetArray("oidc.grant_types_supported"),
		"subject_types_supported":               h.cfg.GetArray("oidc.subject_types_supported"),
		"id_token_signing_alg_values_supported": h.cfg.GetArray("oidc.id_token_signing_alg_values_supported"),
		"token_endpoint_auth_methods_supported": h.cfg.GetArray("oidc.token_endpoint_auth_methods_supported"),
		"claims_supported":                      h.cfg.GetArray("oidc.claims_supported"),
		"code_challenge_methods_supported":      h.cfg.GetArray("oidc.code_challenge_methods_supported"),
		"claims_parameter_supported":            true,
		"request_parameter_supported":           true,
		"request_uri_parameter_supported":       false,
	}

	ctx.JSON(http.StatusOK, discovery)
}

func (h *DiscoveryHandler) JWKS(ctx *kp.Ctx) {
	ctx.Log("get_jwks")

	jwks, err := h.ks.GetJWKS(ctx)
	if err != nil {
		// http.Error(w, "Failed to get JWKS", http.StatusInternalServerError)
		ctx.JSONError(&response.Error{
			Err:     err,
			Message: response.SystemError,
		}, response.SystemError.Error())
		return
	}

	ctx.JSON(http.StatusOK, jwks)
}
