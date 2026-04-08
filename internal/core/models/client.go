package models

type Client struct {
	ClientID         string   `bson:"_id" json:"client_id"`
	ClientSecretHash string   `bson:"client_secret_hash" json:"-"`
	ClientType       string   `bson:"client_type" json:"client_type"` // 'public' or 'confidential'
	ClientName       string   `bson:"client_name" json:"client_name"`
	RedirectURIs     []string `bson:"redirect_uris" json:"redirect_uris"`
	GrantTypes       []string `bson:"grant_types" json:"grant_types"`
	AllowedScopes            []string `bson:"allowed_scopes" json:"allowed_scopes"`
	RequirePKCE              bool     `bson:"require_pkce" json:"require_pkce"`
	IDTokenSignedResponseAlg string   `bson:"id_token_signed_response_alg" json:"id_token_signed_response_alg"`
	SubjectType              string   `bson:"subject_type" json:"subject_type"` // "public" or "pairwise"
	TokenEndpointAuthMethod  string   `bson:"token_endpoint_auth_method" json:"token_endpoint_auth_method"` // "client_secret_basic", "client_secret_post", "none"
	JWKSURI                  string   `bson:"jwks_uri" json:"jwks_uri"` // URL to fetch client public keys for jwt-bearer
	PostLogoutRedirectURIs   []string `bson:"post_logout_redirect_uris" json:"post_logout_redirect_uris"`
}
