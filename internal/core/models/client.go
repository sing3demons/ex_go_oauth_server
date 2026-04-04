package models

type Client struct {
	ClientID         string   `bson:"_id" json:"client_id"`
	ClientSecretHash string   `bson:"client_secret_hash" json:"-"`
	ClientName       string   `bson:"client_name" json:"client_name"`
	RedirectURIs     []string `bson:"redirect_uris" json:"redirect_uris"`
	GrantTypes       []string `bson:"grant_types" json:"grant_types"`
	AllowedScopes    []string `bson:"allowed_scopes" json:"allowed_scopes"`
}
