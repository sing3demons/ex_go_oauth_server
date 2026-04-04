package models

import "time"

type RefreshToken struct {
	Token     string    `bson:"_id" json:"token"`
	ClientID  string    `bson:"client_id" json:"client_id"`
	UserID    string    `bson:"user_id" json:"user_id"`
	Scopes    []string  `bson:"scopes" json:"scopes"`
	ExpiresAt time.Time `bson:"expires_at" json:"expires_at"`
	Revoked   bool      `bson:"revoked" json:"revoked"`
}
