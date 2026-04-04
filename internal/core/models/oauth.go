package models

import "time"

type AuthCodeInfo struct {
	ClientID    string    `json:"client_id"`
	UserID      string    `json:"user_id"`
	RedirectURI string    `json:"redirect_uri"`
	Scopes      []string  `json:"scopes"`
	Nonce       string    `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type SessionInfo struct {
	UserID     string    `json:"user_id"`
	LoggedInAt time.Time `json:"logged_in_at"`
}
