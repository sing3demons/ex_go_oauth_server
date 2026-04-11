package models

import "time"

type AuthTransaction struct {
	ID                  string    `json:"id,omitempty"`
	ClientID            string    `json:"client_id,omitempty"`
	UserID              string    `json:"user_id,omitempty"`
	SID                 string    `json:"sid,omitempty"`
	RedirectURI         string    `json:"redirect_uri,omitempty"`
	Scopes              []string  `json:"scopes,omitempty"`
	State               string    `json:"state,omitempty"`
	Nonce               string    `json:"nonce,omitempty"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `json:"expires_at,omitempty"`
}

type AuthCodeInfo struct {
	ClientID    string    `json:"client_id"`
	UserID      string    `json:"user_id"`
	RedirectURI string    `json:"redirect_uri"`
	Scopes      []string  `json:"scopes"`
	Nonce               string    `json:"nonce"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type SessionInfo struct {
	SID            string    `json:"sid"`
	UserID         string    `json:"user_id"`
	LoggedInAt     time.Time `json:"logged_in_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	IPAddress      string    `json:"ip_address"`
	UserAgent      string    `json:"user_agent"`
	DeviceInfo     string    `json:"device_info"` // e.g. "Chrome on Windows"
}
