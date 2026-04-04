package models

import "time"

type KeyRecord struct {
	Kid           string    `bson:"_id" json:"kid"`
	PrivateKeyPEM string    `bson:"private_key_pem" json:"private_key_pem"`
	PublicKeyPEM  string    `bson:"public_key_pem" json:"public_key_pem"`
	CreatedAt     time.Time `bson:"created_at" json:"created_at"`
	ExpiresAt     time.Time `bson:"expires_at" json:"expires_at"`
}
