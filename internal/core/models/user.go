package models

import "time"

type User struct {
	ID           string    `bson:"_id,omitempty" json:"id"`
	Username     string    `bson:"username" json:"username"`
	Email        string    `bson:"email" json:"email"`
	PasswordHash string    `bson:"password_hash" json:"-"`
	GivenName    string    `bson:"given_name" json:"given_name"`
	FamilyName   string    `bson:"family_name" json:"family_name"`
	CreatedAt    time.Time `bson:"created_at" json:"created_at"`
}
