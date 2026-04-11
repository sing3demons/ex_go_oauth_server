package models

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Scope → Claim Mapping
// | Scope   | Fields                                 |
// | ------- | -------------------------------------- |
// | openid  | sub                                    |
// | profile | name, family_name, given_name, picture |
// | email   | email                                  |
// | phone   | phone_number                           |
// | address | address                                |

type User struct {
	ID       string `bson:"_id,omitempty" json:"id"`
	Username string `bson:"username" json:"username"`
	Email    string `bson:"email" json:"email"`
	// EmailVerified bool   `bson:"email_verified"`

	// PasswordHash string `bson:"password_hash" json:"-"`

	Status     string    `bson:"status"` // active, suspended
	MFAEnabled bool      `bson:"mfa_enabled" json:"mfa_enabled"`

	// GivenName  string    `bson:"given_name" json:"given_name"`
	// FamilyName string    `bson:"family_name" json:"family_name"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`

	webAuthnCredentials []webauthn.Credential `bson:"-" json:"-"`
}

// WebAuthnID returns the user's ID
func (u *User) WebAuthnID() []byte {
	return []byte(u.ID)
}

// WebAuthnName returns the user's username
func (u *User) WebAuthnName() string {
	return u.Username
}

// WebAuthnDisplayName returns the user's display name
func (u *User) WebAuthnDisplayName() string {
	return u.Username
}

// WebAuthnIcon is not (yet) implemented
func (u *User) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns credentials owned by the user
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.webAuthnCredentials
}

func (u *User) AddWebAuthnCredential(cred webauthn.Credential) {
	u.webAuthnCredentials = append(u.webAuthnCredentials, cred)
}

type UserProfile struct {

	// Standard OIDC claims
	UserID string `bson:"user_id"` // MUST (stable id)
	// Sub        string  `bson:"sub"`     // MUST (stable id)
	Name       string `bson:"name,omitempty" json:"name,omitempty"`
	GivenName  string `bson:"given_name,omitempty" json:"given_name,omitempty"`
	FamilyName string `bson:"family_name,omitempty" json:"family_name,omitempty"`
	Nickname   string `bson:"nickname,omitempty" json:"nickname,omitempty"`

	PreferredUsername string `bson:"preferred_username,omitempty" json:"preferred_username,omitempty"`

	Email         string `bson:"email,omitempty" json:"email,omitempty"`
	EmailVerified bool   `bson:"email_verified,omitempty" json:"email_verified,omitempty"`
	Picture       string `bson:"picture,omitempty" json:"picture,omitempty"`
	Website       string `bson:"website,omitempty" json:"website,omitempty"`

	Gender    string  `bson:"gender,omitempty" json:"gender,omitempty"`
	Birthdate *string `bson:"birthdate,omitempty" json:"birthdate,omitempty"`

	ZoneInfo *string `bson:"zone_info,omitempty" json:"zone_info,omitempty"`
	Locale   *string `bson:"locale,omitempty" json:"locale,omitempty"`

	PhoneNumber   *string `bson:"phone_number,omitempty" json:"phone_number,omitempty"`
	PhoneVerified bool    `bson:"phone_verified,omitempty" json:"phone_verified,omitempty"`

	Address *Address `bson:"address,omitempty" json:"address,omitempty"`

	CreatedAt time.Time `bson:"created_at,omitempty" json:"created_at"`
	UpdatedAt time.Time `bson:"updated_at,omitempty" json:"updated_at"`
}

func (p *UserProfile) BuildClaims(scope map[string]bool) map[string]any {
	claims := map[string]any{}
	if p == nil {
		return claims
	}

	if scope["profile"] {
		if p.Name != "" {
			claims["name"] = p.Name
		}
		if p.GivenName != "" {
			claims["given_name"] = p.GivenName
		}
		if p.FamilyName != "" {
			claims["family_name"] = p.FamilyName
		}
		if p.Picture != "" {
			claims["picture"] = p.Picture
		}
		if p.Locale != nil {
			claims["locale"] = *p.Locale
		}
		claims["updated_at"] = p.UpdatedAt
	}

	if scope["email"] {
		if p.Email != "" {
			claims["email"] = p.Email
		}
		claims["email_verified"] = p.EmailVerified
	}

	if scope["phone"] {
		if p.PhoneNumber != nil {
			claims["phone_number"] = *p.PhoneNumber
		}
		claims["phone_verified"] = p.PhoneVerified
	}

	if scope["address"] && p.Address != nil {
		claims["address"] = p.Address
	}

	return claims
}

type Address struct {
	Formatted     string `bson:"formatted"`
	StreetAddress string `bson:"street_address"`
	Locality      string `bson:"locality"`
	Region        string `bson:"region"`
	PostalCode    string `bson:"postal_code"`
	Country       string `bson:"country"`
}

type UserCredential struct {
	ID     string `bson:"_id" json:"id"`
	UserID string `bson:"user_id" json:"user_id"`

	Type string `bson:"type" json:"type"`
	// password | otp | passkey | api_key

	Identifier string `bson:"identifier" json:"identifier"`
	// เช่น email / phone (ไว้หา credential)

	Secret string `bson:"secret" json:"secret"`
	// password hash / otp seed / public key ref

	Verified bool `bson:"verified" json:"verified"`

	CreatedAt  time.Time `bson:"created_at" json:"-"`
	LastUsedAt time.Time `bson:"last_used_at" json:"-"`

	ExpiresAt *time.Time `bson:"expires_at,omitempty" json:"-"`
	Revoked   bool       `bson:"revoked" json:"-"`
}
