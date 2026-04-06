package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
)

// CryptoManager บริหารจัดการ Cryptography ในหน่วยความจำ
type CryptoManager struct {
	PrivateKey interface{}
	PublicKey  interface{}
	KeyID      string
	Kty        string
	Alg        string
}

// GenerateKeyPair สร้างคู่กุญแจใหม่ตาม alg: RS256, ES256, EdDSA
func GenerateKeyPair(kid string, alg string) (*CryptoManager, error) {
	switch alg {
	case "RS256":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return &CryptoManager{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			KeyID:      kid,
			Kty:        "RSA",
			Alg:        "RS256",
		}, nil
	case "ES256":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &CryptoManager{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			KeyID:      kid,
			Kty:        "EC",
			Alg:        "ES256",
		}, nil
	case "EdDSA":
		pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &CryptoManager{
			PrivateKey: privateKey,
			PublicKey:  pubKey,
			KeyID:      kid,
			Kty:        "OKP",
			Alg:        "EdDSA",
		}, nil
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

// ParseFromPEM แปลงกลับจากฐานข้อมูลที่เก็บเป็น PEM String กลับมาเป็น Object
func ParseFromPEM(privPEM, kid string, kty string, alg string) (*CryptoManager, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	var priv interface{}
	var pub interface{}
	var err error

	switch kty {
	case "RSA":
		privRsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8
			priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			if rsaPriv, ok := priv.(*rsa.PrivateKey); ok {
				privRsa = rsaPriv
			} else {
				return nil, errors.New("not an RSA private key")
			}
		}
		priv = privRsa
		pub = &privRsa.PublicKey
	case "EC":
		privEc, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8
			priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			if ecPriv, ok := priv.(*ecdsa.PrivateKey); ok {
				privEc = ecPriv
			} else {
				return nil, errors.New("not an EC private key")
			}
		}
		priv = privEc
		pub = &privEc.PublicKey
	case "OKP":
		priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if edPriv, ok := priv.(ed25519.PrivateKey); ok {
			// ed25519.PrivateKey contains the public key as the last 32 bytes
			pub = edPriv.Public().(ed25519.PublicKey)
		} else {
			return nil, errors.New("not an Ed25519 private key")
		}
	case "":
		// Fallback for older records: assume RSA RS256
		kty = "RSA"
		alg = "RS256"
		privRsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv = privRsa
		pub = &privRsa.PublicKey
	default:
		return nil, errors.New("unsupported key type")
	}

	return &CryptoManager{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      kid,
		Kty:        kty,
		Alg:        alg,
	}, nil
}

func (c *CryptoManager) PrivateKeyPEM() string {
	var bytes []byte
	var err error
	var pemType string

	switch priv := c.PrivateKey.(type) {
	case *rsa.PrivateKey:
		bytes = x509.MarshalPKCS1PrivateKey(priv)
		pemType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		bytes, err = x509.MarshalECPrivateKey(priv)
		if err != nil {
			return ""
		}
		pemType = "EC PRIVATE KEY"
	case ed25519.PrivateKey:
		bytes, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return ""
		}
		pemType = "PRIVATE KEY"
	default:
		return ""
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

func (c *CryptoManager) PublicKeyPEM() string {
	bytes, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		return ""
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`

	// RSA specific
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC specific
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// OKP specific (Crv and X)
}

// GetJWK แปลงกุญแจให้เป็นโครงสร้างย่อยของ JWK
func (c *CryptoManager) GetJWK() JWK {
	jwk := JWK{
		Kty: c.Kty,
		Alg: c.Alg,
		Use: "sig",
		Kid: c.KeyID,
	}

	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		jwk.N = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		jwk.Crv = "P-256"
		jwk.X = base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
		jwk.Y = base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
	case ed25519.PublicKey:
		jwk.Crv = "Ed25519"
		jwk.X = base64.RawURLEncoding.EncodeToString(pub)
	}

	return jwk
}
