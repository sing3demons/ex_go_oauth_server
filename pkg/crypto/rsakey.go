package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
)

// CryptoManager บริหารจัดการ Cryptography ในหน่วยความจำ (Pure Domain, No DB)
type CryptoManager struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	KeyID      string
}

// GenerateRSAKeyPair สร้างคู่กุญแจใหม่โดยรับ kid จากด้านนอก
func GenerateRSAKeyPair(kid string) (*CryptoManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &CryptoManager{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		KeyID:      kid,
	}, nil
}

// ParseFromPEM แปลงกลับจากฐานข้อมูลที่เก็บเป็น PEM String กลับมาเป็น Object
func ParseFromPEM(privPEM, kid string) (*CryptoManager, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &CryptoManager{
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		KeyID:      kid,
	}, nil
}

func (c *CryptoManager) PrivateKeyPEM() string {
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.PrivateKey),
	}
	return string(pem.EncodeToMemory(pemBlock))
}

func (c *CryptoManager) PublicKeyPEM() string {
	pubASN1, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		return ""
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
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
	N   string `json:"n"`
	E   string `json:"e"`
}

// GetJWK แปลงกุญแจให้เป็นโครงสร้างย่อยของ JWK
func (c *CryptoManager) GetJWK() JWK {
	n := base64.RawURLEncoding.EncodeToString(c.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(c.PublicKey.E)).Bytes())

	return JWK{
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		Kid: c.KeyID,
		N:   n,
		E:   e,
	}
}
