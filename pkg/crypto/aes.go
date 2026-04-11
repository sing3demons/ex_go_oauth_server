package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// Encrypt encrypts plain text using AES-256-GCM
// The key must be 32 bytes for AES-256
func Encrypt(plainText, key string) (string, error) {
	if len(key) != 32 && len(key) != 24 && len(key) != 16 {
		return "", errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal appends the ciphertext to the nonce, so we can extract it during decryption
	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)

	return base64.RawURLEncoding.EncodeToString(cipherText), nil
}

// Decrypt decrypts AES-256-GCM encrypted text
func Decrypt(encryptedText, key string) (string, error) {
	if len(key) != 32 && len(key) != 24 && len(key) != 16 {
		return "", errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}

	data, err := base64.RawURLEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}
