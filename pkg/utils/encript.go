package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

func Encrypt(clientID string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := []byte(clientID)
	ciphertext := make([]byte, len(plaintext))

	stream := cipher.NewCTR(block, key[:block.BlockSize()])
	stream.XORKeyStream(ciphertext, plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
