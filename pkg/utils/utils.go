package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/mail"
	"regexp"

	"github.com/mssola/user_agent"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func IsEmail(email string) bool {
	if !emailRegex.MatchString(email) {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}

func NewSessionID() string {
	b := make([]byte, 16) // 16 bytes
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func ValidateSessionID(s string) bool {
	// 1. ความยาวต้อง 22 ตัว
	if len(s) != 22 {
		return false
	}

	// 2. decode base64 (URL-safe, no padding)
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return false
	}

	// 3. ต้องได้ 16 bytes
	if len(b) != 16 {
		return false
	}

	return true
}

func GetDeviceInfo(uaStr string) string {
	ua := user_agent.New(uaStr)
	browser, version := ua.Browser()
	os := ua.OS()
	return fmt.Sprintf("%s (%s %s)", os, browser, version)
}
