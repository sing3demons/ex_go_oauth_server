package utils

import (
	"net/mail"
	"regexp"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func IsEmail(email string) bool {
	if !emailRegex.MatchString(email) {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}
