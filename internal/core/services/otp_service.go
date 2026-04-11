package services

import (
	"context"
	"errors"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/sing3demons/oauth_server/internal/core/ports"
)

type OTPService struct {
	credRepo ports.UserCredentialRepository
	issuer   string
}

func NewOTPService(credRepo ports.UserCredentialRepository, issuer string) *OTPService {
	return &OTPService{
		credRepo: credRepo,
		issuer:   issuer,
	}
}

// GenerateTOTP สร้าง Secret ใหม่สำหรับผู้ใช้
func (s *OTPService) GenerateTOTP(ctx context.Context, userID, accountName string) (secret string, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", err
	}

	return key.Secret(), key.URL(), nil
}

// VerifyOTP ตรวจสอบรหัส 6 หลัก
func (s *OTPService) VerifyOTP(ctx context.Context, userID, code string) (bool, error) {
	// 1. ค้นหา TOTP credential จาก DB
	cred, err := s.credRepo.FindByUserIDAndType(ctx, userID, "totp")
	if err != nil {
		return false, errors.New("mfa_not_configured")
	}

	// 2. ตรวจสอบ Expiration (เผื่อไว้สำหรับ dynamic otp)
	if cred.ExpiresAt != nil && time.Now().After(*cred.ExpiresAt) {
		return false, errors.New("otp_expired")
	}

	// 3. ตรวจสอบรหัส (TOTP รองรับ clock skew เล็กน้อย)
	valid := totp.Validate(code, cred.Secret)
	return valid, nil
}

// EnrollmentVerify ตรวจสอบรหัสครั้งแรกเพื่อเปิดใช้งาน
func (s *OTPService) EnrollmentVerify(ctx context.Context, userID, secret, code string) error {
	valid := totp.Validate(code, secret)
	if !valid {
		return errors.New("invalid_otp_code")
	}
	return nil
}
