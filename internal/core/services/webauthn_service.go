package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/internal/core/ports"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type WebAuthnService struct {
	WebAuthn *webauthn.WebAuthn
	userRepo ports.UserRepository
	credRepo ports.UserCredentialRepository
}

func NewWebAuthnService(cfg *config.Config, userRepo ports.UserRepository, credRepo ports.UserCredentialRepository) (*WebAuthnService, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: cfg.WebAuthnRPDisplayName,
		RPID:          cfg.WebAuthnRPID,
		RPOrigins:     []string{cfg.WebAuthnRPOrigin},
	}

	w, err := webauthn.New(wconfig)
	if err != nil {
		fmt.Println("WebAuthn Service Configuration:", wconfig)
		return nil, fmt.Errorf("failed to init webauthn: %w", err)
	}

	return &WebAuthnService{
		WebAuthn: w,
		userRepo: userRepo,
		credRepo: credRepo,
	}, nil
}

// ---------------------------------------------------------
// REGISTRATION (Setup)
// ---------------------------------------------------------

// BeginRegistration คืนค่า PublicKeyCredentialCreationOptions เป็น JSON และเซสชันของ WebAuthn
func (ws *WebAuthnService) BeginRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	user, err := ws.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found: %w", err)
	}

	// 1. ดึง Credentials ของ User (ถ้าเคยลงทะเบียนไว้) เพื่อไม่ให้ลงทะเบียนเหรียญ/ลายนิ้วมือเดิมซ้ำ
	creds, _ := ws.credRepo.FindAllByUserIDAndType(ctx, user.ID, "passkey")
	for _, c := range creds {
		var wCred webauthn.Credential
		if err := json.Unmarshal([]byte(c.Secret), &wCred); err == nil {
			user.AddWebAuthnCredential(wCred)
		}
	}

	// 2. เรียก WebAuthn Option
	options, sessionData, err := ws.WebAuthn.BeginRegistration(user)
	if err != nil {
		return nil, nil, fmt.Errorf("begin registration error: %w", err)
	}

	return options, sessionData, nil
}

// FinishRegistration รับ Response จาก Client มา Validate และบันทึกลง DB
func (ws *WebAuthnService) FinishRegistration(ctx context.Context, userID string, sessionData webauthn.SessionData, clientResponse []byte) error {
	user, err := ws.userRepo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Parse Response from Client
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(clientResponse))
	if err != nil {
		return fmt.Errorf("failed to parse webauthn response: %w", err)
	}

	// Verify the response against session data
	credential, err := ws.WebAuthn.CreateCredential(user, sessionData, parsedResponse)
	if err != nil {
		return fmt.Errorf("failed to verify credential: %w", err)
	}

	// แปลง WebAuthn Credential -> JSON String
	credBytes, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("failed to serialize credential: %w", err)
	}

	// บันทึกลง UserCredential Collection
	uc := &models.UserCredential{
		ID:         bson.NewObjectID().Hex(),
		UserID:     user.ID,
		Type:       "passkey",
		Identifier: fmt.Sprintf("passkey_%s", time.Now().Format("20060102150405")), // หรือรับชื่ออุปกรณ์จาก user
		Secret:     string(credBytes),
		Verified:   true, // WebAuthn ถือว่า verified ทันที
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	if err := ws.credRepo.Create(ctx, uc); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	// (Optional) Mark User as MFA enabled
	if !user.MFAEnabled {
		_ = ws.userRepo.UpdateMFAEnabled(ctx, user.ID, true)
	}

	return nil
}

// ---------------------------------------------------------
// AUTHENTICATION (Login / Verify)
// ---------------------------------------------------------

// BeginLogin เริ่มกระบวนการตรวจสอบ
func (ws *WebAuthnService) BeginLogin(ctx context.Context, userID string) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	user, err := ws.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("user not found: %w", err)
	}

	// Load credentials
	creds, err := ws.credRepo.FindAllByUserIDAndType(ctx, user.ID, "passkey")
	if err != nil || len(creds) == 0 {
		return nil, nil, fmt.Errorf("no passkey found for user")
	}

	for _, c := range creds {
		var wCred webauthn.Credential
		if err := json.Unmarshal([]byte(c.Secret), &wCred); err == nil {
			user.AddWebAuthnCredential(wCred)
		}
	}

	options, sessionData, err := ws.WebAuthn.BeginLogin(user)
	if err != nil {
		return nil, nil, fmt.Errorf("begin login error: %w", err)
	}

	return options, sessionData, nil
}

// FinishLogin ตรวจสอบยืนยัน Passkey Response
func (ws *WebAuthnService) FinishLogin(ctx context.Context, userID string, sessionData webauthn.SessionData, clientResponse []byte) (*webauthn.Credential, error) {
	user, err := ws.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Load credentials again for validation
	creds, _ := ws.credRepo.FindAllByUserIDAndType(ctx, user.ID, "passkey")
	for _, c := range creds {
		var wCred webauthn.Credential
		if err := json.Unmarshal([]byte(c.Secret), &wCred); err == nil {
			user.AddWebAuthnCredential(wCred)
		}
	}


	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(clientResponse))
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	// Validate assertion
	credential, err := ws.WebAuthn.ValidateLogin(user, sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("validate login error: %w", err)
	}

	// Update LastUsedAt in DB 
	// (หาว่า credential อันไหนถูกใช้โดยเอา id มาเทียบ - WebAuthn ID เป็น byte array)
    for _, c := range creds {
        var wCred webauthn.Credential
        if err := json.Unmarshal([]byte(c.Secret), &wCred); err == nil {
            if string(wCred.ID) == string(credential.ID) {
                // TODO: Update c.LastUsedAt = time.Now() ใน DB (ถ้ามี implementation update ใน user_credential_repo)
                break
            }
        }
    }


	return credential, nil
}
