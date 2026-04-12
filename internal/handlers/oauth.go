package handlers

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mssola/user_agent"
	"github.com/sing3demons/oauth_server/internal/adapters/mongo_store"
	"github.com/sing3demons/oauth_server/internal/adapters/redis_store"
	"github.com/sing3demons/oauth_server/internal/config"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/internal/core/ports"
	"github.com/sing3demons/oauth_server/internal/core/services"
	pkgErrors "github.com/sing3demons/oauth_server/pkg/errors"
	"github.com/sing3demons/oauth_server/pkg/kp"
	"github.com/sing3demons/oauth_server/pkg/logger"
	"github.com/sing3demons/oauth_server/pkg/response"
	"github.com/sing3demons/oauth_server/pkg/utils"
	"golang.org/x/crypto/bcrypt"
)

type OAuthHandler struct {
	oauthService       *services.OAuthService
	otpService         *services.OTPService
	userRepo           ports.UserRepository
	userCredentialRepo ports.UserCredentialRepository
	userProfileRepo    ports.UserProfileRepository
	clientRepo         ports.ClientRepository
	sessionCache       *redis_store.SessionCache
	transactionCache   *redis_store.TransactionCache
	auditRepo          *mongo_store.AuditRepository
	rateLimitStore     ports.RateLimitStore
	cfg                *config.Config
}

func NewOAuthHandler(
	cfg *config.Config,
	clientRepo ports.ClientRepository,
	userRepo ports.UserRepository,
	userProfileRepo ports.UserProfileRepository,
	oauthService *services.OAuthService,
	otpService *services.OTPService,
	userCredentialRepo ports.UserCredentialRepository,
	sessionCache *redis_store.SessionCache,
	transactionCache *redis_store.TransactionCache,
	auditRepo *mongo_store.AuditRepository,
	rateLimitStore ports.RateLimitStore,
) *OAuthHandler {
	return &OAuthHandler{
		cfg:                cfg,
		clientRepo:         clientRepo,
		userRepo:           userRepo,
		userProfileRepo:    userProfileRepo,
		oauthService:       oauthService,
		otpService:         otpService,
		userCredentialRepo: userCredentialRepo,
		sessionCache:       sessionCache,
		transactionCache:   transactionCache,
		auditRepo:          auditRepo,
		rateLimitStore:     rateLimitStore,
	}
}

func (h *OAuthHandler) calculateOTPBan(attempts int) time.Duration {
	step := attempts / 5
	if step == 0 {
		return 0
	}

	// Dynamic Staircase Calculation: 30s * step!
	// Step 1 (5-9): 30s * 1 = 30s
	// Step 2 (10-14): 30s * 2 = 60s
	// Step 3 (15-19): 60s * 3 = 180s
	// Step 4 (20-24): 180s * 4 = 720s (12m)
	// Caps at 1 hour (3600s)

	duration := 30 // base 30s
	for i := 2; i <= step; i++ {
		duration *= i
		if duration > 3600 {
			duration = 3600
			break
		}
	}

	return time.Duration(duration) * time.Second
}

func (h *OAuthHandler) isOTPBanned(user *models.User) (bool, time.Duration) {
	if user == nil || user.OTPBlockedUntil == nil {
		return false, 0
	}
	now := time.Now()
	if now.Before(*user.OTPBlockedUntil) {
		return true, user.OTPBlockedUntil.Sub(now)
	}
	return false, 0
}

func (h *OAuthHandler) insertTransaction(ctx *kp.Ctx, query url.Values, tid string) (response.MessageError, *response.Error) {
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	// 1. Validate client exists and redirect_uri is registered (MUST do first per RFC 6749 4.1.2.1)
	client, err := h.clientRepo.FindByIDWithCache(ctx, clientID)
	if err != nil || client == nil {
		return response.InvalidClient, &response.Error{
			Err:     fmt.Errorf("client not found: %s", clientID),
			Message: response.InvalidClient,
		}
	}

	validURI := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validURI = true
			break
		}
	}
	if !validURI {
		return response.InvalidGrant, &response.Error{
			Err:     fmt.Errorf("redirect_uri not registered: %s", redirectURI),
			Message: response.InvalidGrant,
		}
	}

	responseType := query.Get("response_type")
	// 2. Validate response_type against server's supported list from config
	responseTypeAllowed := false
	for _, rt := range h.cfg.Oidc.SupportedResponseTypes {
		if rt == responseType {
			responseTypeAllowed = true
			break
		}
	}
	if !responseTypeAllowed {
		return response.UnsupportedResponseType, &response.Error{
			Err:     fmt.Errorf("unsupported response_type: %s", responseType),
			Message: response.UnsupportedResponseType,
		}
	}

	// Scope Validation
	requestedScopes := strings.Fields(query.Get("scope"))

	// 1. openid scope บังคับใน OIDC (RFC)
	hasOpenID := false
	for _, s := range requestedScopes {
		if s == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return response.InvalidScope, &response.Error{
			Err:     fmt.Errorf("scope 'openid' is required"),
			Message: "scope 'openid' is required for OIDC requests",
		}
	}

	// 2. กรอง scope ที่ server รองรับก่อน (server-level)
	serverScopesSet := make(map[string]struct{}, len(h.cfg.Oidc.SupportedScopes))
	for _, s := range h.cfg.Oidc.SupportedScopes {
		serverScopesSet[s] = struct{}{}
	}
	// 3. ตรวจว่า Client อนุญาต Scopes ที่ขอไหม (client-level) - กรองทิ้งแทน Error
	allowedSet := make(map[string]struct{}, len(client.AllowedScopes))
	for _, s := range client.AllowedScopes {
		allowedSet[s] = struct{}{}
	}

	var finalScopes []string
	for _, s := range requestedScopes {
		_, isServerSupported := serverScopesSet[s]
		_, isClientAllowed := allowedSet[s]

		if isServerSupported && isClientAllowed {
			finalScopes = append(finalScopes, s)
		}
	}
	requestedScopes = finalScopes
	// PKCE Enforcement
	codeChallenge := query.Get("code_challenge")
	if (client.ClientType == "public" || client.RequirePKCE) && codeChallenge == "" {
		return response.MissingOrInvalidParameter, &response.Error{
			Err:     fmt.Errorf("code_challenge is required for this client"),
			Message: "PKCE is mandatory for this client",
		}
	}

	tx := &models.AuthTransaction{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              requestedScopes,
		State:               query.Get("state"),
		Nonce:               query.Get("nonce"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		ExpiresAt:           time.Now().Add(15 * time.Minute),
	}

	if err := h.transactionCache.SetTransaction(ctx, tid, tx, 15*time.Minute); err != nil {
		return response.SystemError, &response.Error{
			Err:     err,
			Message: response.SystemError,
		}
	}
	return response.Success, nil
}

func (h *OAuthHandler) Authorize(ctx *kp.Ctx) {
	ctx.Log("authorize")

	query := ctx.Req.URL.Query()
	sid := ctx.SessionId() // cookie override จัดการใน ensureRequestMetadata แล้ว
	tid := ctx.TransactionId()
	errMsg := query.Get("error")
	client_id := query.Get("client_id")
	redirect_uri := query.Get("redirect_uri")

	// 0. ตรวจสอบว่ามี Error มาจากหน้า Logout หรือไม่ (Allow rendering without Client context for Logout)
	if errMsg != "" && (client_id == "" || redirect_uri == "") {
		h.renderAuthPage(ctx, "", "", errMsg)
		return
	}

	if errMsg != "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("error: %s", errMsg),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	if client_id == "" || redirect_uri == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing required parameters: client_id=%s, redirect_uri=%s", client_id, redirect_uri),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	queryTid := query.Get("tid")
	// 1. ถ้าไม่มี tid แสดงว่าเป็นการเริ่ม OAuth Flow ใหม่
	if queryTid == "" {
		body, err := h.insertTransaction(ctx, query, tid)
		if err != nil {
			// RFC 6749 4.1.2.1: If redirect_uri/client_id are valid, redirect errors back to the client.
			if body == response.UnsupportedResponseType || body == response.InvalidScope || body == response.SystemError {
				redirectURI := query.Get("redirect_uri")
				if redirectURI != "" {
					u, _ := url.Parse(redirectURI)
					q := u.Query()
					switch body {
					case response.UnsupportedResponseType:
						q.Set("error", "unsupported_response_type")
					case response.InvalidScope:
						q.Set("error", "invalid_scope")
					case response.SystemError:
						q.Set("error", "server_error")
					}
					q.Set("error_description", err.Error())
					if state := query.Get("state"); state != "" {
						q.Set("state", state)
					}
					u.RawQuery = q.Encode()
					ctx.Redirect(u.String(), http.StatusFound)
					return
				}
			}
			ctx.JsonError(err, body.Error())
			return
		}
	} else {
		// 2. ถ้ามี tid อยู่แล้ว เช็คว่าความจำนี้หมดอายุหรือยัง
		_, err := h.transactionCache.GetTransaction(ctx, tid)
		if err != nil {
			if errors.Is(err, pkgErrors.ErrNotFound) {
				body, err := h.insertTransaction(ctx, query, tid)
				if err != nil {
					if body == response.UnsupportedResponseType || body == response.InvalidScope || body == response.SystemError {
						redirectURI := query.Get("redirect_uri")
						if redirectURI != "" {
							u, _ := url.Parse(redirectURI)
							q := u.Query()
							switch body {
							case response.UnsupportedResponseType:
								q.Set("error", "unsupported_response_type")
							case response.InvalidScope:
								q.Set("error", "invalid_scope")
							case response.SystemError:
								q.Set("error", "server_error")
							}
							q.Set("error_description", err.Error())
							if state := query.Get("state"); state != "" {
								q.Set("state", state)
							}
							u.RawQuery = q.Encode()
							ctx.Redirect(u.String(), http.StatusFound)
							return
						}
					}
					ctx.JsonError(err, body.Error())
					return
				}
			} else {
				ctx.JsonError(&response.Error{
					Err:     err,
					Message: "Session or Transaction expired. Please return to your app and try again.",
				}, map[string]string{"error": "transaction_expired"})
				return
			}
		}
	}

	// 2.5 ตรวจสอบว่ามี sid อยู่ในระบบ (Log in ค้างไว้) หรือไม่
	session, _ := h.sessionCache.GetSession(ctx, sid)
	if session != nil {
		// ถ้าเคย Login แล้ว พาไปหน้า Consent ทันที
		ctx.Redirect("/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		return
	}

	// 3. Render Unified Auth Page
	h.renderAuthPage(ctx, sid, tid, errMsg)
}

func (h *OAuthHandler) renderAuthPage(ctx *kp.Ctx, sid, tid, errMsg string) {
	type AuthPageData struct {
		SID   string
		TID   string
		Error string
	}
	data := AuthPageData{
		SID:   sid,
		TID:   tid,
		Error: errMsg,
	}

	ctx.RenderTemplate("templates/auth.html", data, http.StatusOK)
}

func (h *OAuthHandler) findUserByUsernameOrEmail(ctx *kp.Ctx, identifier string) (*models.UserCredential, bool, error) {
	if utils.IsEmail(identifier) {
		result, err := h.userCredentialRepo.FindByEmailPassword(ctx, identifier)
		return result, true, err
	}
	result, err := h.userCredentialRepo.FindByUsernamePassword(ctx, identifier)
	return result, false, err
}
func (h *OAuthHandler) LoginSubmit(ctx *kp.Ctx) {
	maskingOptions := []logger.MaskingOption{
		{
			MaskingField: "body.password",
			MaskingType:  logger.MaskCustom,
			Callback:     utils.MaskPassword,
		}, {
			MaskingField: "body.username",
			MaskingType:  logger.MaskCustom,
			Callback:     utils.MaskUsernameOrEmail,
		}}

	ctx.Log("login", maskingOptions...)
	// RateLimit
	if err := h.RateLimit(ctx, 5, 1*time.Minute); err != nil {
		ctx.JsonError(err, err.Message.Error())
		return
	}

	sid := ctx.Query("sid")
	tid := ctx.Query("tid")

	if sid == "" || tid == "" {
		// http.Error(w, "Missing session or transaction ID", http.StatusBadRequest)
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing session or transaction ID"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	username := ctx.FormValue("username")
	password := ctx.FormValue("password")
	// check if username is email format, if yes, find credential by email, otherwise by username

	credential, isEmail, err := h.findUserByUsernameOrEmail(ctx, username)
	if err != nil || credential == nil {
		h.auditRepo.Save(ctx, &models.AuditLog{
			UserID:     username, // Use username if ID unknown
			Event:      "login_failed",
			IPAddress:  ctx.IP(),
			UserAgent:  ctx.UserAgent(),
			DeviceInfo: ctx.UserAgent(), // Raw for now, parser later
			Reason:     "user_not_found",
		})
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=invalid_credentials", http.StatusFound)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(credential.Secret), []byte(password))
	if err != nil {
		h.auditRepo.Save(ctx, &models.AuditLog{
			UserID:     credential.UserID,
			Event:      "login_failed",
			IPAddress:  ctx.IP(),
			UserAgent:  ctx.UserAgent(),
			DeviceInfo: ctx.UserAgent(),
			Reason:     "password_incorrect",
		})
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=invalid_credentials", http.StatusFound)
		return
	}

	if isEmail {
		// 🔥 Check if user is banned
		u, _ := h.userRepo.FindByID(ctx, credential.UserID)
		if banned, remaining := h.isOTPBanned(u); banned {
			ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+
				"&error=temporary_lockout&error_description="+url.QueryEscape(fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", int(remaining.Seconds()))),
				http.StatusFound)
			return
		}

		// 0. ลบ OTP เก่าของ user คนนี้ทิ้งก่อน เพื่อป้องกันความซ้ำซ้อน
		h.userCredentialRepo.DeleteAllByUserIDAndType(ctx, credential.UserID, "otp")

		// gen otp for email login and save to cache with 5 min TTL, then redirect to OTP verification page
		exp := time.Now().Add(5 * time.Minute)
		otpCode := utils.GenerateOTP(3)
		credential := models.UserCredential{
			ID:         uuid.New().String(),
			UserID:     credential.UserID,
			Type:       "otp",
			Identifier: username,
			Secret:     otpCode,
			Verified:   false,
			CreatedAt:  time.Now(),
			LastUsedAt: time.Now(),
			Revoked:    false,
			ExpiresAt:  &exp,
		}
		if err := h.userCredentialRepo.Create(ctx, &credential); err != nil {
			ctx.JsonError(&response.Error{
				Err:     err,
				Message: response.SystemError,
			}, response.SystemError.Error())
			return
		}

		// ส่ง OTP ผ่าน Email (จำลอง)
		// render OTP page with OTP code for demo (ใน production ต้องส่ง email เท่านั้น)
		ctx.RenderTemplate("templates/otp.html", map[string]any{
			"SID":         sid,
			"TID":         tid,
			"Username":    username,
			"OTP":         otpCode,                                 // For demo purposes, we show the OTP on the page
			"ExpiresAt":   exp.Unix(),                              // OTP expiry
			"ResendAfter": time.Now().Add(60 * time.Second).Unix(), // Can resend after 60s
		}, http.StatusOK)
		return
	}

	// 🔥 MFA Check
	user, _ := h.userRepo.FindByID(ctx, credential.UserID)
	if user != nil && user.MFAEnabled {
		// เก็บสถานะรอการยืนยัน MFA ไว้ใน Transaction Cache (อายุ 5 นาที)
		// ใช้ tid เป็น key เพื่อความปลอดภัยเพราะผูกกับ OAuth Flow
		mfaTx := &models.AuthTransaction{
			ID:     tid,
			UserID: user.ID,
			SID:    sid,
			State:  "mfa_pending",
		}
		h.transactionCache.SetTransaction(ctx, "mfa:"+tid, mfaTx, 5*time.Minute)

		ctx.Redirect("/mfa/verify?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		return
	}

	h.redirectToConsent(ctx, "login_success", credential.UserID, sid, tid)
}
func (h *OAuthHandler) deviceInfo(ctx *kp.Ctx) string {
	ua := user_agent.New(ctx.UserAgent())
	browser, version := ua.Browser()
	os := ua.OS()
	deviceInfo := fmt.Sprintf("%s (%s %s)", os, browser, version)
	return deviceInfo

}

func (h *OAuthHandler) OtpVerifySubmit(ctx *kp.Ctx) {
	ctx.Log("otp_verify")

	sid := ctx.FormValue("sid")
	tid := ctx.FormValue("tid")
	username := ctx.FormValue("username")
	otpCode := ctx.FormValue("otp")

	if sid == "" || tid == "" || username == "" || otpCode == "" {
		ctx.RenderTemplate("templates/otp.html", map[string]any{
			"SID":      sid,
			"TID":      tid,
			"Username": username,
			"Error":    "Missing required parameters",
		}, http.StatusBadRequest)
		return
	}

	// is email format?
	if !utils.IsEmail(username) {
		ctx.RenderTemplate("templates/otp.html", map[string]any{
			"SID":      sid,
			"TID":      tid,
			"Username": username,
			"Error":    "Invalid username",
		}, http.StatusBadRequest)
		return
	}

	// 1. Find User to get UserID
	user, err := h.userRepo.FindByEmail(ctx, username)
	if err != nil || user == nil {
		ctx.RenderTemplate("templates/otp.html", map[string]any{
			"SID":      sid,
			"TID":      tid,
			"Username": username,
			"Error":    "User not found",
		}, http.StatusNotFound)
		return
	}

	// 🔥 Check if user is banned
	if banned, remaining := h.isOTPBanned(user); banned {
		ctx.RenderTemplate("templates/otp.html", map[string]any{
			"SID":      sid,
			"TID":      tid,
			"Username": username,
			"Error":    fmt.Sprintf("Your account is temporarily locked due to too many failed attempts. Please try again in %d seconds.", int(remaining.Seconds())),
		}, http.StatusTooManyRequests)
		return
	}

	// 2. Find OTP credential
	credential, err := h.userCredentialRepo.FindByUserIDAndType(ctx, user.ID, "otp")
	if err != nil || credential == nil {
		ctx.RenderTemplate("templates/otp.html", map[string]any{
			"SID":      sid,
			"TID":      tid,
			"Username": username,
			"Error":    "Invalid or expired OTP",
		}, http.StatusUnauthorized)
		return
	}

	// Prepare common data for error rendering
	renderData := map[string]any{
		"SID":         sid,
		"TID":         tid,
		"Username":    username,
		"ExpiresAt":   credential.ExpiresAt.Unix(),
		"ResendAfter": credential.CreatedAt.Add(60 * time.Second).Unix(), // Approximate
	}

	// check if OTP expired
	if credential.ExpiresAt == nil || time.Now().After(*credential.ExpiresAt) {
		renderData["Error"] = "OTP expired"
		ctx.RenderTemplate("templates/otp.html", renderData, http.StatusUnauthorized)
		return
	}

	// 3. Validate OTP
	if credential.Secret != otpCode {
		// 🔥 Handle Failure and Throttling
		newAttempts := user.OTPFailedAttempts + 1
		var blockedUntil *time.Time
		banDuration := h.calculateOTPBan(newAttempts)

		if banDuration > 0 {
			exp := time.Now().Add(banDuration)
			blockedUntil = &exp
		}

		// Update throttling state in DB
		h.userRepo.UpdateOTPThrottling(ctx, user.ID, newAttempts, blockedUntil)

		errorMsg := fmt.Sprintf("Invalid OTP code. You have failed %d times.", newAttempts)
		if banDuration > 0 {
			errorMsg = fmt.Sprintf("Too many failed attempts. Account locked for %d seconds. Please request a new code after the ban expires.", int(banDuration.Seconds()))
			// Invalidate current OTP on ban milestones
			if newAttempts%5 == 0 {
				h.userCredentialRepo.DeleteByID(ctx, credential.ID)
			}
		}

		renderData["Error"] = errorMsg
		ctx.RenderTemplate("templates/otp.html", renderData, http.StatusOK)
		return
	}

	// 4. Success Logic - Reset Throttling
	h.userRepo.UpdateOTPThrottling(ctx, user.ID, 0, nil)

	// Mark OTP as used (Delete it)
	h.userCredentialRepo.DeleteByID(ctx, credential.ID)

	// 5. Success Logic
	h.redirectToConsent(ctx, "login_success_otp", credential.UserID, sid, tid)
}

func (h *OAuthHandler) redirectToConsent(ctx *kp.Ctx, event, uid, sid, tid string) {
	deviceInfo := h.deviceInfo(ctx)
	h.auditRepo.Save(ctx, &models.AuditLog{
		UserID:     uid,
		Event:      event,
		IPAddress:  ctx.IP(),
		UserAgent:  ctx.UserAgent(),
		DeviceInfo: deviceInfo,
	})

	sessionInfo := &models.SessionInfo{
		SID:            sid,
		UserID:         uid,
		LoggedInAt:     time.Now(),
		LastActivityAt: time.Now(),
		IPAddress:      ctx.IP(),
		UserAgent:      ctx.UserAgent(),
		DeviceInfo:     deviceInfo,
	}
	h.sessionCache.SetSession(ctx, sid, sessionInfo, 24*time.Hour)

	// ฝัง Cookie เพื่อทำ SSO ทะลุ Flow
	http.SetCookie(ctx.Res, &http.Cookie{
		Name:     "oidc_session",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		// Secure:   true,                 // ← เพิ่ม: HTTPS only
		SameSite: http.SameSiteLaxMode, // ← เพิ่ม: ป้องกัน CSRF
		MaxAge:   86400,
	})

	ctx.Redirect("/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
}

func (h *OAuthHandler) OtpResendSubmit(ctx *kp.Ctx) {
	ctx.Log("otp_resend")

	sid := ctx.FormValue("sid")
	tid := ctx.FormValue("tid")
	username := ctx.FormValue("username")

	if sid == "" || tid == "" || username == "" {
		ctx.JSON(http.StatusBadRequest, map[string]any{"error": "missing_parameters"})
		return
	}

	// 1. Find User to get UserID
	user, err := h.userRepo.FindByEmail(ctx, username)
	if err != nil || user == nil {
		ctx.JSON(http.StatusNotFound, map[string]any{"error": "user_not_found"})
		return
	}

	// 🔥 Check if user is banned
	if banned, remaining := h.isOTPBanned(user); banned {
		ctx.JSON(http.StatusForbidden, map[string]any{
			"error":           "temporary_lockout",
			"message":         fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", int(remaining.Seconds())),
			"remaining_delay": int(remaining.Seconds()),
		})
		return
	}

	// 2. Delete existing OTPs
	h.userCredentialRepo.DeleteAllByUserIDAndType(ctx, user.ID, "otp")

	// 3. Generate New OTP
	exp := time.Now().Add(5 * time.Minute)
	resendAfter := time.Now().Add(60 * time.Second)
	otpCode := utils.GenerateOTP(3)
	credential := models.UserCredential{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		Type:       "otp",
		Identifier: username,
		Secret:     otpCode,
		Verified:   false,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		Revoked:    false,
		ExpiresAt:  &exp,
	}
	if err := h.userCredentialRepo.Create(ctx, &credential); err != nil {
		ctx.JSON(http.StatusInternalServerError, map[string]any{"error": "system_error"})
		return
	}

	// 4. Return success
	ctx.JSON(http.StatusOK, map[string]any{
		"success":      true,
		"otp":          otpCode,
		"expires_at":   exp.Unix(),
		"resend_after": resendAfter.Unix(),
	})
}

func (h *OAuthHandler) RegisterSubmit(ctx *kp.Ctx) {
	maskRegister := []logger.MaskingOption{
		{
			MaskingField: "body.password",
			MaskingType:  logger.MaskCustom,
			Callback:     utils.MaskPassword,
		}, {
			MaskingField: "body.username",
			MaskingType:  logger.MaskCustom,
			Callback:     utils.MaskUsername,
		}, {
			MaskingField: "body.email",
			MaskingType:  logger.MaskCustom,
			Callback:     utils.MaskEmail,
		},
	}
	ctx.Log("register", maskRegister...)

	sid := ctx.Query("sid")
	tid := ctx.Query("tid")

	if sid == "" || tid == "" {
		// http.Error(w, "Missing session or transaction ID", http.StatusBadRequest)
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing session or transaction ID"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())

		return
	}

	username := ctx.FormValue("username")
	email := ctx.FormValue("email")
	password := ctx.FormValue("password")
	givenName := ctx.FormValue("given_name")
	familyName := ctx.FormValue("family_name")
	nickname := ctx.FormValue("nickname")
	gender := ctx.FormValue("gender")
	phoneNumber := ctx.FormValue("phone_number")

	// validate input
	if username == "" || email == "" || password == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing required fields"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	if len(password) < 6 {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("password too short"),
			Message: "Password must be at least 6 characters",
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	if !strings.Contains(email, "@") {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("invalid email format"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	existing, _ := h.userRepo.FindByUsername(ctx, username)
	if existing != nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Username+already+taken#register", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=username_already_taken#register", http.StatusFound)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Server+Error#register", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=server_error#register", http.StatusFound)
		return
	}

	dateNow := time.Now()

	user := &models.User{
		ID:       uuid.New().String(),
		Username: username,
		Email:    email,
		// PasswordHash: string(hash),
		CreatedAt: dateNow,
		UpdatedAt: dateNow,
		Status:    "",
	}
	userCredentialEmail := &models.UserCredential{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		Type:       "password",
		Identifier: email,
		Secret:     string(hash),
		Verified:   true,
		CreatedAt:  dateNow,
		LastUsedAt: dateNow,
	}
	userCredentialUser := &models.UserCredential{
		ID:         uuid.New().String(),
		UserID:     user.ID,
		Type:       "password",
		Identifier: username,
		Secret:     string(hash),
		Verified:   true,
		CreatedAt:  dateNow,
		LastUsedAt: dateNow,
	}

	profile := &models.UserProfile{
		UserID:            user.ID,
		Name:              fmt.Sprintf("%s %s", givenName, familyName),
		GivenName:         givenName,
		FamilyName:        familyName,
		Nickname:          nickname,
		PreferredUsername: username,
		Email:             email,
		EmailVerified:     true,
		Gender:            gender,
		CreatedAt:         dateNow,
		UpdatedAt:         dateNow,
	}
	if phoneNumber != "" {
		profile.PhoneNumber = &phoneNumber
	}

	if err := h.userRepo.Create(ctx, user); err != nil {
		// http.Redirect(w, r, "/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=Database+Error#register", http.StatusFound)
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=database_error#register", http.StatusFound)
		return
	}
	if err := h.userCredentialRepo.CreateMany(ctx, []*models.UserCredential{userCredentialUser, userCredentialEmail}); err != nil {
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=database_error#register", http.StatusFound)
		return
	}
	if err := h.userProfileRepo.Create(ctx, profile); err != nil {
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=database_error#register", http.StatusFound)
		return
	}

	// สร้างสำเร็จ ก็ให้ Login ผ่านต่อเลย
	// sessionInfo := &models.SessionInfo{
	// 	UserID:     user.ID,
	// 	LoggedInAt: time.Now(),
	// }
	// h.sessionCache.SetSession(ctx, sid, sessionInfo, 24*time.Hour)

	// // ฝัง Cookie เพื่อทำ SSO ทะลุ Flow
	// http.SetCookie(ctx.Res, &http.Cookie{
	// 	Name:     "oidc_session",
	// 	Value:    sid,
	// 	Path:     "/",
	// 	HttpOnly: true,
	// 	MaxAge:   86400,
	// })

	// ctx.Redirect("/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
	h.redirectToConsent(ctx, "register_success", user.ID, sid, tid)
}

func (h *OAuthHandler) completeAuth(ctx *kp.Ctx, sid, tid, userID string) {

	// 2. ดึง Transaction ก้อนเดิมออกมา
	tx, err := h.transactionCache.GetTransaction(ctx.Context(), tid)
	if err != nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Transaction expired"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// 3. ปล่อย AuthCode ตามระบบ OAuth2
	code, err := h.oauthService.GenerateAuthCode(ctx.Context(), sid, tx.ClientID, userID, tx.RedirectURI, tx.Nonce, tx.Scopes, tx.CodeChallenge, tx.CodeChallengeMethod)
	if err != nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Failed to authorize: %s", err.Error()),
			Message: response.ServerError,
		}, response.ServerError.Error())
		return
	}

	// 4. ลบ Transaction ทิ้งเมื่อใช้งานเสร็จ
	h.transactionCache.DeleteTransaction(ctx.Context(), tid)

	// 5. บินกลับไปเวป Client หรือส่ง JSON ถ่าไม่มี Redirect URI
	if tx.RedirectURI == "" {
		ctx.JSON(http.StatusOK, map[string]string{
			"code":  code,
			"state": tx.State,
		})
		return
	}

	redirectURL, err := url.Parse(tx.RedirectURI)
	if err != nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Invalid redirect_uri"),
			Message: response.InvalidGrant,
		}, response.InvalidGrant.Error())
		return
	}

	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", tx.State)
	redirectURL.RawQuery = q.Encode()

	ctx.Redirect(redirectURL.String(), http.StatusFound)
}

func (h *OAuthHandler) ConsentUI(ctx *kp.Ctx) {
	ctx.Log("consent_ui")

	sid := ctx.Query("sid")
	tid := ctx.Query("tid")

	if sid == "" || tid == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Missing session or transaction"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	session, err := h.sessionCache.GetSession(ctx, sid)
	if err != nil || session == nil {
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		return
	}

	tx, err := h.transactionCache.GetTransaction(ctx, tid)
	if err != nil || tx == nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Transaction expired"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	client, err := h.clientRepo.FindByIDWithCache(ctx, tx.ClientID)
	if err != nil || client == nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Invalid Client"),
			Message: response.InvalidClient,
		}, response.InvalidClient.Error())
		return
	}

	type ConsentPageData struct {
		SID        string
		TID        string
		ClientName string
		Scopes     []string
	}

	data := ConsentPageData{
		SID:        sid,
		TID:        tid,
		ClientName: client.ClientName,
		Scopes:     tx.Scopes,
	}

	ctx.RenderTemplate("templates/consent.html", data, http.StatusOK)
}

func (h *OAuthHandler) ConsentSubmit(ctx *kp.Ctx) {
	ctx.Log("consent_submit")

	sid := ctx.FormValue("sid")
	tid := ctx.FormValue("tid")
	action := ctx.FormValue("action")

	if sid == "" || tid == "" {
		// http.Error(w, "Missing mapping", http.StatusBadRequest)
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Missing session or transaction ID"),
			Message: response.MissingOrInvalidParameter,
		}, response.MissingOrInvalidParameter.Error())
		return
	}

	session, err := h.sessionCache.GetSession(ctx, sid)
	if err != nil || session == nil {
		ctx.Redirect("/authorize?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
		return
	}

	tx, err := h.transactionCache.GetTransaction(ctx, tid)
	if err != nil || tx == nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Transaction expired"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	if action == "deny" {
		h.transactionCache.DeleteTransaction(ctx, tid)
		if tx.RedirectURI == "" {
			ctx.JsonError(&response.Error{
				Err:     fmt.Errorf("access denied by user"),
				Message: response.AccessDenied,
			}, response.AccessDenied.Error())
			return
		}

		redirectURL, _ := url.Parse(tx.RedirectURI)
		q := redirectURL.Query()
		q.Set("error", "access_denied")
		if tx.State != "" {
			q.Set("state", tx.State)
		}
		redirectURL.RawQuery = q.Encode()
		ctx.Redirect(redirectURL.String(), http.StatusFound)
		return
	}

	// ถ้ากด Allow อนุญาตให้ดำเนินการสร้าง Authorization Code
	h.completeAuth(ctx, sid, tid, session.UserID)
}

// Token (POST /token) เปิดรับให้ Backend เอารหัสมาแลกเป็นตัว JWT
func (h *OAuthHandler) Token(ctx *kp.Ctx) {

	if err := ctx.Req.ParseForm(); err != nil {
		ctx.Log("token")
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Invalid form data: %s", err.Error()),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	grantType := ctx.FormValue("grant_type")

	// Validate grant_type against server-supported list from config
	supportedGrants := h.cfg.GetArray("oidc.grant_types_supported")
	grantAllowed := slices.Contains(supportedGrants, grantType)
	if !grantAllowed {
		ctx.Log("token")
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Unsupported grant type: %s", grantType),
			Message: response.UnsupportedResponseType,
		}, response.UnsupportedResponseType.Error())
		return
	}

	ctx.Log("token_" + grantType)

	code := ctx.FormValue("code")
	clientID := ctx.FormValue("client_id")
	clientSecret := ctx.FormValue("client_secret")

	// Detect which auth method the client used
	var usedAuthMethod string
	basicID, basicSecret, hasBasicAuth := ctx.Req.BasicAuth()
	if hasBasicAuth {
		usedAuthMethod = "client_secret_basic"
		if clientID == "" {
			clientID = basicID
		}
		if clientSecret == "" {
			clientSecret = basicSecret
		}
	} else if clientSecret != "" {
		usedAuthMethod = "client_secret_post"
	} else {
		usedAuthMethod = "none"
	}

	var resp map[string]any
	var err error

	type TokenBody struct {
		GrantType    string `json:"grant_type"`
		Code         string `json:"code,omitempty"`
		RedirectURI  string `json:"redirect_uri,omitempty"`
		ClientID     string `json:"client_id,omitempty"`
		ClientSecret string `json:"client_secret,omitempty"`
		CodeVerifier string `json:"code_verifier,omitempty"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Scope        string `json:"scope,omitempty"`

		// For Token Exchange
		SubjectToken     string `json:"subject_token,omitempty"`
		SubjectTokenType string `json:"subject_token_type,omitempty"`
		Audience         string `json:"audience,omitempty"`

		// For JWT Bearer
		Assertion string `json:"assertion,omitempty"`
	}

	body := TokenBody{
		RedirectURI:      ctx.FormValue("redirect_uri"),
		CodeVerifier:     ctx.FormValue("code_verifier"),
		RefreshToken:     ctx.FormValue("refresh_token"),
		Scope:            ctx.FormValue("scope"),
		SubjectToken:     ctx.FormValue("subject_token"),
		SubjectTokenType: ctx.FormValue("subject_token_type"),
		Audience:         ctx.FormValue("audience"),
		Assertion:        ctx.FormValue("assertion"),
	}

	switch grantType {
	case "authorization_code":
		resp, err = h.oauthService.ExchangeToken(ctx, code, clientID, clientSecret, body.RedirectURI, body.CodeVerifier, usedAuthMethod)
	case "refresh_token":
		resp, err = h.oauthService.RefreshToken(ctx, body.RefreshToken, clientID, clientSecret, usedAuthMethod)
	case "client_credentials":
		scopes := strings.Fields(body.Scope)
		resp, err = h.oauthService.ClientCredentials(ctx, clientID, clientSecret, scopes, usedAuthMethod)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		scopes := strings.Fields(body.Scope)
		resp, err = h.oauthService.TokenExchange(ctx, body.SubjectToken, body.SubjectTokenType, clientID, clientSecret, scopes, body.Audience, usedAuthMethod)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		if body.Assertion == "" {
			err = errors.New("invalid_request: missing assertion parameter")
		} else {
			resp, err = h.oauthService.JWTBearer(ctx, body.Assertion)
		}
	}

	if err != nil {
		// RFC 6749 § 5.2: Error response MUST be in JSON with "error" and "error_description"
		errorType := "invalid_request"
		errorMsg := err.Error()
		if er, ok := err.(*response.Error); ok {
			errorMsg = er.Err.Error()
		}

		// Map common errors to OAuth2 error codes
		errStr := err.Error()
		if strings.Contains(errStr, "invalid_client") {
			errorType = "invalid_client"
		} else if strings.Contains(errStr, "invalid_grant") {
			errorType = "invalid_grant"
		} else if strings.Contains(errStr, "unauthorized_client") {
			errorType = "unauthorized_client"
		} else if strings.Contains(errStr, "unsupported_grant_type") {
			errorType = "unsupported_grant_type"
		} else if strings.Contains(errStr, "invalid_scope") {
			errorType = "invalid_scope"
		}

		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.InvalidRequest,
		}, map[string]string{
			"error":             errorType,
			"error_description": errorMsg,
		})
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

// UserInfo (GET /userinfo) เปิดรับให้ Web/Mobile ตรวจข้อมูลส่วนตัว
func (h *OAuthHandler) UserInfo(ctx *kp.Ctx) {
	ctx.Log("userinfo")
	authHeader := ctx.Req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Missing or invalid Bearer token"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// 1. ตรวจสอบความถูกต้องของ JWT
	claims, err := h.oauthService.ValidateAccessToken(ctx, tokenStr)
	if err != nil {
		// http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// 2. ควัก ID ผู้ใช้จาก 'uid' (Internal/Encrypted) และ 'sub' (Public)
	encryptedUID, _ := claims["uid"].(string)
	sub, _ := claims["sub"].(string)

	var uid string
	// var err error
	if encryptedUID != "" {
		uid, err = h.oauthService.DecryptUserID(encryptedUID)
		if err != nil {
			ctx.JsonError(&response.Error{
				Err:     fmt.Errorf("failed to decrypt user identity"),
				Message: response.InvalidRequest,
			}, response.InvalidRequest.Error())
			return
		}
	} else {
		// Fallback for older tokens or systems not using encrypted UID
		uid = sub
	}

	if uid == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("Invalid token claims: missing user identifier"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// 3. ดึงข้อมูล User และ Profile จาก DB
	user, _ := h.userRepo.FindByID(ctx, uid)
	profile, _ := h.userProfileRepo.FindByID(ctx, uid)

	if user == nil {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("User not found"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// 4. ประกอบร่าง JSON ตามมาตรฐาน OIDC
	userInfo := map[string]any{
		"sub": sub, // MUST match the 'sub' in the token
	}

	// ตรวจสอบ Scopes และดึงข้อมูลที่ได้รับอนุญาต
	scopeMap := make(map[string]bool)
	if scopesRaw, ok := claims["scopes"].([]any); ok {
		for _, sRaw := range scopesRaw {
			if s, ok := sRaw.(string); ok {
				scopeMap[s] = true
			}
		}
	}

	if scopeMap["email"] {
		userInfo["email"] = user.Email
		userInfo["email_verified"] = true
	}

	if profile != nil {
		// Use the BuildClaims helper we created earlier
		maps.Copy(userInfo, profile.BuildClaims(scopeMap))
	} else if scopeMap["profile"] {
		// Fallback for basic profile if no rich profile exists
		userInfo["name"] = user.Username
		userInfo["preferred_username"] = user.Username
	}

	ctx.JSON(http.StatusOK, userInfo)
}

// Logout (GET /logout) เปิดรับให้ยุติ Session และลบ Cookie
// Logout (GET /logout) ยุติ Session และลบนามแฝงของผู้ใช้ตามมาตรฐาน OIDC RP-Initiated Logout
func (h *OAuthHandler) Logout(ctx *kp.Ctx) {
	ctx.Log("logout")

	idTokenHint := ctx.Query("id_token_hint")
	postLogoutRedirectURI := ctx.Query("post_logout_redirect_uri")
	state := ctx.Query("state")

	var redirectURI string
	var client *models.Client

	// 1. ถ้ามี id_token_hint ต้องตรวจสอบว่ากุญแจถูกต้องไหม
	if idTokenHint != "" {
		claims, err := h.oauthService.ValidateIDToken(ctx, idTokenHint)
		if err == nil {
			// ดึง client_id จาก aud ใน id_token
			var clientID string
			switch aud := claims["aud"].(type) {
			case string:
				clientID = aud
			case []interface{}:
				if len(aud) > 0 {
					clientID, _ = aud[0].(string)
				}
			}

			if clientID != "" {
				client, _ = h.clientRepo.FindByIDWithCache(ctx, clientID)
			}
		}
	}

	// 2. ตรวจสอบ post_logout_redirect_uri (ต้องมี idTokenHint เสมอเพื่อความปลอดภัย)
	if postLogoutRedirectURI != "" && client != nil {
		valid := slices.Contains(client.PostLogoutRedirectURIs, postLogoutRedirectURI)
		if valid {
			redirectURI = postLogoutRedirectURI
			if state != "" {
				u, _ := url.Parse(redirectURI)
				q := u.Query()
				q.Set("state", state)
				u.RawQuery = q.Encode()
				redirectURI = u.String()
			}
		}
	}

	// Default fallback redirect
	if redirectURI == "" {
		redirectURI = "/authorize?error=Logged+out+successfully"
	}

	// 3. เคลียร์ Session
	if cookie, err := ctx.Req.Cookie("oidc_session"); err == nil {
		sid := cookie.Value
		if sid != "" {
			// บันทึก Logout ใน Audit Log
			if session, err := h.sessionCache.GetSession(ctx, cookie.Value); err == nil {
				h.auditRepo.Save(ctx, &models.AuditLog{
					UserID:    session.UserID,
					Event:     "logout",
					IPAddress: ctx.Req.RemoteAddr,
					UserAgent: ctx.Req.UserAgent(),
				})
			}

			h.sessionCache.DeleteSession(ctx, cookie.Value)
		}
	}

	// ลบ Cookie ก้อนเดิมทิ้ง
	http.SetCookie(ctx.Res, &http.Cookie{
		Name:     "oidc_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	ctx.Redirect(redirectURI, http.StatusFound)
}

// Revoke (POST /revoke) เคลียร์ Token ตาม RFC 7009
func (h *OAuthHandler) Revoke(ctx *kp.Ctx) {
	ctx.Log("revoke")

	if err := ctx.Req.ParseForm(); err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	token := ctx.FormValue("token")
	clientID := ctx.FormValue("client_id")
	clientSecret := ctx.FormValue("client_secret")

	// Detect auth method
	var usedAuthMethod string
	basicID, basicSecret, hasBasicAuth := ctx.Req.BasicAuth()
	if hasBasicAuth {
		usedAuthMethod = "client_secret_basic"
		if clientID == "" {
			clientID = basicID
		}
		if clientSecret == "" {
			clientSecret = basicSecret
		}
	} else if clientSecret != "" {
		usedAuthMethod = "client_secret_post"
	} else {
		usedAuthMethod = "none"
	}

	if token == "" || clientID == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing token or client ID"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	err := h.oauthService.RevokeToken(ctx, token, clientID, clientSecret, usedAuthMethod)
	if err != nil {
		// RFC 7009: Client authentication failed
		errorType := "invalid_client"
		ctx.JSON(http.StatusUnauthorized, map[string]string{
			"error":             errorType,
			"error_description": err.Error(),
		})
		return
	}

	// Always return 200 OK for successful revocation or invalid token
	ctx.JSON(http.StatusOK, map[string]string{"result": "success"})
}

// Introspect (POST /introspect) ตรวจสอบสถานะของ Token ตาม RFC 7662
func (h *OAuthHandler) Introspect(ctx *kp.Ctx) {
	ctx.Log("introspect")
	if err := ctx.Req.ParseForm(); err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// 1. Detect and parse client credentials
	clientID := ctx.FormValue("client_id")
	clientSecret := ctx.FormValue("client_secret")

	var usedAuthMethod string
	basicID, basicSecret, hasBasicAuth := ctx.Req.BasicAuth()
	if hasBasicAuth {
		usedAuthMethod = "client_secret_basic"
		if clientID == "" {
			clientID = basicID
		}
		if clientSecret == "" {
			clientSecret = basicSecret
		}
	} else if clientSecret != "" {
		usedAuthMethod = "client_secret_post"
	} else {
		usedAuthMethod = "none"
	}

	if clientID == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing client credentials"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// 2. Authenticate the calling client
	if _, err := h.oauthService.AuthenticateClient(ctx, clientID, clientSecret, usedAuthMethod); err != nil {
		// RFC 7662: If client auth fails, MUST return HTTP 401
		ctx.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": "client authentication failed"})
		return
	}

	token := ctx.FormValue("token")
	if token == "" {
		ctx.JsonError(&response.Error{
			Err:     fmt.Errorf("missing token"),
			Message: response.InvalidRequest,
		}, response.InvalidRequest.Error())
		return
	}

	// รันผ่านระบบ Validate
	claims, err := h.oauthService.ValidateAccessToken(ctx, token)
	if err != nil {
		// RFC กำหนดไว้ว่าถ้า Token ผิด ให้ตอบแค่ active: false
		ctx.JSON(http.StatusOK, map[string]bool{"active": false})
		return
	}

	var uid string
	if encryptedUID, ok := claims["uid"].(string); ok && encryptedUID != "" {
		uid, _ = h.oauthService.DecryptUserID(encryptedUID)
	}

	// ถ้าถูกต้อง นำข้อมูลกลับมาแพคตามมาตรฐาน
	resp := map[string]any{
		"active": true,
		"iss":    claims["iss"],
		"sub":    claims["sub"],
		"aud":    claims["aud"],
		"exp":    claims["exp"],
		"iat":    claims["iat"],
		"uid":    uid, // Decrypted for internal convenience
	}

	// แปลง Array Scopes กลับเป็นวรรค (Space-separated)
	if scopesRaw, ok := claims["scopes"].([]any); ok {
		var scopes []string
		for _, s := range scopesRaw {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
		resp["scope"] = strings.Join(scopes, " ")
	}

	if cid, ok := claims["client_id"].(string); ok {
		resp["client_id"] = cid
	}

	ctx.JSON(http.StatusOK, resp)
}
