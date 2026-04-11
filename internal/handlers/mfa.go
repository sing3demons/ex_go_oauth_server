package handlers

import (
	"net/http"
	"net/url"
	"time"

	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/pkg/kp"
	"github.com/sing3demons/oauth_server/pkg/utils"
)

type MFAHandler struct {
	oauthHandler *OAuthHandler
}

func NewMFAHandler(oauthHandler *OAuthHandler) *MFAHandler {
	return &MFAHandler{
		oauthHandler: oauthHandler,
	}
}

// VerifyUI (GET /mfa/verify)
func (h *MFAHandler) VerifyUI(ctx *kp.Ctx) {
	sid := ctx.Req.URL.Query().Get("sid")
	tid := ctx.Req.URL.Query().Get("tid")

	if sid == "" || tid == "" {
		ctx.Redirect("/login?error=invalid_request", http.StatusFound)
		return
	}

	// ตรวจสอบสถานะการรอ MFA ใน Redis
	pending, err := h.oauthHandler.transactionCache.GetTransaction(ctx, "mfa:"+tid)
	if err != nil || pending == nil || pending.State != "mfa_pending" {
		ctx.Redirect("/login?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=session_expired", http.StatusFound)
		return
	}

	data := struct {
		SID   string
		TID   string
		Error string
	}{
		SID:   sid,
		TID:   tid,
		Error: ctx.Req.URL.Query().Get("error"),
	}

	ctx.RenderTemplate("templates/mfa_verify.html", data)
}

// VerifySubmit (POST /mfa/verify)
func (h *MFAHandler) VerifySubmit(ctx *kp.Ctx) {
	sid := ctx.Req.URL.Query().Get("sid")
	tid := ctx.Req.URL.Query().Get("tid")
	code := ctx.Req.FormValue("code")

	if sid == "" || tid == "" || code == "" {
		ctx.Redirect("/mfa/verify?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error=missing_code", http.StatusFound)
		return
	}

	// 1. ตรวจสอบสถานะการรอ MFA ใน Redis
	pending, err := h.oauthHandler.transactionCache.GetTransaction(ctx, "mfa:"+tid)
	if err != nil || pending == nil || pending.State != "mfa_pending" {
		ctx.Redirect("/login?error=session_expired", http.StatusFound)
		return
	}

	// 2. ตรวจสอบรหัส OTP
	valid, err := h.oauthHandler.otpService.VerifyOTP(ctx, pending.UserID, code)
	if err != nil || !valid {
		reason := "invalid_code"
		if err != nil && err.Error() == "otp_expired" {
			reason = "code_expired"
		}

		ctx.Redirect("/mfa/verify?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid)+"&error="+reason, http.StatusFound)
		return
	}

	// 3. หากผ่าน: ลบสถานะ Pending และสร้าง Session จริง
	h.oauthHandler.transactionCache.DeleteTransaction(ctx, "mfa:"+tid)

	// Fetch User info for session
	user, _ := h.oauthHandler.userRepo.FindByID(ctx, pending.UserID)
	if user == nil {
		ctx.Redirect("/login?error=server_error", http.StatusFound)
		return
	}

	// สร้าง Session (Logic เดียวกับ LoginSuccess)
	deviceInfo := utils.GetDeviceInfo(ctx.Req.UserAgent())
	sessionInfo := &models.SessionInfo{
		SID:            sid,
		UserID:         user.ID,
		LoggedInAt:     time.Now(),
		LastActivityAt: time.Now(),
		IPAddress:      ctx.Req.RemoteAddr,
		UserAgent:      ctx.Req.UserAgent(),
		DeviceInfo:     deviceInfo,
	}
	h.oauthHandler.sessionCache.SetSession(ctx, sid, sessionInfo, 24*time.Hour)

	// บันทึก Audit Log
	h.oauthHandler.auditRepo.Save(ctx, &models.AuditLog{
		UserID:     user.ID,
		Event:      "mfa_success",
		IPAddress:  ctx.Req.RemoteAddr,
		UserAgent:  ctx.Req.UserAgent(),
		DeviceInfo: deviceInfo,
	})

	// ฝัง Cookie
	http.SetCookie(ctx.Res, &http.Cookie{
		Name:     "oidc_session",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})

	ctx.Redirect("/consent?sid="+url.QueryEscape(sid)+"&tid="+url.QueryEscape(tid), http.StatusFound)
}

// SetupUI (GET /mfa/setup) - สำหรับเรียกจากหน้า Account
func (h *MFAHandler) SetupUI(ctx *kp.Ctx) {
	// ต้องมี Session ก่อน
	cookie, err := ctx.Req.Cookie("oidc_session")
	if err != nil || cookie.Value == "" {
		ctx.Redirect("/login", http.StatusFound)
		return
	}

	session, _ := h.oauthHandler.sessionCache.GetSession(ctx, cookie.Value)
	if session == nil {
		ctx.Redirect("/login", http.StatusFound)
		return
	}

	user, _ := h.oauthHandler.userRepo.FindByID(ctx, session.UserID)

	// สร้าง Secret สำหรับการ Setup
	secret, qrUrl, err := h.oauthHandler.otpService.GenerateTOTP(ctx, user.ID, user.Username)
	if err != nil {
		ctx.Redirect("/account?error=setup_failed", http.StatusFound)
		return
	}

	// เก็บ Secret ชั่วคราวไว้ใน Redis ระหว่างรอการ Verify ครั้งแรก (อายุ 10 นาที)
	h.oauthHandler.transactionCache.SetTransaction(ctx, "mfa_setup:"+user.ID, &models.AuthTransaction{
		UserID: user.ID,
		State:  secret, // เก็บ Secret ไว้ที่นี่ชั่วคราว
	}, 10*time.Minute)

	data := struct {
		QRUrl  string
		Secret string
		Error  string
	}{
		QRUrl:  qrUrl,
		Secret: secret,
		Error:  ctx.Req.URL.Query().Get("error"),
	}

	ctx.RenderTemplate("templates/mfa_setup.html", data)
}

// SetupSubmit (POST /mfa/setup)
func (h *MFAHandler) SetupSubmit(ctx *kp.Ctx) {
	cookie, err := ctx.Req.Cookie("oidc_session")
	if err != nil {
		ctx.Redirect("/login", http.StatusFound)
		return
	}

	session, _ := h.oauthHandler.sessionCache.GetSession(ctx, cookie.Value)
	if session == nil {
		ctx.Redirect("/login", http.StatusFound)
		return
	}

	code := ctx.Req.FormValue("code")

	// 1. ดึง Secret ที่เก็บไว้ชั่วคราว
	pending, err := h.oauthHandler.transactionCache.GetTransaction(ctx, "mfa_setup:"+session.UserID)
	if err != nil || pending == nil {
		ctx.Redirect("/mfa/setup?error=timeout", http.StatusFound)
		return
	}

	// 2. ตรวจสอบรหัสครั้งแรก
	err = h.oauthHandler.otpService.EnrollmentVerify(ctx, session.UserID, pending.State, code)
	if err != nil {
		ctx.Redirect("/mfa/setup?error=invalid_code", http.StatusFound)
		return
	}

	// 3. บันทึกลง UserCredential
	cred := &models.UserCredential{
		UserID:     session.UserID,
		Type:       "totp",
		Secret:     pending.State,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}
	h.oauthHandler.userCredentialRepo.Create(ctx, cred)

	// 4. อัปเดต User.MFAEnabled = true
	h.oauthHandler.userRepo.UpdateMFAEnabled(ctx, session.UserID, true)

	// 5. บันทึก Audit Log
	h.oauthHandler.auditRepo.Save(ctx, &models.AuditLog{
		UserID:    session.UserID,
		Event:     "mfa_enabled",
		IPAddress: ctx.Req.RemoteAddr,
		UserAgent: ctx.Req.UserAgent(),
	})

	h.oauthHandler.transactionCache.DeleteTransaction(ctx, "mfa_setup:"+session.UserID)
	ctx.Redirect("/account?success=mfa_enabled", http.StatusFound)
}
