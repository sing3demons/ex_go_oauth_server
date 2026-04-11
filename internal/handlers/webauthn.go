package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/internal/core/services"
	"github.com/sing3demons/oauth_server/pkg/kp"
	"github.com/sing3demons/oauth_server/pkg/utils"
)

type WebAuthnHandler struct {
	oauthHandler    *OAuthHandler
	webAuthnService *services.WebAuthnService
}

func NewWebAuthnHandler(oauthHandler *OAuthHandler, ws *services.WebAuthnService) *WebAuthnHandler {
	return &WebAuthnHandler{
		oauthHandler:    oauthHandler,
		webAuthnService: ws,
	}
}

// ------------------------------------------------------------------
// REGISTRATION
// ------------------------------------------------------------------

// RegisterBegin (GET /webauthn/register/begin)
func (h *WebAuthnHandler) RegisterBegin(ctx *kp.Ctx) {
	// ต้องมี Session (ผู้ใช้อยู่ในระบบ)
	cookie, err := ctx.Req.Cookie("oidc_session")
	if err != nil || cookie.Value == "" {
		ctx.JSON(http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	session, err := h.oauthHandler.sessionCache.GetSession(ctx, cookie.Value)
	if err != nil || session == nil {
		ctx.JSON(http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	options, sessionData, err := h.webAuthnService.BeginRegistration(ctx, session.UserID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	// บันทึก SessionData ไว้ใน TransactionCache (10 นาที)
	sessionDataJSON, _ := json.Marshal(sessionData)
	h.oauthHandler.transactionCache.SetTransaction(ctx, "webauthn_reg:"+session.UserID, &models.AuthTransaction{
		UserID: session.UserID,
		State:  string(sessionDataJSON),
	}, 10*time.Minute)

	ctx.JSON(http.StatusOK, options)
}

// RegisterFinish (POST /webauthn/register/finish)
func (h *WebAuthnHandler) RegisterFinish(ctx *kp.Ctx) {
	cookie, err := ctx.Req.Cookie("oidc_session")
	if err != nil || cookie.Value == "" {
		ctx.JSON(http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	session, err := h.oauthHandler.sessionCache.GetSession(ctx, cookie.Value)
	if err != nil || session == nil {
		ctx.JSON(http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	// ดึง SessionData 
	tx, err := h.oauthHandler.transactionCache.GetTransaction(ctx, "webauthn_reg:"+session.UserID)
	if err != nil || tx == nil {
		ctx.JSON(http.StatusBadRequest, map[string]any{"error": "registration session expired"})
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(tx.State), &sessionData); err != nil {
		ctx.JSON(http.StatusInternalServerError, map[string]any{"error": "failed to decode session data"})
		return
	}

	clientResponse, err := io.ReadAll(ctx.Req.Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]any{"error": "invalid format"})
		return
	}

	err = h.webAuthnService.FinishRegistration(ctx, session.UserID, sessionData, clientResponse)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	// ลบ Transaction 
	h.oauthHandler.transactionCache.DeleteTransaction(ctx, "webauthn_reg:"+session.UserID)

	// บันทึก Audit Log
	h.oauthHandler.auditRepo.Save(ctx, &models.AuditLog{
		UserID:     session.UserID,
		Event:      "webauthn_registered",
		IPAddress:  ctx.Req.RemoteAddr,
		UserAgent:  ctx.Req.UserAgent(),
		DeviceInfo: utils.GetDeviceInfo(ctx.Req.UserAgent()),
	})

	ctx.JSON(http.StatusOK, map[string]any{"status": "ok"})
}

// ------------------------------------------------------------------
// LOGIN
// ------------------------------------------------------------------

// LoginBegin (GET /webauthn/login/begin)
func (h *WebAuthnHandler) LoginBegin(ctx *kp.Ctx) {
	username := ctx.Req.URL.Query().Get("username")
	if username == "" {
		ctx.JSON(http.StatusBadRequest, map[string]any{"error": "username required"})
		return
	}

	user, err := h.oauthHandler.userRepo.FindByUsername(ctx, username)
	if err != nil || user == nil {
		ctx.JSON(http.StatusBadRequest, map[string]any{"error": "user not found"})
		return
	}

	options, sessionData, err := h.webAuthnService.BeginLogin(ctx, user.ID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}

	sessionDataJSON, _ := json.Marshal(sessionData)
	h.oauthHandler.transactionCache.SetTransaction(ctx, "webauthn_login:"+user.ID, &models.AuthTransaction{
		UserID: user.ID,
		State:  string(sessionDataJSON),
	}, 10*time.Minute)

	ctx.JSON(http.StatusOK, options)
}

// LoginFinish (POST /webauthn/login/finish)
func (h *WebAuthnHandler) LoginFinish(ctx *kp.Ctx) {
	username := ctx.Req.URL.Query().Get("username")
	sid := ctx.Req.URL.Query().Get("sid")
	tid := ctx.Req.URL.Query().Get("tid")

	if username == "" || sid == "" || tid == "" {
		ctx.JSON(http.StatusBadRequest, map[string]any{"error": "missing parameters (username, sid, tid)"})
		return
	}

	user, err := h.oauthHandler.userRepo.FindByUsername(ctx, username)
	if err != nil || user == nil {
		ctx.JSON(http.StatusBadRequest, map[string]any{"error": "user not found"})
		return
	}

	txID := "webauthn_login:" + user.ID
	tx, err := h.oauthHandler.transactionCache.GetTransaction(ctx, txID)
	if err != nil || tx == nil {
		ctx.JSON(http.StatusBadRequest, map[string]any{"error": "login session expired"})
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(tx.State), &sessionData); err != nil {
		ctx.JSON(http.StatusInternalServerError, map[string]any{"error": "failed to decode session data"})
		return
	}

	clientResponse, err := io.ReadAll(ctx.Req.Body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]any{"error": "invalid format"})
		return
	}

	_, err = h.webAuthnService.FinishLogin(ctx, user.ID, sessionData, clientResponse)
	if err != nil {
		h.oauthHandler.auditRepo.Save(ctx, &models.AuditLog{
			UserID:     user.ID,
			Event:      "webauthn_login_failed",
			Reason:     err.Error(),
			IPAddress:  ctx.Req.RemoteAddr,
			UserAgent:  ctx.Req.UserAgent(),
		})
		ctx.JSON(http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}

	h.oauthHandler.transactionCache.DeleteTransaction(ctx, txID)

	// Login Success! Set up real session
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

	h.oauthHandler.auditRepo.Save(ctx, &models.AuditLog{
		UserID:     user.ID,
		Event:      "login_success",
		IPAddress:  ctx.Req.RemoteAddr,
		UserAgent:  ctx.Req.UserAgent(),
		DeviceInfo: deviceInfo,
	})

	http.SetCookie(ctx.Res, &http.Cookie{
		Name:     "oidc_session",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})

	// Redirect frontend logic
	nextUrl := "/consent?sid=" + url.QueryEscape(sid) + "&tid=" + url.QueryEscape(tid)
	ctx.JSON(http.StatusOK, map[string]any{"status": "ok", "redirect_to": nextUrl})
}
