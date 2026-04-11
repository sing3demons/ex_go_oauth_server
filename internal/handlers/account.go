package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/sing3demons/oauth_server/internal/adapters/mongo_store"
	"github.com/sing3demons/oauth_server/internal/adapters/redis_store"
	"github.com/sing3demons/oauth_server/internal/core/models"
	"github.com/sing3demons/oauth_server/internal/core/ports"
	"github.com/sing3demons/oauth_server/pkg/kp"
)

type AccountHandler struct {
	sessionCache *redis_store.SessionCache
	auditRepo    *mongo_store.AuditRepository
	userRepo     ports.UserRepository
	credRepo     ports.UserCredentialRepository
}

func NewAccountHandler(sessionCache *redis_store.SessionCache, auditRepo *mongo_store.AuditRepository, userRepo ports.UserRepository, credRepo ports.UserCredentialRepository) *AccountHandler {
	return &AccountHandler{sessionCache: sessionCache, auditRepo: auditRepo, userRepo: userRepo, credRepo: credRepo}
}

// SessionsUI (GET /account/sessions)
func (h *AccountHandler) SessionsUI(ctx *kp.Ctx) {
	ctx.Log("account_sessions_ui")

	// 1. Get SID from cookie
	cookie, err := ctx.Req.Cookie("oidc_session")
	if err != nil || cookie.Value == "" {
		ctx.Redirect("/authorize?error=session_expired", http.StatusFound)
		return
	}
	sid := cookie.Value

	// 2. Get UserID from current session
	session, err := h.sessionCache.GetSession(ctx, sid)
	if err != nil || session == nil {
		ctx.Redirect("/authorize?error=session_expired", http.StatusFound)
		return
	}

	// 3. Get all active sessions for this user
	allSessions, _ := h.sessionCache.GetUserSessions(ctx, session.UserID)

	// 4. Get last 15 audit logs for this user (skip 0)
	history, err := h.auditRepo.FindByUserID(ctx, session.UserID, 15, 0)
	if err != nil {
		history = nil // Fallback to no history if error
	}

	// 5. Get User to check MFA status
	user, _ := h.userRepo.FindByID(ctx, session.UserID)
	mfaEnabled := false
	if user != nil {
		mfaEnabled = user.MFAEnabled
	}

	// 6. Get Passkey count
	creds, _ := h.credRepo.FindAllByUserIDAndType(ctx, session.UserID, "passkey")
	passkeysCount := len(creds)

	data := struct {
		CurrentSID    string
		Sessions      any
		History       any
		MFAEnabled    bool
		PasskeysCount int
	}{
		CurrentSID:    sid,
		Sessions:      allSessions,
		History:       history,
		MFAEnabled:    mfaEnabled,
		PasskeysCount: passkeysCount,
	}

	ctx.RenderTemplate("templates/account_sessions.html", data)
}

// RevokeSession (POST /account/sessions/revoke)
func (h *AccountHandler) RevokeSession(ctx *kp.Ctx) {
	ctx.Log("revoke_session")

	targetSID := ctx.Req.FormValue("sid")
	if targetSID == "" {
		ctx.Redirect("/account/sessions", http.StatusFound)
		return
	}

	// 1. Get current SID from cookie (security check)
	cookie, err := ctx.Req.Cookie("oidc_session")
	if err != nil || cookie.Value == "" {
		ctx.Redirect("/authorize?error=session_expired", http.StatusFound)
		return
	}
	currentSID := cookie.Value

	// 2. Get current session to find UserID
	currentSession, err := h.sessionCache.GetSession(ctx, currentSID)
	if err != nil || currentSession == nil {
		ctx.Redirect("/authorize?error=session_expired", http.StatusFound)
		return
	}

	// 3. Verify target session belongs to current user
	targetSession, err := h.sessionCache.GetSession(ctx, targetSID)
	if err != nil || targetSession == nil || targetSession.UserID != currentSession.UserID {
		// Not allowed or already gone
		ctx.Redirect("/account/sessions", http.StatusFound)
		return
	}

	// 4. Delete the session
	h.sessionCache.DeleteSession(ctx, targetSID)

	// 5. If revoked self, redirect to login
	if targetSID == currentSID {
		http.SetCookie(ctx.Res, &http.Cookie{
			Name:     "oidc_session",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
		ctx.Redirect("/authorize?error=logged_out", http.StatusFound)
		return
	}

	ctx.Redirect("/account/sessions", http.StatusFound)
}

// HistoryUI (GET /account/history)
func (h *AccountHandler) HistoryUI(ctx *kp.Ctx) {
	ctx.Log("account_history_ui")

	// 1. Get SID from cookie
	cookie, err := ctx.Req.Cookie("oidc_session")
	if err != nil || cookie.Value == "" {
		ctx.Redirect("/authorize?error=session_expired", http.StatusFound)
		return
	}
	sid := cookie.Value

	// 2. Get UserID from current session
	session, err := h.sessionCache.GetSession(ctx, sid)
	if err != nil || session == nil {
		ctx.Redirect("/authorize?error=session_expired", http.StatusFound)
		return
	}

	// 3. Handle Pagination
	pageStr := ctx.Req.URL.Query().Get("page")
	page, _ := strconv.Atoi(pageStr)
	if page < 1 {
		page = 1
	}
	limit := int64(20)
	skip := int64(page-1) * limit

	// 4. Get logs and total count
	history, err := h.auditRepo.FindByUserID(ctx, session.UserID, limit, skip)
	if err != nil {
		log.Printf("failed to fetch audit history for user %s: %v", session.UserID, err)
		history = []*models.AuditLog{}
	}
	total, _ := h.auditRepo.CountByUserID(ctx, session.UserID)

	data := struct {
		History     any
		Page        int
		HasPrev     bool
		HasNext     bool
		PrevPage    int
		NextPage    int
		TotalCounts int64
	}{
		History:     history,
		Page:        page,
		HasPrev:     page > 1,
		HasNext:     int64(page)*limit < total,
		PrevPage:    page - 1,
		NextPage:    page + 1,
		TotalCounts: total,
	}

	ctx.RenderTemplate("templates/account_history.html", data)
}

// PasskeysUI (GET /account/passkeys)
func (h *AccountHandler) PasskeysUI(ctx *kp.Ctx) {
	ctx.Log("account_passkeys_ui")

	cookie, err := ctx.Req.Cookie("oidc_session")
	if err != nil || cookie.Value == "" {
		ctx.Redirect("/authorize?error=session_expired", http.StatusFound)
		return
	}
	sid := cookie.Value

	session, err := h.sessionCache.GetSession(ctx, sid)
	if err != nil || session == nil {
		ctx.Redirect("/authorize?error=session_expired", http.StatusFound)
		return
	}

	creds, _ := h.credRepo.FindAllByUserIDAndType(ctx, session.UserID, "passkey")

	data := struct {
		CurrentSID string
		Passkeys   any
	}{
		CurrentSID: sid,
		Passkeys:   creds,
	}

	ctx.RenderTemplate("templates/account_passkeys.html", data)
}

// RevokePasskey (POST /account/passkeys/revoke)
func (h *AccountHandler) RevokePasskey(ctx *kp.Ctx) {
	ctx.Log("revoke_passkey")

	credID := ctx.Req.FormValue("id")
	if credID == "" {
		ctx.Redirect("/account/passkeys", http.StatusFound)
		return
	}

	cookie, err := ctx.Req.Cookie("oidc_session")
	if err != nil || cookie.Value == "" {
		ctx.Redirect("/authorize?error=session_expired", http.StatusFound)
		return
	}

	session, err := h.sessionCache.GetSession(ctx, cookie.Value)
	if err != nil || session == nil {
		ctx.Redirect("/authorize?error=session_expired", http.StatusFound)
		return
	}

	// Verify the credential belongs to the current user
	cred, err := h.credRepo.FindByID(ctx, credID)
	if err == nil && cred.UserID == session.UserID {
		h.credRepo.DeleteByID(ctx, credID)
	}

	ctx.Redirect("/account/passkeys", http.StatusFound)
}
