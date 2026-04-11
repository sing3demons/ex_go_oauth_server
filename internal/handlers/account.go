package handlers

import (
	"net/http"

	"github.com/sing3demons/oauth_server/internal/adapters/redis_store"
	"github.com/sing3demons/oauth_server/pkg/kp"
	"github.com/sing3demons/oauth_server/pkg/response"
)

type AccountHandler struct {
	sessionCache *redis_store.SessionCache
}

func NewAccountHandler(sessionCache *redis_store.SessionCache) *AccountHandler {
	return &AccountHandler{sessionCache: sessionCache}
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

	// 3. Get all sessions for this user
	sessions, err := h.sessionCache.GetUserSessions(ctx, session.UserID)
	if err != nil {
		ctx.JsonError(&response.Error{
			Err:     err,
			Message: response.ServerError,
		}, response.ServerError.Error())
		return
	}

	data := struct {
		CurrentSID string
		Sessions   any
	}{
		CurrentSID: sid,
		Sessions:   sessions,
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
