// Package auth implements the demo's login flows: password, TOTP, passwordless
// push approval and WebAuthn. Sessions are tracked with an HttpOnly cookie — the
// exact auth_token an Evilginx phishlet is configured to capture.
package auth

import (
	"context"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/inovex/backend-demo-evilginx/internal/store"
)

const (
	SessionCookie  = "demo_session"
	pendingCookie  = "demo_pending"
	pushCookie     = "demo_push"
	ceremonyCookie = "demo_waceremony"
	contextUserKey = ctxKey("user")
)

type ctxKey string

// Auth bundles the dependencies shared across login flows.
type Auth struct {
	Store    *store.Store
	WebAuthn *webauthn.WebAuthn
	// Secure controls the Secure flag on cookies. Enable it when the backend
	// is served over TLS (or sits behind a TLS-terminating proxy like Evilginx).
	Secure bool
}

// setCookie writes a session-style cookie. SameSite=Lax (not Strict) is used on
// purpose: it mirrors how real login sites behave and keeps the flow proxyable.
func (a *Auth) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (a *Auth) clearCookie(w http.ResponseWriter, name string) {
	a.setCookie(w, name, "", -1)
}

// CompleteLogin creates a session for the user and sets the session cookie.
func (a *Auth) CompleteLogin(w http.ResponseWriter, userID string) {
	sess := a.Store.CreateSession(userID)
	a.setCookie(w, SessionCookie, sess.ID, 3600)
}

// Logout destroys the current session.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		a.Store.DeleteSession(c.Value)
	}
	a.clearCookie(w, SessionCookie)
}

// CurrentUser returns the logged-in user for a request, if any.
func (a *Auth) CurrentUser(r *http.Request) (*store.User, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, false
	}
	sess, ok := a.Store.Session(c.Value)
	if !ok {
		return nil, false
	}
	return a.Store.UserByID(sess.UserID)
}

// RequireAuth is middleware that redirects unauthenticated requests to /login
// and stashes the user in the request context for downstream handlers.
func (a *Auth) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := a.CurrentUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), contextUserKey, u)
		next(w, r.WithContext(ctx))
	}
}

// UserFromContext returns the user injected by RequireAuth.
func UserFromContext(r *http.Request) (*store.User, bool) {
	u, ok := r.Context().Value(contextUserKey).(*store.User)
	return u, ok
}
