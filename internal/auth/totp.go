package auth

import (
	"net/http"

	"github.com/inovex/backend-demo-evilginx/internal/store"
	"github.com/pquerna/otp/totp"
)

// BeginTOTPStep records a pending login (password done, TOTP outstanding) and
// sets a short-lived cookie identifying it.
func (a *Auth) BeginTOTPStep(w http.ResponseWriter, userID string) {
	id := a.Store.CreatePendingLogin(userID)
	a.setCookie(w, pendingCookie, id, 300)
}

// PendingUser returns the user currently in the TOTP step, if any.
func (a *Auth) PendingUser(r *http.Request) (*store.User, bool) {
	c, err := r.Cookie(pendingCookie)
	if err != nil {
		return nil, false
	}
	userID, ok := a.Store.PendingLogin(c.Value)
	if !ok {
		return nil, false
	}
	return a.Store.UserByID(userID)
}

// ClearPending removes the pending-login state and cookie.
func (a *Auth) ClearPending(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(pendingCookie); err == nil {
		a.Store.DeletePendingLogin(c.Value)
	}
	a.clearCookie(w, pendingCookie)
}

// VerifyTOTP validates a 6-digit code against the secret.
func VerifyTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}
