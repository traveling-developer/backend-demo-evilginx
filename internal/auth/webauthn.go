package auth

import (
	"errors"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/inovex/backend-demo-evilginx/internal/store"
)

var errNoCeremony = errors.New("no active webauthn ceremony")

// BeginRegistration starts a passkey enrolment, stashing the challenge in a
// short-lived ceremony cookie and returning the creation options for the browser.
func (a *Auth) BeginRegistration(w http.ResponseWriter, u *store.User) (*protocol.CredentialCreation, error) {
	options, sessionData, err := a.WebAuthn.BeginRegistration(u)
	if err != nil {
		return nil, err
	}
	id := a.Store.PutWebAuthnSession(sessionData)
	a.setCookie(w, ceremonyCookie, id, 300)
	return options, nil
}

// FinishRegistration verifies the attestation and stores the new credential.
func (a *Auth) FinishRegistration(w http.ResponseWriter, r *http.Request, u *store.User) error {
	data, err := a.takeCeremony(w, r)
	if err != nil {
		return err
	}
	cred, err := a.WebAuthn.FinishRegistration(u, *data, r)
	if err != nil {
		return err
	}
	a.Store.AddCredential(u.ID, *cred)
	return nil
}

// BeginLogin starts a passkey assertion for a known user.
func (a *Auth) BeginLogin(w http.ResponseWriter, u *store.User) (*protocol.CredentialAssertion, error) {
	options, sessionData, err := a.WebAuthn.BeginLogin(u)
	if err != nil {
		return nil, err
	}
	id := a.Store.PutWebAuthnSession(sessionData)
	a.setCookie(w, ceremonyCookie, id, 300)
	return options, nil
}

// FinishLogin verifies the assertion and returns the authenticated user. The
// browser only produces a valid assertion when the page origin matches the
// configured RP origin — which is why an Evilginx proxy on a look-alike domain
// cannot complete this flow.
func (a *Auth) FinishLogin(w http.ResponseWriter, r *http.Request) (*store.User, error) {
	data, err := a.takeCeremony(w, r)
	if err != nil {
		return nil, err
	}
	u, ok := a.Store.UserByID(string(data.UserID))
	if !ok {
		return nil, errors.New("unknown user for ceremony")
	}
	if _, err := a.WebAuthn.FinishLogin(u, *data, r); err != nil {
		return nil, err
	}
	return u, nil
}

func (a *Auth) takeCeremony(w http.ResponseWriter, r *http.Request) (*webauthn.SessionData, error) {
	c, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return nil, errNoCeremony
	}
	data, ok := a.Store.TakeWebAuthnSession(c.Value)
	if !ok {
		return nil, errNoCeremony
	}
	a.clearCookie(w, ceremonyCookie)
	return data, nil
}
