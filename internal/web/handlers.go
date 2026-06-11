package web

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/inovex/backend-demo-evilginx/internal/auth"
)

const magicLinkTTL = 10 * time.Minute

// handleIndex shows the landing page, or sends logged-in users to the dashboard.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.Auth.CurrentUser(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.render(w, "home", nil)
}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login", map[string]any{"Error": r.URL.Query().Get("error")})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	u, ok := s.Store.UserByName(username)
	if !ok || !auth.VerifyPassword(u, password) {
		// Credentials are captured by Evilginx on the POST regardless of outcome.
		http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
		return
	}

	if auth.HasTOTP(u) {
		s.Auth.BeginTOTPStep(w, u.ID)
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
		return
	}

	s.Auth.CompleteLogin(w, u.ID)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) handleTOTPGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.Auth.PendingUser(r); !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, "totp", map[string]any{"Error": r.URL.Query().Get("error")})
}

func (s *Server) handleTOTPPost(w http.ResponseWriter, r *http.Request) {
	u, ok := s.Auth.PendingUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !auth.VerifyTOTP(u.TOTPSecret, r.FormValue("code")) {
		http.Redirect(w, r, "/login/totp?error=invalid", http.StatusSeeOther)
		return
	}
	s.Auth.ClearPending(w, r)
	s.Auth.CompleteLogin(w, u.ID)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) handleMagicGet(w http.ResponseWriter, r *http.Request) {
	s.render(w, "magic", nil)
}

// handleMagicPost issues a single-use login link. There is no mail server in the
// demo, so the link is logged server-side AND shown on the page (a "dev panel").
// Showing it on the page is deliberate: it keeps the whole flow inside the
// proxied session so Evilginx can capture the resulting session cookie. See
// README for the OTP-on-page vs real-email nuance.
func (s *Server) handleMagicPost(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	data := map[string]any{"Submitted": true, "Email": email}

	if u, ok := s.Store.UserByEmail(email); ok {
		t := s.Store.CreateMagicToken(u.ID, magicLinkTTL)
		link := s.BaseURL + "/login/magic/verify?token=" + t.Token
		log.Printf("magic link for %s: %s", email, link)
		data["Link"] = link
	}
	// Always render the same "if the address exists, a link was sent" page to
	// avoid leaking which emails are valid.
	s.render(w, "magic", data)
}

func (s *Server) handleMagicVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	userID, ok := s.Store.ConsumeMagicToken(token)
	if !ok {
		http.Redirect(w, r, "/login?error=magic", http.StatusSeeOther)
		return
	}
	s.Auth.CompleteLogin(w, userID)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) handlePasskeyGet(w http.ResponseWriter, r *http.Request) {
	s.render(w, "passkey", nil)
}

func (s *Server) handleRegisterPasskeyGet(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFromContext(r)
	s.render(w, "register_passkey", map[string]any{"Username": u.Username})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFromContext(r)
	s.render(w, "dashboard", map[string]any{
		"Username":     u.Username,
		"Email":        u.Email,
		"HasTOTP":      u.TOTPSecret != "",
		"PasskeyCount": len(u.Credentials),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.Auth.Logout(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- WebAuthn JSON endpoints ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	u, ok := s.Store.UserByName(body.Username)
	if !ok || len(u.Credentials) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no passkey for user"})
		return
	}
	options, err := s.Auth.BeginLogin(w, u)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	u, err := s.Auth.FinishLogin(w, r)
	if err != nil {
		// This is exactly where an Evilginx-proxied login fails: the origin in
		// the assertion does not match the configured RP origin.
		log.Printf("webauthn login failed: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "assertion failed"})
		return
	}
	s.Auth.CompleteLogin(w, u.ID)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/dashboard"})
}

func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFromContext(r)
	options, err := s.Auth.BeginRegistration(w, u)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFromContext(r)
	if err := s.Auth.FinishRegistration(w, r, u); err != nil {
		log.Printf("webauthn registration failed: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "registration failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/dashboard"})
}
