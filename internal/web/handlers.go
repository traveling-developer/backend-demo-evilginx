package web

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/inovex/backend-demo-evilginx/internal/auth"
	"github.com/inovex/backend-demo-evilginx/internal/store"
)

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

// --- Passwordless push approval (number matching) ---

func (s *Server) handlePushGet(w http.ResponseWriter, r *http.Request) {
	s.render(w, "push", map[string]any{"Stage": "form"})
}

// handlePushPost creates a push approval request and shows the waiting page with
// the match number. The same page renders whether or not the username exists, so
// we don't leak which accounts are valid; an unknown user simply gets a request
// that is never approved.
func (s *Server) handlePushPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	data := map[string]any{"Stage": "waiting", "Username": username}

	if u, ok := s.Store.UserByName(username); ok {
		match := s.Auth.BeginPush(w, u)
		data["Match"] = match
		log.Printf("push approval request for %s: match number %02d", username, match)
	} else {
		data["Match"] = auth.NewMatchNumber()
	}
	s.render(w, "push", data)
}

// handlePushStatus is polled by the waiting page. On approval it completes the
// login (setting the demo_session cookie) — the exact token an AitM proxy grabs.
func (s *Server) handlePushStatus(w http.ResponseWriter, r *http.Request) {
	req, ok := s.Auth.PendingPush(r)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]string{"status": "expired"})
		return
	}
	switch req.Status {
	case store.PushApproved:
		s.Auth.ClearPush(w, r)
		s.Auth.CompleteLogin(w, req.UserID)
		writeJSON(w, http.StatusOK, map[string]string{"status": "approved", "redirect": "/dashboard"})
	case store.PushDenied:
		s.Auth.ClearPush(w, r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "pending"})
	}
}

// handleAuthenticatorGet renders the simulated authenticator: it stands in for
// an app on a second device, listing pending requests with number-matching.
func (s *Server) handleAuthenticatorGet(w http.ResponseWriter, r *http.Request) {
	reqs := s.Store.PendingPushRequests()
	views := make([]map[string]any, 0, len(reqs))
	for _, req := range reqs {
		views = append(views, map[string]any{
			"ID":       req.ID,
			"Username": req.Username,
			"Choices":  auth.NumberChoices(req.MatchNumber),
		})
	}
	s.render(w, "authenticator", map[string]any{"Requests": views})
}

// handleAuthenticatorApprove records the decision. Picking the wrong number
// denies the request, mirroring real number-matching.
func (s *Server) handleAuthenticatorApprove(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	number, _ := strconv.Atoi(r.FormValue("number"))

	if req, ok := s.Store.PushByID(id); ok && req.Status == store.PushPending && time.Now().Before(req.ExpiresAt) {
		if number == req.MatchNumber {
			s.Store.SetPushStatus(id, store.PushApproved)
			log.Printf("push %s approved for %s", id, req.Username)
		} else {
			s.Store.SetPushStatus(id, store.PushDenied)
			log.Printf("push %s denied for %s (wrong number)", id, req.Username)
		}
	}
	http.Redirect(w, r, "/authenticator", http.StatusSeeOther)
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
