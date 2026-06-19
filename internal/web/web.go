// Package web wires up the HTTP handlers, templates and static assets for the
// demo login site.
package web

import (
	"embed"
	"html/template"
	"log"
	"net/http"

	"github.com/inovex/backend-demo-evilginx/internal/auth"
	"github.com/inovex/backend-demo-evilginx/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// pages are the standalone templates, each composed with the shared layout.
var pages = []string{"home", "login", "totp", "push", "authenticator", "passkey", "register_passkey", "dashboard"}

// Server holds handler dependencies.
type Server struct {
	Auth      *auth.Auth
	Store     *store.Store
	templates map[string]*template.Template
	// CorpName is shown in the UI.
	CorpName string
}

// NewServer parses templates and returns a ready Server.
func NewServer(a *auth.Auth, s *store.Store, corpName string) *Server {
	ts := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		ts[p] = template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/"+p+".html"))
	}
	return &Server{Auth: a, Store: s, templates: ts, CorpName: corpName}
}

// Routes returns the configured HTTP handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	staticHandler := http.FileServer(http.FS(staticFS))
	mux.Handle("GET /static/", staticHandler)

	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("GET /login/totp", s.handleTOTPGet)
	mux.HandleFunc("POST /login/totp", s.handleTOTPPost)
	mux.HandleFunc("GET /login/push", s.handlePushGet)
	mux.HandleFunc("POST /login/push", s.handlePushPost)
	mux.HandleFunc("GET /login/push/status", s.handlePushStatus)
	mux.HandleFunc("GET /authenticator", s.handleAuthenticatorGet)
	mux.HandleFunc("POST /authenticator/approve", s.handleAuthenticatorApprove)
	mux.HandleFunc("GET /login/passkey", s.handlePasskeyGet)

	mux.HandleFunc("POST /webauthn/login/begin", s.handleWebAuthnLoginBegin)
	mux.HandleFunc("POST /webauthn/login/finish", s.handleWebAuthnLoginFinish)

	mux.HandleFunc("GET /register/passkey", s.Auth.RequireAuth(s.handleRegisterPasskeyGet))
	mux.HandleFunc("POST /webauthn/register/begin", s.Auth.RequireAuth(s.handleWebAuthnRegisterBegin))
	mux.HandleFunc("POST /webauthn/register/finish", s.Auth.RequireAuth(s.handleWebAuthnRegisterFinish))

	mux.HandleFunc("GET /dashboard", s.Auth.RequireAuth(s.handleDashboard))
	mux.HandleFunc("POST /logout", s.handleLogout)

	return logRequests(mux)
}

// render executes a page template against the shared layout.
func (s *Server) render(w http.ResponseWriter, page string, data map[string]any) {
	t, ok := s.templates[page]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["CorpName"] = s.CorpName
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("template error (%s): %v", page, err)
	}
}

// logRequests is minimal access logging so the demo operator can watch the flow.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
