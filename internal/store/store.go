// Package store holds all demo state in memory. There is no database: this is a
// throwaway target application for an Evilginx demo, so state intentionally
// resets on restart.
package store

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// User is a demo account. It also implements the webauthn.User interface so it
// can be passed straight into the go-webauthn ceremonies.
type User struct {
	ID           string
	Username     string
	Email        string
	PasswordHash []byte
	// TOTPSecret is empty when the user has no MFA enrolled.
	TOTPSecret  string
	Credentials []webauthn.Credential
}

// --- webauthn.User interface ---

func (u *User) WebAuthnID() []byte                         { return []byte(u.ID) }
func (u *User) WebAuthnName() string                       { return u.Username }
func (u *User) WebAuthnDisplayName() string                { return u.Username }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// Session is a logged-in browser session. The session ID lives in the
// `demo_session` cookie — this is exactly the auth_token Evilginx captures.
type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
}

// PushStatus is the lifecycle state of a push approval request.
type PushStatus int

const (
	PushPending PushStatus = iota
	PushApproved
	PushDenied
)

// PushRequest models a passwordless "approve on your phone" login (like the
// Microsoft Authenticator number-matching flow). The browser polls its status;
// a second device (the simulated authenticator) approves or denies it.
type PushRequest struct {
	ID          string
	UserID      string
	Username    string
	MatchNumber int
	Status      PushStatus
	ExpiresAt   time.Time
}

// Store is the concurrency-safe in-memory state container.
type Store struct {
	mu sync.Mutex

	usersByName map[string]*User
	usersByID   map[string]*User
	sessions    map[string]*Session
	// pushRequests holds passwordless push approval requests, keyed by a random
	// id round-tripped through a short-lived cookie on the polling browser.
	pushRequests map[string]*PushRequest
	// pendingLogins holds users who passed the password step but still owe a
	// TOTP code, keyed by a random id round-tripped through a short-lived cookie.
	pendingLogins map[string]string
	// webauthnSessions holds the challenge data between the begin and finish
	// steps of a ceremony, keyed by a per-browser ceremony id.
	webauthnSessions map[string]*webauthn.SessionData
}

func New() *Store {
	return &Store{
		usersByName:      make(map[string]*User),
		usersByID:        make(map[string]*User),
		sessions:         make(map[string]*Session),
		pushRequests:     make(map[string]*PushRequest),
		pendingLogins:    make(map[string]string),
		webauthnSessions: make(map[string]*webauthn.SessionData),
	}
}

// randToken returns a URL-safe random token with n bytes of entropy.
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is unrecoverable; for a demo, panic is fine.
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- Users ---

func (s *Store) AddUser(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usersByName[u.Username] = u
	s.usersByID[u.ID] = u
}

func (s *Store) UserByName(name string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByName[name]
	return u, ok
}

func (s *Store) UserByID(id string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByID[id]
	return u, ok
}

// AddCredential appends a registered WebAuthn credential to a user.
func (s *Store) AddCredential(userID string, cred webauthn.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.usersByID[userID]; ok {
		u.Credentials = append(u.Credentials, cred)
	}
}

// --- Sessions ---

func (s *Store) CreateSession(userID string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := &Session{ID: randToken(32), UserID: userID, CreatedAt: time.Now()}
	s.sessions[sess.ID] = sess
	return sess
}

func (s *Store) Session(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

func (s *Store) DeleteSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// --- Push approval requests (passwordless) ---

// CreatePushRequest registers a pending push approval valid for ttl.
func (s *Store) CreatePushRequest(userID, username string, match int, ttl time.Duration) *PushRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	req := &PushRequest{
		ID:          randToken(16),
		UserID:      userID,
		Username:    username,
		MatchNumber: match,
		Status:      PushPending,
		ExpiresAt:   time.Now().Add(ttl),
	}
	s.pushRequests[req.ID] = req
	return req
}

// PushByID returns a push request without consuming it.
func (s *Store) PushByID(id string) (*PushRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.pushRequests[id]
	return req, ok
}

// PendingPushRequests returns all not-yet-expired requests still awaiting a
// decision, for display on the simulated authenticator.
func (s *Store) PendingPushRequests() []*PushRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []*PushRequest
	for _, req := range s.pushRequests {
		if req.Status == PushPending && now.Before(req.ExpiresAt) {
			out = append(out, req)
		}
	}
	return out
}

// SetPushStatus records an approve/deny decision on a request.
func (s *Store) SetPushStatus(id string, status PushStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req, ok := s.pushRequests[id]; ok {
		req.Status = status
	}
}

// DeletePushRequest removes a request once it has been consumed.
func (s *Store) DeletePushRequest(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pushRequests, id)
}

// --- Pending logins (password done, TOTP outstanding) ---

func (s *Store) CreatePendingLogin(userID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randToken(16)
	s.pendingLogins[id] = userID
	return id
}

// PendingLogin returns the user id for a pending login without consuming it,
// so a wrong TOTP code can be retried.
func (s *Store) PendingLogin(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, ok := s.pendingLogins[id]
	return userID, ok
}

func (s *Store) DeletePendingLogin(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingLogins, id)
}

// --- WebAuthn ceremony session data ---

// PutWebAuthnSession stores ceremony challenge data and returns a ceremony id
// to round-trip through a short-lived cookie.
func (s *Store) PutWebAuthnSession(data *webauthn.SessionData) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := randToken(16)
	s.webauthnSessions[id] = data
	return id
}

// TakeWebAuthnSession retrieves and removes ceremony data.
func (s *Store) TakeWebAuthnSession(id string) (*webauthn.SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.webauthnSessions[id]
	if ok {
		delete(s.webauthnSessions, id)
	}
	return data, ok
}
