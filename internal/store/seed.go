package store

import (
	"fmt"
	"net/url"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// demoPassword is shared by every seeded account to keep the demo simple.
const demoPassword = "Password123!"

// Seed populates the store with the three demo accounts and returns
// human-readable notes (e.g. bob's TOTP secret) to print at startup.
//
//   - alice: password only          → pure credential phish
//   - bob:   password + TOTP MFA     → MFA bypass via captured cookie
//   - carol: password, enrols passkey → phishing-resistant (Evilginx fails)
//
// bobSecret, if non-empty, fixes bob's TOTP secret (must be base32) so it stays
// stable across restarts — otherwise a fresh random secret is generated each run.
func Seed(s *Store, issuer, bobSecret string) ([]string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(demoPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	var notes []string

	s.AddUser(&User{ID: "u-alice", Username: "alice", Email: "alice@democorp.example", PasswordHash: hash})

	// bob has TOTP enrolled. Use the fixed secret if provided, otherwise generate
	// one. Either way, surface the secret + otpauth URL so it can be added to an
	// authenticator app for the demo.
	if bobSecret == "" {
		key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: "bob@democorp.example"})
		if err != nil {
			return nil, err
		}
		bobSecret = key.Secret()
	}
	if _, err := totp.GenerateCode(bobSecret, time.Now()); err != nil {
		return nil, fmt.Errorf("invalid TOTP_BOB_SECRET (must be base32): %w", err)
	}
	otpauthURL := fmt.Sprintf("otpauth://totp/%s:bob@democorp.example?%s",
		url.PathEscape(issuer),
		url.Values{
			"secret":    {bobSecret},
			"issuer":    {issuer},
			"algorithm": {"SHA1"},
			"digits":    {"6"},
			"period":    {"30"},
		}.Encode())
	s.AddUser(&User{ID: "u-bob", Username: "bob", Email: "bob@democorp.example", PasswordHash: hash, TOTPSecret: bobSecret})
	notes = append(notes,
		fmt.Sprintf("bob TOTP secret: %s", bobSecret),
		fmt.Sprintf("bob TOTP otpauth URL: %s", otpauthURL),
	)

	s.AddUser(&User{ID: "u-carol", Username: "carol", Email: "carol@democorp.example", PasswordHash: hash})

	notes = append(notes, fmt.Sprintf("demo password for all users: %s", demoPassword))
	return notes, nil
}
