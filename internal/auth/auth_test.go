package auth_test

import (
	"testing"
	"time"

	"github.com/inovex/backend-demo-evilginx/internal/auth"
	"github.com/inovex/backend-demo-evilginx/internal/store"
	"github.com/pquerna/otp/totp"
)

func TestTOTPRoundTrip(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "DemoCorp", AccountName: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyTOTP(key.Secret(), code) {
		t.Fatal("valid TOTP code rejected")
	}
	if auth.VerifyTOTP(key.Secret(), "000000") {
		t.Fatal("bogus TOTP code accepted")
	}
}

func TestMagicTokenSingleUse(t *testing.T) {
	s := store.New()
	s.AddUser(&store.User{ID: "u1", Username: "alice", Email: "a@x"})

	tok := s.CreateMagicToken("u1", time.Minute)
	if id, ok := s.ConsumeMagicToken(tok.Token); !ok || id != "u1" {
		t.Fatalf("first consume failed: id=%q ok=%v", id, ok)
	}
	if _, ok := s.ConsumeMagicToken(tok.Token); ok {
		t.Fatal("token reused — should be single-use")
	}
}

func TestMagicTokenExpiry(t *testing.T) {
	s := store.New()
	s.AddUser(&store.User{ID: "u1"})
	tok := s.CreateMagicToken("u1", -time.Second) // already expired
	if _, ok := s.ConsumeMagicToken(tok.Token); ok {
		t.Fatal("expired token accepted")
	}
}
