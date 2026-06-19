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

func TestNumberChoices(t *testing.T) {
	const match = 42
	choices := auth.NumberChoices(match)
	if len(choices) != 3 {
		t.Fatalf("want 3 choices, got %d", len(choices))
	}
	seen := map[int]bool{}
	found := false
	for _, c := range choices {
		if seen[c] {
			t.Fatalf("duplicate choice %d", c)
		}
		seen[c] = true
		if c == match {
			found = true
		}
	}
	if !found {
		t.Fatal("match number not among choices")
	}
}

func TestPushRequestLifecycle(t *testing.T) {
	s := store.New()
	req := s.CreatePushRequest("u1", "alice", 42, time.Minute)
	if got := s.PendingPushRequests(); len(got) != 1 {
		t.Fatalf("want 1 pending request, got %d", len(got))
	}
	s.SetPushStatus(req.ID, store.PushApproved)
	if got := s.PendingPushRequests(); len(got) != 0 {
		t.Fatal("approved request should no longer be pending")
	}
	if r, ok := s.PushByID(req.ID); !ok || r.Status != store.PushApproved {
		t.Fatalf("approval not recorded: ok=%v", ok)
	}
}

func TestPushRequestExpiry(t *testing.T) {
	s := store.New()
	s.CreatePushRequest("u1", "alice", 42, -time.Second) // already expired
	if got := s.PendingPushRequests(); len(got) != 0 {
		t.Fatal("expired request should not be pending")
	}
}
