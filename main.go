// Command backend-demo-evilginx is a self-contained demo login site used as the
// TARGET application in an authorized Evilginx (adversary-in-the-middle)
// demonstration. It supports password login (with optional TOTP MFA),
// passwordless push approval (number matching), and WebAuthn/passkey login.
//
// Use only in isolated, authorized security training environments.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/inovex/backend-demo-evilginx/internal/auth"
	"github.com/inovex/backend-demo-evilginx/internal/store"
	"github.com/inovex/backend-demo-evilginx/internal/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	// Honor $PORT (Cloud Run, Render, Koyeb, …) when LISTEN_ADDR isn't set.
	listenAddr := env("LISTEN_ADDR", "")
	if listenAddr == "" {
		if p := os.Getenv("PORT"); p != "" {
			listenAddr = ":" + p
		} else {
			listenAddr = ":8080"
		}
	}

	var (
		rpID      = env("WEBAUTHN_RPID", "localhost")
		rpOrigin  = env("WEBAUTHN_ORIGIN", "http://localhost:8080")
		corpName  = env("CORP_NAME", "DemoCorp")
		behindTLS = os.Getenv("BEHIND_TLS") == "1"
	)

	wconfig := &webauthn.Config{
		RPDisplayName: corpName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	}
	wa, err := webauthn.New(wconfig)
	if err != nil {
		log.Fatalf("webauthn config: %v", err)
	}

	st := store.New()
	notes, err := store.Seed(st, corpName, os.Getenv("TOTP_BOB_SECRET"))
	if err != nil {
		log.Fatalf("seed: %v", err)
	}

	a := &auth.Auth{Store: st, WebAuthn: wa, Secure: behindTLS}
	srv := web.NewServer(a, st, corpName)

	log.Printf("=== %s demo login backend ===", corpName)
	log.Printf("listening on %s", listenAddr)
	log.Printf("webauthn RPID=%s origin=%s  | cookies Secure=%t", rpID, rpOrigin, behindTLS)
	for _, n := range notes {
		log.Printf("seed: %s", n)
	}

	httpSrv := &http.Server{
		Addr:              listenAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(httpSrv.ListenAndServe())
}
