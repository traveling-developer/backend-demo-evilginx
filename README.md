# Demo Login Backend für Evilginx-Schulungen

Ein selbst entwickeltes Go-Login-Backend, das als **Ziel-Anwendung** in einer
autorisierten [Evilginx](https://github.com/kgretzky/evilginx2)-Demo
(Adversary-in-the-Middle / AitM) dient. Es zeigt anschaulich, **welche
Login-Verfahren sich phishen lassen und welche nicht**.

> ⚠️ **Nur für autorisierte, isolierte Security-Schulungen.** Dieses Backend ist
> bewusst unsicher konfiguriert (Demo-Passwörter, In-Memory-State, On-Page-Magic-
> Links). Nicht produktiv und nicht in fremden Umgebungen einsetzen.

## Login-Verfahren & Lerneffekt

| Verfahren | Demo-User | Phishbar mit Evilginx? | Warum |
|---|---|---|---|
| Passwort | `alice` | ✅ ja | Credentials + Session-Cookie werden im Proxy abgegriffen |
| Passwort + TOTP-MFA | `bob` | ✅ ja | MFA-Bypass: der **Session-Cookie** wird gestohlen, der Code ist nur Einmal-Hürde |
| Magic-Link (passwordless) | alle | ⚠️ bedingt | siehe Hinweis unten |
| WebAuthn / Passkey | `carol`* | ❌ nein | **Origin-Binding** — der Browser bindet den Passkey an die echte Domain |

\* `carol` muss ihren Passkey zuerst registrieren (siehe unten).

Der **Aha-Moment** der Demo: Bei `alice`/`bob` landet die Session in Evilginx,
bei einem Passkey scheitert die Anmeldung über die Phishing-Domain, weil die
Browser-Origin nicht zur konfigurierten `rpId` passt.

## Starten

```bash
go run .
```

Standardmäßig auf `http://localhost:8080`. Beim Start werden die Demo-User
geseedet und u. a. das **TOTP-Secret von `bob`** ins Log geschrieben:

```
seed: bob TOTP secret: JBSWY3DPEHPK3PXP
seed: bob TOTP otpauth URL: otpauth://totp/DemoCorp:bob@democorp.example?...&secret=...
```

In eine Authenticator-App (Google/Microsoft Authenticator, Aegis, …) bekommst du
das so:

- **Secret manuell eingeben** → das Secret aus dem Log abtippen, oder
- **QR scannen** → die `otpauth://`-URL in einen QR wandeln und scannen, z. B.
  `qrencode -t ANSI 'otpauth://totp/...'`.

> Ohne `TOTP_BOB_SECRET` wird bei **jedem Neustart ein neues Secret** erzeugt
> (In-Memory-Store) — die App-Codes stimmen dann nicht mehr. Für eine stabile
> Demo `TOTP_BOB_SECRET` setzen (siehe unten), dann bleibt das Secret konstant.

Demo-Passwort für alle User: `Password123!`

### Konfiguration (ENV)

| Variable | Default | Zweck |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | Listen-Adresse |
| `BASE_URL` | `http://localhost:8080` | externe URL, für Magic-Links |
| `WEBAUTHN_RPID` | `localhost` | WebAuthn Relying-Party-ID (die **legitime** Domain) |
| `WEBAUTHN_ORIGIN` | `http://localhost:8080` | erwartete Origin für Passkeys |
| `CORP_NAME` | `DemoCorp` | Anzeigename im UI |
| `BEHIND_TLS` | – | `1` setzt das `Secure`-Flag auf Cookies (hinter TLS) |
| `TOTP_BOB_SECRET` | – | fixes base32-Secret für `bob`s TOTP (stabil über Neustarts) |

Für einen realistischen Aufbau das Backend hinter eine TLS-Domain stellen, z. B.:

```bash
BASE_URL=https://login.democorp.example \
WEBAUTHN_RPID=login.democorp.example \
WEBAUTHN_ORIGIN=https://login.democorp.example \
BEHIND_TLS=1 go run .
```

## Passkey für `carol` registrieren

WebAuthn braucht einen echten oder virtuellen Authenticator:

1. Als `carol` per Passwort anmelden (`/login`).
2. Auf `/register/passkey` einen Passkey erstellen.
   - Lokal ohne Hardware: in Chrome DevTools → **WebAuthn**-Tab einen *virtual
     authenticator* aktivieren.
3. Danach unter `/login/passkey` mit Benutzername + Passkey anmelden.

## Magic-Link-Hinweis (didaktisch wichtig)

Es gibt **keinen Mailserver**: Der Link wird ins Server-Log und in ein Dev-Panel
auf der Seite geschrieben. Das ist Absicht.

- Ein per **echter E-Mail** versendeter Link zeigt auf die **echte** Domain.
  Klickt das Opfer aus dem Postfach, landet es nicht im Proxy → Evilginx greift
  nichts ab.
- Phishbar wird der Flow, wenn das Token **innerhalb der proxied Session**
  konsumiert wird (Link/Code wird auf der Seite angezeigt — wie bei
  OTP-Eingabe). Genau das bildet das On-Page-Dev-Panel ab: Evilginx erfasst den
  resultierenden `demo_session`-Cookie.

## Evilginx-Setup (Kurzfassung)

1. Phishlet `phishlets/demo.yaml` nach Evilginx kopieren, Domain/Subdomains an
   die Umgebung anpassen.
2. In Evilginx:
   ```
   config domain <deine-phishing-domain>
   config ipv4 <server-ip>
   phishlets hostname democorp login.democorp.example
   phishlets enable democorp
   lures create democorp
   lures get-url 0
   ```
3. Lokales Testen ohne öffentliche Domain: Evilginx im `developer`-Mode
   (self-signed Zertifikate) starten.

Wichtig: `auth_tokens` im Phishlet erfasst `demo_session`; `auth_urls` enthält
`/dashboard`, sodass das Erreichen des Dashboards die erfolgreiche Capture
markiert.

## Demo-Ablauf (Vorschlag)

1. **`alice`** anmelden → in Evilginx erscheinen Credentials + `demo_session`.
   Cookie in Evilginx importieren → Session übernommen, ohne Passwort.
2. **`bob`** (Passwort + TOTP) anmelden → trotz MFA wird der Session-Cookie
   abgegriffen → MFA-Bypass sichtbar.
3. **Magic-Link** für eine Demo-Adresse anfordern → Capture zeigen + Nuance
   echte E-Mail vs. On-Page erklären.
4. **`carol`** mit Passkey → Anmeldung über die Phishing-Domain **schlägt fehl**
   (Origin-Mismatch). Kernbotschaft: *Passkeys/FIDO2 schützen vor AitM-Phishing.*

## Hosting

**Wichtig:** Evilginx selbst braucht eine **VM mit öffentlicher IP und Root**
(bindet 443, holt eigene Let's-Encrypt-Zerts) — das geht *nicht* auf
Serverless/PaaS-Gratis-Tiers. Dieses Backend dagegen läuft überall. Daraus zwei
Topologien:

### A) Alles auf einer kostenlosen VM (empfohlen für eine öffentliche Demo)

[Oracle Cloud **Always Free**](https://www.oracle.com/cloud/free/) bietet eine
dauerhaft kostenlose ARM-VM (genug für Backend **und** Evilginx). Alternativen:
Google Cloud / AWS Free-Tier-VM (zeitlich begrenzt).

1. Binary bauen (statisch, CGO-frei): `CGO_ENABLED=0 go build -o demo .` und per
   `scp` auf die VM, oder das `Dockerfile` nutzen.
2. Hinter [Caddy](https://caddyserver.com) (automatisches TLS) auf z. B.
   `login.deine-domain.tld` legen, Backend lauscht intern auf `:8080`:
   ```
   login.deine-domain.tld {
       reverse_proxy localhost:8080
   }
   ```
3. Backend mit den passenden ENV-Variablen starten:
   ```bash
   BASE_URL=https://login.deine-domain.tld \
   WEBAUTHN_RPID=login.deine-domain.tld \
   WEBAUTHN_ORIGIN=https://login.deine-domain.tld \
   BEHIND_TLS=1 ./demo
   ```
4. DNS: A-Record `login.deine-domain.tld` → VM-IP. Für Evilginx eine separate
   (Look-alike-)Domain + Wildcard auf die Evilginx-IP.

### B) Backend kostenlos auf PaaS, Evilginx lokal/auf VM

Container-Deploy via `Dockerfile` auf **Google Cloud Run**, **Render** oder
**Koyeb** (gratis, Auto-HTTPS, eigene Domain, skaliert auf null). Die App
honoriert die `PORT`-Variable automatisch. Custom Domain auf das Backend mappen
und dieselben `WEBAUTHN_*`/`BASE_URL`-Variablen setzen.

### C) Komplett lokal (am günstigsten & sichersten)

Für eine geschlossene Raum-Demo Backend + Evilginx auf dem Laptop laufen lassen,
Evilginx im `developer`-Mode (self-signed). Kein Hosting, keine öffentliche
Exposition.

> ⚠️ **ToS & Abuse:** Eine öffentlich erreichbare Phishing-Proxy-Infrastruktur
> verstößt häufig gegen die Nutzungsbedingungen von Gratis-Providern und kann
> Domain/IP auf Blocklisten bringen. Öffentliche Setups eng absichern
> (IP-Allowlist, kurze Laufzeit) oder Variante C wählen.

## Projektstruktur

```
main.go                 # Bootstrap: Config (ENV), Router, Server
internal/
  store/                # In-Memory-State (Users, Sessions, Magic-Tokens, Passkeys)
  auth/                 # Login-Flows: session, password, totp, webauthn (+ Tests)
  web/                  # HTTP-Handler, Templates, Static-Assets
phishlets/demo.yaml     # Beispiel-Evilginx-Phishlet
```

## Tests

```bash
go test ./...
```

Deckt TOTP-Roundtrip und Magic-Token-Semantik (Single-Use, Ablauf) ab.
