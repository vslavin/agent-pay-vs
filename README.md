# Agent Pay — passkey sign-in demo

A small demo of passwordless sign-in with **Keycloak** and **passkeys**. A user opens the app on a computer, scans a QR code with their phone, approves with a passkey on the phone, and the computer is signed in. The user never types a password.

The demo covers:

- **QR / device sign-in** using the OAuth 2.0 Device Authorization Grant.
- **Classic browser sign-in** using OIDC with PKCE.
- **Passkey registration** on the current computer, or on a phone via QR code.
- **A custom Keycloak theme** that puts the passkey first and hides the password form behind a link.
- **A consent screen that shows who is signing in**, so a phone user can check before tapping *Yes*.

## Architecture

```
Browser / phone
      │  https://<domain>
      ▼
   ngrok tunnel
      │
      ▼
 proxy.py :8000 ──  /realms/*, /resources/*  →  Keycloak :8080
                ──  /admin*                  →  403 (admin console stays local)
                ──  everything else          →  demo app :3000
```

One public domain serves both the app and Keycloak. Passkeys are bound to that domain, so the realm's passkey `rpId` must equal the ngrok domain.

## Contents

| Path | What it is |
|------|------------|
| [demo-app/](demo-app/) | Demo web app (`app.py`, Python stdlib only) with its templates and CSS. It runs the OIDC/PKCE and device-grant flows. |
| [proxy.py](proxy.py) | Reverse proxy (Python stdlib only) that puts the app and Keycloak behind one domain. |
| [keycloak-extension/](keycloak-extension/) | Java provider that exposes the signed-in user (`apUser`) to the consent page template. |
| [keycloak-theme/agent-pay/](keycloak-theme/agent-pay/) | Keycloak login theme: CSS, a passkey-first JS script and the consent template. |
| [demo.sh](demo.sh) | Starts, stops and checks Keycloak, the app, the proxy and ngrok. |

### Demo app routes

| Route | Purpose |
|-------|---------|
| `/` | Splash page when signed out, identity card when signed in |
| `/login` | QR sign-in (device grant); `/login/poll` is polled until the phone approves |
| `/login/browser` | Classic in-browser OIDC/PKCE sign-in |
| `/register` | Keycloak sign-up form |
| `/passkey/add` | Register a passkey on a phone via QR code |
| `/passkey/add/local` | Register a passkey on this computer |
| `/account/password` | Keycloak change-password screen |
| `/logout` | RP-initiated logout |

## Prerequisites

- macOS with zsh (the scripts use zsh and Homebrew paths)
- Java: `brew install openjdk`
- Python 3 (no third-party packages)
- ngrok, with an authtoken and a reserved domain: `brew install ngrok && ngrok config add-authtoken <token>`
- Keycloak 26.x, unpacked at `~/dev/keycloak-setup/keycloak-26.8.2`

## Setup

### 1. Keycloak realm

Create a realm named `passkey-demo` with:

- A public client `demo-app`. Enable the standard flow and the OAuth 2.0 Device Authorization Grant.
  - Valid redirect URIs: `http://localhost:3000/*` and `https://<your-ngrok-domain>/*`.
- **Passkeys enabled:** the WebAuthn Passwordless policy's *Relying Party ID* must be your ngrok domain.
  - Set it with `kcadm.sh update realms/passkey-demo -s webAuthnPolicyPasswordlessRpId=<domain>`.
- Realm login theme set to `agent-pay`.

Realm settings live in Keycloak's database, so you only need to do this once.

### 2. Install the theme and extension

```sh
# Theme
cp -R keycloak-theme/agent-pay "$KC_HOME/themes/"

# Extension (compiles the Java provider and copies the jar into Keycloak's providers/)
./keycloak-extension/build.sh
```

Restart Keycloak after installing either one.

### 3. Set your ngrok domain

`demo.sh` defaults to the author's domain. Override it with your own:

```sh
export NGROK_DOMAIN=your-domain.ngrok-free.dev
```

## Running

```sh
./demo.sh            # start Keycloak, demo app, proxy and ngrok, then open the browser
./demo.sh status     # show what's running
./demo.sh stop       # stop everything and close the public tunnel
./demo.sh restart
```

Set `NO_OPEN=1` to skip opening the browser. Logs are written to `~/dev/keycloak-setup/{keycloak,demo-app,proxy,ngrok}.log`.

The demo is public while it runs. The proxy blocks `/admin`, so the Keycloak admin console is only reachable on localhost:8080.

The app also works locally at http://localhost:3000, but passkeys only match on the ngrok domain.

## Configuration

| Variable | Used by | Default | Meaning |
|----------|---------|---------|---------|
| `NGROK_DOMAIN` | `demo.sh` | author's domain | Public domain for the tunnel and Keycloak hostname |
| `KC_PUBLIC_URL` | `demo-app/app.py` | `http://localhost:8080` | Browser- and phone-facing Keycloak URL (`demo.sh` sets this) |
| `PROXY_PORT` | `proxy.py` | `8000` | Proxy listen port |
| `NO_OPEN` | `demo.sh` | unset | Skip opening the browser |

## Notes

- This is a demo. Keycloak runs in `start-dev` mode, and the proxy and app are single-file stdlib servers. They are not hardened for production.
- Paths in `demo.sh` and `build.sh` assume Keycloak at `~/dev/keycloak-setup/keycloak-26.8.2` and Java at `/opt/homebrew/opt/openjdk`. Edit them if yours differ.
