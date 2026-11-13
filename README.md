# Agent Pay — passkey sign-in and agent payments demo

A small demo of passwordless sign-in with **Keycloak** and **passkeys**. A user opens the app on a computer, scans a QR code with their phone, approves with a passkey on the phone, and the computer is signed in. The user never types a password.

On top of sign-in sits an early **agent payments** layer. Every user gets a wallet holding test **OUSD** on Tempo's testnet, an admin can send OUSD from a treasury wallet, and users can create agents. It uses test tokens only; nothing here moves real money.

The demo covers:

- **QR / device sign-in** using the OAuth 2.0 Device Authorization Grant.
- **Classic browser sign-in** using OIDC with PKCE.
- **Passkey registration** on the current computer, or on a phone via QR code.
- **A custom Keycloak theme** that puts the passkey first and hides the password form behind a link.
- **A consent screen that shows who is signing in**, so a phone user can check before tapping *Yes*.
- **A testnet OUSD wallet per user**, created on first sign-in with a 100 OUSD welcome gift, and a wallet page with on-chain transaction history, including memos.
- **An admin treasury page** that shows the treasury balance and every user's balance, and sends OUSD to a user with an optional memo.
- **Roles.** Keycloak realm roles `admin` and `merchant`; anyone without either is a plain `user`. Users create agents named `<username>.<agent>`, for example `user4.sneaker-hunter`.

## Architecture

```
Browser / phone
      │  https://<domain>
      ▼
   ngrok tunnel
      │
      ▼
 proxy.py :8000 ──  /realms/*, /resources/*  →  Keycloak :8080
                ──  /admin*, /internal*      →  403 (admin console and the Keycloak→app hook stay local)
                ──  everything else          →  demo app :3000
                                                   │
                                                   ▼
                                       wallet service :3100 (local only)  ──►  Tempo testnet RPC
```

One public domain serves both the app and Keycloak. Passkeys are bound to that domain, so the realm's passkey `rpId` must equal the ngrok domain.

The wallet service is never exposed publicly. Only the app calls it, with a shared token, and it holds the treasury and user wallet keys.

## Contents

| Path | What it is |
|------|------------|
| [demo-app/](demo-app/) | Demo web app (`app.py`, Python stdlib only) with its templates and CSS. It runs the OIDC/PKCE and device-grant flows. |
| [proxy.py](proxy.py) | Reverse proxy (Python stdlib only) that puts the app and Keycloak behind one domain. |
| [agent-wallet-demo/wallet-service/](agent-wallet-demo/wallet-service/) | Node service (`server.mjs`, uses `viem`) that holds the treasury and per-user testnet wallets, sends gifts and treasury transfers, and reads transaction history from the chain. |
| [agent-wallet-demo/spike/](agent-wallet-demo/spike/) | Two small scripts: `spike.mjs` makes a wallet and funds it from the Tempo faucet; `gift.mjs` sends OUSD from it. Used to create the treasury key. |
| [keycloak-extension/](keycloak-extension/) | Java provider that exposes the signed-in user (`apUser`) to the consent page template, and tells the app who is confirming a QR sign-in on the phone. |
| [keycloak-theme/agent-pay/](keycloak-theme/agent-pay/) | Keycloak login theme: CSS, a passkey-first JS script and the consent template. |
| [demo.sh](demo.sh) | Starts, stops and checks Keycloak, the app, the proxy and ngrok. |

### Demo app routes

| Route | Purpose |
|-------|---------|
| `/` | Splash page when signed out, identity card when signed in |
| `/login` | QR sign-in (device grant); `/login/poll` is polled until the phone approves, and `/login/who` shows who is confirming |
| `/login/browser` | Classic in-browser OIDC/PKCE sign-in |
| `/register` | Keycloak sign-up form |
| `/passkey/add` | Register a passkey on a phone via QR code |
| `/passkey/add/local` | Register a passkey on this computer |
| `/account/password` | Keycloak change-password screen |
| `/wallet` | Any signed-in user: their OUSD balance, wallet address and transaction history |
| `/treasury` | Role `admin` only: treasury balance, every user's balance, and a form to send OUSD (amount, user, optional memo of up to 32 bytes) |
| `/agents` | Role `user` only: create an agent (name and description) and list your own agents |
| `/internal/device-user` | Local only: called by the Keycloak extension; blocked by the proxy |
| `/logout` | RP-initiated logout |

The treasury page is at `/treasury`, not `/admin`, because the proxy blocks every path starting with `/admin` to keep the Keycloak admin console private.

## Prerequisites

- macOS with zsh (the scripts use zsh and Homebrew paths)
- Java: `brew install openjdk`
- Python 3 (no third-party packages)
- Node.js, for the wallet service: `brew install node`
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
- Realm roles `admin` and `merchant`. Give `admin` to the user who should see the treasury page. Users with neither role are plain `user`s. Roles are read from the access token (`realm_access.roles`) at sign-in, so a role change takes effect after the user signs in again.

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

### 4. Wallet service and treasury key

The wallet service needs a funded Tempo testnet key to act as the treasury. The faucet gives 1,000,000 test OUSD.

```sh
cd agent-wallet-demo/spike && npm install
node spike.mjs                       # creates a throwaway wallet and funds it from the faucet
cd ../wallet-service && npm install
mkdir -p data && cp ../spike/.wallet.json data/treasury.json
```

`demo.sh` starts the wallet service when `data/treasury.json` exists. The key files (`spike/.wallet.json` and everything under `wallet-service/data/`) are git-ignored.

## Running

```sh
./demo.sh            # start Keycloak, wallet service, demo app, proxy and ngrok, then open the browser
./demo.sh status     # show what's running
./demo.sh stop       # stop everything and close the public tunnel
./demo.sh restart
```

Set `NO_OPEN=1` to skip opening the browser. Logs are written to `~/dev/keycloak-setup/{keycloak,wallet-service,demo-app,proxy,ngrok}.log`.

The demo is public while it runs. The proxy blocks `/admin`, so the Keycloak admin console is only reachable on localhost:8080 (`demo.sh` starts Keycloak with `--hostname-admin=http://localhost:8080` for this). Sign-in to the console goes through the public host's `/realms` path and returns to localhost. If the console won't load, stop the demo and run Keycloak plainly (`./bin/kc.sh start-dev`) while you do admin work.

The app also works locally at http://localhost:3000, but passkeys only match on the ngrok domain.

## Configuration

| Variable | Used by | Default | Meaning |
|----------|---------|---------|---------|
| `NGROK_DOMAIN` | `demo.sh` | author's domain | Public domain for the tunnel and Keycloak hostname |
| `KC_PUBLIC_URL` | `demo-app/app.py` | `http://localhost:8080` | Browser- and phone-facing Keycloak URL (`demo.sh` sets this) |
| `WALLET_SERVICE_URL` | `demo-app/app.py` | `http://127.0.0.1:3100` | Where the app finds the wallet service |
| `WALLET_SERVICE_PORT` | wallet service | `3100` | Wallet service listen port (bound to 127.0.0.1) |
| `AGENT_PAY_NOTIFY_URL` | Keycloak extension | `http://127.0.0.1:3000/internal/device-user` | Where the extension reports who is confirming a QR sign-in |
| `PROXY_PORT` | `proxy.py` | `8000` | Proxy listen port |
| `NO_OPEN` | `demo.sh` | unset | Skip opening the browser |

## Notes

- This is a demo. Keycloak runs in `start-dev` mode, and the proxy and app are single-file stdlib servers. They are not hardened for production.
- The wallet layer is testnet-only. Wallet private keys are stored as plain JSON under `agent-wallet-demo/wallet-service/data/`, and agents in `demo-app/data/agents.json` (both git-ignored). Do not reuse this storage for real funds.
- Each treasury transfer and gift pays a tiny network fee from the sender's OUSD balance. Memos are written on-chain with Tempo's `transferWithMemo`, so they are public and limited to 32 bytes.
- App sessions are held in memory, so restarting the app signs everyone out.
- Paths in `demo.sh` and `build.sh` assume Keycloak at `~/dev/keycloak-setup/keycloak-26.8.2` and Java at `/opt/homebrew/opt/openjdk`. Edit them if yours differ.
