# Agent Pay — passkey sign-in and agent payments demo

A small demo of passwordless sign-in with **Keycloak** and **passkeys**. A user opens the app on a computer, scans a QR code with their phone, approves with a passkey on the phone, and the computer is signed in. The user never types a password.

On top of sign-in sits an early **agent payments** layer. Every user gets a wallet holding test **OUSD** on Tempo's testnet, an admin can send OUSD from a treasury wallet, and users can create agents. It uses test tokens only; nothing here moves real money.

I wrote up what this is and what I learned building it: [I let an AI agent buy sneakers without me. Here is how I made sure it could not buy anything else.](https://medium.com/@vslavin/i-let-an-ai-agent-buy-sneakers-without-me-here-is-how-i-made-sure-it-could-not-buy-anything-else-498e89f2e6ef)

The demo covers:

- **QR / device sign-in** using the OAuth 2.0 Device Authorization Grant.
- **Classic browser sign-in** using OIDC with PKCE.
- **Passkey registration** on the current computer, or on a phone via QR code.
- **A custom Keycloak theme** that puts the passkey first and hides the password form behind a link.
- **A consent screen that shows who is signing in**, so a phone user can check before tapping *Yes*.
- **A testnet OUSD wallet per user**, created on first sign-in with a 100 OUSD welcome gift, and a wallet page with on-chain transaction history, including memos.
- **An admin treasury page** that shows the treasury balance and every user's balance, and sends OUSD to a user with an optional memo.
- **TAP-style agent identities.** Each agent gets its own Ed25519 key. Its public key is published at `/tap/keys`, and the wallet service can sign requests for it as RFC 9421 HTTP Message Signatures, the mechanism Visa's Trusted Agent Protocol uses. **These identities are not registered with Visa.** Visa's TAP developer portal is written for merchants: it says agents are "certified AI platforms" onboarded to Visa's program, and it offers independent developers no agent registration. This demo's own key registry stands in for that, with a lookup that follows Visa's documented `GET /keys?keyID=` shape.
- **Roles.** Keycloak enforces one realm role, `admin`. Everyone else is a `user` or a `merchant` according to the *Account type* chosen at sign-up, which is a Keycloak user attribute. Users create agents named `<username>.<agent>`, for example `user4.sneaker-hunter`.
- **Merchant sign-up.** The sign-up form has an *Account type* dropdown (User or Merchant) plus a business name and description for merchants. Choosing Merchant gives the merchant role, which is harmless on its own.
- **Merchant storefronts.** Each merchant gets a public store at `/shop/<username>` with a rack of sneakers and a JSON catalog. Every merchant shows a demo catalog under their own name. There are two store profiles (below).
- **Admin-only registration with Visa's sandbox.** On the treasury page, each merchant row has a *Register with Visa* button. It creates the merchant in Visa's Merchant Registry Service (TAP indicator, an encrypted-payload key pair generated locally, key activated). Merchants cannot register themselves.

- **Mandates (AP2-style).** A user grants an agent authority by signing an *open mandate* (`vct` `mandate.payment.open.1`): an array of typed constraints (`payment.allowed_payees`, `payment.amount_range`, `payment.budget`, amounts as integer micro-OUSD), an expiry, and the agent's key in `cnf`. Creating one needs a fresh passkey sign-in. The agent then signs a *closed mandate* (`mandate.payment.1`: `transaction_id`, `payee`, `payment_amount`) for each exact order. Both are compact JWS (EdDSA); the code is in `wallet-service/mandate.mjs`. Where we depart from AP2 v0.2 is listed under Notes.
- **A verifying checkout.** `POST /shop/<store>/checkout` checks, in order: the agent's signed request (401 if it fails), the open mandate's signature, binding to the agent, validity, payee, limit and budget, then the closed mandate (403 if any fails), then the store's purchase mode. If everything passes it answers **402** with a payment quote that is good for 5 minutes. Every decision on a verifiable mandate comes with a signed **Mandate Receipt** (`result` success or error, `error` from AP2's list, `reference` = hash of the closed mandate).
- **Two kinds of store.** *Sneakers* (the default) is autonomous: a valid mandate is enough. *Atelier* sells 420 to 2400 OUSD watches and is human-present: the first valid checkout opens an approval request, the user approves that exact cart at `/approvals` with a fresh passkey sign-in, and the agent's retry then gets its quote. An approval covers one item, price, agent and mandate, once, for 15 minutes. Registration with Visa's sandbox is separate and optional: the demo registers the sneaker store and leaves the atelier unregistered.
- **Payment and receipts.** To pay, the wallet that holds the mandate sends the quoted OUSD to the store with `transferWithMemo`, memo = the order id. It refuses if the quote has expired, the mandate was revoked, or the order is not that agent's. The store then confirms from the chain: one transfer log must show the right payer (the mandate holder's wallet), payee, amount and memo. Only then is the order `paid` and a signed **Payment Receipt** issued (`status`, `payment_id` = order id, `network_confirmation_id` = transaction hash). Receipts are verified with the store's `receiptKey` in its catalog. An unpaid quote stops counting against the budget when it expires.

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
| [agent-wallet-demo/wallet-service/](agent-wallet-demo/wallet-service/) | Node service (`server.mjs`, uses `viem`) that holds the treasury and per-user testnet wallets, sends gifts and treasury transfers, reads transaction history from the chain, and holds the agents' identity keys (`tap.mjs` does the key generation and request signing and verification; run its tests with `node --test tap.test.mjs`). |
| [agent-wallet-demo/spike/](agent-wallet-demo/spike/) | Two small scripts: `spike.mjs` makes a wallet and funds it from the Tempo faucet; `gift.mjs` sends OUSD from it. Used to create the treasury key. |
| [agent-wallet-demo/visa-sandbox/](agent-wallet-demo/visa-sandbox/) | Client for Visa's sandbox using X-Pay Token (`client.mjs`, `visa.mjs`), a connectivity check (`check.mjs`, `probe.mjs`) and a helper that decrypts the shared secret Visa issues (`decrypt-secret.mjs`). Credentials live in the git-ignored `credentials/` folder. |
| [keycloak-realm/](keycloak-realm/) | The merchant sign-up fields as JSON, and a script that applies them to the realm. |
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
| `/treasury` | Role `admin` only: treasury balance, every user's balance, a form to send OUSD (amount, user, optional memo of up to 32 bytes), and for each merchant a *Register with Visa* button |
| `/treasury/agents` | Role `admin` only: every agent from every user (name, ID, owner, description, TAP key with a registry check, created time). Each name links to its read-only page |
| `/treasury/agents/<agt_id>` | Role `admin` only: read-only view of any agent: identity, owner, its mandates (with spent and remaining) and purchase approvals. No grant or revoke controls |
| `/treasury/visa/<sub>` | Role `admin` only: a merchant's live record fetched from Visa's registry (name, IDs, URL, indicator, key table, raw JSON). Linked as *View Visa record* from each merchant row. Shows public keys only |
| `POST /treasury/register-merchant` | Role `admin` only: registers the chosen merchant in Visa's sandbox. Idempotent; a half-finished attempt can be completed with *Finish registration* |
| `/shop/<username>`, `/shop/<username>/catalog.json` | Public: a merchant's storefront and its machine-readable catalog for AI shoppers (it states the store's purchase mode and how to check out). Only merchants have one. Sneakers store: 12 shoes, 75 to 210 OUSD, autonomous. Atelier store: 8 watches, 420 to 2400 OUSD, human-present |
| `/agents` | Role `user` only: create an agent (name and description) and list your own agents, each with its TAP-style key id. Each name links to its page |
| `/agents/direct`, `/agents/run/<run_id>` | Role `user` only: **Direct an agent**, linked from My agents and from each agent's page. Choose an agent, one of its active mandates, a store, an item ID (for example `VSE-010`) and *Quote only* or *Pay*. The app plays the agent runtime: the wallet service signs the request and a closed mandate, the app makes the same checkout request an outside agent would, and with *Pay* the wallet pays and the store confirms. The errand page shows each step, every check the store ran (a store or item outside the mandate is refused, and you see why), the quote, the transaction and the receipts. At a human-present store it waits up to 5 minutes for you to approve. Runs are held in memory |
| `/agents/<agt_id>` | Role `user`, owner only: the agent's identity, its mandates (status, stores, limits, spent and remaining, expiry, *Revoke*) and a form to grant a new one. *Approve with passkey* re-authenticates you (`prompt=login`, `max_age=0`) and the mandate is created only if the ID token's `auth_time` is under two minutes old |
| `/approvals`, `/approvals/<apr_id>` | Role `user` only: purchase approval requests from human-present stores. The detail page shows the exact cart and has *Approve this purchase with passkey* and *Decline* |
| `GET /shop/<username>/orders/<ord_id>` | Public: an order's status, amount, transaction hash and receipts |
| `POST /shop/<username>/orders/<ord_id>/confirm` | Public: body `{"txHash"}`. The store checks the chain and, if that transaction pays this order, marks it paid and issues the Payment Receipt |
| `POST /shop/<username>/checkout` | Public, for agents: body `{"sku", "mandates": {"open", "closed"}}` plus the `Signature-Input` and `Signature` headers (tag `agent-payer-auth`). 402 authorized, 401 identity rejected, 403 mandate rejected or waiting for approval (the body then carries `approval.url`) |
| `/keys`, `/keys?keyID=<kid>` | Public: the registry of agent public keys (JWK), shaped like Visa's TAP key retrieval. Never contains private keys. `/tap/keys` and `/tap/keys/<kid>` are aliases |
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
- A realm role `admin`. Give it to the user who should see the treasury page. There is no `merchant` realm role: user versus merchant comes from the *Account type* attribute below. An admin is always treated as an admin, whatever their account type. Roles are read from the access token (`realm_access.roles`) and the account type from the ID token, both at sign-in, so a change takes effect after the user signs in again.
- Sign-up fields `account_type`, `business_name` and `business_description`, plus token mappers that send them to the app. Apply both with `keycloak-realm/apply-signup-fields.sh` after logging in with `kcadm.sh config credentials` (it is safe to run more than once). `account_type` is required at sign-up; Keycloak cannot require the business name only for merchants, so the app checks it before an admin can register a merchant.

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

### 5. Visa sandbox credentials (optional)

Only needed for the *Register with Visa* button. In the Visa Developer portal, add the Trusted Agent Protocol product to a sandbox project, then under *Credentials > X-Pay Token > Inbound*:

```sh
cd agent-wallet-demo/visa-sandbox && mkdir -p credentials/xpay && chmod 700 credentials credentials/xpay
openssl genrsa -out credentials/xpay/private.pem 2048
openssl rsa -in credentials/xpay/private.pem -pubout -out credentials/xpay/public.pem
grep -v '^-----' credentials/xpay/public.pem | tr -d '\r\n' | pbcopy   # paste into the portal's public key field
```

Visa then shows an API key and the shared secret encrypted to your public key. Save the encrypted value with `pbpaste > credentials/xpay/shared-secret.enc`, copy `visa.example.json` to `credentials/visa.json` and put the API key in it, then run `node decrypt-secret.mjs` (it fills in the shared secret without printing it) and `node check.mjs` to test the connection.

#### Two-Way SSL for Visa Intelligent Commerce (experimental)

Visa Intelligent Commerce APIs use mutual TLS. In the portal, under *Credentials > Two-Way SSL*, add an inbound credential and submit your own CSR (Visa requires `C`, `ST`, `L`, `O`, `OU` and `CN` in the subject):

```sh
cd agent-wallet-demo/visa-sandbox/credentials/twoway
openssl req -new -newkey rsa:2048 -nodes -keyout private.pem -out request.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Agent Pay Demo/OU=Engineering/CN=agent-pay-demo"
```

Save Visa's issued client certificate as `client.pem` and the Sandbox Root and Issuing CAs as `ca-root.pem` and `ca-issuing.pem`. Copy `visa-basic.example.json` to `credentials/twoway/basic.json` and fill in the HTTP Basic username and password shown on the credential row. Then `node check-vic.mjs` calls Visa's Hello World and an empty Intelligent Commerce request. `vic-variants.mjs` tries different credential combinations.

Status: Hello World succeeds, so the certificate and Basic credentials are accepted. The Intelligent Commerce `credentials-for-instruction` endpoint returns `400 9125 Expected input credential was not present` under every credential combination we can send. The likely causes are Message Level Encryption (not started for this project) or Intelligent Commerce onboarding prerequisites (Token Requestor ID, consumer token, FIDO assurance data); this is unconfirmed.

Run the tests with `node --test` in `wallet-service/` and in `visa-sandbox/`. They use fakes and never contact Visa.

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

## Trying the checkout

A store's profile comes from `demo-app/data/stores.json` (git-ignored), for example `{"luxe": "atelier"}`. Any merchant not listed is a sneakers store. Create a merchant account at sign-up, add it there, and it becomes the stricter store (restart the app).

To act as your own agent with a mandate you granted in the app, use `wallet-service/buy.mjs`: it signs the request, presents the mandate, waits for your approval at a human-present store, and with `--pay` pays and verifies the receipts.

```sh
cd agent-wallet-demo/wallet-service
node buy.mjs --store https://<domain>/shop/<store> --agent agt_xxxxxxxxxxxx --mandate mnd_xxxxxxxxxxxx --item 11 --pay
```

`wallet-service/scenarios.mjs` plays an agent against a store and checks that each attempt gets the right answer. It needs the wallet service running locally and the agent's id:

```sh
cd agent-wallet-demo/wallet-service
node scenarios.mjs --store https://<domain>/shop/<sneakers store> --agent agt_xxxxxxxxxxxx --sub <your Keycloak user id>
node scenarios.mjs --store https://<domain>/shop/<atelier store>  --agent agt_xxxxxxxxxxxx --sub <your Keycloak user id>
```

It chooses the scenario set from the store's purchase mode: 9 autonomous cases (no mandate, unsigned request, over the limit, wrong product, wrong store, revoked, replay, budget used up) or 9 human-present cases (waiting for approval, approval is single-use, approval for one item does not unlock another, decline, stale sign-in, someone else approving). It creates short-lived mandates itself, and calls the wallet service's approve and decline endpoints where a person would use the app; a successful purchase only gets a quote and nothing is paid. With `--pay` it runs the payment cases instead, with real testnet transfers from the `--sub` user's wallet (which must hold enough OUSD: 75 per sneaker, 420 per watch): pay a quote and check the receipts and the on-chain memo, paying twice pays once, revoked before paying, one transaction cannot confirm another order, another agent cannot pay, and (only if the wallet service runs with `WALLET_QUOTE_TTL_SECONDS=3`) an expired quote cannot be paid. The wallet service exposes `POST /agents/<agt_id>/pay` with `{orderId}` for this; it is local and token-protected, standing in for an agent's wallet runtime. Run the unit tests with `node --test` in the same folder.

## Configuration

| Variable | Used by | Default | Meaning |
|----------|---------|---------|---------|
| `NGROK_DOMAIN` | `demo.sh` | author's domain | Public domain for the tunnel and Keycloak hostname |
| `KC_PUBLIC_URL` | `demo-app/app.py` | `http://localhost:8080` | Browser- and phone-facing Keycloak URL (`demo.sh` sets this) |
| `WALLET_SERVICE_URL` | `demo-app/app.py` | `http://127.0.0.1:3100` | Where the app finds the wallet service |
| `WALLET_SERVICE_PORT` | wallet service | `3100` | Wallet service listen port (bound to 127.0.0.1) |
| `WALLET_QUOTE_TTL_SECONDS` | wallet service | `300` | How long a checkout quote stays payable |
| `WALLET_DATA_DIR` | wallet service | `wallet-service/data` | Where wallets, keys and the service token are stored |
| `VISA_BASE_URL` | wallet service | Visa's sandbox | Override the Visa server, for tests against a local fake |
| `AGENT_PAY_NOTIFY_URL` | Keycloak extension | `http://127.0.0.1:3000/internal/device-user` | Where the extension reports who is confirming a QR sign-in |
| `PROXY_PORT` | `proxy.py` | `8000` | Proxy listen port |
| `NO_OPEN` | `demo.sh` | unset | Skip opening the browser |

## Notes

- This is a demo. Keycloak runs in `start-dev` mode, and the proxy and app are single-file stdlib servers. They are not hardened for production.
- The wallet layer is testnet-only. Wallet private keys are stored as plain JSON under `agent-wallet-demo/wallet-service/data/`, and agents in `demo-app/data/agents.json` (both git-ignored). Do not reuse this storage for real funds.
- Each treasury transfer and gift pays a tiny network fee from the sender's OUSD balance. Memos are written on-chain with Tempo's `transferWithMemo`, so they are public and limited to 32 bytes.
- Registering a merchant with Visa's sandbox is permanent: the Merchant Registry API offers no way to delete a merchant. Each merchant's registered URL is `<public domain>/shop/<username>`, which serves their storefront. Visa's API requires a `vmid` (Visa Merchant ID) even though its docs call it optional; a real merchant would have one from its acquirer, so demo merchants get a stable 11-digit placeholder starting with 9, derived from their Keycloak ID. Merchant encryption private keys are stored as plain JSON in `wallet-service/data/merchant-keys.json` (git-ignored).
- Visa's sandbox differs from its docs in two ways we observed: the merchant's key is already active right after creation (a second activation returns 409 "already active", which we accept), and keys get a default expiry of 14 days. Key rotation is not built.
- "TAP-style" means the signing format follows Visa's published spec (signed `@authority` and `@path`, `created`/`expires`/`nonce`/`tag`/`keyid`/`alg`, an 8-minute window, replay protection). It is built from the spec's description, not from Visa sample code or an official test suite, and no Visa service is involved. Agent keys are stored as plain JSON in the wallet service's `data/` folder.
- **Where we depart from AP2 v0.2** (read from its published spec pages, which give examples, not a formal schema): mandates are plain JWS rather than SD-JWT, so there is no selective disclosure or key-binding JWT; there is no checkout mandate, so the closed mandate's `transaction_id` is a hash of the order the store builds rather than of a merchant-signed checkout JWT; amounts are integer micro-OUSD, not an ISO 4217 currency; `payee` carries an `address` because payment is an on-chain transfer; the open mandate also carries `iss`, `sub` and `jti` and the closed one a `nonce` and an `open` hash of the open mandate. There is no credential provider or payment processor role, and no A2A transport.
- Mandates, orders and approvals are JSON files in the wallet service's `data/` folder (`mandates.json`, `orders.json`, `approvals.json`), with each user's mandate-signing key in `user-keys.json` and each store's receipt-signing key in `receipt-keys.json`. The service signs mandates on the user's behalf after the app has verified a fresh passkey sign-in, so the signature proves what the service did, not that the user's own device signed. A production design would sign on the user's device.
- App sessions are held in memory, so restarting the app signs everyone out.
- Paths in `demo.sh` and `build.sh` assume Keycloak at `~/dev/keycloak-setup/keycloak-26.8.2` and Java at `/opt/homebrew/opt/openjdk`. Edit them if yours differ.
