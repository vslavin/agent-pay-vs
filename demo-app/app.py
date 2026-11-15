#!/usr/bin/env python3
"""
Agent Pay Demo — Keycloak passkey demo app. Python 3 stdlib only.

Routes:
  GET /          → splash (not logged in) | identity card (logged in)
  GET /login     → QR sign-in page (OAuth 2.0 Device Authorization Grant):
                   shows a QR code; scan with phone, sign in there with passkey
  GET /login/poll→ JSON: has the phone approved yet? (sets session when done)
  GET /login/browser → classic in-browser OIDC/PKCE flow
  GET /register  → Keycloak's sign-up form (same OIDC/PKCE flow, then back here)
  GET /passkey/add      → (signed in) QR code to register a passkey on a phone
  GET /passkey/add/poll → JSON: has the phone finished registering?
  GET /passkey/phone    → (phone, from QR) Keycloak sign-in + passkey setup
                          via kc_action=webauthn-register-passwordless
  GET /passkey/add/local → (signed in) register a passkey in THIS browser/computer
                          via kc_action=webauthn-register-passwordless, then back to /
  GET /account/password → (signed in) Keycloak's change-password screen
                          via kc_action=UPDATE_PASSWORD, then back to /
  GET /callback  → exchange code, store session, redirect to /
  GET/POST /agents → (role "user") create agents (name + description), list your own
  GET /keys[?keyID=<kid>] → public registry of agent public keys, in the shape of Visa's TAP key
                           retrieval (/tap/keys and /tap/keys/<kid> are aliases)
  GET /wallet    → (signed in) own OUSD wallet: balance + on-chain transaction history
  GET /treasury  → (role "admin") OUSD treasury balance + every user's wallet balance
  GET /logout    → Keycloak RP-initiated logout
  GET /static/*  → serve files from ./static/
"""

import base64
import hashlib
import html
import http.server
import json
import mimetypes
import os
import pathlib
import re
import secrets
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal, ROUND_DOWN
from http.cookies import SimpleCookie

import shop

# ── Config ────────────────────────────────────────────────────────────────────
PORT = 3000
KEYCLOAK_BASE  = "http://localhost:8080"           # app → Keycloak (backchannel)
# Browser/phone-facing Keycloak URL. Set to the ngrok https URL so the phone
# can reach it and passkeys are bound to that domain.
KC_PUBLIC      = os.environ.get("KC_PUBLIC_URL", KEYCLOAK_BASE).rstrip("/")
REALM          = "passkey-demo"
CLIENT_ID      = "demo-app"
# The app is reached either at http://localhost:3000 or through the public
# proxy (ngrok). Redirect URLs are built from the request's own host.

ISSUER         = f"{KEYCLOAK_BASE}/realms/{REALM}"
PUBLIC_ISSUER  = f"{KC_PUBLIC}/realms/{REALM}"
AUTH_ENDPOINT  = f"{PUBLIC_ISSUER}/protocol/openid-connect/auth"
REGISTER_ENDPOINT = f"{PUBLIC_ISSUER}/protocol/openid-connect/registrations"
LOGOUT_ENDPOINT= f"{PUBLIC_ISSUER}/protocol/openid-connect/logout"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
DEVICE_ENDPOINT= f"{ISSUER}/protocol/openid-connect/auth/device"
DEVICE_GRANT   = "urn:ietf:params:oauth:grant-type:device_code"

BASE_DIR    = pathlib.Path(__file__).parent
STATIC_DIR  = BASE_DIR / "static"
TMPL_DIR    = BASE_DIR / "templates"

# Wallet service (agent-wallet-demo/wallet-service): holds the OUSD treasury and
# per-user testnet wallets. Local only; the app is its only client.
WALLET_URL        = os.environ.get("WALLET_SERVICE_URL", "http://127.0.0.1:3100")
WALLET_TOKEN_FILE = BASE_DIR.parent / "agent-wallet-demo" / "wallet-service" / "data" / "service-token"
EXPLORER          = "https://explore.testnet.tempo.xyz"

_sessions: dict = {}   # sid → {claims, id_token} | {state, code_verifier}
# Phone passkey enrollment: token → {sub, username, status, expires}
#   status: pending | done | cancelled | error | mismatch
_enroll: dict = {}
_enroll_lock = threading.Lock()
ENROLL_TTL = 600   # seconds a "add passkey" QR code stays valid
PASSKEY_ACTION = "webauthn-register-passwordless"
# Result banners for Keycloak application-initiated actions run in this browser.
ACTION_MESSAGES = {
    "UPDATE_PASSWORD": {
        "success":   ("ok",   "Password updated."),
        "cancelled": ("info", "Password not changed."),
        "error":     ("err",  "The password could not be changed. Please try again."),
    },
    PASSKEY_ACTION: {
        "success":   ("ok",   "Passkey added on this computer."),
        "cancelled": ("info", "No passkey was added."),
        "error":     ("err",  "The passkey could not be added. Please try again."),
    },
}

# ── Template rendering ────────────────────────────────────────────────────────
def _render(name: str, **replacements) -> str:
    """Load a template and substitute <!-- KEY --> placeholders."""
    text = (TMPL_DIR / name).read_text()
    for key, value in replacements.items():
        text = text.replace(f"<!-- {key} -->", value)
    return text

def _store_links_html():
    """A 'Stores' block of links to every public storefront, or '' if the wallet service is unreachable."""
    try:
        stores = _wallet_call("GET", "/merchants", timeout=5)["merchants"]
    except Exception:
        return ""
    if not stores:
        return ""
    links = "".join(
        f'<a class="btn btn-secondary" href="/shop/{urllib.parse.quote(s["username"], safe="")}">'
        f'{html.escape(s.get("businessName") or s["username"])}</a>'
        for s in sorted(stores, key=lambda s: (s.get("businessName") or s["username"]).lower()))
    return f'<div class="divider stores-divider">STORES</div><div class="btn-row store-links">{links}</div>'

# ── PKCE ──────────────────────────────────────────────────────────────────────
def _pkce_pair():
    verifier  = secrets.token_urlsafe(64)
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge

# ── Session helpers ───────────────────────────────────────────────────────────
def _base_url(handler):
    """http://localhost:3000 locally; https://<ngrok-domain> via proxy.py."""
    host  = handler.headers.get("X-Forwarded-Host") or handler.headers.get("Host") or f"localhost:{PORT}"
    proto = handler.headers.get("X-Forwarded-Proto") or "http"
    return f"{proto}://{host}"

def _get_sid(handler):
    c = SimpleCookie(handler.headers.get("Cookie", ""))
    return c["sid"].value if "sid" in c else None

# ── HTTP utils ────────────────────────────────────────────────────────────────
def _redirect(handler, url, extra_headers=None):
    handler.send_response(302)
    handler.send_header("Location", url)
    for k, v in (extra_headers or []):
        handler.send_header(k, v)
    handler.end_headers()

def _html(handler, body, status=200):
    enc = body.encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(enc)))
    handler.end_headers()
    handler.wfile.write(enc)

def _fetch_json(url, data):
    payload = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

def _post_json_allow_errors(url, data):
    """Like _fetch_json, but returns the JSON body of 4xx OAuth errors."""
    try:
        return _fetch_json(url, data)
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return {"error": f"http_{e.code}"}

def _json(handler, obj, status=200, indent=None):
    enc = json.dumps(obj, indent=indent).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(enc)))
    handler.end_headers()
    handler.wfile.write(enc)

def _sid_cookie(sid):
    return ("Set-Cookie", f"sid={sid}; Path=/; HttpOnly; SameSite=Lax")

def _decode_jwt(token):
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    return json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

_device_users: dict = {}   # normalised device user code → {t, name, username}

def _norm_code(c):
    return "".join(ch for ch in str(c).upper() if ch.isalnum())

def _claims_from_tokens(tok):
    """ID-token claims plus the user's realm roles (carried in the access token)."""
    claims = _decode_jwt(tok.get("id_token", ""))
    try:
        access = _decode_jwt(tok.get("access_token", ""))
        claims["roles"] = list((access.get("realm_access") or {}).get("roles") or [])
    except Exception:
        claims["roles"] = []
    return claims

# ── Wallet service client ─────────────────────────────────────────────────────
def _wallet_call(method, path, payload=None, timeout=15):
    req = urllib.request.Request(
        WALLET_URL + path, method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"X-Wallet-Token": WALLET_TOKEN_FILE.read_text().strip(),
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())

def _wallet_summary(claims):
    """Balance row + 'My wallet' button for the main screen. Never raises: if the wallet
    service is down or the wallet is still being created, the row says so."""
    try:
        w = _wallet_call("GET", "/wallets/" + urllib.parse.quote(claims.get("sub", ""), safe="") + "/balance", timeout=8)
        bal = f'{_usd(w.get("balance"))} {html.escape(w.get("symbol", "OUSD"))}'
        cls = "info-val big"
    except urllib.error.HTTPError as e:
        bal, cls = ("Being set up…" if e.code == 404 else "Unavailable"), "info-val"
    except Exception:
        bal, cls = "Unavailable", "info-val"
    return ('<div class="divider">WALLET</div>'
            '<div class="info-row wallet-row"><span class="info-label">Balance</span>'
            f'<span class="{cls}">{bal}</span>'
            '<a class="btn btn-small" href="/wallet">View details</a></div>')

def _role_label(roles, account_type=None):
    """'admin' (the Keycloak realm role, the only one Keycloak enforces); everyone else is a
    'merchant' or a 'user' according to the Account type chosen at sign-up."""
    if "admin" in (roles or []):
        return "admin"
    return "merchant" if account_type == "merchant" else "user"

def _provision_wallet(claims):
    """Create the user's wallet (and queue the $100 gift) on sign-in, and refresh
    the stored display name and role; idempotent."""
    sub, username = claims.get("sub"), claims.get("preferred_username", "")
    if not sub:
        return
    payload = {"sub": sub, "username": username, "name": claims.get("name", ""),
               "role": _role_label(claims.get("roles"), claims.get("account_type")),
               "businessName": claims.get("business_name", ""),
               "businessDescription": claims.get("business_description", "")}
    def run():
        try:
            _wallet_call("POST", "/wallets", payload)
        except Exception as e:
            print(f"  wallet provisioning failed for {username}: {e}")
    threading.Thread(target=run, daemon=True).start()

def _person(w):
    """Dropdown/flash label: 'Name (username) — role'."""
    name = (w.get("name") or "").strip()
    user = w.get("username") or "—"
    who = f"{name} ({user})" if name and name != user else (name or user)
    return f"{who} — {w.get('role') or 'user'}"

def _ousd(value):
    try:
        return f"{Decimal(value):,.4f}"
    except Exception:
        return "—"

def _usd(value):
    """'$1,234.50': dollars and cents, used for balances. Always rounds DOWN, so 26.999998 shows as $26.99:
    a balance is never displayed as more than the wallet holds."""
    try:
        return f"${Decimal(value).quantize(Decimal('0.01'), rounding=ROUND_DOWN):,.2f}"
    except Exception:
        return "—"

def _when(ts):
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%b %d, %H:%M UTC")
    except Exception:
        return "—"

def _explorer_link(kind, value, text):
    v = html.escape(value, quote=True)
    return f'<a href="{EXPLORER}/{kind}/{v}" target="_blank" rel="noopener">{text}</a>'

def _wallet_html(w):
    addr = w.get("address", "")
    gift_tx = (w.get("gift") or {}).get("tx")
    rows = []
    for t in w.get("history", []):
        incoming = t.get("direction") == "in"
        from_treasury = t.get("label") == "treasury"
        memo = t.get("memo") or ""
        is_order = re.fullmatch(r"ord_[0-9a-f]{12}", memo) is not None
        if incoming and from_treasury:
            what = "Welcome gift" if t.get("hash") == gift_tx else "From treasury"
        elif is_order:
            what = "Sale" if incoming else "Purchase"
        else:
            what = "Received" if incoming else "Sent"
        cp = t.get("counterparty", "")
        who = "Agent Pay treasury" if from_treasury else f"{html.escape(cp[:8])}…{html.escape(cp[-6:])}"
        amount = ("+" if incoming else "−") + _ousd(t.get("amount"))
        rows.append(
            "<tr>"
            f'<td>{html.escape(_when(t.get("timestamp")))}</td>'
            f"<td>{what}</td>"
            f'<td class="mono">{_explorer_link("address", cp, who)}</td>'
            f'<td class="memo">{html.escape(memo)}</td>'
            f'<td class="num {"st-ok" if incoming else ""}">{amount}</td>'
            f'<td class="mono" style="white-space:nowrap">{_explorer_link("tx", t.get("hash", ""), "view")}'
            f'{" · <a href=/receipt/" + memo + ">receipt</a>" if is_order else ""}</td></tr>')
    if not rows:
        rows.append('<tr><td colspan="6" class="empty">No transactions yet.</td></tr>')
    gift = (w.get("gift") or {}).get("status")
    notice = ""
    if gift in ("queued", "pending"):
        notice = '<div class="flash flash-info" role="status">Your $100 welcome gift is on its way…</div>'
    elif gift == "failed":
        notice = ('<div class="flash flash-err" role="status">The welcome gift could not be sent. '
                  "It will be retried the next time you sign in.</div>")
    return (
        f"{notice}"
        '<div class="divider">BALANCE</div>'
        '<div class="info-row"><span class="info-label">Available</span>'
        f'<span class="info-val big">{_usd(w.get("balance"))} {html.escape(w.get("symbol", "OUSD"))}</span></div>'
        '<div class="info-row"><span class="info-label">Wallet</span>'
        f'<span class="info-val mono">{_explorer_link("address", addr, html.escape(addr[:10]) + "…" + html.escape(addr[-8:]))}</span></div>'
        '<div class="info-row"><span class="info-label">Test token</span>'
        '<span class="info-val">Tempo testnet · no real value</span></div>'
        '<div class="divider" style="margin-top:28px">TRANSACTION HISTORY</div>'
        '<table class="tbl"><thead><tr><th>When</th><th>Type</th><th>With</th><th>Memo</th>'
        '<th class="num">OUSD</th><th>Tx</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>')

# ── Agents (each "user" creates and owns agents; JSON file store) ─────────────
AGENTS_FILE = BASE_DIR / "data" / "agents.json"
_agents_lock = threading.Lock()
MAX_AGENTS_PER_USER = 20
AGENT_NAME_MAX, AGENT_DESC_MAX = 40, 280
AGENT_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9_-]*")

def _agent_fullname(claims, slug):
    """'<username>.<agent>', e.g. user4.sneaker-hunter (no spaces anywhere)."""
    owner = re.sub(r"\s+", "_", claims.get("preferred_username") or claims["sub"][:8])
    return f"{owner}.{slug}"

def _is_user(claims):
    """True for account type 'user' (not an admin, not a merchant)."""
    return _role_label(claims.get("roles"), claims.get("account_type")) == "user"

def _agents_read():
    try:
        return json.loads(AGENTS_FILE.read_text())
    except FileNotFoundError:
        return []

def _agents_write(agents):
    AGENTS_FILE.parent.mkdir(exist_ok=True)
    tmp = AGENTS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(agents, indent=2))
    os.replace(tmp, AGENTS_FILE)

def _agents_all():
    with _agents_lock:
        everyone = _agents_read()
    return sorted(everyone, key=lambda a: a.get("created", 0), reverse=True)

def _all_agents_html(agents, registry_kids, registry_ok):
    """Admin page body: every agent from every owner, checked against the public key registry."""
    e = html.escape
    owners = {a.get("owner_sub") for a in agents}
    summary = (
        '<div class="divider">OVERVIEW</div>'
        f'<div class="info-row"><span class="info-label">Agents</span><span class="info-val">{len(agents)}</span></div>'
        f'<div class="info-row" style="margin-bottom:16px"><span class="info-label">Owners</span>'
        f'<span class="info-val">{len(owners)}</span></div>')
    notice = ("" if registry_ok else
              '<div class="flash flash-err" role="status">The key registry is unreachable, so registry '
              "checks are not shown.</div>")
    rows = []
    for a in agents:
        kid = a.get("keyid") or ""
        if not kid:
            reg = '<span class="st-wait">no identity yet</span>'
        elif not registry_ok:
            reg = "—"
        elif kid in registry_kids:
            reg = '<span class="st-ok">✔ in registry</span>'
        else:
            reg = '<span class="st-err">missing</span>'
        key = (f'<a href="/keys?keyID={urllib.parse.quote(kid, safe="")}" target="_blank" rel="noopener">{e(kid[:10])}…</a>'
               if kid else "—")
        rows.append(
            "<tr>"
            f'<td class="mono"><a href="/treasury/agents/{e(a.get("id", ""), quote=True)}">{e(a.get("name", "—"))}</a><div class="dim small">{e(a.get("id", ""))}</div></td>'
            f'<td>{e(a.get("owner_username") or "—")}</td>'
            f'<td class="agent-desc">{e(a.get("description") or "")}</td>'
            f'<td class="mono">{key}<div class="small">{reg}</div></td>'
            f'<td>{e(_when(a.get("created")))}</td></tr>')
    if not rows:
        rows.append('<tr><td colspan="5" class="empty">No agents yet. Users with the “user” account type '
                    "create them from My agents.</td></tr>")
    return (f"{notice}{summary}"
            '<div class="divider">AGENTS</div>'
            '<table class="tbl"><thead><tr><th>Agent</th><th>Owner</th><th>Description</th>'
            '<th>TAP key</th><th>Created</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>')

def _agents_of(sub):
    with _agents_lock:
        mine = [a for a in _agents_read() if a.get("owner_sub") == sub]
    return sorted(mine, key=lambda a: a.get("created", 0), reverse=True)

def _agent_create(claims, slug, description):
    """Returns (agent, error_message). The agent's name is '<username>.<slug>'."""
    full = _agent_fullname(claims, slug)
    with _agents_lock:
        agents = _agents_read()
        mine = [a for a in agents if a.get("owner_sub") == claims["sub"]]
        if len(mine) >= MAX_AGENTS_PER_USER:
            return None, f"You can have at most {MAX_AGENTS_PER_USER} agents."
        if any(a["name"].casefold() == full.casefold() for a in agents):
            return None, f"An agent named “{full}” already exists."
        agent_id = "agt_" + secrets.token_hex(6)
        try:
            ident = _wallet_call("POST", "/agents/identity", {"agentId": agent_id, "name": full}, timeout=10)
        except Exception:
            return None, "Could not create the agent’s identity right now. Please try again in a moment."
        agent = {"id": agent_id, "owner_sub": claims["sub"],
                 "owner_username": claims.get("preferred_username", ""),
                 "slug": slug, "name": full, "keyid": ident["kid"],
                 "description": description, "created": int(time.time())}
        agents.append(agent)
        _agents_write(agents)
    return agent, None

def _agents_backfill(agents):
    """Give agents created before identities existed a TAP identity (idempotent)."""
    missing = [a for a in agents if not a.get("keyid")]
    if not missing:
        return agents
    with _agents_lock:
        stored = {a["id"]: a for a in _agents_read()}
        changed = False
        for a in missing:
            try:
                ident = _wallet_call("POST", "/agents/identity", {"agentId": a["id"], "name": a["name"]}, timeout=10)
            except Exception:
                continue
            a["keyid"] = ident["kid"]
            if a["id"] in stored:
                stored[a["id"]]["keyid"] = ident["kid"]
                changed = True
        if changed:
            _agents_write(list(stored.values()))
    return agents

# ── Mandates: grant an agent authority (owner only; a fresh passkey sign-in signs it) ──
_pending_mandates = {}   # token -> {sub, agent_id, params, created}
MANDATE_HOURS = {1: "1 hour", 24: "24 hours", 168: "7 days", 720: "30 days"}
AMOUNT_RE = re.compile(r"[0-9]+(\.[0-9]{1,6})?")

def _norm_amount(text):
    """Same normal form as the wallet service (150.00 -> 150, 0.50 -> 0.5), so both sides hash the same terms."""
    return format(Decimal(text).normalize(), "f")

def _terms_hash(terms):
    """Hash of the exact terms the user is about to approve. It travels as the sign-in's nonce, so Keycloak's signed
    ID token proves this account signed in again for these terms and nothing else."""
    raw = json.dumps(terms, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()

def _agent_owned(sub, agent_id):
    return next((a for a in _agents_all() if a.get("id") == agent_id and a.get("owner_sub") == sub), None)

def _finish_mandate_stepup(claims, token, id_token):
    """Runs after the owner signed in again. Returns ((kind, text), page to show)."""
    p = _pending_mandates.pop(token, None)
    if not p or p["sub"] != claims.get("sub") or time.time() - p["created"] > 300:
        return ("err", "That approval expired or belongs to another account, so nothing was signed. Please try again."), "/agents"
    idc = _decode_jwt(id_token)
    auth_time = idc.get("auth_time")
    fresh = isinstance(auth_time, (int, float)) and time.time() - auth_time <= 120 and idc.get("nonce") == p.get("nonce")
    if p.get("kind") == "approval":
        back = f"/approvals/{p['approval_id']}"
        if not fresh:
            return ("err", "We couldn’t confirm that you signed in again just now, so the purchase was not approved."), back
        try:
            _wallet_call("POST", f"/approvals/{p['approval_id']}/approve", {"sub": claims["sub"], "idToken": id_token}, timeout=20)
            return ("ok", "Approved. The agent can now repeat its checkout and the store will quote this exact purchase."), back
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error") or f"error {e.code}"
            except Exception:
                msg = f"error {e.code}"
            return ("err", f"Not approved: {msg}"), back
        except Exception as e:
            return ("err", f"Wallet service unreachable: {e}"), back
    back = f"/agents/{p['agent_id']}"
    if not fresh:
        return ("err", "We couldn’t confirm that you signed in again just now, so no mandate was created."), back
    if not _agent_owned(claims["sub"], p["agent_id"]):
        return ("err", "That agent isn’t yours."), "/agents"
    try:
        out = _wallet_call("POST", "/mandates", {"sub": claims["sub"], "agentId": p["agent_id"], **p["params"], "proof": {"idToken": id_token}}, timeout=20)
        return ("ok", f"Mandate {out['id']} granted. Your agent can now buy within those limits."), back
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error") or f"error {e.code}"
        except Exception:
            msg = f"error {e.code}"
        return ("err", f"The mandate was not created: {msg}"), back
    except Exception as e:
        return ("err", f"Wallet service unreachable: {e}"), back

def _iso_to_epoch(text):
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None

def _agent_detail_html(agent, mandates, merchants, csrf, flash="", approvals=(), readonly=False, orders=()):
    e = html.escape
    pend = [] if readonly else [a for a in approvals if a["status"] == "pending"]
    approvals_html = ('<div class="divider" style="margin-top:28px">WAITING FOR YOUR APPROVAL</div>' + ''.join(
        f'<a class="btn" style="margin-bottom:8px" href="/approvals/{e(a["id"], quote=True)}">Review: {e(a.get("item") or a["sku"])} at {e(a["businessName"])} for {e(_ousd(a["amount"]))} OUSD</a>' for a in pend)) if pend else ""
    kid = agent.get("keyid") or ""
    key = (f'<a href="/keys?keyID={urllib.parse.quote(kid, safe="")}" target="_blank" rel="noopener">{e(kid[:14])}…</a>'
           if kid else "—")
    def row(label, value, mono=False):
        return (f'<div class="info-row"><span class="info-label">{e(label)}</span>'
                f'<span class="info-val{" mono" if mono else ""}">{value}</span></div>')
    stores = "".join(
        f'<label class="check"><input type="checkbox" name="merchants" value="{e(m["username"], quote=True)}"> '
        f'{e(m["businessName"])} <span class="dim">({e(m["username"])})</span></label>' for m in merchants
    ) or '<div class="dim">No stores exist yet.</div>'
    hours = "".join(f'<option value="{h}"{" selected" if h == 24 else ""}>{e(t)}</option>' for h, t in MANDATE_HOURS.items())
    form = (
        '<form class="send-form" method="post" action="/agents/' + e(agent["id"], quote=True) + '/mandates"'
        ' data-confirm="You will be asked to sign in again with your passkey to approve this mandate. Continue?">'
        f'<input type="hidden" name="csrf" value="{e(csrf, quote=True)}">'
        f'<label class="info-label">Stores this agent may buy from</label><div class="checks">{stores}</div>'
        '<label class="info-label" for="maxPerPurchase">Limit per purchase (OUSD)</label>'
        '<input class="field" id="maxPerPurchase" name="maxPerPurchase" inputmode="decimal" autocomplete="off" placeholder="150" required pattern="[0-9]+(\\.[0-9]{1,6})?">'
        '<label class="info-label" for="budget">Total budget (OUSD)</label>'
        '<input class="field" id="budget" name="budget" inputmode="decimal" autocomplete="off" placeholder="300" required pattern="[0-9]+(\\.[0-9]{1,6})?">'
        f'<label class="info-label" for="hours">Valid for</label><select class="field" id="hours" name="hours">{hours}</select>'
        '<button class="btn" type="submit">Approve with passkey</button></form>')
    rows = []
    for m in mandates:
        cls = {"active": "st-ok", "expired": "st-wait", "revoked": "st-err"}.get(m["status"], "")
        exp = _iso_to_epoch(m.get("expiresAt"))
        revoke = (f'<form class="inline-form" method="post" action="/agents/{e(agent["id"], quote=True)}/mandates/{e(m["id"], quote=True)}/revoke" '
                  f'data-confirm="Revoke this mandate? The agent will not be able to buy with it any more.">'
                  f'<input type="hidden" name="csrf" value="{e(csrf, quote=True)}"><button class="btn-mini" type="submit">Revoke</button></form>'
                  if m["status"] == "active" and not readonly else "")
        rows.append(
            "<tr>"
            f'<td class="mono">{e(m["id"])}<div class="small {cls}">{e(m["status"])}</div></td>'
            f'<td>{e(", ".join(m.get("merchants", [])))}</td>'
            f'<td>{e(_ousd(m["maxPerPurchase"]))}<div class="dim small">per purchase · {e(_ousd(m["budget"]))} total</div></td>'
            f'<td>{e(_ousd(m["spent"]))}<div class="dim small">{e(_ousd(m["remaining"]))} left</div></td>'
            f'<td>{e(_when(exp)) if exp else "—"}</td>{"" if readonly else f"<td>{revoke}</td>"}</tr>')
    ord_rows = "".join(
        f'<tr><td>{e(o.get("item") or o["sku"])}<div class="dim small">{e(o["businessName"])} · {e(o["id"])}</div></td>'
        f'<td>{e(_ousd(o["amount"]))}</td>'
        f'<td><span class="{ {"paid": "st-ok", "payment_required": "st-wait", "paying": "st-wait"}.get(o["status"], "st-err") }">{e(o["status"].replace("_", " "))}</span>'
        + (f'<form class="inline-form" method="post" action="/agents/retry"><input type="hidden" name="csrf" value="{e(csrf, quote=True)}">'
           f'<input type="hidden" name="order" value="{e(o["id"], quote=True)}"><button class="btn-mini" type="submit">Retry</button></form>'
           if not readonly and csrf and o["status"] in ("failed", "expired") else "") +
        (f'<form class="inline-form" method="post" action="/agents/pay-order"><input type="hidden" name="csrf" value="{e(csrf, quote=True)}">'
         f'<input type="hidden" name="order" value="{e(o["id"], quote=True)}"><button class="btn-mini" type="submit">Pay now</button></form>'
         if not readonly and csrf and o["status"] == "payment_required" else "") +
        f'{"<div class=small>signed receipts ✔</div>" if o["status"] == "paid" and (o.get("receipts") or {}).get("payment") else ""}'
        f'{"<div class=small><a href=/receipt/" + e(o["id"]) + ">receipt</a> · <a href=/orders/" + e(o["id"]) + "/evidence.json>evidence</a></div>" if (o.get("receipts") or {}).get("mandate") else ""}</td>'
        f'<td class="mono">{_explorer_link("tx", o["txHash"], e(o["txHash"][:10]) + "…") if o.get("txHash") else "—"}</td>'
        f'<td>{e(_when(_iso_to_epoch(o["createdAt"])))}</td></tr>' for o in orders)
    purchases_html = ('<div class="divider" style="margin-top:28px">PURCHASES</div>'
                      '<table class="tbl"><thead><tr><th>Item</th><th>OUSD</th><th>Status</th><th>Transaction</th><th>Quoted</th></tr></thead>'
                      f'<tbody>{ord_rows or "<tr><td colspan=5 class=empty>No purchases yet.</td></tr>"}</tbody></table>')
    cols = 5 if readonly else 6
    empty = "No mandates yet. This agent cannot buy anything." if readonly else "No mandates yet. This agent cannot buy anything until you grant one."
    table = ('<table class="tbl"><thead><tr><th>Mandate</th><th>Stores</th><th>Limits (OUSD)</th><th>Used</th><th>Expires</th>' + ("" if readonly else "<th></th>") + '</tr></thead>'
             f'<tbody>{"".join(rows) or f"<tr><td colspan={cols} class=empty>{empty}</td></tr>"}</tbody></table>')
    if readonly:
        ap_rows = "".join(
            f'<tr><td class="mono">{e(a["id"])}</td><td>{e(a["businessName"])}</td><td>{e(a.get("item") or a["sku"])}</td>'
            f'<td>{e(_ousd(a["amount"]))}</td><td>{e(a["status"])}</td></tr>' for a in approvals)
        approvals_html = ('<div class="divider" style="margin-top:28px">PURCHASE APPROVALS</div>'
                          '<table class="tbl"><thead><tr><th>Request</th><th>Store</th><th>Item</th><th>OUSD</th><th>Status</th></tr></thead>'
                          f'<tbody>{ap_rows or "<tr><td colspan=5 class=empty>None.</td></tr>"}</tbody></table>')
        return (f"{flash}"
                '<div class="divider">IDENTITY</div>'
                + row("Name", e(agent["name"]), mono=True) + row("Agent ID", e(agent["id"]), mono=True)
                + row("Owner", e(agent.get("owner_username") or "—")) + row("TAP-style key", key, mono=True)
                + row("Description", e(agent.get("description") or "—")) + row("Created", e(_when(agent.get("created"))))
                + '<div class="divider" style="margin-top:28px">MANDATES</div>' + table + purchases_html + approvals_html)
    return (
        f"{flash}"
        '<div class="divider">IDENTITY</div>'
        + row("Name", e(agent["name"]), mono=True) + row("Agent ID", e(agent["id"]), mono=True)
        + row("TAP-style key", key, mono=True) + row("Description", e(agent.get("description") or "—"))
        + f'<a class="btn" style="margin-top:14px" href="/agents/direct?agent={e(agent["id"], quote=True)}">Direct this agent</a>'
        + '<div class="divider" style="margin-top:28px">GRANT AUTHORITY</div>'
        '<p class="dim" style="margin-bottom:14px">A mandate is a permission slip you sign for this agent: which stores, how much per purchase, '
        'how much in total, and for how long. Stores check it, along with the agent’s signed request, before they quote a price.</p>'
        + form
        + '<div class="divider" style="margin-top:28px">MANDATES</div>' + table
        + purchases_html + approvals_html)

# ── Direct an agent: send one of your agents shopping, using one of its mandates ─────────────────────────
# The app plays the agent runtime for you: it has the wallet service sign the request with the agent's key and sign a
# closed mandate for the exact order, then makes the same checkout request an outside agent would make, and (optionally)
# asks the wallet to pay. Runs live in memory and are shown at /agents/run/<id>.
_runs = {}
_runs_lock = threading.Lock()
RUN_TTL = 3600
APPROVAL_WAIT = 300
SKU_RE = re.compile(r"[A-Za-z0-9-]{1,40}")
RUN_LABELS = {"running": ("Working…", "st-wait"), "waiting_approval": ("Waiting for your approval", "st-wait"),
              "quoted": ("Quoted: nothing was paid", "st-ok"), "paid": ("Paid", "st-ok"),
              "refused": ("Refused by the store", "st-err"), "declined": ("You declined the purchase", "st-err"),
              "failed": ("Failed", "st-err")}

def _err_text(e):
    try:
        return json.loads(e.read()).get("error") or f"error {e.code}"
    except Exception:
        return f"error {e.code}"

def _run_step(run, text):
    run["log"].append(text)

def _run_agent(run):
    """Background thread: one agent errand from start to quote or payment."""
    try:
        agent_id, username, sku = run["agent_id"], run["store"], run["sku"]
        ms = _wallet_call("GET", f"/agents/{agent_id}/mandates")["mandates"]
        mandate = next((x for x in ms if x["id"] == run["mandate_id"]), None)
        if not mandate or mandate["status"] != "active":
            run["status"] = "failed"
            _run_step(run, "That mandate is not active any more, so the agent has no authority to act.")
            return
        _run_step(run, f"Agent {run['agent_name']} presents mandate {mandate['id']}: up to {_ousd(mandate['maxPerPurchase'])} per purchase, {_ousd(mandate['remaining'])} of {_ousd(mandate['budget'])} left.")
        merchant = _wallet_call("GET", "/merchants/" + urllib.parse.quote(username, safe=""), timeout=10)
        store_url = f"{run['base']}/shop/{urllib.parse.quote(username)}"
        product = next((p for p in shop.products(username, store_url) if p["sku"].upper() == sku.upper()), None)
        if not product:
            run["status"] = "failed"
            _run_step(run, f"{merchant['businessName'] or username} has no item {sku}.")
            return
        sku = product["sku"]
        run["item_name"], run["price"] = product["name"], product["price"]
        _run_step(run, f"The agent wants {product['name']} ({sku}) for {product['price']} OUSD from {merchant['businessName'] or username}.")

        def pay_it(order_id):
            _run_step(run, "Paying from your wallet on Tempo testnet…")
            try:
                out = _wallet_call("POST", f"/agents/{agent_id}/pay", {"orderId": order_id}, timeout=120)
            except urllib.error.HTTPError as e:
                run["status"], run["retry"] = "failed", True
                _run_step(run, f"The payment did not go through: {_err_text(e)} Nothing was charged. Fix that, then retry: the agent will ask the store again, and any approval you gave is reused while it is still valid.")
                return
            run["tx"], run["receipts"] = out.get("txHash"), sorted((out.get("receipts") or {}).keys())
            run["status"] = "paid"
            _run_step(run, "The store confirmed the transfer on-chain and issued a signed payment receipt. Done.")

        if run.get("existing_order"):
            o = _wallet_call("GET", f"/orders/{run['existing_order']}", timeout=10)
            if o["status"] != "payment_required" or o["agentId"] != agent_id:
                run["status"], run["retry"] = "failed", o["status"] in ("failed", "expired")
                _run_step(run, f"That quote is {o['status'].replace('_', ' ')}, so it can’t be paid any more." + (" Use Retry to ask the store again." if run["retry"] else ""))
                return
            run["quote"], run["order_id"] = {"amount": o["amount"], "payTo": merchant["address"]}, o["id"]
            _run_step(run, f"The agent already holds an open quote for this ({o['id']}, valid until {_long_time(o['expiresAt'])}), so it pays that one without asking the store again.")
            pay_it(o["id"])
            return
        order = {"amount": product["price"], "currency": "OUSD", "merchant": username, "quantity": 1, "sku": sku}
        path = f"/shop/{username}/checkout"

        def attempt():
            headers = _wallet_call("POST", "/agents/sign", {"agentId": agent_id, "authority": run["authority"], "path": path,
                                                          "tag": "agent-payer-auth"})["headers"]
            closed = _wallet_call("POST", f"/agents/{agent_id}/closed-mandate",
                                  {"openJws": mandate["jws"], "order": order, "payee": merchant["address"]})["jws"]
            status, resp = _checkout_core(run["base"], run["authority"], path, username, sku,
                                          {"open": mandate["jws"], "closed": closed}, headers)
            run["checks"] = resp.get("checks", run["checks"])
            return status, resp

        _run_step(run, "The agent signs its request (TAP style) and a closed mandate for exactly this order, then asks the store to check out.")
        status, resp = attempt()
        if resp.get("status") == "approval_required":
            run["status"], run["approval_path"] = "waiting_approval", f"/approvals/{resp['approval']['id']}"
            _run_step(run, "This store needs you to approve this exact purchase. Review it and approve with your passkey; the agent is waiting.")
            deadline = time.time() + APPROVAL_WAIT
            while time.time() < deadline:
                time.sleep(3)
                status, resp = attempt()
                if status == 402:
                    break
                if "declined" in (resp.get("reason") or ""):
                    run["status"] = "declined"
                    _run_step(run, "You declined, so the store refused the purchase.")
                    return
            else:
                run["status"], run["retry"] = "failed", True
                _run_step(run, "Nobody approved within 5 minutes, so the agent gave up. You can retry.")
                return
            run["status"], run["approval_path"] = "running", None
            _run_step(run, "Approved. The agent retries the checkout.")
        if status != 402:
            run["status"] = "refused"
            _run_step(run, f"The store refused: {resp.get('reason') or resp.get('code')}")
            return
        run["quote"], run["order_id"] = resp["payment"], resp["orderId"]
        _run_step(run, f"The store verified the agent and the mandate and quoted {resp['payment']['amount']} OUSD (order {resp['orderId']}). A signed mandate receipt came with it.")
        if not run["pay"]:
            run["status"] = "quoted"
            _run_step(run, "You chose quote only, so nothing was paid. The quote is valid for 5 minutes.")
            return
        pay_it(resp["orderId"])
    except urllib.error.HTTPError as e:
        run["status"] = "failed"
        _run_step(run, f"Something was refused along the way: {_err_text(e)}")
    except Exception as e:
        run["status"] = "failed"
        _run_step(run, f"Something went wrong: {e}")

def _start_run(sub, agent, mandate_id, store, sku, pay, base, existing_order=None):
    now = time.time()
    with _runs_lock:
        for k in [k for k, v in _runs.items() if now - v["created"] > RUN_TTL]:
            del _runs[k]
        active = [v for v in _runs.values() if v["sub"] == sub and v["status"] in ("running", "waiting_approval")]
        if len(active) >= 3:
            return None
        run = {"id": "run_" + secrets.token_hex(8), "sub": sub, "agent_id": agent["id"], "agent_name": agent["name"],
               "mandate_id": mandate_id, "store": store, "sku": sku, "pay": pay, "created": now, "status": "running",
               "log": [], "checks": [], "base": base, "authority": urllib.parse.urlparse(base).netloc,
               "approval_path": None, "retry": False, "existing_order": existing_order, "quote": None, "order_id": None, "tx": None, "receipts": [], "item_name": None, "price": None}
        _runs[run["id"]] = run
    threading.Thread(target=_run_agent, args=(run,), daemon=True).start()
    return run

def _run_html(run, csrf=None):
    e = html.escape
    label, cls = RUN_LABELS[run["status"]]
    active = run["status"] in ("running", "waiting_approval")
    def row(k, v, mono=False):
        return f'<div class="info-row"><span class="info-label">{e(k)}</span><span class="info-val{" mono" if mono else ""}">{v}</span></div>'
    item = f'{e(run["item_name"])} <span class="dim">{e(run["sku"])}</span> · {e(run["price"])} OUSD' if run["item_name"] else e(run["sku"])
    out = (f'<div class="divider">THE ERRAND</div>'
           + row("Status", f'<span class="{cls}">{e(label)}</span>')
           + row("Agent", e(run["agent_name"]), True) + row("Mandate", e(run["mandate_id"]), True)
           + row("Store", e(run["store"]), True) + row("Item", item)
           + row("Action", "Pay" if run["pay"] else "Quote only"))
    if run["approval_path"] and run["status"] == "waiting_approval":
        out += f'<a class="btn" style="margin-top:14px" href="{e(run["approval_path"], quote=True)}">Review and approve this purchase</a>'
    out += '<div class="divider" style="margin-top:28px">WHAT THE AGENT DID</div><ol class="steps">' + "".join(f"<li>{e(t)}</li>" for t in run["log"]) + ("<li class=\"dim\">…</li>" if active else "") + "</ol>"
    if run["checks"]:
        rows = "".join(f'<tr><td class="{"st-ok" if c.get("ok") else "st-err"}">{"✔" if c.get("ok") else "✘"}</td><td class="mono">{e(c["name"])}</td><td>{e(c.get("detail", ""))}</td></tr>' for c in run["checks"])
        out += ('<div class="divider" style="margin-top:28px">WHAT THE STORE CHECKED</div>'
                f'<table class="tbl"><thead><tr><th></th><th>Check</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table>')
    if run["quote"]:
        out += ('<div class="divider" style="margin-top:28px">QUOTE AND PAYMENT</div>'
                + row("Order", e(run["order_id"]), True) + row("Amount", f'{e(run["quote"]["amount"])} OUSD')
                + row("Pay to", e(run["quote"]["payTo"]), True))
        if run["tx"]:
            out += row("Transaction", _explorer_link("tx", run["tx"], e(run["tx"][:18]) + "…"), True)
            out += row("Receipts", e(" and ".join(run["receipts"]) or "—") + f' (signed by the store) · <a href="/receipt/{e(run["order_id"], quote=True)}">view the receipt</a>')
    retry = ""
    if run["retry"] and run["status"] == "failed" and csrf:
        retry = ('<form method="post" action="/agents/retry" style="margin-top:20px">'
                 f'<input type="hidden" name="csrf" value="{e(csrf, quote=True)}"><input type="hidden" name="run" value="{e(run["id"], quote=True)}">'
                 '<button class="btn" type="submit">Retry the purchase</button></form>')
    if run["status"] == "quoted" and run["order_id"] and csrf:
        retry = ('<form method="post" action="/agents/pay-order" style="margin-top:20px">'
                 f'<input type="hidden" name="csrf" value="{e(csrf, quote=True)}"><input type="hidden" name="run" value="{e(run["id"], quote=True)}">'
                 '<button class="btn" type="submit">Pay for it now</button></form>')
    out += retry
    nav = f'<a class="btn" style="margin-top:28px" href="/agents/direct?agent={e(run["agent_id"], quote=True)}">Direct another errand</a>'
    refresh = '<script>setTimeout(function () { location.reload(); }, 2500);</script>' if active else ""
    return out + nav + refresh

def _direct_html(agents, mandates, merchants, csrf, flash="", pick="", runs=()):
    e = html.escape
    if not agents:
        return f'{flash}<p class="dim">You need an agent first. <a href="/agents">Create one</a>.</p>'
    data = json.dumps({"agents": [{"id": a["id"], "name": a["name"]} for a in agents],
                       "mandates": [{"id": m["id"], "agentId": m["agentId"], "merchants": m["merchants"], "maxPerPurchase": m["maxPerPurchase"],
                                     "remaining": m["remaining"]} for m in mandates],
                       "stores": [{"username": m["username"], "name": m["businessName"]} for m in merchants]}).replace("</", "<\\/")
    agent_opts = "".join(f'<option value="{e(a["id"], quote=True)}"{" selected" if a["id"] == pick else ""}>{e(a["name"])}</option>' for a in agents)
    recent = "".join(
        f'<tr><td class="mono"><a href="/agents/run/{e(r["id"], quote=True)}">{e(r["id"][4:12])}</a></td><td>{e(r["store"])}</td><td>{e(r["sku"])}</td>'
        f'<td>{"pay" if r["pay"] else "quote"}</td><td class="{RUN_LABELS[r["status"]][1]}">{e(RUN_LABELS[r["status"]][0])}</td></tr>' for r in runs)
    form = f"""{flash}
<div class="divider">DIRECT AN AGENT</div>
<p class="dim" style="margin-bottom:14px">Send one of your agents on an errand. It can only act within the mandate you choose, and the store checks it exactly as it would check any outside agent.</p>
<form id="directform" class="send-form" method="post" action="/agents/direct">
<input type="hidden" name="csrf" value="{e(csrf, quote=True)}">
<label class="info-label" for="d-agent">Agent</label>
<select class="field" id="d-agent" name="agent">{agent_opts}</select>
<label class="info-label" for="d-mandate">Mandate</label>
<select class="field" id="d-mandate" name="mandate"></select>
<label class="info-label" for="d-store">Store</label>
<select class="field" id="d-store" name="store"></select>
<label class="info-label" for="d-sku">Item ID</label>
<input class="field" id="d-sku" name="sku" list="d-items" placeholder="VSE-010" autocomplete="off" required pattern="[A-Za-z0-9\\-]{{1,40}}">
<datalist id="d-items"></datalist>
<label class="info-label">What should the agent do?</label>
<div class="checks">
<label class="check"><input type="radio" name="mode" value="quote" checked> Quote only: check out and get a price, pay nothing</label>
<label class="check"><input type="radio" name="mode" value="pay"> Pay: buy it from my wallet if the store accepts</label>
</div>
<button class="btn" id="d-go" type="submit">Send the agent</button>
</form>
<script type="application/json" id="direct-data">{data}</script>
<script>
(function () {{
  var D = JSON.parse(document.getElementById('direct-data').textContent);
  var agent = document.getElementById('d-agent'), mandate = document.getElementById('d-mandate'),
      store = document.getElementById('d-store'), sku = document.getElementById('d-sku'),
      items = document.getElementById('d-items'), go = document.getElementById('d-go');
  function opt(v, t, sel) {{ var o = document.createElement('option'); o.value = v; o.textContent = t; if (sel) o.selected = true; return o; }}
  function current() {{ return D.mandates.filter(function (m) {{ return m.id === mandate.value; }})[0]; }}
  function fillStores() {{
    var keep = store.value, m = current();
    store.textContent = '';
    D.stores.forEach(function (s) {{
      var ok = m && m.merchants.indexOf(s.username) >= 0;
      store.appendChild(opt(s.username, s.name + ' (' + s.username + ')' + (ok ? '' : ' - not on this mandate'), s.username === keep));
    }});
    fillItems();
  }}
  function fillMandates() {{
    mandate.textContent = '';
    var list = D.mandates.filter(function (m) {{ return m.agentId === agent.value; }});
    list.forEach(function (m) {{ mandate.appendChild(opt(m.id, m.id + ' - up to ' + m.maxPerPurchase + ' each, ' + m.remaining + ' left')); }});
    if (!list.length) mandate.appendChild(opt('', 'No active mandate for this agent'));
    go.disabled = !list.length;
    fillStores();
  }}
  function fillItems() {{
    items.textContent = '';
    if (!store.value) return;
    fetch('/shop/' + encodeURIComponent(store.value) + '/catalog.json').then(function (r) {{ return r.json(); }}).then(function (c) {{
      c.products.forEach(function (p) {{ var o = document.createElement('option'); o.value = p.sku; o.label = p.name + ' - ' + p.price + ' OUSD'; items.appendChild(o); }});
      sku.placeholder = c.products[0] ? c.products[0].sku : '';
    }}).catch(function () {{}});
  }}
  agent.addEventListener('change', fillMandates);
  mandate.addEventListener('change', fillStores);
  store.addEventListener('change', fillItems);
  document.getElementById('directform').addEventListener('submit', function (e) {{
    var pay = document.querySelector('input[name=mode]:checked').value === 'pay';
    if (pay && !confirm('The agent will pay for ' + sku.value + ' from your wallet if the store accepts it. Continue?')) {{ e.preventDefault(); return; }}
    go.disabled = true;
  }});
  fillMandates();
}}());
</script>"""
    if runs:
        form += ('<div class="divider" style="margin-top:28px">RECENT ERRANDS</div>'
                 '<table class="tbl"><thead><tr><th>Run</th><th>Store</th><th>Item</th><th>Action</th><th>Status</th></tr></thead>'
                 f'<tbody>{recent}</tbody></table>')
    return form

def _checkout_core(base_url, authority, path, username, sku, mandates, sig_headers):
    """What a store does with a checkout request. Returns (http status, response dict). Used by the public
    endpoint and by 'Direct an agent', which makes the same request the agent would."""
    try:
        m = _wallet_call("GET", "/merchants/" + urllib.parse.quote(username, safe=""), timeout=10)
    except urllib.error.HTTPError as e:
        return (404 if e.code == 404 else 503), {"status": "rejected", "code": "no_such_store"}
    except Exception:
        return 503, {"status": "rejected", "code": "unavailable"}
    store_url = f"{base_url}/shop/{urllib.parse.quote(m['username'])}"
    product = next((p for p in shop.products(m["username"], store_url) if p["sku"] == sku), None)
    if not product:
        return 404, {"status": "rejected", "code": "unknown_sku", "reason": f"This store has no product {sku[:40]!r}."}
    order = {"amount": product["price"], "currency": "OUSD", "merchant": m["username"], "quantity": 1, "sku": product["sku"]}
    request = {"method": "POST", "authority": authority, "path": path, "headers": sig_headers}
    try:
        out = _wallet_call("POST", "/merchants/" + urllib.parse.quote(m["username"], safe="") + "/verify-checkout",
                           {"request": request, "order": order,
                            "mandates": {"open": mandates.get("open"), "closed": mandates.get("closed")},
                            "policy": shop.policy(m), "meta": {"name": product["name"]}, "issuer": store_url}, timeout=15)
    except Exception:
        return 503, {"status": "rejected", "code": "unavailable"}
    checks = out.get("checks", [])
    if out.get("ok"):
        return 402, {"status": "payment_required", "orderId": out["orderId"], "payment": out["payment"],
                     "order": order, "agent": out.get("agent"), "mandateId": out.get("mandateId"), "checks": checks,
                     "receipts": out.get("receipts", {})}
    why = next((c["detail"] for c in checks if not c.get("ok")), "rejected")
    resp = {"status": "rejected", "code": out.get("code"), "reason": why, "agent": out.get("agent"), "checks": checks}
    if out.get("receipts"):
        resp["receipts"] = out["receipts"]
    ap = out.get("approval")
    if ap:
        resp["approval"] = {"id": ap["id"], "status": ap["status"], "url": f"{base_url}/approvals/{ap['id']}",
                            "expiresAt": ap["expiresAt"], "item": ap.get("item"), "amount": ap["amount"], "currency": ap["currency"]}
        if ap["status"] == "pending":
            resp["status"] = "approval_required"
    return out.get("httpStatus", 403), resp

def _amount(value):
    """An exact amount for a receipt: at least two decimals, never rounded ('420' -> '420.00', '10.15678' stays)."""
    try:
        s = format(Decimal(str(value)).normalize(), "f")
        whole, _, frac = s.partition(".")
        return f"{int(whole):,}.{(frac + '00')[:max(2, len(frac))]}"
    except Exception:
        return "—"

def _long_time(iso):
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")
    except Exception:
        return "—"

# status -> (stamp, stamp style, heading, receipt-number label, date label, total label)
RECEIPT_KINDS = {
    "paid":             ("PAID",    "paid",   "Receipt",          "Receipt no.", "Date",   "Total paid"),
    "payment_required": ("UNPAID",  "quoted", "Quote, not paid",  "Quote no.",   "Quoted", "Amount due"),
    "paying":           ("PAYING",  "quoted", "Payment in progress", "Order no.", "Quoted", "Amount due"),
    "expired":          ("EXPIRED", "void",   "Quote expired, not paid", "Quote no.", "Quoted", "Amount due"),
    "failed":           ("FAILED",  "void",   "Payment failed",   "Order no.",   "Quoted", "Amount due"),
}

def _claims_table(jws):
    try:
        c = _decode_jwt(jws)
    except Exception:
        return ""
    rows = []
    for k in ("iss", "iat", "result", "status", "error", "error_description", "reference", "payment_id", "network_confirmation_id"):
        if k in c:
            v = _long_time(datetime.fromtimestamp(c[k], timezone.utc).isoformat()) if k == "iat" else c[k]
            rows.append(f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>")
    return f"<table>{''.join(rows)}</table>"

def _receipt_html(o, owner=False, csrf=None):
    """A printable page for one order: a receipt if it was paid, otherwise a quote or a failed payment. Public-safe:
    no user or agent names unless the viewer owns the order."""
    e = html.escape
    stamp, cls, heading, no_label, date_label, total_label = RECEIPT_KINDS.get(
        o["status"], (o["status"].upper(), "void", "Order", "Order no.", "Date", "Amount"))
    paid, failed = o["status"] == "paid", o["status"] == "failed"
    store = f'/shop/{urllib.parse.quote(o["merchant"])}'
    raw = f'{store}/orders/{o["id"]}'
    when = o.get("paidAt") or o.get("createdAt")
    def row(k, v):
        return f'<div class="row"><span>{e(k)}</span><span>{v}</span></div>'
    def check(state, text):
        return f'<li><span class="{ {True: "ok", False: "no", None: "na"}[state] }">{ {True: "✔", False: "✘", None: "–"}[state] }</span><span>{text}</span></li>'
    v = o.get("verified") or {}
    has_mr = v.get("mandate") is not None
    out = (f'<div class="head"><div class="kicker">{e(heading)}</div><h1><a href="{e(store, quote=True)}">{e(o["businessName"])}</a></h1>'
           f'<div class="sub">{e(o["merchant"])} · Agent Pay demo store</div></div><div class="stamp {cls}">{stamp}</div>')
    out += '<div class="rows">' + row(no_label, e(o["id"])) + row(date_label, e(_long_time(when))) + row("Status", e(stamp.title())) + "</div>"
    out += (f'<div class="item"><div class="line"><span class="name">{e(o.get("item") or o["sku"])}</span><span>{e(_amount(o["amount"]))}</span></div>'
            f'<small>SKU {e(o["sku"])} · quantity 1</small></div>')
    out += f'<div class="total"><span>{total_label}</span><span>{e(_amount(o["amount"]))} {e(o["currency"])}</span></div>'
    out += ('<div class="note">' + ("Paid in OUSD on Tempo testnet. Test tokens, no real money." if paid
            else f'Nothing was charged. {e(o["error"])}' if failed and o.get("error")
            else "Nothing was charged. OUSD is a test token on Tempo testnet.") + "</div>")
    out += "<h2>Payment</h2>" + (
        row("Transaction", _explorer_link("tx", o["txHash"], e(o["txHash"][:10]) + "…" + e(o["txHash"][-6:]))) + (row("Block", e(str(o["blockNumber"]))) if o.get("blockNumber") else "")
        if o.get("txHash") else row("Payment", "failed: no money moved" if failed else "not paid" + (f' · quote valid until {e(_long_time(o["expiresAt"]))}' if o["status"] == "payment_required" else "")))
    pay_text = ("Store’s signed payment receipt: signature " + ("valid" if v.get("payment") else "not valid")) if paid else \
               ("Store’s signed record of the failed payment: signature " + ("valid" if v.get("payment") else "not valid")) if v.get("payment") is not None else \
               "No payment receipt: nothing was paid"
    out += "<h2>How it was authorized</h2><ul class=\"checks\">" + "".join([
        check(True if has_mr else None, "Agent’s signed request verified by the store"),
        check(True if has_mr else None, "Within a mandate signed by the buyer: store, limit and budget checked"),
        check(True if o.get("approved") else None, "Buyer approved this exact purchase" if o.get("approved") else "No per-purchase approval needed at this store"),
        check(v.get("mandate"), "Store’s signed mandate receipt: signature " + ("valid" if v.get("mandate") else "not valid" if v.get("mandate") is False else "not issued")),
        check(v.get("payment") if v.get("payment") is not None else None, pay_text),
    ]) + "</ul>"
    if owner:
        out += (f'<div class="owner"><b>Your purchase</b><br>Agent {e(o["agentName"])}<br>Mandate {e(o["mandateId"])}'
                f'<br><a href="/orders/{e(o["id"], quote=True)}/evidence.json">Download the evidence bundle</a> to check it independently.')
        if o["status"] in ("failed", "expired") and csrf:
            out += ('<form method="post" action="/agents/retry" style="margin-top:10px">'
                    f'<input type="hidden" name="csrf" value="{e(csrf, quote=True)}"><input type="hidden" name="order" value="{e(o["id"], quote=True)}">'
                    '<button class="btn primary" type="submit">Ask the agent to try again</button></form>'
                    '<div style="margin-top:6px;color:var(--muted)">The agent asks the store again and pays from your wallet. If the store needed your approval, it is reused while it is still valid.</div>')
        if o["status"] == "payment_required" and csrf:
            out += ('<form method="post" action="/agents/pay-order" style="margin-top:10px">'
                    f'<input type="hidden" name="csrf" value="{e(csrf, quote=True)}"><input type="hidden" name="order" value="{e(o["id"], quote=True)}">'
                    '<button class="btn primary" type="submit">Pay this quote now</button></form>'
                    '<div style="margin-top:6px;color:var(--muted)">The agent pays the quote it already holds, from your wallet, without asking the store again.</div>')
        out += "</div>"
    for key, title in (("mandate", "Mandate receipt"), ("payment", "Payment receipt" if paid else "Record of the failed payment")):
        jws = (o.get("receipts") or {}).get(key)
        if jws:
            out += f'<details><summary>{title} (signed by the store)</summary>{_claims_table(jws)}<pre class="jws">{e(jws)}</pre></details>'
    out += (f'<div class="actions"><a class="btn primary" href="{e(raw, quote=True)}">View raw JSON</a>'
            '<a class="btn" href="#" onclick="window.print();return false">Print</a>'
            f'<a class="btn" href="{e(store, quote=True)}">Back to the store</a></div>'
            '<div class="foot">Agent Pay · signed receipts, checked on-chain</div>')
    return out

def _agent_page(body, title="AGENT", subtitle="Identity and mandates", back_href="/agents", back_text="Back to my agents"):
    return _render("agent_detail.html", AGENT_BODY=body, TITLE=html.escape(title), SUBTITLE=html.escape(subtitle),
                   BACK_HREF=html.escape(back_href, quote=True), BACK_TEXT=html.escape(back_text))

def _approval_card(a, csrf=None):
    """One purchase approval request. With csrf and status pending it carries the Approve / Decline buttons."""
    e = html.escape
    cls = {"approved": "st-ok", "used": "st-ok", "pending": "st-wait", "rejected": "st-err", "expired": "st-err"}.get(a["status"], "")
    label = {"used": "approved, quote issued"}.get(a["status"], a["status"])
    def row(k, v, mono=False):
        return (f'<div class="info-row"><span class="info-label">{e(k)}</span><span class="info-val{" mono" if mono else ""}">{v}</span></div>')
    out = (row("Status", f'<span class="{cls}">{e(label)}</span>')
           + row("Store", f'{e(a["businessName"])} <span class="dim">({e(a["merchant"])})</span>')
           + row("Item", f'{e(a.get("item") or a["sku"])} <span class="dim">{e(a["sku"])}</span>')
           + row("Price", f'{e(_ousd(a["amount"]))} {e(a["currency"])}')
           + row("Agent", e(a["agentName"]), mono=True)
           + row("Under mandate", e(a["mandateId"]), mono=True)
           + row("Asked", e(_when(_iso_to_epoch(a["createdAt"]))))
           + row("Valid until", e(_when(_iso_to_epoch(a["expiresAt"])))))
    if csrf and a["status"] == "pending":
        base = f'/approvals/{e(a["id"], quote=True)}'
        hidden = f'<input type="hidden" name="csrf" value="{e(csrf, quote=True)}">'
        out += (f'<form class="send-form" method="post" action="{base}/approve" '
                f'data-confirm="You will be asked to sign in again with your passkey to approve this exact purchase. Continue?">{hidden}'
                '<button class="btn" type="submit">Approve this purchase with passkey</button></form>'
                f'<form class="send-form" method="post" action="{base}/reject">{hidden}'
                '<button class="btn btn-secondary" type="submit">Decline</button></form>')
    return out

def _identity_cell(a):
    kid = a.get("keyid")
    if not kid:
        return '<span class="st-wait">pending</span>'
    k = html.escape(kid, quote=True)
    return f'<a href="/tap/keys/{k}" target="_blank" rel="noopener">{html.escape(kid[:10])}…</a>'

def _agents_html(agents, csrf, prefix, flash=""):
    rows = "".join(
        "<tr>"
        f'<td class="mono"><a href="/agents/{html.escape(a["id"], quote=True)}">{html.escape(a["name"])}</a></td>'
        f'<td class="agent-desc">{html.escape(a.get("description") or "")}</td>'
        f'<td class="mono">{_identity_cell(a)}</td>'
        f'<td>{html.escape(_when(a.get("created")))}</td></tr>'
        for a in agents) or ('<tr><td colspan="4" class="empty">You haven’t created any agents yet.</td></tr>')
    return (
        f"{flash}"
        '<div class="divider">CREATE AN AGENT</div>'
        '<form id="agentform" class="send-form" method="post" action="/agents">'
        f'<input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">'
        '<label class="info-label" for="name">Agent name</label>'
        f'<input class="field" id="name" name="name" maxlength="{AGENT_NAME_MAX}" required '
        'autocomplete="off" autocapitalize="none" spellcheck="false" pattern="[A-Za-z0-9][A-Za-z0-9_\\-]*" '
        'title="Letters, numbers, - and _ only. No spaces or dots." placeholder="e.g. sneaker-hunter">'
        '<div class="hint">Full name: '
        f'<span class="mono" id="fullname" data-prefix="{html.escape(prefix, quote=True)}.">{html.escape(prefix)}.</span></div>'
        '<div class="hint dim">Letters, numbers, “-” and “_” only — no spaces or dots.</div>'
        '<label class="info-label" for="description">Description</label>'
        f'<textarea class="field" id="description" name="description" maxlength="{AGENT_DESC_MAX}" rows="3" '
        'placeholder="What should this agent do?"></textarea>'
        '<button class="btn" type="submit">Create agent</button></form>'
        '<div class="divider" style="margin-top:28px">MY AGENTS</div>'
        '<table class="tbl"><thead><tr><th>Name</th><th>Description</th><th>TAP identity</th><th>Created</th></tr></thead>'
        f"<tbody>{rows}</tbody></table>")

def _send_form(wallets, csrf):
    people = sorted(wallets, key=lambda w: _person(w).lower())
    options = "".join(f'<option value="{html.escape(w["sub"], quote=True)}">{html.escape(_person(w))}</option>'
                      for w in people)
    off = "" if people else " disabled"
    first = "Choose a user…" if people else "No users with wallets yet"
    return (
        '<div class="divider" style="margin-top:28px">SEND OUSD</div>'
        '<form id="sendform" class="send-form" method="post" action="/treasury/send">'
        f'<input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">'
        '<label class="info-label" for="amount">Amount (OUSD)</label>'
        '<input class="field" id="amount" name="amount" inputmode="decimal" autocomplete="off" '
        'placeholder="0.00" required pattern="[0-9]+(\\.[0-9]{1,6})?" '
        f'title="A positive number, up to 6 decimals"{off}>'
        '<label class="info-label" for="to">Send to</label>'
        f'<select class="field" id="to" name="to" required{off}><option value="">{first}</option>{options}</select>'
        '<label class="info-label" for="memo">Memo (optional)</label>'
        '<input class="field" id="memo" name="memo" maxlength="32" autocomplete="off" '
        f'placeholder="e.g. Q4 bonus"{off}>'
        f'<button class="btn" type="submit"{off}>Send from treasury</button></form>')

def _public_base(handler):
    """The public address merchant storefront URLs are registered under."""
    return KC_PUBLIC if KC_PUBLIC != KEYCLOAK_BASE else _base_url(handler)

def _visa_cell(w, csrf, base):
    """Visa column: merchants get a Register button (admin only); everyone else a dash."""
    if "merchant" not in (w.get("role") or ""):
        return "—"
    v = w.get("visa") or {}
    view = (f'<div class="small"><a href="/treasury/visa/{urllib.parse.quote(w.get("sub", ""), safe="")}">'
            "View Visa record</a></div>") if v.get("merchantId") else ""
    if v.get("status") == "registered":
        mid = v.get("merchantId") or ""
        return (f'<span class="st-ok" title="{html.escape(mid, quote=True)}">✔ registered</span> '
                f'<span class="mono dim">{html.escape(mid[:8])}…</span>{view}')
    business = w.get("businessName") or ""
    if not business:
        return '<span class="st-wait" title="The merchant gave no business name at sign-up.">needs business name</span>'
    url = f'{base}/shop/{urllib.parse.quote(w.get("username") or "")}'
    label = {"partial": "Finish registration", "failed": "Retry"}.get(v.get("status"), "Register with Visa")
    confirm = (f"Register {business} with Visa’s sandbox? URL: {url} — this creates a permanent record "
               "at Visa that cannot be deleted from here.")
    err = f'<div class="st-err small">{html.escape(v["error"])}</div>' if v.get("error") else ""
    return (f'<form method="post" action="/treasury/register-merchant" class="inline-form" '
            f'data-confirm="{html.escape(confirm, quote=True)}">'
            f'<input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">'
            f'<input type="hidden" name="sub" value="{html.escape(w.get("sub", ""), quote=True)}">'
            f'<button class="btn-mini" type="submit">{label}</button></form>{err}{view}')

def _visa_record_html(data):
    """Admin page body: a merchant's live record from Visa's registry (public keys only)."""
    e = html.escape
    rec = data.get("record") or {}
    def val(v):
        if v in (None, ""):
            return "—"
        return e(re.sub(r"^(\d{4}-\d{2}-\d{2})T", r"\1 ", str(v)))
    def row(label, value, mono=False):
        cls = "info-val mono" if mono else "info-val"
        return f'<div class="info-row"><span class="info-label">{e(label)}</span><span class="{cls}">{value}</span></div>'
    notice = ""
    if data.get("ourStatus") != "registered":
        notice = ('<div class="flash flash-info" role="status">This merchant exists at Visa, but our records show the '
                  f'registration as “{e(str(data.get("ourStatus")))}”. Use the button on the treasury page to finish it.</div>')
    url = rec.get("merchantUrl") or ""
    url_html = (f'<a href="{e(url, quote=True)}" target="_blank" rel="noopener">{e(url)}</a>' if url.startswith("http") else val(url))
    keys = "".join(
        "<tr>"
        f'<td>{val(k.get("keyName"))}</td><td class="mono">{e((k.get("id") or "")[:8])}…</td>'
        f'<td>{val(k.get("algorithm"))}<div class="dim small">{val(k.get("encryptionType"))}</div></td>'
        f'<td>{val(k.get("expirationDate"))}</td><td class="mono">{val(k.get("fingerprint"))}</td></tr>'
        for k in rec.get("keys", [])) or '<tr><td colspan="5" class="empty">Visa lists no keys for this merchant.</td></tr>'
    raw = e(json.dumps(rec, indent=2))
    return (
        f"{notice}"
        '<div class="divider">MERCHANT AT VISA</div>'
        + row("Name", val(rec.get("merchantName")))
        + row("Visa merchant ID", val(rec.get("id")), mono=True)
        + row("VMID", val(rec.get("vmid")), mono=True)
        + row("URL", url_html)
        + row("Indicator", val(rec.get("indicator")))
        + row("Active", "yes" if rec.get("isActive") else val(rec.get("isActive")))
        + row("Cryptogram type", val(rec.get("cryptogramType")))
        + row("Payment payload", val(rec.get("paymentPayloadType")))
        + row("Created (as Visa reports it)", val(rec.get("createdAt")))
        + '<div class="divider" style="margin-top:28px">ENCRYPTION KEYS</div>'
        '<table class="tbl"><thead><tr><th>Name</th><th>Key ID</th><th>Algorithm</th><th>Expires</th><th>Fingerprint</th></tr></thead>'
        f"<tbody>{keys}</tbody></table>"
        f'<details class="raw"><summary>Raw record from Visa</summary><pre>{raw}</pre></details>')

def _admin_html(treasury, wallets, csrf="", flash="", base=""):
    total =sum((Decimal(w["balance"]) for w in wallets if w.get("balance") is not None), Decimal(0))
    rows = []
    for w in wallets:
        addr = w.get("address", "")
        business = (f'<div class="dim small">{html.escape(w["businessName"])}</div>'
                    if "merchant" in (w.get("role") or "") and w.get("businessName") else "")
        rows.append(
            "<tr>"
            f'<td>{html.escape(w.get("username") or "—")}{business}</td>'
            f'<td>{html.escape(w.get("role") or "user")}</td>'
            f'<td class="mono"><a href="{EXPLORER}/address/{html.escape(addr, quote=True)}" '
            f'target="_blank" rel="noopener">{html.escape(addr[:8])}…{html.escape(addr[-6:])}</a></td>'
            f'<td class="num">{_usd(w.get("balance"))}</td>'
            f'<td>{_visa_cell(w, csrf, base)}</td></tr>')
    if not rows:
        rows.append('<tr><td colspan="5" class="empty">No wallets yet — one is created the first '
                    "time each user signs in.</td></tr>")
    taddr = treasury.get("address", "")
    return (
        f"{flash}"
        '<div class="divider">TREASURY</div>'
        '<div class="info-row"><span class="info-label">Balance</span>'
        f'<span class="info-val big">{_usd(treasury.get("balance"))} {html.escape(treasury.get("symbol", "OUSD"))}</span></div>'
        '<div class="info-row"><span class="info-label">Wallet</span>'
        f'<span class="info-val mono"><a href="{EXPLORER}/address/{html.escape(taddr, quote=True)}" '
        f'target="_blank" rel="noopener">{html.escape(taddr[:10])}…{html.escape(taddr[-8:])}</a></span></div>'
        '<div class="info-row"><span class="info-label">Test token</span>'
        '<span class="info-val">Tempo testnet · no real value</span></div>'
        f"{_send_form(wallets, csrf)}"
        '<div class="divider" style="margin-top:28px">USER WALLETS</div>'
        '<div class="info-row"><span class="info-label">Users with wallets</span>'
        f'<span class="info-val">{len(wallets)}</span></div>'
        '<div class="info-row" style="margin-bottom:16px"><span class="info-label">Held by users</span>'
        f'<span class="info-val">{_usd(total)} OUSD</span></div>'
        '<table class="tbl"><thead><tr><th>User</th><th>Role</th><th>Wallet</th><th class="num">OUSD</th>'
        f'<th>Visa</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')

# ── Request handler ───────────────────────────────────────────────────────────
class DemoHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} {fmt % args}")

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(p.query)

        if   p.path == "/":           self._root()
        elif p.path == "/login":      self._login_qr()
        elif p.path == "/login/poll": self._login_poll()
        elif p.path == "/login/who":  self._login_who()
        elif p.path == "/login/browser": self._login()
        elif p.path == "/register":   self._login(REGISTER_ENDPOINT)
        elif p.path == "/passkey/add":      self._passkey_add()
        elif p.path == "/passkey/add/poll": self._passkey_add_poll(qs)
        elif p.path == "/passkey/phone":    self._passkey_phone(qs)
        elif p.path == "/account/password": self._account_password()
        elif p.path == "/passkey/add/local": self._passkey_add_local()
        elif p.path == "/callback":   self._callback(qs)
        elif p.path == "/logout":     self._logout()
        elif p.path == "/treasury":   self._admin()
        elif p.path == "/wallet":     self._wallet()
        elif p.path == "/agents":     self._agents()
        elif p.path == "/agents/direct": self._direct_form(qs)
        elif re.fullmatch(r"/agents/run/run_[0-9a-f]{16}", p.path): self._run_page(p.path)
        elif re.fullmatch(r"/agents/agt_[0-9a-f]{12}", p.path): self._agent_detail(p.path)
        elif re.fullmatch(r"/orders/ord_[0-9a-f]{12}/evidence\.json", p.path): self._evidence(p.path)
        elif p.path == "/approvals":  self._approvals()
        elif re.fullmatch(r"/approvals/apr_[0-9a-f]{12}", p.path): self._approval_detail(p.path)
        elif p.path == "/tap/keys" or p.path.startswith("/tap/keys/"): self._tap_keys(p.path, qs)
        elif p.path == "/keys":       self._tap_keys(p.path, qs)
        elif re.fullmatch(r"/receipt/ord_[0-9a-f]{12}", p.path): self._receipt(p.path)
        elif re.fullmatch(r"/shop/[^/]+/orders/ord_[0-9a-f]{12}", p.path): self._shop_order(p.path)
        elif p.path.startswith("/shop/"): self._shop(p.path)
        elif p.path.startswith("/treasury/visa/"): self._visa_record(p.path)
        elif p.path == "/treasury/agents": self._all_agents()
        elif re.fullmatch(r"/treasury/agents/agt_[0-9a-f]{12}", p.path): self._admin_agent(p.path)
        elif p.path.startswith("/static/"): self._static(p.path)
        else: _html(self, "<h1>404</h1>", 404)

    # ── / ─────────────────────────────────────────────────────────────────────
    def _root(self):
        sid    = _get_sid(self)
        session = _sessions.get(sid) or {}
        claims = session.get("claims")
        flash  = session.pop("flash", None)
        if claims:
            name     = claims.get("name") or claims.get("preferred_username", "UNKNOWN")
            username = claims.get("preferred_username", "—")
            email    = claims.get("email", "—")
            flash_html = ""
            if flash:
                kind, text = flash
                flash_html = f'<div class="flash flash-{kind}" role="status">{html.escape(text)}</div>'
            roles = claims.get("roles") or []
            admin_html = ('<div class="admin-banner" role="status">★ &nbsp; ADMIN ACCESS &nbsp; ★'
                          '<span>You are signed in as an administrator</span>'
                          '<a class="admin-link" href="/treasury">Treasury &amp; wallets →</a> '
                          '<a class="admin-link" href="/treasury/agents">All agents →</a></div>'
                          if "admin" in roles else "")
            agents_btn = ('<a class="btn" href="/agents" style="margin-bottom: 12px">My agents</a>'
                          if _is_user(claims) else "")
            body = _render("logged_in.html", NAME=name, USERNAME=username, EMAIL=email,
                           FLASH=flash_html, ADMIN_BANNER=admin_html, AGENTS_BUTTON=agents_btn,
                           WALLET_SUMMARY=_wallet_summary(claims), STORE_LINKS=_store_links_html())
        else:
            body = _render("splash.html", STORE_LINKS=_store_links_html())
        _html(self, body)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/treasury/send":
            self._treasury_send()
        elif path == "/agents":
            self._agents_create()
        elif path == "/agents/direct":
            self._direct_start()
        elif path == "/agents/retry":
            self._retry()
        elif path == "/agents/pay-order":
            self._pay_order()
        elif re.fullmatch(r"/approvals/apr_[0-9a-f]{12}/(approve|reject)", path):
            self._approval_decide(path)
        elif re.fullmatch(r"/agents/agt_[0-9a-f]{12}/mandates", path):
            self._mandate_create(path)
        elif re.fullmatch(r"/agents/agt_[0-9a-f]{12}/mandates/mnd_[0-9a-f]{12}/revoke", path):
            self._mandate_revoke(path)
        elif path == "/treasury/register-merchant":
            self._merchant_register()
        elif path.startswith("/shop/") and path.endswith("/checkout"):
            self._shop_checkout(path)
        elif re.fullmatch(r"/shop/[^/]+/orders/ord_[0-9a-f]{12}/confirm", path):
            self._shop_confirm(path)
        elif path == "/internal/device-user":
            self._device_user()
        else:
            _html(self, "<h1>404</h1>", 404)

    # ── /agents  (a "user" creates agents and sees their own) ─────────────────
    def _agents_gate(self):
        """Returns (session, claims) for a signed-in 'user', else answers and returns None."""
        session = _sessions.get(_get_sid(self)) or {}
        claims = session.get("claims")
        if not claims:
            _redirect(self, "/")
            return None
        if not _is_user(claims):
            _html(self, "<h1>403</h1><p>Agents are created by users with the “user” role. "
                        "<a href='/'>Back</a></p>", 403)
            return None
        return session, claims

    def _agents(self):
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        csrf = session.setdefault("csrf", secrets.token_urlsafe(24))
        flash = session.pop("aflash", None)
        flash_html = (f'<div class="flash flash-{flash[0]}" role="status">{html.escape(flash[1])}</div>'
                      if flash else "")
        prefix = _agent_fullname(claims, "")[:-1]
        _html(self, _render("agents.html",
                            AGENTS_BODY=_agents_html(_agents_backfill(_agents_of(claims["sub"])),
                                                     csrf, prefix, flash_html)))

    # ── /tap/keys  (public registry of agent public keys: TAP-style key directory) ─
    def _tap_keys(self, path, qs):
        """Public key lookup. Visa's TAP spec: GET /keys with a keyID parameter returns the key's JWK;
        /tap/keys and /tap/keys/<kid> are kept as aliases."""
        try:
            keys = _wallet_call("GET", "/agents/keys", timeout=10)["keys"]
        except Exception:
            _json(self, {"error": "key registry unavailable"}, 503)
            return
        kid = path[len("/tap/keys/"):] if path.startswith("/tap/keys/") else next(
            (v[0] for k, v in qs.items() if k.lower() in ("keyid", "kid") and v), None)
        if kid is None:
            _json(self, {"keys": keys})
            return
        key = next((k for k in keys if k.get("kid") == kid), None)
        _json(self, key if key else {"error": "unknown key id"}, 200 if key else 404)

    # ── /treasury/agents  (admin: every agent from every user) ────────────────
    def _all_agents(self):
        claims = (_sessions.get(_get_sid(self)) or {}).get("claims")
        if not claims:
            _redirect(self, "/")
            return
        if "admin" not in (claims.get("roles") or []):
            _html(self, "<h1>403</h1><p>Administrators only. <a href='/'>Back</a></p>", 403)
            return
        try:
            kids = {k.get("kid") for k in _wallet_call("GET", "/agents/keys", timeout=10)["keys"]}
            ok = True
        except Exception:
            kids, ok = set(), False
        _html(self, _render("all_agents.html", ALL_AGENTS_BODY=_all_agents_html(_agents_all(), kids, ok)))

    # ── /treasury/agents/<id>  (admin: read-only view of any agent and its mandates) ──
    def _admin_agent(self, path):
        claims = (_sessions.get(_get_sid(self)) or {}).get("claims")
        if not claims:
            _redirect(self, "/")
            return
        if "admin" not in (claims.get("roles") or []):
            _html(self, "<h1>403</h1><p>Administrators only. <a href='/'>Back</a></p>", 403)
            return
        agent_id = path.rsplit("/", 1)[1]
        agent = next((a for a in _agents_all() if a.get("id") == agent_id), None)
        if not agent:
            _html(self, "<h1>404</h1><p>No such agent. <a href='/treasury/agents'>Back</a></p>", 404)
            return
        q = urllib.parse.quote(agent.get("owner_sub") or "", safe="")
        try:
            mandates = [m for m in _wallet_call("GET", "/mandates?sub=" + q)["mandates"] if m.get("agentId") == agent_id]
            approvals = [a for a in _wallet_call("GET", "/approvals?sub=" + q)["approvals"] if a.get("agentId") == agent_id]
            orders = [o for o in _wallet_call("GET", "/orders?sub=" + q)["orders"] if o.get("agentId") == agent_id]
            body = _agent_detail_html(agent, mandates, [], "", "", approvals, readonly=True, orders=orders)
        except Exception as ex:
            body = f'<div class="flash flash-err" role="status">Wallet service unreachable: {html.escape(str(ex))}</div>'
        page = _agent_page(body, subtitle="Admin view · read only", back_href="/treasury/agents", back_text="Back to all agents")
        _html(self, page)

    # ── /treasury/visa/<sub>  (admin: a merchant's live record from Visa's registry) ──
    def _visa_record(self, path):
        claims = (_sessions.get(_get_sid(self)) or {}).get("claims")
        if not claims:
            _redirect(self, "/")
            return
        if "admin" not in (claims.get("roles") or []):
            _html(self, "<h1>403</h1><p>Administrators only. <a href='/'>Back</a></p>", 403)
            return
        sub = urllib.parse.unquote(path[len("/treasury/visa/"):]).strip("/")
        try:
            data = _wallet_call("GET", "/merchants/" + urllib.parse.quote(sub, safe="") + "/visa", timeout=40)
            body = _visa_record_html(data)
        except urllib.error.HTTPError as ex:
            try:
                msg = json.loads(ex.read()).get("error") or f"error {ex.code}"
            except Exception:
                msg = f"error {ex.code}"
            body = f'<div class="flash flash-err" role="status">{html.escape(msg)}</div>'
        except Exception as ex:
            body = f'<div class="flash flash-err" role="status">Wallet service unreachable: {html.escape(str(ex))}</div>'
        _html(self, _render("visa_record.html", VISA_BODY=body))

    # ── POST /shop/<username>/checkout  (public: a signed agent asks to buy) ──
    def _shop_checkout(self, path):
        parts = path[len("/shop/"):].strip("/").split("/")
        if len(parts) != 2:
            _json(self, {"status": "rejected", "code": "not_found"}, 404)
            return
        username = urllib.parse.unquote(parts[0])
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 20000:
                raise ValueError("body too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            sku = body["sku"]
            mandates = body.get("mandates") or {}
            if not isinstance(sku, str) or not isinstance(mandates, dict):
                raise ValueError("bad fields")
        except (ValueError, KeyError, TypeError):
            _json(self, {"status": "rejected", "code": "bad_request",
                         "reason": 'Send JSON like {"sku": "...", "mandates": {"open": "...", "closed": "..."}}.'}, 400)
            return
        sig_headers = {k: self.headers.get(k) for k in ("Signature-Input", "Signature") if self.headers.get(k)}
        authority = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
        status, resp = _checkout_core(_public_base(self), authority, urllib.parse.urlparse(self.path).path, username, sku, mandates, sig_headers)
        _json(self, resp, status)

    # ── GET /shop/<u>/orders/<id>  and  POST /shop/<u>/orders/<id>/confirm  (public, for agents and the store) ──
    def _order_public(self, o):
        return {"orderId": o["id"], "status": o["status"], "merchant": o["merchant"], "businessName": o["businessName"],
                "sku": o["sku"], "item": o["item"], "amount": o["amount"], "currency": o["currency"], "createdAt": o["createdAt"],
                "expiresAt": o["expiresAt"], "paidAt": o["paidAt"], "txHash": o["txHash"], "blockNumber": o.get("blockNumber"),
                "approvedByBuyer": o.get("approved", False), "receiptsVerified": o.get("verified"), "receipts": o["receipts"],
                "receiptPage": f"/receipt/{o['id']}"}

    def _shop_order(self, path):
        _, _, user, _, oid = path.split("/")
        try:
            o = _wallet_call("GET", f"/orders/{oid}", timeout=10)
        except urllib.error.HTTPError:
            _json(self, {"status": "rejected", "code": "no_such_order"}, 404)
            return
        except Exception:
            _json(self, {"status": "rejected", "code": "unavailable"}, 503)
            return
        if o["merchant"].lower() != urllib.parse.unquote(user).lower():
            _json(self, {"status": "rejected", "code": "no_such_order"}, 404)
            return
        _json(self, self._order_public(o), indent=2)

    def _shop_confirm(self, path):
        _, _, user, _, oid, _ = path.split("/")
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 2000:
                raise ValueError("body too large")
            tx = json.loads(self.rfile.read(length) or b"{}")["txHash"]
            if not isinstance(tx, str):
                raise ValueError("bad txHash")
        except (ValueError, KeyError, TypeError):
            _json(self, {"status": "rejected", "code": "bad_request", "reason": 'Send JSON like {"txHash": "0x..."}.'}, 400)
            return
        try:
            o = _wallet_call("POST", f"/merchants/{urllib.parse.quote(urllib.parse.unquote(user), safe='')}/orders/{oid}/confirm", {"txHash": tx}, timeout=45)
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error") or f"error {e.code}"
            except Exception:
                msg = f"error {e.code}"
            _json(self, {"status": "rejected", "code": "not_confirmed", "reason": msg}, e.code if e.code in (400, 404, 409) else 502)
            return
        except Exception:
            _json(self, {"status": "rejected", "code": "unavailable"}, 503)
            return
        _json(self, self._order_public(o))

    # ── /shop/<username>[/catalog.json]  (public merchant storefront) ─────────
    def _shop(self, path):
        parts = path[len("/shop/"):].strip("/").split("/")
        username = urllib.parse.unquote(parts[0]) if parts and parts[0] else ""
        what = parts[1] if len(parts) == 2 else ""
        if not username or len(parts) > 2 or what not in ("", "catalog.json"):
            _html(self, shop.not_found(username), 404)
            return
        try:
            m = _wallet_call("GET", "/merchants/" + urllib.parse.quote(username, safe=""), timeout=10)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                _html(self, shop.not_found(username), 404)
            else:
                _html(self, "<h1>This store is unavailable right now.</h1>", 503)
            return
        except Exception:
            _html(self, "<h1>This store is unavailable right now.</h1>", 503)
            return
        store_url = f"{_public_base(self)}/shop/{urllib.parse.quote(m['username'])}"
        if what == "catalog.json":
            _json(self, shop.catalog(m, store_url))
        else:
            try:
                history = _wallet_call("GET", f"/merchants/{urllib.parse.quote(username, safe='')}/orders", timeout=10)["orders"]
            except Exception:
                history = None
            _html(self, shop.render(m, store_url, history))

    # ── /receipt/<id>  (public receipt; the buyer and admins also see who bought it) ──
    def _receipt(self, path):
        oid = path.rsplit("/", 1)[1]
        try:
            o = _wallet_call("GET", f"/orders/{oid}", timeout=10)
        except urllib.error.HTTPError:
            _html(self, _render("receipt.html", TITLE="No such receipt", RECEIPT='<div class="head"><h1>No such receipt</h1><div class="sub">Check the link, or ask the store.</div></div>'), 404)
            return
        except Exception:
            _html(self, "<h1>Receipts are unavailable right now.</h1>", 503)
            return
        owner = False
        session = _sessions.get(_get_sid(self)) or {}
        claims = session.get("claims")
        if claims:
            try:
                owner = "admin" in (claims.get("roles") or []) or any(
                    x["id"] == oid for x in _wallet_call("GET", "/orders?sub=" + urllib.parse.quote(claims["sub"], safe=""), timeout=10)["orders"])
            except Exception:
                owner = False
        csrf = session.setdefault("csrf", secrets.token_urlsafe(24)) if owner and claims and _is_user(claims) else None
        _html(self, _render("receipt.html", TITLE=html.escape(f"{RECEIPT_KINDS.get(o['status'], ('', '', 'Order'))[2]} {oid} · {o['businessName']}"), RECEIPT=_receipt_html(o, owner, csrf)))

    # ── /orders/<id>/evidence.json  (owner or admin: everything needed to check the purchase independently) ──
    def _evidence(self, path):
        claims = (_sessions.get(_get_sid(self)) or {}).get("claims")
        if not claims:
            _redirect(self, "/")
            return
        oid = path.split("/")[2]
        try:
            if "admin" not in (claims.get("roles") or []):
                mine = _wallet_call("GET", "/orders?sub=" + urllib.parse.quote(claims["sub"], safe=""), timeout=10)["orders"]
                if not any(o["id"] == oid for o in mine):
                    _html(self, "<h1>404</h1><p>No such purchase.</p>", 404)
                    return
            bundle = _wallet_call("GET", f"/orders/{oid}/evidence", timeout=15)
        except urllib.error.HTTPError:
            _html(self, "<h1>404</h1><p>No such purchase.</p>", 404)
            return
        except Exception as ex:
            _html(self, f"<h1>Wallet service unreachable</h1><p>{html.escape(str(ex))}</p>", 503)
            return
        enc = json.dumps(bundle, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", f'attachment; filename="evidence-{oid}.json"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)

    # ── /agents/direct  (pick agent, mandate, store, item and action; the agent does the errand) ──
    def _direct_form(self, qs):
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        csrf = session.setdefault("csrf", secrets.token_urlsafe(24))
        flash = session.pop("aflash", None)
        flash_html = (f'<div class="flash flash-{flash[0]}" role="status">{html.escape(flash[1])}</div>' if flash else "")
        try:
            agents = _agents_of(claims["sub"])
            mandates = [m for m in _wallet_call("GET", "/mandates?sub=" + urllib.parse.quote(claims["sub"], safe=""))["mandates"] if m["status"] == "active"]
            merchants = _wallet_call("GET", "/merchants")["merchants"]
            with _runs_lock:
                runs = sorted((r for r in _runs.values() if r["sub"] == claims["sub"]), key=lambda r: r["created"], reverse=True)[:5]
            body = _direct_html(agents, mandates, merchants, csrf, flash_html, (qs.get("agent") or [""])[0], runs)
        except Exception as ex:
            body = f'<div class="flash flash-err" role="status">Wallet service unreachable: {html.escape(str(ex))}</div>'
        _html(self, _agent_page(body, title="DIRECT", subtitle="Send an agent shopping"))

    def _direct_start(self):
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        length = min(int(self.headers.get("Content-Length") or 0), 8192)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        one = lambda k: (form.get(k) or [""])[0].strip()
        if not session.get("csrf") or not secrets.compare_digest(one("csrf").encode(), session["csrf"].encode()):
            _html(self, "<h1>403</h1><p>This form expired. <a href='/agents/direct'>Reload the page</a> and try again.</p>", 403)
            return
        agent = _agent_owned(claims["sub"], one("agent"))
        sku, store, mandate_id, pay = one("sku"), one("store"), one("mandate"), one("mode") == "pay"
        back = "/agents/direct?agent=" + urllib.parse.quote(one("agent"), safe="")
        err = None
        try:
            mandates = {m["id"]: m for m in _wallet_call("GET", "/mandates?sub=" + urllib.parse.quote(claims["sub"], safe=""))["mandates"]}
            stores = {m["username"] for m in _wallet_call("GET", "/merchants")["merchants"]}
        except Exception as ex:
            mandates, stores, err = {}, set(), f"Wallet service unreachable: {ex}"
        m = mandates.get(mandate_id)
        if err:
            pass
        elif not agent:
            err = "Choose one of your agents."
        elif not m or m["agentId"] != agent["id"] or m["status"] != "active":
            err = "Choose an active mandate that belongs to that agent."
        elif store not in stores:
            err = "Choose a store from the list."
        elif not SKU_RE.fullmatch(sku):
            err = "Item IDs look like VSE-010: letters, digits and dashes."
        elif one("mode") not in ("quote", "pay"):
            err = "Choose whether the agent should quote or pay."
        if err:
            session["aflash"] = ("err", err)
            _redirect(self, back)
            return
        run = _start_run(claims["sub"], agent, mandate_id, store, sku, pay, _public_base(self))
        if not run:
            session["aflash"] = ("err", "Three errands are already running. Wait for one to finish.")
            _redirect(self, back)
            return
        _redirect(self, f"/agents/run/{run['id']}")

    def _retry(self):
        """Send the agent again for a purchase that did not go through: from an unpaid order or from a failed errand."""
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        length = min(int(self.headers.get("Content-Length") or 0), 8192)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        one = lambda k: (form.get(k) or [""])[0].strip()
        if not session.get("csrf") or not secrets.compare_digest(one("csrf").encode(), session["csrf"].encode()):
            _html(self, "<h1>403</h1><p>This form expired. <a href='/agents'>Reload the page</a> and try again.</p>", 403)
            return
        src = None
        if one("run"):
            with _runs_lock:
                r = _runs.get(one("run"))
            if r and r["sub"] == claims["sub"] and r["status"] == "failed" and r["retry"]:
                src = (r["agent_id"], r["mandate_id"], r["store"], r["sku"])
        elif one("order"):
            try:
                mine = _wallet_call("GET", "/orders?sub=" + urllib.parse.quote(claims["sub"], safe=""), timeout=10)["orders"]
            except Exception:
                mine = []
            o = next((x for x in mine if x["id"] == one("order")), None)
            if o and o["status"] in ("failed", "expired"):
                src = (o["agentId"], o["mandateId"], o["merchant"], o["sku"])
        if not src:
            session["aflash"] = ("err", "That purchase can’t be retried from here. Start a new errand instead.")
            _redirect(self, "/agents/direct")
            return
        agent_id, mandate_id, store, sku = src
        agent = _agent_owned(claims["sub"], agent_id)
        try:
            m = next((x for x in _wallet_call("GET", "/mandates?sub=" + urllib.parse.quote(claims["sub"], safe=""))["mandates"] if x["id"] == mandate_id), None)
        except Exception:
            m = None
        if not agent or not m or m["status"] != "active":
            session["aflash"] = ("err", "The mandate for that purchase is no longer active, so the agent can’t try again. Grant a new one on the agent’s page.")
            _redirect(self, f"/agents/{agent_id}" if agent else "/agents")
            return
        run = _start_run(claims["sub"], agent, mandate_id, store, sku, True, _public_base(self))
        if not run:
            session["aflash"] = ("err", "Three errands are already running. Wait for one to finish.")
            _redirect(self, "/agents/direct")
            return
        _redirect(self, f"/agents/run/{run['id']}")

    def _pay_order(self):
        """Pay a quote that is still open: the agent pays the order it already holds, with no new checkout."""
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        length = min(int(self.headers.get("Content-Length") or 0), 8192)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        one = lambda k: (form.get(k) or [""])[0].strip()
        if not session.get("csrf") or not secrets.compare_digest(one("csrf").encode(), session["csrf"].encode()):
            _html(self, "<h1>403</h1><p>This form expired. <a href='/agents'>Reload the page</a> and try again.</p>", 403)
            return
        src = None
        try:
            mine = _wallet_call("GET", "/orders?sub=" + urllib.parse.quote(claims["sub"], safe=""), timeout=10)["orders"]
        except Exception:
            mine = []
        oid = one("order")
        if one("run"):
            with _runs_lock:
                r = _runs.get(one("run"))
            oid = r["order_id"] if r and r["sub"] == claims["sub"] and r["status"] == "quoted" else ""
        o = next((x for x in mine if x["id"] == oid), None)
        if o and o["status"] == "payment_required":
            src = (o["agentId"], o["mandateId"], o["merchant"], o["sku"], o["id"])
        if not src:
            session["aflash"] = ("err", "That quote is no longer open (it was paid, or it expired). Use Retry or start a new errand.")
            _redirect(self, "/agents/direct")
            return
        agent_id, mandate_id, store, sku, order_id = src
        agent = _agent_owned(claims["sub"], agent_id)
        try:
            m = next((x for x in _wallet_call("GET", "/mandates?sub=" + urllib.parse.quote(claims["sub"], safe=""))["mandates"] if x["id"] == mandate_id), None)
        except Exception:
            m = None
        if not agent or not m or m["status"] != "active":
            session["aflash"] = ("err", "The mandate for that purchase is no longer active, so the agent can’t pay. Grant a new one on the agent’s page.")
            _redirect(self, f"/agents/{agent_id}" if agent else "/agents")
            return
        run = _start_run(claims["sub"], agent, mandate_id, store, sku, True, _public_base(self), existing_order=order_id)
        if not run:
            session["aflash"] = ("err", "Three errands are already running. Wait for one to finish.")
            _redirect(self, "/agents/direct")
            return
        _redirect(self, f"/agents/run/{run['id']}")

    def _run_page(self, path):
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        with _runs_lock:
            run = _runs.get(path.rsplit("/", 1)[1])
        if not run or run["sub"] != claims["sub"]:
            _html(self, "<h1>404</h1><p>No such errand. <a href='/agents/direct'>Back</a></p>", 404)
            return
        csrf = session.setdefault("csrf", secrets.token_urlsafe(24))
        _html(self, _agent_page(_run_html(run, csrf), title="ERRAND", subtitle="Your agent at work", back_href="/agents/direct", back_text="Back to Direct an agent"))

    # ── /agents/<id>  (owner: identity, mandates, and the form to grant one) ──
    def _agent_detail(self, path):
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        agent_id = path[len("/agents/"):]
        agent = _agent_owned(claims["sub"], agent_id)
        if not agent:
            _html(self, "<h1>404</h1><p>No such agent. <a href='/agents'>Back</a></p>", 404)
            return
        csrf = session.setdefault("csrf", secrets.token_urlsafe(24))
        flash = session.pop("aflash", None)
        flash_html = (f'<div class="flash flash-{flash[0]}" role="status">{html.escape(flash[1])}</div>' if flash else "")
        try:
            mandates = [m for m in _wallet_call("GET", "/mandates?sub=" + urllib.parse.quote(claims["sub"], safe=""))["mandates"]
                        if m.get("agentId") == agent_id]
            merchants = _wallet_call("GET", "/merchants")["merchants"]
            approvals = [a for a in _wallet_call("GET", "/approvals?sub=" + urllib.parse.quote(claims["sub"], safe=""))["approvals"]
                         if a.get("agentId") == agent_id]
            orders = [o for o in _wallet_call("GET", "/orders?sub=" + urllib.parse.quote(claims["sub"], safe=""))["orders"]
                      if o.get("agentId") == agent_id]
            body = _agent_detail_html(agent, mandates, merchants, csrf, flash_html, approvals, orders=orders)
        except Exception as ex:
            body = f'<div class="flash flash-err" role="status">Wallet service unreachable: {html.escape(str(ex))}</div>'
        _html(self, _agent_page(body))

    def _owner_post(self, path):
        """Common checks for the agent POST forms. Returns (session, claims, agent, form, rest) or None."""
        gate = self._agents_gate()
        if not gate:
            return None
        session, claims = gate
        agent = _agent_owned(claims["sub"], path.split("/")[2])
        length = min(int(self.headers.get("Content-Length") or 0), 8192)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        token = form.get("csrf", [""])[0]
        if not session.get("csrf") or not secrets.compare_digest(token.encode(), session["csrf"].encode()):
            _html(self, "<h1>403</h1><p>This form expired. <a href='/agents'>Reload the page</a> and try again.</p>", 403)
            return None
        if not agent:
            _html(self, "<h1>404</h1><p>No such agent. <a href='/agents'>Back</a></p>", 404)
            return None
        return session, claims, agent, form

    # ── /approvals  (human-present stores ask the user to approve each exact cart) ──
    def _approvals(self):
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        flash = session.pop("aflash", None)
        flash_html = (f'<div class="flash flash-{flash[0]}" role="status">{html.escape(flash[1])}</div>' if flash else "")
        try:
            items = _wallet_call("GET", "/approvals?sub=" + urllib.parse.quote(claims["sub"], safe=""))["approvals"]
        except Exception as ex:
            items = None
            flash_html += f'<div class="flash flash-err" role="status">Wallet service unreachable: {html.escape(str(ex))}</div>'
        rows = "".join(
            f'<tr><td class="mono"><a href="/approvals/{html.escape(a["id"], quote=True)}">{html.escape(a["id"])}</a></td>'
            f'<td>{html.escape(a["businessName"])}</td><td>{html.escape(a.get("item") or a["sku"])}</td>'
            f'<td>{html.escape(_ousd(a["amount"]))}</td><td>{html.escape(a["status"])}</td></tr>' for a in (items or []))
        body = (flash_html + '<div class="divider">PURCHASE APPROVALS</div>'
                '<p class="dim" style="margin-bottom:14px">Stores that require you to be present ask here before they quote a price. '
                'Approve the exact cart with your passkey, or decline it.</p>'
                '<table class="tbl"><thead><tr><th>Request</th><th>Store</th><th>Item</th><th>OUSD</th><th>Status</th></tr></thead><tbody>'
                + (rows or "<tr><td colspan=5 class=empty>No approval requests yet.</td></tr>") + "</tbody></table>")
        _html(self, _agent_page(body, title="APPROVALS", subtitle="Purchases waiting for you"))

    def _approval_detail(self, path):
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        csrf = session.setdefault("csrf", secrets.token_urlsafe(24))
        flash = session.pop("aflash", None)
        flash_html = (f'<div class="flash flash-{flash[0]}" role="status">{html.escape(flash[1])}</div>' if flash else "")
        try:
            a = _wallet_call("GET", f"{path}?sub=" + urllib.parse.quote(claims["sub"], safe=""))
        except urllib.error.HTTPError:
            _html(self, "<h1>404</h1><p>No such approval request. <a href='/approvals'>Back</a></p>", 404)
            return
        except Exception as ex:
            _html(self, f"<h1>Wallet service unreachable</h1><p>{html.escape(str(ex))}</p>", 503)
            return
        intro = ('<p class="dim" style="margin-bottom:14px">Your agent is trying to buy this at a store that requires you to approve each purchase. '
                 'Check the details. Approving signs in again with your passkey and covers this exact item, price and agent, once.</p>')
        _html(self, _agent_page(flash_html + '<div class="divider">APPROVE THIS PURCHASE?</div>' + intro + _approval_card(a, csrf),
                                title="APPROVE", subtitle="Review this purchase", back_href="/approvals", back_text="Back to approvals"))

    def _approval_decide(self, path):
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        _, _, apr_id, action = path.split("/")
        length = min(int(self.headers.get("Content-Length") or 0), 8192)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        token = form.get("csrf", [""])[0]
        if not session.get("csrf") or not secrets.compare_digest(token.encode(), session["csrf"].encode()):
            _html(self, "<h1>403</h1><p>This form expired. <a href='/approvals'>Reload the page</a> and try again.</p>", 403)
            return
        back = f"/approvals/{apr_id}"
        if action == "approve":
            now = time.time()
            for k in [k for k, v in _pending_mandates.items() if now - v["created"] > 300]:
                del _pending_mandates[k]
            try:
                a = _wallet_call("GET", f"/approvals/{apr_id}?sub=" + urllib.parse.quote(claims["sub"], safe=""))
            except Exception:
                session["aflash"] = ("err", "Could not load that approval request. Try again.")
                _redirect(self, back)
                return
            nonce = _terms_hash({"type": "approval", "approvalId": apr_id, "orderHash": a["orderHash"], "mandateId": a["mandateId"]})
            tok = secrets.token_urlsafe(24)
            _pending_mandates[tok] = {"kind": "approval", "sub": claims["sub"], "approval_id": apr_id, "created": now, "nonce": nonce}
            self._login(extra={"prompt": "login", "max_age": "0", "nonce": nonce, "login_hint": claims.get("preferred_username", "")}, mandate=tok)
            return
        try:
            _wallet_call("POST", f"/approvals/{apr_id}/reject", {"sub": claims["sub"]}, timeout=15)
            session["aflash"] = ("ok", "Declined. The store will refuse this purchase.")
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error") or f"error {e.code}"
            except Exception:
                msg = f"error {e.code}"
            session["aflash"] = ("err", f"Could not decline: {msg}")
        except Exception as ex:
            session["aflash"] = ("err", f"Wallet service unreachable: {ex}")
        _redirect(self, back)

    def _mandate_create(self, path):
        got = self._owner_post(path)
        if not got:
            return
        session, claims, agent, form = got
        back = f"/agents/{agent['id']}"
        merchants = form.get("merchants", [])
        max_pp = form.get("maxPerPurchase", [""])[0].strip()
        budget = form.get("budget", [""])[0].strip()
        try:
            hours = int(form.get("hours", ["0"])[0])
        except ValueError:
            hours = 0
        known = set()
        try:
            known = {m["username"] for m in _wallet_call("GET", "/merchants")["merchants"]}
        except Exception:
            pass
        if not merchants or not set(merchants) <= known:
            session["aflash"] = ("err", "Choose at least one store from the list.")
        elif not AMOUNT_RE.fullmatch(max_pp) or not AMOUNT_RE.fullmatch(budget) or Decimal(max_pp) <= 0 or Decimal(budget) <= 0:
            session["aflash"] = ("err", "Limits must be amounts above zero with at most 6 decimals.")
        elif Decimal(max_pp) > Decimal(budget):
            session["aflash"] = ("err", "The per-purchase limit can’t be more than the total budget.")
        elif hours not in MANDATE_HOURS:
            session["aflash"] = ("err", "Choose how long the mandate stays valid.")
        else:
            now = time.time()
            for k in [k for k, v in _pending_mandates.items() if now - v["created"] > 300]:
                del _pending_mandates[k]
            token = secrets.token_urlsafe(24)
            terms = {"type": "mandate", "sub": claims["sub"], "agentId": agent["id"], "merchants": sorted(set(merchants)),
                     "maxPerPurchase": _norm_amount(max_pp), "budget": _norm_amount(budget), "hours": hours}
            nonce = _terms_hash(terms)
            _pending_mandates[token] = {"sub": claims["sub"], "agent_id": agent["id"], "created": now, "nonce": nonce,
                                        "params": {"merchants": merchants, "maxPerPurchase": max_pp, "budget": budget, "hours": hours}}
            # Force a fresh sign-in bound to these exact terms (the nonce): Keycloak's signed ID token is the proof.
            self._login(extra={"prompt": "login", "max_age": "0", "nonce": nonce, "login_hint": claims.get("preferred_username", "")}, mandate=token)
            return
        _redirect(self, back)

    def _mandate_revoke(self, path):
        got = self._owner_post(path)
        if not got:
            return
        session, claims, agent, form = got
        mandate_id = path.split("/")[4]
        try:
            _wallet_call("POST", f"/mandates/{mandate_id}/revoke", {"sub": claims["sub"]}, timeout=15)
            session["aflash"] = ("ok", f"Mandate {mandate_id} revoked. Stores will refuse it from now on.")
        except Exception as ex:
            session["aflash"] = ("err", f"Could not revoke: {ex}")
        _redirect(self, f"/agents/{agent['id']}")

    def _agents_create(self):
        gate = self._agents_gate()
        if not gate:
            return
        session, claims = gate
        length = min(int(self.headers.get("Content-Length") or 0), 8192)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        token = form.get("csrf", [""])[0]
        if not session.get("csrf") or not secrets.compare_digest(token.encode(), session["csrf"].encode()):
            _html(self, "<h1>403</h1><p>This form expired. <a href='/agents'>Reload the page</a> and try again.</p>", 403)
            return
        slug = form.get("name", [""])[0].strip().lower()
        desc = form.get("description", [""])[0].replace("\r\n", "\n").strip()
        if len(slug) > AGENT_NAME_MAX or not AGENT_SLUG_RE.fullmatch(slug):
            session["aflash"] = ("err", "Agent names can only use letters, numbers, “-” and “_” (no spaces or dots), "
                                        f"must start with a letter or number, and be at most {AGENT_NAME_MAX} characters.")
        elif len(desc) > AGENT_DESC_MAX or not all(c.isprintable() or c == "\n" for c in desc):
            session["aflash"] = ("err", f"The description must be plain text, up to {AGENT_DESC_MAX} characters.")
        else:
            agent, err = _agent_create(claims, slug, desc)
            session["aflash"] = ("err", err) if err else ("ok", f"Agent “{agent['name']}” created.")
        _redirect(self, "/agents")

    # ── POST /treasury/send  (admin: pay a user from the treasury wallet) ─────
    def _treasury_send(self):
        session = _sessions.get(_get_sid(self)) or {}
        claims = session.get("claims")
        if not claims:
            _redirect(self, "/")
            return
        if "admin" not in (claims.get("roles") or []):
            _html(self, "<h1>403</h1><p>Administrators only. <a href='/'>Back</a></p>", 403)
            return
        length = min(int(self.headers.get("Content-Length") or 0), 4096)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        token = form.get("csrf", [""])[0]
        if not session.get("csrf") or not secrets.compare_digest(token.encode(), session["csrf"].encode()):
            _html(self, "<h1>403</h1><p>This form expired. <a href='/treasury'>Reload the page</a> and try again.</p>", 403)
            return
        amount = form.get("amount", [""])[0].strip()
        sub = form.get("to", [""])[0]
        memo = form.get("memo", [""])[0].strip()
        if not re.fullmatch(r"[0-9]+(\.[0-9]{1,6})?", amount) or Decimal(amount) <= 0 or not sub:
            session["tflash"] = ("err", "Enter an amount above zero (up to 6 decimals) and choose a user.")
        elif len(memo.encode("utf-8")) > 32 or not memo.isprintable():
            session["tflash"] = ("err", "The memo must be plain text of at most 32 bytes.")
        else:
            try:
                out = _wallet_call("POST", "/treasury/send", {"sub": sub, "amount": amount, "memo": memo}, timeout=75)
                memo_note = f" Memo: “{html.escape(out['memo'])}”." if out.get("memo") else ""
                session["tflash"] = ("ok", f"Sent {html.escape(_ousd(amount))} OUSD to "
                                           f"{html.escape(_person(out['recipient']))}.{memo_note} "
                                           + _explorer_link("tx", out["hash"], "View transaction"))
            except urllib.error.HTTPError as e:
                try:
                    msg = json.loads(e.read()).get("error") or f"error {e.code}"
                except Exception:
                    msg = f"error {e.code}"
                session["tflash"] = ("err", f"Could not send: {html.escape(msg)}")
            except Exception as e:
                session["tflash"] = ("err", f"Wallet service unreachable: {html.escape(str(e))}")
        _redirect(self, "/treasury")

    # ── POST /treasury/register-merchant  (admin: register a merchant with Visa's sandbox) ─
    def _merchant_register(self):
        session = _sessions.get(_get_sid(self)) or {}
        claims = session.get("claims")
        if not claims:
            _redirect(self, "/")
            return
        if "admin" not in (claims.get("roles") or []):
            _html(self, "<h1>403</h1><p>Administrators only. <a href='/'>Back</a></p>", 403)
            return
        length = min(int(self.headers.get("Content-Length") or 0), 4096)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        token = form.get("csrf", [""])[0]
        if not session.get("csrf") or not secrets.compare_digest(token.encode(), session["csrf"].encode()):
            _html(self, "<h1>403</h1><p>This form expired. <a href='/treasury'>Reload the page</a> and try again.</p>", 403)
            return
        sub = form.get("sub", [""])[0]
        try:
            out = _wallet_call("POST", "/merchants/register-visa", {"sub": sub, "baseUrl": _public_base(self)}, timeout=120)
            mid = ((out.get("visa") or {}).get("merchantId") or "")[:8]
            note = "was already registered" if out.get("already") else "registered with Visa’s sandbox"
            session["tflash"] = ("ok", f"Merchant {note} (merchant ID {html.escape(mid)}…).")
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error") or f"error {e.code}"
            except Exception:
                msg = f"error {e.code}"
            session["tflash"] = ("err", f"Could not register the merchant: {html.escape(msg)}")
        except Exception as e:
            session["tflash"] = ("err", f"Wallet service unreachable: {html.escape(str(e))}")
        _redirect(self, "/treasury")

    # ── /treasury  (treasury + user wallets; "admin" realm role only) ─────────
    def _admin(self):
        session = _sessions.get(_get_sid(self)) or {}
        claims = session.get("claims")
        if not claims:
            _redirect(self, "/")
            return
        if "admin" not in (claims.get("roles") or []):
            _html(self, "<h1>403</h1><p>Administrators only. <a href='/'>Back</a></p>", 403)
            return
        csrf = session.setdefault("csrf", secrets.token_urlsafe(24))
        flash = session.pop("tflash", None)
        flash_html = (f'<div class="flash flash-{flash[0]}" role="status">{flash[1]}</div>' if flash else "")
        try:
            treasury = _wallet_call("GET", "/treasury")
            wallets = _wallet_call("GET", "/wallets")["wallets"]
            content = _admin_html(treasury, wallets, csrf, flash_html, _public_base(self))
        except Exception as e:
            content = ('<div class="flash flash-err" role="status">Wallet service unreachable: '
                       f"{html.escape(str(e))}</div>")
        _html(self, _render("admin.html", ADMIN_BODY=content))

    # ── /wallet  (the signed-in user's own wallet + transaction history) ─────
    def _wallet(self):
        claims = (_sessions.get(_get_sid(self)) or {}).get("claims")
        if not claims:
            _redirect(self, "/")
            return
        refresh = ""
        try:
            w = _wallet_call("GET", "/wallets/" + urllib.parse.quote(claims.get("sub", ""), safe=""))
            content = _wallet_html(w)
            if (w.get("gift") or {}).get("status") in ("queued", "pending"):
                refresh = '<meta http-equiv="refresh" content="5">'
        except urllib.error.HTTPError as e:
            if e.code == 404:
                _provision_wallet(claims)
                content = '<div class="flash flash-info" role="status">Setting up your wallet…</div>'
                refresh = '<meta http-equiv="refresh" content="4">'
            else:
                content = f'<div class="flash flash-err" role="status">Wallet service error ({e.code}).</div>'
        except Exception as e:
            content = ('<div class="flash flash-err" role="status">Wallet service unreachable: '
                       f"{html.escape(str(e))}</div>")
        _html(self, _render("wallet.html", WALLET_BODY=content, REFRESH=refresh))

    # ── /login  (QR / device authorization grant) ─────────────────────────────
    def _login_qr(self):
        try:
            dev = _fetch_json(DEVICE_ENDPOINT, {
                "client_id": CLIENT_ID,
                "scope":     "openid profile email",
            })
        except Exception as e:
            _html(self, f"<h1>Could not start QR sign-in</h1><pre>{html.escape(str(e))}</pre>"
                        "<p><a href='/login/browser'>Sign in on this computer instead</a></p>", 502)
            return
        # Keycloak builds verification URLs from the host the app called it on
        # (localhost); the phone needs the public (ngrok) host instead.
        qr_url = dev.get("verification_uri_complete") or dev.get("verification_uri", "")
        if qr_url.startswith(KEYCLOAK_BASE):
            qr_url = KC_PUBLIC + qr_url[len(KEYCLOAK_BASE):]

        sid = secrets.token_urlsafe(16)
        _sessions[sid] = {"device_code": dev["device_code"],
                          "user_code": _norm_code(dev.get("user_code", ""))}
        body = _render("qr_login.html",
                       QR_URL=html.escape(qr_url, quote=True),
                       USER_CODE=html.escape(dev.get("user_code", "")),
                       INTERVAL=str(int(dev.get("interval", 5))),
                       EXPIRES=str(int(dev.get("expires_in", 600))))
        enc = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header(*_sid_cookie(sid))
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)

    # ── /internal/device-user  (called by the Keycloak extension, localhost only) ─
    # The phone user has signed in and is on the consent screen: record WHO, keyed
    # by the device user code, so the QR page can say so while waiting.
    def _device_user(self):
        # Direct local call only. The public proxy adds X-Forwarded-* headers (and
        # also blocks /internal), so anything carrying them did not come from Keycloak.
        if self.headers.get("X-Forwarded-For") or self.headers.get("X-Forwarded-Host") \
                or self.client_address[0] not in ("127.0.0.1", "::1"):
            _html(self, "<h1>403</h1>", 403); return
        try:
            n = min(int(self.headers.get("Content-Length") or 0), 4096)
            d = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            _json(self, {"error": "bad request"}, 400); return
        code = _norm_code(d.get("user_code", ""))
        if code:
            now = time.time()
            for k in [k for k, v in _device_users.items() if now - v["t"] > 900]:
                _device_users.pop(k, None)
            _device_users[code] = {"t": now,
                                   "name": str(d.get("name") or "")[:120],
                                   "username": str(d.get("username") or "")[:120]}
        _json(self, {"ok": True})

    # ── /login/who  (QR page polls this quickly: who is confirming on the phone?) ─
    def _login_who(self):
        session = _sessions.get(_get_sid(self)) or {}
        u = _device_users.get(session.get("user_code") or "")
        if not u:
            _json(self, {"who": None}); return
        _json(self, {"who": {"name": u["name"], "username": u["username"]}})

    # ── /login/poll ───────────────────────────────────────────────────────────
    def _login_poll(self):
        sid = _get_sid(self)
        session = _sessions.get(sid) or {}
        if session.get("claims"):
            _json(self, {"status": "done"})
            return
        device_code = session.get("device_code")
        if not device_code:
            _json(self, {"status": "expired"})
            return
        tok = _post_json_allow_errors(TOKEN_ENDPOINT, {
            "grant_type":  DEVICE_GRANT,
            "device_code": device_code,
            "client_id":   CLIENT_ID,
        })
        err = tok.get("error")
        if not err and tok.get("id_token"):
            id_token = tok["id_token"]
            claims = _claims_from_tokens(tok)
            _sessions[sid] = {"claims": claims, "id_token": id_token}
            _provision_wallet(claims)
            _json(self, {"status": "done"})
        elif err in ("authorization_pending", "slow_down"):
            _json(self, {"status": "pending", "slow_down": err == "slow_down"})
        elif err == "access_denied":
            _json(self, {"status": "denied"})
        else:   # expired_token, invalid_grant, ...
            _json(self, {"status": "expired", "error": err})

    # ── /login/browser  (classic OIDC + PKCE in this browser) ─────────────────
    def _login(self, endpoint=AUTH_ENDPOINT, extra=None, enroll=None, mandate=None):
        sid = secrets.token_urlsafe(16)
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(16)
        redirect_uri = _base_url(self) + "/callback"
        _sessions[sid] = {"state": state, "code_verifier": verifier,
                          "redirect_uri": redirect_uri, "enroll": enroll, "mandate": mandate,
                          "action": (extra or {}).get("kc_action")}
        params = urllib.parse.urlencode({
            **(extra or {}),
            "response_type": "code",
            "client_id":     CLIENT_ID,
            "redirect_uri":  redirect_uri,
            "scope":         "openid profile email",
            "state":         state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
        })
        _redirect(self, f"{endpoint}?{params}",
                  extra_headers=[("Set-Cookie",
                                  f"sid={sid}; Path=/; HttpOnly; SameSite=Lax")])

    # ── /callback ─────────────────────────────────────────────────────────────
    def _callback(self, qs):
        sid     = _get_sid(self)
        session = _sessions.get(sid)

        if session and session.get("enroll"):
            self._passkey_phone_callback(qs, session)
            return

        err = qs.get("error", [None])[0]
        if err:
            desc = qs.get("error_description", [""])[0]
            _html(self, f"<h1>Auth error: {err}</h1><p>{desc}</p>", 400)
            return
        if not session:
            _html(self, "<h1>No session — <a href='/'>start over</a></h1>", 400)
            return
        if qs.get("state", [None])[0] != session.get("state"):
            _html(self, "<h1>State mismatch</h1>", 400)
            return

        code = qs.get("code", [None])[0]
        if not code:
            _html(self, "<h1>Missing code</h1>", 400)
            return

        try:
            tok = _fetch_json(TOKEN_ENDPOINT, {
                "grant_type":    "authorization_code",
                "client_id":     CLIENT_ID,
                "redirect_uri":  session["redirect_uri"],
                "code":          code,
                "code_verifier": session["code_verifier"],
            })
        except Exception as e:
            _html(self, f"<h1>Token exchange failed</h1><pre>{e}</pre>", 500)
            return

        id_token = tok.get("id_token", "")
        new_session = {"claims": _claims_from_tokens(tok), "id_token": id_token}
        _provision_wallet(new_session["claims"])
        messages = ACTION_MESSAGES.get(session.get("action"))
        if messages:
            status = qs.get("kc_action_status", [""])[0]
            new_session["flash"] = messages.get(status, messages["error"])
        back = "/"
        if session.get("mandate"):
            new_session["aflash"], back = _finish_mandate_stepup(new_session["claims"], session["mandate"], id_token)
        _sessions[sid] = new_session
        _redirect(self, back)

    # ── /passkey/add  (signed-in computer shows a QR for the phone) ──────────
    def _passkey_add(self):
        claims = (_sessions.get(_get_sid(self)) or {}).get("claims")
        if not claims:
            _redirect(self, "/")
            return
        token = secrets.token_urlsafe(24)
        with _enroll_lock:
            now = time.time()
            for k in [k for k, v in _enroll.items() if v["expires"] < now]:
                del _enroll[k]
            _enroll[token] = {"sub": claims.get("sub"),
                              "username": claims.get("preferred_username", ""),
                              "status": "pending", "expires": now + ENROLL_TTL}
        phone_url = f"{_base_url(self)}/passkey/phone?t={token}"
        body = _render("passkey_add.html",
                       QR_URL=html.escape(phone_url, quote=True),
                       TOKEN=html.escape(token, quote=True),
                       USERNAME=html.escape(claims.get("preferred_username", "")),
                       EXPIRES=str(ENROLL_TTL))
        enc = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)

    def _passkey_add_poll(self, qs):
        claims = (_sessions.get(_get_sid(self)) or {}).get("claims") or {}
        token = qs.get("t", [""])[0]
        with _enroll_lock:
            e = _enroll.get(token)
        if not e or e["sub"] != claims.get("sub"):
            _json(self, {"status": "expired"})
        elif e["status"] == "pending" and e["expires"] < time.time():
            _json(self, {"status": "expired"})
        else:
            _json(self, {"status": e["status"]})

    # ── /passkey/phone  (phone opened the QR link) ───────────────────────────
    def _passkey_phone(self, qs):
        token = qs.get("t", [""])[0]
        with _enroll_lock:
            e = _enroll.get(token)
        if not e or e["status"] != "pending" or e["expires"] < time.time():
            _html(self, _render("passkey_phone_done.html", ICON="✘",
                  TITLE="Link expired",
                  MESSAGE="This QR code is no longer valid. Create a new one on your computer."), 410)
            return
        # Sign in on the phone (username pre-filled), then Keycloak runs the
        # passkey-registration action and comes back to /callback.
        self._login(extra={"kc_action": PASSKEY_ACTION, "login_hint": e["username"]},
                    enroll=token)

    def _passkey_phone_callback(self, qs, session):
        token = session["enroll"]
        sid = _get_sid(self)
        _sessions.pop(sid, None)            # the phone isn't signed in to the app

        def finish(status, icon, title, message, http_status=200):
            with _enroll_lock:
                if token in _enroll:
                    _enroll[token]["status"] = status
            _html(self, _render("passkey_phone_done.html", ICON=icon, TITLE=title,
                                MESSAGE=message), http_status)

        with _enroll_lock:
            e = dict(_enroll.get(token) or {})
        if not e:
            finish("error", "✘", "Link expired",
                   "This QR code is no longer valid. Create a new one on your computer.", 410)
            return
        if qs.get("state", [None])[0] != session.get("state"):
            finish("error", "✘", "Something went wrong", "State mismatch — please try again.", 400)
            return
        if qs.get("error", [None])[0]:
            finish("cancelled", "✘", "Not completed",
                   html.escape(qs.get("error_description", ["Sign-in was cancelled."])[0]))
            return

        action_status = qs.get("kc_action_status", [""])[0]
        code = qs.get("code", [None])[0]
        sub = None
        if code:
            try:
                tok = _fetch_json(TOKEN_ENDPOINT, {
                    "grant_type": "authorization_code", "client_id": CLIENT_ID,
                    "redirect_uri": session["redirect_uri"], "code": code,
                    "code_verifier": session["code_verifier"]})
                sub = _decode_jwt(tok.get("id_token", "")).get("sub")
            except Exception:
                pass

        if sub and sub != e["sub"]:
            finish("mismatch", "✘", "Different account",
                   "You signed in on the phone as a different user than on your computer, "
                   "so the passkey went to that other account, not yours. "
                   "Scan the QR code again and sign in as "
                   f"<b>{html.escape(e['username'])}</b>.")
        elif action_status == "success":
            finish("done", "✔", "Passkey added",
                   f"Your phone can now sign in as <b>{html.escape(e['username'])}</b>. "
                   "You can close this page.")
        elif action_status == "cancelled":
            finish("cancelled", "✘", "Not completed",
                   "Passkey setup was cancelled. Scan the QR code again to retry.")
        else:
            finish("error", "✘", "Something went wrong",
                   "The passkey could not be registered. Scan the QR code again to retry.")

    # ── /account/password  (Keycloak change-password action) ──────────────────
    def _account_password(self):
        claims = (_sessions.get(_get_sid(self)) or {}).get("claims")
        if not claims:
            _redirect(self, "/")
            return
        self._login(extra={"kc_action": "UPDATE_PASSWORD",
                           "login_hint": claims.get("preferred_username", "")})

    # ── /passkey/add/local  (register a passkey in this browser) ──────────────
    def _passkey_add_local(self):
        claims = (_sessions.get(_get_sid(self)) or {}).get("claims")
        if not claims:
            _redirect(self, "/")
            return
        self._login(extra={"kc_action": PASSKEY_ACTION,
                           "login_hint": claims.get("preferred_username", "")})

    # ── /logout ───────────────────────────────────────────────────────────────
    def _logout(self):
        sid = _get_sid(self)
        id_token_hint = ""
        if sid and sid in _sessions:
            id_token_hint = _sessions[sid].get("id_token", "")
            del _sessions[sid]
        params = urllib.parse.urlencode({
            "client_id":               CLIENT_ID,
            "post_logout_redirect_uri": _base_url(self) + "/",
            "id_token_hint":           id_token_hint,
        })
        _redirect(self, f"{LOGOUT_ENDPOINT}?{params}",
                  extra_headers=[("Set-Cookie",
                                  "sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")])

    # ── /static/* ─────────────────────────────────────────────────────────────
    def _static(self, path):
        # Strip leading /static/ and resolve safely within STATIC_DIR
        rel  = pathlib.PurePosixPath(path).relative_to("/static")
        full = (STATIC_DIR / rel).resolve()
        if not str(full).startswith(str(STATIC_DIR)) or not full.is_file():
            _html(self, "<h1>404</h1>", 404)
            return
        mime, _ = mimetypes.guess_type(str(full))
        data = full.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), DemoHandler)
    print(f"Agent Pay Demo → http://localhost:{PORT}")
    print("Ctrl+C to stop.")
    server.serve_forever()
