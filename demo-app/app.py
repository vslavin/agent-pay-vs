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
from decimal import Decimal
from http.cookies import SimpleCookie

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

def _json(handler, obj, status=200):
    enc = json.dumps(obj).encode()
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

def _role_label(roles):
    found = [r for r in ("admin", "merchant") if r in (roles or [])]
    return ", ".join(found) or "user"

def _provision_wallet(claims):
    """Create the user's wallet (and queue the $100 gift) on sign-in, and refresh
    the stored display name and role; idempotent."""
    sub, username = claims.get("sub"), claims.get("preferred_username", "")
    if not sub:
        return
    payload = {"sub": sub, "username": username, "name": claims.get("name", ""),
               "role": _role_label(claims.get("roles"))}
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
        if incoming and from_treasury:
            what = "Welcome gift" if t.get("hash") == gift_tx else "From treasury"
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
            f'<td class="memo">{html.escape(t.get("memo") or "")}</td>'
            f'<td class="num {"st-ok" if incoming else ""}">{amount}</td>'
            f'<td class="mono">{_explorer_link("tx", t.get("hash", ""), "view")}</td></tr>')
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
        f'<span class="info-val big">{_ousd(w.get("balance"))} {html.escape(w.get("symbol", "OUSD"))}</span></div>'
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
    """True for the plain 'user' role (not admin, not merchant)."""
    return _role_label(claims.get("roles")) == "user"

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
        agent = {"id": "agt_" + secrets.token_hex(6), "owner_sub": claims["sub"],
                 "owner_username": claims.get("preferred_username", ""),
                 "slug": slug, "name": full, "description": description, "created": int(time.time())}
        agents.append(agent)
        _agents_write(agents)
    return agent, None

def _agents_html(agents, csrf, prefix, flash=""):
    rows = "".join(
        "<tr>"
        f'<td class="mono">{html.escape(a["name"])}</td>'
        f'<td class="agent-desc">{html.escape(a.get("description") or "")}</td>'
        f'<td>{html.escape(_when(a.get("created")))}</td>'
        f'<td class="mono">{html.escape(a["id"])}</td></tr>'
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
        '<table class="tbl"><thead><tr><th>Name</th><th>Description</th><th>Created</th><th>ID</th></tr></thead>'
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

def _admin_html(treasury, wallets, csrf="", flash=""):
    total =sum((Decimal(w["balance"]) for w in wallets if w.get("balance") is not None), Decimal(0))
    rows = []
    for w in wallets:
        addr = w.get("address", "")
        rows.append(
            "<tr>"
            f'<td>{html.escape(w.get("username") or "—")}</td>'
            f'<td>{html.escape(w.get("role") or "user")}</td>'
            f'<td class="mono"><a href="{EXPLORER}/address/{html.escape(addr, quote=True)}" '
            f'target="_blank" rel="noopener">{html.escape(addr[:8])}…{html.escape(addr[-6:])}</a></td>'
            f'<td class="num">{_ousd(w.get("balance"))}</td></tr>')
    if not rows:
        rows.append('<tr><td colspan="4" class="empty">No wallets yet — one is created the first '
                    "time each user signs in.</td></tr>")
    taddr = treasury.get("address", "")
    return (
        f"{flash}"
        '<div class="divider">TREASURY</div>'
        '<div class="info-row"><span class="info-label">Balance</span>'
        f'<span class="info-val big">{_ousd(treasury.get("balance"))} {html.escape(treasury.get("symbol", "OUSD"))}</span></div>'
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
        f'<span class="info-val">{_ousd(total)} OUSD</span></div>'
        '<table class="tbl"><thead><tr><th>User</th><th>Role</th><th>Wallet</th><th class="num">OUSD</th>'
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>')

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
                          '<a class="admin-link" href="/treasury">Treasury &amp; wallets →</a></div>'
                          if "admin" in roles else "")
            agents_btn = ('<a class="btn" href="/agents" style="margin-bottom: 12px">My agents</a>'
                          if _is_user(claims) else "")
            body = _render("logged_in.html", NAME=name, USERNAME=username, EMAIL=email,
                           FLASH=flash_html, ADMIN_BANNER=admin_html, AGENTS_BUTTON=agents_btn)
        else:
            body = _render("splash.html")
        _html(self, body)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/treasury/send":
            self._treasury_send()
        elif path == "/agents":
            self._agents_create()
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
                            AGENTS_BODY=_agents_html(_agents_of(claims["sub"]), csrf, prefix, flash_html)))

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
            content = _admin_html(treasury, wallets, csrf, flash_html)
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
    def _login(self, endpoint=AUTH_ENDPOINT, extra=None, enroll=None):
        sid = secrets.token_urlsafe(16)
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(16)
        redirect_uri = _base_url(self) + "/callback"
        _sessions[sid] = {"state": state, "code_verifier": verifier,
                          "redirect_uri": redirect_uri, "enroll": enroll,
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
        _sessions[sid] = new_session
        _redirect(self, "/")

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
