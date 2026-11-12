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
import secrets
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
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
        elif p.path == "/login/browser": self._login()
        elif p.path == "/register":   self._login(REGISTER_ENDPOINT)
        elif p.path == "/passkey/add":      self._passkey_add()
        elif p.path == "/passkey/add/poll": self._passkey_add_poll(qs)
        elif p.path == "/passkey/phone":    self._passkey_phone(qs)
        elif p.path == "/account/password": self._account_password()
        elif p.path == "/passkey/add/local": self._passkey_add_local()
        elif p.path == "/callback":   self._callback(qs)
        elif p.path == "/logout":     self._logout()
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
            body = _render("logged_in.html", NAME=name, USERNAME=username, EMAIL=email,
                           FLASH=flash_html)
        else:
            body = _render("splash.html")
        _html(self, body)

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
        _sessions[sid] = {"device_code": dev["device_code"]}
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
            _sessions[sid] = {"claims": _decode_jwt(id_token), "id_token": id_token}
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
        new_session = {"claims": _decode_jwt(id_token), "id_token": id_token}
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
