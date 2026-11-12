/*
 * Agent Pay theme — tapping login shows the browser's "scan with your phone"
 * QR code, so the user signs in with a passkey from their iPhone.
 *
 * Keycloak 26 (realm setting "Passkeys" enabled) renders one login page with
 * the username/password form plus a "Sign in with passkey" button. This
 * script turns that into passkey-first:
 *
 * 1. Handles the "Sign in with passkey" click itself (before Keycloak's own
 *    handler) and calls WebAuthn with `hints: ["hybrid"]`, which makes Chrome
 *    128+ open straight to the phone QR code. The call goes through a hidden
 *    same-origin iframe's navigator.credentials, because password-manager
 *    extensions (1Password) lock the page's navigator.credentials.get to their
 *    own picker, which has no QR. The result is handed back to Keycloak's own
 *    webauthnAuthenticate.js (returnSuccess / returnFailure) to submit.
 * 2. Moves "Sign in with passkey" to the top and hides the password form
 *    behind a "Use username & password instead" link.
 * 3. Starts the passkey prompt automatically on page load (computers only —
 *    phones require a tap). It does NOT auto-start when the page is showing an error (e.g. the user cancelled
 *    the prompt), to avoid an endless loop.
 */
(function () {
  "use strict";

  // .../resources/<ver>/login/agent-pay  (this file lives in <that>/js/)
  var RESOURCES = (document.currentScript && document.currentScript.src || "")
    .replace(/\/js\/passkey-default\.js(\?.*)?$/, "");

  var IS_MOBILE = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) ||
    (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);  // iPadOS

  // The demo app now shows its own QR code (OAuth device grant), so Keycloak's
  // sign-in page is the "sign in on this computer" path: use the computer's
  // passkeys (e.g. 1Password desktop). Set to true to route the passkey
  // button to Chrome's own "scan with your phone" dialog instead.
  var BROWSER_PHONE_QR = false;

  // The app's QR sign-in page, derived from the OIDC redirect_uri. Keycloak
  // carries it in ?redirect_uri= on the first page and in client_data (base64
  // JSON, field "ru") on later pages.
  function appQrLoginUrl() {
    function origin(u) { try { return new URL(u).origin; } catch (e) { return null; } }
    var here = new URL(location.href);
    var ru = here.searchParams.get("redirect_uri");
    if (!ru) {
      var el = document.querySelector('a[href*="client_data="], form[action*="client_data="]');
      var src = el ? (el.href || el.action) : location.href;
      var cd = new URL(src, location.href).searchParams.get("client_data");
      if (cd) {
        try {
          cd = cd.replace(/-/g, "+").replace(/_/g, "/");
          while (cd.length % 4) cd += "=";
          ru = JSON.parse(atob(cd)).ru;
        } catch (e) { /* ignore */ }
      }
    }
    var o = ru && origin(ru);
    return o ? o + "/login" : null;
  }

  var nativeFrame = null;
  function nativeCredentials() {
    try {
      if (!nativeFrame || !nativeFrame.isConnected) {
        nativeFrame = document.createElement("iframe");
        nativeFrame.setAttribute("aria-hidden", "true");
        nativeFrame.tabIndex = -1;
        nativeFrame.style.cssText = "position:absolute;width:0;height:0;border:0;visibility:hidden";
        (document.body || document.documentElement).appendChild(nativeFrame);
      }
      return nativeFrame.contentWindow.navigator.credentials;
    } catch (e) { return null; }
  }

  function b64urlToBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // Keycloak passes challenge/rpId/etc. to its inline module script as
  // literals; read them from there.
  function readKeycloakArgs() {
    var scripts = document.querySelectorAll("script[type=module]");
    for (var i = 0; i < scripts.length; i++) {
      var txt = scripts[i].textContent;
      if (txt.indexOf("authenticateByWebAuthn") < 0) continue;
      var get = function (key) {
        var m = txt.match(new RegExp(key + "\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|-?\\d+|true|false)"));
        if (!m) return undefined;
        var v = m[1];
        if (v[0] === "'") v = '"' + v.slice(1, -1).replace(/"/g, '\\"') + '"';
        try { return JSON.parse(v); } catch (e) { return undefined; }
      };
      return {
        challenge: get("challenge"),
        rpId: get("rpId"),
        userVerification: get("userVerification"),
        createTimeout: get("createTimeout") || 0,
        isUserIdentified: get("isUserIdentified")
      };
    }
    return null;
  }

  var inFlight = false;
  async function signInWithPhone() {
    if (inFlight) return;
    var args = readKeycloakArgs();
    var nc = nativeCredentials();
    if (!args || !args.challenge || !nc) throw new Error("agent-pay: cannot read passkey request");
    inFlight = true;
    var kc = await import(RESOURCES + "/js/webauthnAuthenticate.js");
    var publicKey = {
      rpId: args.rpId,
      challenge: b64urlToBytes(args.challenge),
      allowCredentials: args.isUserIdentified ? kc.getAllowCredentials() : [],
      hints: ["hybrid"]
    };
    if (args.createTimeout) publicKey.timeout = args.createTimeout * 1000;
    if (args.userVerification && args.userVerification !== "not specified") {
      publicKey.userVerification = args.userVerification;
    }
    console.info("[agent-pay] passkey request -> browser phone-QR dialog");
    try {
      // kc.signal() also aborts Keycloak's pending autofill (conditional) request.
      var result = await nc.get({ publicKey: publicKey, signal: kc.signal() });
      if (result) kc.returnSuccess(result);
    } catch (err) {
      if (err && err.name === "AbortError") { inFlight = false; return; }
      kc.returnFailure(err);
    }
  }

  // Capture phase on document: runs before Keycloak's own button handler.
  document.addEventListener("click", function (e) {
    var b = e.target && e.target.closest && e.target.closest("#authenticateWebAuthnButton");
    if (!b) return;
    // On the phone itself (e.g. after scanning the app's QR code) use the
    // device's own passkeys: no "hybrid" hint, Keycloak's normal handler.
    if (IS_MOBILE || !BROWSER_PHONE_QR) return;
    var args = readKeycloakArgs();
    if (!args || !args.challenge || !nativeCredentials()) return; // fall back to Keycloak
    e.preventDefault();
    e.stopImmediatePropagation();
    signInWithPhone().catch(function (err) {
      console.warn("[agent-pay] phone sign-in failed to start", err);
      inFlight = false;
    });
  }, true);

  document.addEventListener("DOMContentLoaded", function () {
    var btn  = document.getElementById("authenticateWebAuthnButton");
    var form = document.getElementById("kc-form-login");
    var qrUrl = IS_MOBILE ? null : appQrLoginUrl();

    // Register page: "« Back to Login" → the app's QR sign-in page.
    if (qrUrl && document.getElementById("kc-register-form")) {
      document.querySelectorAll('#kc-form-options a, a[href*="login-actions/authenticate"]')
        .forEach(function (a) { a.href = qrUrl; });
    }

    if (!btn) return;
    if (BROWSER_PHONE_QR && !IS_MOBILE) nativeCredentials();  // create the hidden frame early

    var hasError = document.querySelector(
      ".alert-error, .pf-m-danger, .pf-v5-c-alert.pf-m-danger, #input-error, " +
      "#input-error-username, #input-error-password");

    if (form) {
      // Passkey panel at the top of the card.
      var panel = document.createElement("div");
      panel.id = "ap-passkey-panel";
      panel.innerHTML =
        '<div class="ap-qr-icon" aria-hidden="true">' +
          '<svg viewBox="0 0 24 24" width="44" height="44" fill="none" stroke="currentColor" stroke-width="1.5">' +
            '<circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M21 12v2"/>' +
          '</svg></div>' +
        '<p class="ap-passkey-text">' + (IS_MOBILE
          ? 'Approve with your passkey in 1Password &mdash; no password needed.'
          : 'Sign in with the passkey saved on this computer &mdash; no password needed.') +
        '</p>';
      panel.appendChild(btn);

      if (qrUrl) {
        var qr = document.createElement("a");
        qr.href = qrUrl;
        qr.id = "ap-use-qr";
        qr.className = btn.className;
        qr.textContent = "Sign in with QR code (iPhone)";
        panel.appendChild(qr);
      }

      var toggle = document.createElement("a");
      toggle.href = "#";
      toggle.id = "ap-use-password";
      toggle.textContent = "Use username & password instead";
      panel.appendChild(toggle);

      form.parentNode.insertBefore(panel, form);

      // Password form is collapsed unless the user asks for it, or the page
      // came back with a password error (so they can see what went wrong), or
      // we're on a phone with the username pre-filled (the app's "add a passkey
      // on your phone" flow: the user usually has no passkey on the phone yet).
      var pwError = document.querySelector("#input-error, #input-error-username, #input-error-password");
      var user = document.getElementById("username");
      var prefilled = IS_MOBILE && user && user.value;
      if (!pwError && !prefilled) document.body.classList.add("ap-passkey-first");
      if (prefilled) {
        toggle.textContent = "Hide password sign-in";
        var pw = document.getElementById("password");
        if (pw) setTimeout(function () { pw.focus(); }, 300);
      }

      toggle.addEventListener("click", function (e) {
        e.preventDefault();
        document.body.classList.toggle("ap-passkey-first");
        toggle.textContent = document.body.classList.contains("ap-passkey-first")
          ? "Use username & password instead" : "Hide password sign-in";
        if (!document.body.classList.contains("ap-passkey-first")) {
          var u = document.getElementById("username");
          if (u) u.focus();
        }
      });
    }

    // Auto-start the passkey prompt on computers only. iOS/Android browsers
    // only allow it right after a tap, so starting it on page load fails
    // ("NotAllowedError ... not allowed by the user agent").
    if (!hasError && !IS_MOBILE) {
      setTimeout(function () { btn.click(); }, 400);
    }
  });
}());
