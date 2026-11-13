#!/bin/zsh
# Agent Pay passkey demo — one command to bring everything up (e.g. after a reboot).
#
#   ~/dev/agent-pay-vs/demo.sh            # = start
#   ~/dev/agent-pay-vs/demo.sh start      # Keycloak + demo app + proxy + ngrok tunnel, opens the browser
#   ~/dev/agent-pay-vs/demo.sh stop       # stop all three (closes the public tunnel)
#   ~/dev/agent-pay-vs/demo.sh status     # what's running
#
# Override the ngrok domain with:  NGROK_DOMAIN=other.ngrok-free.dev ./demo.sh
#
# Public layout (one ngrok domain, shareable with friends):
#   https://<domain>  → ngrok → proxy.py :8000 → /realms,/resources → Keycloak :8080
#                                               /admin            → blocked (403)
#                                               everything else   → demo app :3000
#
# Needs no passwords: the realm settings (passkey rpId = the ngrok domain)
# are stored in Keycloak's database and survive restarts.
set -uo pipefail

DOMAIN="${NGROK_DOMAIN:-implosive-unlaced-hertz.ngrok-free.dev}"
PUBLIC="https://$DOMAIN"

export JAVA_HOME=/opt/homebrew/opt/openjdk
KC_HOME="$HOME/dev/keycloak-setup/keycloak-26.8.2"
KCADM="$KC_HOME/bin/kcadm.sh"
APP_DIR="$HOME/dev/agent-pay-vs/demo-app"
LOG_DIR="$HOME/dev/keycloak-setup"
APP_URL="$PUBLIC"
PROXY_PY="$HOME/dev/agent-pay-vs/proxy.py"
WALLET_DIR="$HOME/dev/agent-pay-vs/agent-wallet-demo/wallet-service"
NODE=/opt/homebrew/bin/node

ok()   { print -P "  %F{green}✔%f $*"; }
warn() { print -P "  %F{yellow}!%f $*"; }
fail() { print -P "  %F{red}✘%f $*"; }

wait_for() {  # url seconds label  [extra curl args...]
  local url=$1 secs=$2 label=$3; shift 3
  for i in {1..$secs}; do
    curl -s -o /dev/null -m 2 "$@" "$url" && { ok "$label is up"; return 0; }
    sleep 1
  done
  fail "$label did not come up ($url)"; return 1
}

kc_running()     { lsof -tiTCP:8080 -sTCP:LISTEN >/dev/null 2>&1; }
kc_has_domain()  { pgrep -f "kc.sh start-dev.*--hostname=$PUBLIC" >/dev/null; }
app_running()    { lsof -tiTCP:3000 -sTCP:LISTEN >/dev/null 2>&1; }
ngrok_running()  { pgrep -f "ngrok http 8000 --url=$PUBLIC" >/dev/null; }
proxy_running()  { lsof -tiTCP:8000 -sTCP:LISTEN >/dev/null 2>&1; }
wallet_running() { lsof -tiTCP:3100 -sTCP:LISTEN >/dev/null 2>&1; }

stop_keycloak() {
  pkill -f 'kc.sh start-dev' 2>/dev/null
  pkill -f 'kc.script.pid' 2>/dev/null
  for i in {1..30}; do kc_running || return 0; sleep 1; done
}

start() {
  print "Agent Pay demo → $PUBLIC"

  # Preflight
  [[ -x "$JAVA_HOME/bin/java" ]] || { fail "Java not found at $JAVA_HOME (brew install openjdk)"; return 1; }
  command -v ngrok >/dev/null    || { fail "ngrok not installed (brew install ngrok)"; return 1; }
  ngrok config check >/dev/null 2>&1 || { fail "ngrok has no authtoken (ngrok config add-authtoken <token>)"; return 1; }

  # 1. Keycloak
  print "1/4 Keycloak"
  if kc_running && kc_has_domain; then
    ok "already running"
  else
    kc_running && { warn "running without the ngrok hostname — restarting"; stop_keycloak; }
    (cd "$KC_HOME" && nohup ./bin/kc.sh start-dev --http-port=8080 \
        --hostname="$PUBLIC" --hostname-admin=http://localhost:8080 \
        --hostname-backchannel-dynamic=true \
        --proxy-headers=xforwarded > "$LOG_DIR/keycloak.log" 2>&1 &)
    print "  starting (takes ~20-40 s)…"
  fi
  wait_for "http://localhost:8080/realms/passkey-demo" 120 "Keycloak" || {
    print "  last log lines:"; tail -5 "$LOG_DIR/keycloak.log" | sed 's/^/    /'; return 1; }

  # Sanity check (only if an admin CLI session happens to be valid; never prompts).
  if rp=$("$KCADM" get realms/passkey-demo --fields webAuthnPolicyPasswordlessRpId \
            --format csv --noquotes 2>/dev/null); then
    [[ "$rp" == "$DOMAIN" ]] && ok "passkey rpId = $DOMAIN" \
      || warn "passkey rpId is '$rp', expected '$DOMAIN' — passkeys won't match (fix: kcadm update realms/passkey-demo -s webAuthnPolicyPasswordlessRpId=$DOMAIN)"
  fi

  # Wallet service (OUSD treasury + user wallets on Tempo testnet). Optional: the
  # app still runs without it; the admin page then says the service is unreachable.
  print "Wallet service :3100"
  if wallet_running; then
    ok "already running"
  elif [[ -x "$NODE" && -f "$WALLET_DIR/data/treasury.json" ]]; then
    (cd "$WALLET_DIR" && nohup "$NODE" server.mjs > "$LOG_DIR/wallet-service.log" 2>&1 &)
    wait_for "http://127.0.0.1:3100/" 10 "Wallet service" || tail -5 "$LOG_DIR/wallet-service.log" | sed 's/^/    /'
  else
    warn "skipped (needs node at $NODE and $WALLET_DIR/data/treasury.json)"
  fi

  # 2. Demo app (always restarted so it picks up the public URL)
  print "2/4 Demo app"
  app_running && { lsof -tiTCP:3000 -sTCP:LISTEN | xargs kill 2>/dev/null; sleep 1; }
  (cd "$APP_DIR" && KC_PUBLIC_URL="$PUBLIC" nohup python3 -u app.py > "$LOG_DIR/demo-app.log" 2>&1 &)
  wait_for "http://localhost:3000/" 15 "Demo app" || { tail -5 "$LOG_DIR/demo-app.log" | sed 's/^/    /'; return 1; }

  # 3. Proxy (one public domain for app + Keycloak)
  print "3/4 Proxy :8000"
  proxy_running && { lsof -tiTCP:8000 -sTCP:LISTEN | xargs kill 2>/dev/null; sleep 1; }
  nohup python3 -u "$PROXY_PY" > "$LOG_DIR/proxy.log" 2>&1 &
  wait_for "http://localhost:8000/" 10 "Proxy" || { tail -5 "$LOG_DIR/proxy.log" | sed 's/^/    /'; return 1; }

  # 4. ngrok tunnel → proxy
  print "4/4 ngrok tunnel"
  if ngrok_running; then
    ok "already running"
  else
    pkill -x ngrok 2>/dev/null
    nohup ngrok http 8000 --url="$PUBLIC" --log=stdout > "$LOG_DIR/ngrok.log" 2>&1 &
  fi
  wait_for "$PUBLIC/" 30 "Tunnel" -H 'ngrok-skip-browser-warning: 1' || {
    print "  last log lines:"; grep -iE 'err|fail' "$LOG_DIR/ngrok.log" | tail -3 | sed 's/^/    /'; return 1; }

  print
  print -P "%F{green}Ready.%f  Share this link: $PUBLIC"
  print "  (also works locally at http://localhost:3000; public until './demo.sh stop')"
  print "Logs: $LOG_DIR/{keycloak,demo-app,proxy,ngrok}.log"
  [[ -z "${NO_OPEN:-}" ]] && open "$APP_URL"
  return 0
}

stop() {
  print "Stopping Agent Pay demo"
  pkill -x ngrok 2>/dev/null && ok "ngrok stopped (tunnel closed)" || ok "ngrok not running"
  if proxy_running; then lsof -tiTCP:8000 -sTCP:LISTEN | xargs kill 2>/dev/null; ok "proxy stopped"; else ok "proxy not running"; fi
  if app_running; then lsof -tiTCP:3000 -sTCP:LISTEN | xargs kill 2>/dev/null; ok "demo app stopped"; else ok "demo app not running"; fi
  if wallet_running; then lsof -tiTCP:3100 -sTCP:LISTEN | xargs kill 2>/dev/null; ok "wallet service stopped"; else ok "wallet service not running"; fi
  if kc_running; then stop_keycloak; ok "Keycloak stopped"; else ok "Keycloak not running"; fi
}

status() {
  kc_running    && { kc_has_domain && ok "Keycloak (hostname $PUBLIC)" || warn "Keycloak running WITHOUT ngrok hostname"; } || fail "Keycloak"
  ngrok_running && ok "ngrok → $PUBLIC" || fail "ngrok"
  app_running   && ok "Demo app http://localhost:3000" || fail "Demo app"
  proxy_running && ok "Proxy :8000" || fail "Proxy"
  wallet_running && ok "Wallet service :3100" || warn "Wallet service not running"
}

case "${1:-start}" in
  start)  start ;;
  stop)   stop ;;
  status) status ;;
  restart) stop; start ;;
  *) print "usage: $0 [start|stop|status|restart]"; exit 2 ;;
esac
