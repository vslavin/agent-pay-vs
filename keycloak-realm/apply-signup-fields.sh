#!/bin/zsh
# Adds the sign-up fields (account type, business name, business description) to the passkey-demo realm's
# user profile and sends them to the app in the token. Idempotent. Needs a kcadm session first:
#   $KC_HOME/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin
set -euo pipefail
KC_HOME="${KC_HOME:-$HOME/dev/keycloak-setup/keycloak-26.8.2}"
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk}"
KCADM="$KC_HOME/bin/kcadm.sh"
HERE="${0:A:h}"
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT

"$KCADM" get users/profile -r passkey-demo > "$TMP"
python3 - "$TMP" "$HERE/signup-attributes.json" <<'PY'
import json, sys
profile = json.load(open(sys.argv[1]))
have = {a["name"] for a in profile["attributes"]}
profile["attributes"] += [a for a in json.load(open(sys.argv[2])) if a["name"] not in have]
json.dump(profile, open(sys.argv[1], "w"), indent=2)
PY
"$KCADM" update users/profile -r passkey-demo -f "$TMP"

CID="$("$KCADM" get clients -r passkey-demo -q clientId=demo-app --fields id --format csv --noquotes)"
for attr in account_type business_name business_description; do
  "$KCADM" get "clients/$CID/protocol-mappers/models" -r passkey-demo --fields name | grep -q "\"$attr\"" && continue
  "$KCADM" create "clients/$CID/protocol-mappers/models" -r passkey-demo \
    -s name=$attr -s protocol=openid-connect -s protocolMapper=oidc-usermodel-attribute-mapper \
    -s "config.\"user.attribute\"=$attr" -s "config.\"claim.name\"=$attr" -s 'config."jsonType.label"=String' \
    -s 'config."id.token.claim"=true' -s 'config."access.token.claim"=true' -s 'config."userinfo.token.claim"=true'
done
echo "Sign-up fields and token mappers are in place."
