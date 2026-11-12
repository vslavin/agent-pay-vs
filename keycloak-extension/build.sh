#!/bin/zsh
# Build the Agent Pay Keycloak extension and install it into Keycloak's providers/.
# Keycloak (start-dev) picks it up on its next start.
set -euo pipefail
export JAVA_HOME=/opt/homebrew/opt/openjdk
HERE=${0:A:h}
KC_HOME="$HOME/dev/keycloak-setup/keycloak-26.8.2"
OUT="$HERE/build"; rm -rf "$OUT"; mkdir -p "$OUT/classes"
"$JAVA_HOME/bin/javac" --release 21 -nowarn -cp "$KC_HOME/lib/lib/main/*" \
  -d "$OUT/classes" $(find "$HERE/src" -name '*.java')
cp -R "$HERE/src/META-INF" "$OUT/classes/"
"$JAVA_HOME/bin/jar" --create --file "$OUT/agent-pay-keycloak.jar" -C "$OUT/classes" .
cp "$OUT/agent-pay-keycloak.jar" "$KC_HOME/providers/"
echo "Installed $KC_HOME/providers/agent-pay-keycloak.jar (restart Keycloak to load it)"
