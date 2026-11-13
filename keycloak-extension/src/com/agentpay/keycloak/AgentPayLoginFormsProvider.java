package com.agentpay.keycloak;

import jakarta.ws.rs.core.Response;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

/**
 * Keycloak's consent ("Grant Access to …") page is rendered without the
 * signed-in user, so the theme can't show who is signing in. On a phone (QR /
 * device sign-in) that is exactly what the user needs to check before tapping
 * Yes. This exposes the authenticated user to that template as `apUser`
 * (username, email, firstName, lastName).
 */
public class AgentPayLoginFormsProvider extends FreeMarkerLoginFormsProvider {

    public AgentPayLoginFormsProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    public Response createOAuthGrant() {
        UserModel u = authenticationSession != null ? authenticationSession.getAuthenticatedUser() : null;
        if (u == null) u = user;
        if (u != null) {
            Map<String, String> info = new HashMap<>();
            info.put("username",  nz(u.getUsername()));
            info.put("email",     nz(u.getEmail()));
            info.put("firstName", nz(u.getFirstName()));
            info.put("lastName",  nz(u.getLastName()));
            setAttribute("apUser", info);
            notifyApp(info);
        }
        return super.createOAuthGrant();
    }

    private static final Logger LOG = Logger.getLogger("agent-pay");
    private static final String NOTIFY_URL = System.getenv().getOrDefault(
            "AGENT_PAY_NOTIFY_URL", "http://127.0.0.1:3000/internal/device-user");
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2)).build();

    /**
     * Device (QR) sign-in: tell the demo app WHO is confirming on the phone, so the
     * computer showing the QR code can say so. Best-effort and asynchronous; a
     * failure never affects the login.
     */
    private void notifyApp(Map<String, String> info) {
        try {
            String code = authenticationSession == null ? null
                    : authenticationSession.getClientNote("OAUTH2_DEVICE_VERIFIED_USER_CODE");
            LOG.info("agent-pay: consent page for " + info.get("username") + ", device user code "
                    + (code == null || code.isEmpty() ? "(none)" : "present"));
            if (code == null || code.isEmpty()) return;   // not a device-grant login
            String name = (info.get("firstName") + " " + info.get("lastName")).trim();
            String body = "{\"user_code\":" + q(code) + ",\"username\":" + q(info.get("username"))
                    + ",\"name\":" + q(name) + ",\"email\":" + q(info.get("email")) + "}";
            HTTP.sendAsync(HttpRequest.newBuilder(URI.create(NOTIFY_URL))
                    .timeout(Duration.ofSeconds(3))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                    HttpResponse.BodyHandlers.discarding())
                .whenComplete((r, e) -> LOG.info("agent-pay: notify app -> "
                        + (e != null ? e.toString() : String.valueOf(r.statusCode()))));
        } catch (Exception e) { LOG.log(Level.WARNING, "agent-pay: notify failed", e); }
    }

    private static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    private static String nz(String s) { return s == null ? "" : s; }
}
