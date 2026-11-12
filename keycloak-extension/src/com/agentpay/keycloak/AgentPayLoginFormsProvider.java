package com.agentpay.keycloak;

import jakarta.ws.rs.core.Response;
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
        }
        return super.createOAuthGrant();
    }

    private static String nz(String s) { return s == null ? "" : s; }
}
