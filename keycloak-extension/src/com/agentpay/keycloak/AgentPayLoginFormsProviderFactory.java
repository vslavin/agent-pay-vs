package com.agentpay.keycloak;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;

/** Registers AgentPayLoginFormsProvider; order() > 0 makes it the default. */
public class AgentPayLoginFormsProviderFactory extends FreeMarkerLoginFormsProviderFactory {

    @Override
    public LoginFormsProvider create(KeycloakSession session) {
        return new AgentPayLoginFormsProvider(session);
    }

    @Override
    public String getId() {
        return "agent-pay-freemarker";
    }

    @Override
    public int order() {
        return 10;
    }
}
