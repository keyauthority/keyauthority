package net.keyauthority.grants;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.grants.JWTAuthorizationGrantType;
import org.keycloak.protocol.oidc.grants.JWTAuthorizationGrantTypeFactory;

public class KeyAuthorityJWTAuthorizationGrantTypeFactory extends JWTAuthorizationGrantTypeFactory {

    private static final String CFG_FALLBACK_ENABLED = "fallback-enabled";
    private static final String CFG_FALLBACK_DOMAIN = "fallback-domain";

    private boolean fallbackEnabled = true;
    private String fallbackDomain = "keyauthority.net";

    @Override
    public JWTAuthorizationGrantType create(KeycloakSession session) {
        return new KeyAuthorityJWTAuthorizationGrantType(fallbackEnabled, fallbackDomain);
    }

    @Override
    public void init(Config.Scope config) {
      fallbackEnabled = config.getBoolean(CFG_FALLBACK_ENABLED, true);
      fallbackDomain = config.get(CFG_FALLBACK_DOMAIN, "keyauthority.net");
    }

    @Override
    public int order() {
      return 1000;
    }
}