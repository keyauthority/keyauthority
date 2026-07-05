package net.keyauthority.grants;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.grants.JWTAuthorizationGrantType;
import org.keycloak.protocol.oidc.grants.JWTAuthorizationGrantTypeFactory;

public class KeyAuthorityJWTAuthorizationGrantTypeFactory extends JWTAuthorizationGrantTypeFactory {

    @Override
    public JWTAuthorizationGrantType create(KeycloakSession session) {
        return new KeyAuthorityJWTAuthorizationGrantType();
    }
}