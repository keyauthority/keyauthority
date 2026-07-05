package net.keyauthority.provider;

import org.keycloak.broker.jwtauthorizationgrant.JWTAuthorizationGrantIdentityProvider;
import org.keycloak.broker.jwtauthorizationgrant.JWTAuthorizationGrantIdentityProviderConfig;
import org.keycloak.broker.jwtauthorizationgrant.JWTAuthorizationGrantIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class KeyAuthorityJWTAuthorizationGrantIdentityProviderFactory extends JWTAuthorizationGrantIdentityProviderFactory {

    @Override
    public JWTAuthorizationGrantIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new KeyAuthorityJWTAuthorizationGrantIdentityProvider(
                session,
                new JWTAuthorizationGrantIdentityProviderConfig(model)
        );
    }
}