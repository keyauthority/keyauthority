package net.keyauthority.provider;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.broker.jwtauthorizationgrant.JWTAuthorizationGrantIdentityProvider;
import org.keycloak.broker.jwtauthorizationgrant.JWTAuthorizationGrantIdentityProviderConfig;
import org.keycloak.models.KeycloakSession;

public class KeyAuthorityJWTAuthorizationGrantIdentityProvider extends JWTAuthorizationGrantIdentityProvider {

    public KeyAuthorityJWTAuthorizationGrantIdentityProvider(
            KeycloakSession session,
            JWTAuthorizationGrantIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public List<String> getAllowedAudienceForJWTGrant() {
        List<String> audiences = new ArrayList<>(super.getAllowedAudienceForJWTGrant());
        // Add the KeyAuthority-specific audiences  
        audiences.add("keyauthority://signers");
        audiences.add("keyauthority://secrets");
        audiences.add("system:konnectivity-server");
        audiences.add(getConfig().getIssuer());
        return audiences;
    }
}