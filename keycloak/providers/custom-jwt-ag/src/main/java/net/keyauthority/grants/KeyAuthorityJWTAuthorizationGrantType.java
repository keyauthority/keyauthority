package net.keyauthority.grants;

import org.keycloak.authentication.authenticators.client.ClientAssertionState;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.grants.JWTAuthorizationGrantType;

public class KeyAuthorityJWTAuthorizationGrantType extends JWTAuthorizationGrantType {

    @Override
    protected UserModel lookupUserByFederatedIdentity(FederatedIdentityModel federatedIdentity, ClientAssertionState clientAssertionState) {
        UserModel user = super.lookupUserByFederatedIdentity(federatedIdentity, clientAssertionState);
        if (user != null || federatedIdentity == null) {
            return user;
        }
        // If the user is not found, fallback to the service account user for the client
        return session.users().getServiceAccount(clientAssertionState.getClient());
    }
}