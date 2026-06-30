package net.keyauthority.grants;

import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.client.ClientAssertionState;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.grants.JWTAuthorizationGrantType;

public class KeyAuthorityJWTAuthorizationGrantType extends JWTAuthorizationGrantType {

    private static final Logger LOG = Logger.getLogger(KeyAuthorityJWTAuthorizationGrantType.class);

    private final boolean fallbackEnabled;
    private final String fallbackDomain;

    public KeyAuthorityJWTAuthorizationGrantType(boolean fallbackEnabled, String fallbackDomain) {
        super();
        this.fallbackEnabled = fallbackEnabled;
        this.fallbackDomain = fallbackDomain;
    }

    @Override
    protected UserModel lookupUserByFederatedIdentity(FederatedIdentityModel federatedIdentity, ClientAssertionState clientAssertionState) {
        UserModel user = super.lookupUserByFederatedIdentity(federatedIdentity, clientAssertionState);
        if (user != null || !fallbackEnabled || federatedIdentity == null) {
            return user;
        }

        String alias = federatedIdentity.getIdentityProvider();
        if (alias == null || alias.isBlank()) {
            return null;
        }

        String fallbackEmail = alias + "-default@" + fallbackDomain;
        RealmModel realm = session.getContext().getRealm();
        UserModel fallback = session.users().getUserByEmail(realm, fallbackEmail);

        if (fallback != null) {
            LOG.warnf("Federated user '%s' not found for IdP '%s'. Falling back to '%s'.", 
                federatedIdentity.getUserId(), alias, fallbackEmail);
        }

        return fallback;
    }
}