package net.keyauthority.grants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.keycloak.authentication.authenticators.client.ClientAssertionState;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.grants.JWTAuthorizationGrantType;

import org.jboss.logging.Logger;

public class KeyAuthorityJWTAuthorizationGrantType extends JWTAuthorizationGrantType {
    
    private static final Logger logger = Logger.getLogger(KeyAuthorityJWTAuthorizationGrantType.class);

    @Override
    protected UserModel lookupUserByFederatedIdentity(FederatedIdentityModel federatedIdentity, ClientAssertionState clientAssertionState) {
        UserModel exact = super.lookupUserByFederatedIdentity(federatedIdentity, clientAssertionState);
        if (exact != null || federatedIdentity == null) {
            return exact;
        }

        String subject = federatedIdentity.getUserId();
        String alias = federatedIdentity.getIdentityProvider();
        if (subject == null || subject.isBlank() || alias == null || alias.isBlank()) {
            return null;
        }

        Set<String> candidatePatterns = new LinkedHashSet<>();

        addKubernetesCandidates(subject, candidatePatterns);
        addGitLabCandidates(subject, candidatePatterns);
        logger.debugf("Candidate federated identity patterns for subject '%s': %s", subject, candidatePatterns);

        for (String pattern : candidatePatterns) {
            FederatedIdentityModel wildcardLookup = new FederatedIdentityModel(
                alias,
                pattern,
                federatedIdentity.getUserName()
            );

            UserModel user = super.lookupUserByFederatedIdentity(wildcardLookup, clientAssertionState);
            if (user != null) {
                return user;
            }
            logger.debugf("No user found for federated identity pattern: %s", wildcardLookup);
        }

        // fallback to the service account user for the client
        UserModel serviceAccount = session.users().getServiceAccount(clientAssertionState.getClient());
        if (serviceAccount != null) {
            logger.warnf("Falling back to service account user: %s", serviceAccount.getUsername());
        }
        return serviceAccount;
    }

    private static void addKubernetesCandidates(String subject, Set<String> out) {
        // Kubernetes: system:serviceaccount:<NAMESPACE>:<SERVICEACCOUNT>
        String[] k8s = subject.split(":", -1);
        if (k8s.length == 4
                && "system".equals(k8s[0])
                && "serviceaccount".equals(k8s[1])
                && !k8s[2].isBlank()
                && !k8s[3].isBlank()) {
            String namespace = k8s[2];
            String serviceAccount = k8s[3];

            out.add("system:serviceaccount:" + namespace + ":" + serviceAccount);
            out.add("system:serviceaccount:" + namespace + ":*");
            out.add("system:serviceaccount:*:" + serviceAccount);
            out.add("system:serviceaccount:*:*");
        }
    }

    private static void addGitLabCandidates(String subject, Set<String> out) {
        // GitLab: project_path:<PROJECT_PATH>:ref_type:<REF_TYPE>:ref:<REF>
        String[] gl = subject.split(":", -1);
        if (gl.length != 6
                || !"project_path".equals(gl[0])
                || !"ref_type".equals(gl[2])
                || !"ref".equals(gl[4])
                || gl[1].isBlank()
                || gl[3].isBlank()
                || gl[5].isBlank()) {
            return;
        }

        String projectPath = gl[1];
        String refType = gl[3];
        String ref = gl[5];

        List<String> pathPatterns = buildProjectPathPatterns(projectPath);

        for (String p : pathPatterns) {
            out.add("project_path:" + p + ":ref_type:" + refType + ":ref:" + ref);
            out.add("project_path:" + p + ":ref_type:" + refType + ":ref:*");
            out.add("project_path:" + p + ":ref_type:*:ref:*");
        }

        // Broad global fallbacks
        out.add("project_path:*:ref_type:" + refType + ":ref:" + ref);
        out.add("project_path:*:ref_type:" + refType + ":ref:*");
        out.add("project_path:*:ref_type:*:ref:*");

        out.add("*:ref_type:" + refType + ":ref:" + ref);
        out.add("*:ref_type:" + refType + ":ref:*");
        out.add("*:ref_type:*:ref:*");
    }

    private static List<String> buildProjectPathPatterns(String projectPath) {
        List<String> patterns = new ArrayList<>();
        patterns.add(projectPath); // exact

        String[] parts = projectPath.split("/", -1);
        if (parts.length <= 1) {
            patterns.add("*");
            return patterns;
        }

        // my-root/path/to/project -> my-root/path/to/*, my-root/path/*, my-root/*
        for (int keep = parts.length - 1; keep >= 1; keep--) {
            String prefix = String.join("/", Arrays.copyOfRange(parts, 0, keep));
            if (!prefix.isBlank()) {
                patterns.add(prefix + "/*");
            }
        }

        patterns.add("*");
        return patterns;
    }
}