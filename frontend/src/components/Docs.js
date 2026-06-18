import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Alert, Button, Table } from "react-bootstrap";
import { getApi } from "../axios";
import { getKeycloak } from "../keycloak";
import { copyToClipboard, disclaimer, prettyCode } from "../utils/utils";
import KeyValueTable from "./KeyValueTable";

export function UsefulLinks() {
  const api = getApi();
  const apiUrl = new URL(api.defaults.baseURL);
  const apiRootUrl = apiUrl.href.replace(/\/v1\/?$/, "");
  const swaggerUrl = apiRootUrl + "/swagger/";
  const keycloak = getKeycloak();

  return (
    <Table responsive striped hover className="align-middle">
      <thead>
        <tr>
          <th>Resource</th>
          <th>URL</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Project Home Page</td>
          <td>
            <a
              href="https://keyauthority.net"
              target="_blank"
              rel="noopener noreferrer"
            >
              https://keyauthority.net
            </a>
          </td>
        </tr>
        <tr>
          <td>Project Docker Hub</td>
          <td>
            <a
              href="https://hub.docker.com/u/keyauthoritydh"
              target="_blank"
              rel="noopener noreferrer"
            >
              https://hub.docker.com/u/keyauthoritydh
            </a>
          </td>
        </tr>
        <tr>
          <td>Helm Chart in Artifact Hub</td>
          <td>
            <a
              href="https://artifacthub.io/packages/helm/keyauthority/keyauthority"
              target="_blank"
              rel="noopener noreferrer"
            >
              https://artifacthub.io/packages/helm/keyauthority/keyauthority
            </a>
          </td>
        </tr>
        <tr>
          <td>REST API Swagger UI</td>
          <td>
            <a href={swaggerUrl} target="_blank" rel="noopener noreferrer">
              {swaggerUrl}
            </a>
          </td>
        </tr>
        <tr>
          <td>Integrated Keycloak's Admin Console</td>
          <td>
            <a
              href={`${keycloak?.authServerUrl}/admin/master/console/#/${keycloak?.realm}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              {keycloak?.authServerUrl}/admin/master/console/#/{keycloak?.realm}
            </a>
          </td>
        </tr>
      </tbody>
    </Table>
  );
}

export function Administration() {
  const keycloak = getKeycloak();

  const apiUrl = new URL(getApi().defaults.baseURL);
  const apiRootUrl = apiUrl.href.replace(/\/v1\/?$/, "");

  return (
    <>
      <p>
        KeyAuthority provides a comprehensive API and web interface for managing
        certificates, signers, secrets, and cryptographic operations. User
        authentication and RBAC (role-based access control) are managed through
        the integrated Keycloak identity provider. This design ensures that
        KeyAuthority focuses on cryptographic operations while delegating
        identity management to a proven, enterprise-grade solution.
      </p>
      <p>
        This section guides you through the essential administrative tasks
        needed to set up clients, configure roles, and manage access for your
        KeyAuthority deployment.
      </p>

      <h4>Keycloak Administration</h4>
      <p>
        Start by logging into the Keycloak admin console using the URL{" "}
        <a
          href={`${keycloak?.authServerUrl}/admin/master/console/#/${keycloak?.realm}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          {keycloak?.authServerUrl}/admin/master/console/#/{keycloak?.realm}
        </a>
        .
      </p>
      <p>
        Use the admin credentials you set up during the Keycloak installation.
        Once logged in, make sure you select the realm{" "}
        <code>{keycloak?.realm}</code> for your KeyAuthority deployment and
        proceed with the administrative tasks, including:
      </p>
      <ul>
        <li>
          <strong>Define Roles</strong>: Create roles that correspond to the
          various access levels required for your users and services.
        </li>
        <li>
          <strong>Create Clients</strong>: Set up clients for applications and
          services that will interact with KeyAuthority. Configure client roles
          and access types as needed.
        </li>
        <li>
          <strong>Manage Users</strong>: Add users to the realm and assign them
          appropriate roles based on their responsibilities.
        </li>
        <li>
          <strong>Map Roles</strong>: Define role mappings to associate users
          and clients with the appropriate roles.
        </li>
      </ul>
      <p>
        For native instructions on performing these tasks, refer to the{" "}
        <a
          href="https://www.keycloak.org/docs/latest/server_admin/"
          target="_blank"
          rel="noopener noreferrer"
        >
          Keycloak Server Administration Guide
        </a>
        .
      </p>

      <h4>Role-Based Access Control</h4>
      <p>
        KeyAuthority defines the following built-in roles that can be assigned
        to users and clients via Keycloak:
      </p>
      <KeyValueTable
        body={{
          //KEYAUTHORITY_ADMIN: "Full access to all features and settings",
          KEYAUTHORITY_OPERATOR:
            "Access to manage resources such as keys, signers and secrets",
          KEYAUTHORITY_AUDITOR: "Read-only access to view logs",
          KEYAUTHORITY_APPROVER:
            "Permissions to approve requests that are pending review and approval",
        }}
        header={["Role", "Access"]}
        minKeyLen={30}
        keysTag={"code"}
        borderBottom={true}
      />

      <h5>Environment-Scoped Roles</h5>
      <p>
        In addition to the global roles mentioned above, KeyAuthority also
        supports scoped roles that can be assigned on a <i>per-environment</i>{" "}
        basis.{" "}
        <span className="fw-semibold">
          Environments are logical groupings of cryptographic keys
        </span>
        . A signer belongs to the environment of its private key and a secret
        belongs to the environment of its encryption key. This allows for more
        granular access control, enabling users to have specific permissions for
        individual signers or secrets without granting them broader access.
      </p>

      <p>
        The environment-scoped role names are of the form{" "}
        <code>KEYAUTHORITY_OPERATOR_env</code>, where <code>env</code> is the
        name of the environment. For example, a user with a single role{" "}
        <code>KEYAUTHORITY_OPERATOR_dev</code> has access to resources within
        the <code>dev</code> environment only. To assign scoped roles, navigate
        to the respective user or client in the Keycloak admin interface and use
        the role assignment options to grant the desired permissions.
      </p>

      <p>
        It is recommended to use scoped roles to enforce the principle of least
        privilege, ensuring users have only the access necessary for their
        specific tasks. It is also important to note that scoped roles are
        additive to global roles. A user with a global role will retain those
        permissions in addition to any scoped roles they possess.
      </p>

      <h4>Clients</h4>
      <p>
        Applications and services that interact with KeyAuthority must be
        registered as users in Keycloak. These services include any automation
        tools, CI/CD pipelines, or Kubernetes clusters that need to request
        certificates or manage secrets.
      </p>

      <p>
        Users can access KeyAuthority resources via clients registered in
        Keycloak. A KeyAuthority deployment defines two default clients:
      </p>

      <KeyValueTable
        body={{
          "keyauthority-frontend":
            "The web frontend client used for UI interactions",
          "keyauthority-exchange":
            "Used by applications and services to exchange credentials like username and password for Keycloak-issued access tokens",
        }}
        header={["Client", "Description"]}
        minKeyLen={30}
        keysTag={"code"}
        borderBottom={true}
      />

      <h4>External Identity Providers</h4>

      <p>
        In some cases, you may need to integrate external{" "}
        <strong>Identity Providers</strong> to allow users to authenticate using
        existing credentials from platforms like GitLab, Kubernetes, or Google
        Cloud. Keycloak supports this through its{" "}
        <a
          href="https://www.keycloak.org/securing-apps/jwt-authorization-grant"
          target="_blank"
          rel="noopener noreferrer"
        >
          JWT Authorization Grant
        </a>{" "}
        feature, which allows you to accept tokens issued by external providers
        and exchange them for Keycloak-issued tokens. This is particularly
        useful for machine-to-machine authentication, where services can present
        tokens from their native identity systems without needing to interact
        with the frontend.
      </p>

      <p>
        This section provides a step-by-step guide on how to set up an external
        Identity Provider, using GitLab as an example.
      </p>

      <h5>Step 1: Create Identity Provider</h5>

      <p>
        Create an Identity Provider <code>jwt-gitlab</code> of type{" "}
        <strong>JWT Authorization Grant</strong> in your Keycloak realm with the
        appropriate settings.
      </p>

      <img
        src="/new-idp.png"
        alt="Identity Provider Config"
        className="img-fluid"
      />

      <h5>Step 2: Configure Client for Token Exchange</h5>

      <p>
        Next, go to <code>keyauthority-exchange</code> client{" "}
        <i className="bi bi-caret-right-fill"></i> <strong>Settings</strong> tab{" "}
        <i className="bi bi-caret-right-fill"></i>{" "}
        <strong>Capability config</strong> section, and configure the client to
        allow token exchange for the newly created Identity Provider.
      </p>

      <img src="/exchange-client-config1.png" className="img-fluid" />

      <h5>Step 3: Set Custom Audience for Token Exchange</h5>

      <p>
        Next, go to <code>keyauthority-exchange</code> client{" "}
        <i className="bi bi-caret-right-fill"></i> <strong>Advanced</strong> tab{" "}
        <i className="bi bi-caret-right-fill"></i>{" "}
        <strong>OpenID Connect Compatibility Modes</strong> section, and add an
        entry into the <strong>Custom audience mapping</strong> with the
        expected audience claim of the external Identity Provider token.
      </p>

      <img src="/exchange-client-config2.png" className="img-fluid" />

      <h5>Step 4: Link Identity Provider User ID to Keycloak User</h5>

      <p>
        Finally, ensure that there is a Keycloak user with an{" "}
        <strong>Identity provider link</strong> that matches the User ID
        (subject of the external token) from the external provider. This allows
        Keycloak to associate incoming tokens with the correct user and apply
        the appropriate roles and permissions.
      </p>

      <img src="/user-idp-link.png" className="img-fluid" />

      <p>
        If you encounter any issues with token exchange, check the Keycloak
        server logs for errors related to JWT authorization grant validation or
        audience mismatches. In some cases, the backend server will also show in
        DEBUG logs some information on the exchange process, including the
        external token's claims and the result of the exchange attempt. This can
        help diagnose issues with token validation or role mapping.
      </p>

      {/*<h4>Fine-Grained Access Control via Client Configuration (Advanced)</h4>
      <p>
        For advanced use cases, you may need to customize the client settings
        further. This can include configuring protocol mappers to include
        specific claims in tokens, setting up custom authentication flows, or
        adjusting token lifespans.
      </p>

      <h5>Token Verification</h5>
      <p>
        The KeyAuthority backend API authentication works by looping through the
        the list of configured OIDC providers until the token presented is
        verified. This list is composed of:
      </p>
      <p>
        <ul>
          <li>
            <strong>the internal OIDC provider</strong>, discoverable at{" "}
            <a
              href={`${keycloak?.authServerUrl}/realms/${keycloak?.realm}/.well-known/openid-configuration`}
              target="_blank"
              rel="noopener noreferrer"
            >
              {`${keycloak?.authServerUrl}/realms/${keycloak?.realm}/.well-known/openid-configuration`}
            </a>{" "}
            and represents the Keycloak realm <code>{keycloak?.realm}</code>{" "}
            where KeyAuthority is deployed, and
          </li>
          <li>
            <strong>the external OIDC providers</strong>, corresponding to
            Keycloak clients that have <code>client-jwt</code> as Client
            Authenticator Type, ordered by their client ID in alphabetical
            order.
          </li>
        </ul>
      </p>

      <p>
        When a token is presented to the API, KeyAuthority will check its
        validity against each OIDC provider in sequence. If the token is
        successfully verified by any of the providers, access is granted based
        on the roles in the token, if the verifier provider is the internal; or
        the assigned client roles, if the verifier provider is external.
        Providers are refreshed automatically every 30 minutes.
      </p>

      <h5>External Token Verification</h5>
      <p>
        Some clients, such as <code>keyauthority-kubernetes</code> and{" "}
        <code>keyauthority-gitlab</code>, are configured to verify tokens issued
        by external identity providers rather than Keycloak itself. This design
        allows KeyAuthority to trust tokens from platforms like Kubernetes and
        GitLab without requiring those systems to integrate directly with
        Keycloak.
      </p>
      <p>
        When these external tokens are presented to KeyAuthority, the system:
      </p>
      <ul>
        <li>
          Validates the token signature against the external provider's public
          keys.
        </li>
        <li>Verifies the token claims (issuer, expiration, etc...).</li>
        <li>
          Maps the external identity to appropriate KeyAuthority roles and
          permissions.
        </li>
      </ul>
      <p>
        This approach enables secure, federated authentication while maintaining
        centralized access control through Keycloak for user management and role
        assignments.
      </p>

      <h5>Scoping External Tokens</h5>
      <p>
        For external tokens, KeyAuthority supports scoping based on claims
        present in the token. For example, Kubernetes service account tokens
        include namespace and service account name claims that can be used to
        assign scoped roles dynamically.
      </p>
      <p>
        When configuring clients for external providers, ensure that the token
        claims used for scoping align with your access control policies. This
        allows you to enforce least-privilege access for workloads based on
        their identities. This is achieved by specifying <i>required claims</i>{" "}
        in the client's description field.
      </p>

      <p>
        For example, let's assume that you want to allow Kubernetes service
        accounts in the the entire cluster to have access to all secrets in the{" "}
        <code>dev</code> environment, and only service accounts in the{" "}
        <code>prod</code> namespace to have access to secrets in the{" "}
        <code>prod</code> environment. You can achieve this by creating the
        following two clients in Keycloak:
      </p>

      <Table responsive>
        <thead>
          <tr>
            <th>Client</th>
            <th>Description</th>
            <th>Roles</th>
            <th>Configuration</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              <code>keyauthority-kubernetes-1-prod</code>
            </td>
            <td>
              Client for Kubernetes service accounts in the <code>prod</code>{" "}
              namespace
            </td>
            <td>
              <code>KEYAUTHORITY_OPERATOR_dev</code>,{" "}
              <code>KEYAUTHORITY_OPERATOR_prod</code>
            </td>
            <td>
              {prettyCode("json", {
                clientId: "keyauthority-kubernetes-1-prod",
                clientAuthenticatorType: "client-jwt",
                description:
                  '{"requiredClaims":{"kubernetes.io":{"namespace":"prod"}}}',
                attributes: {
                  "jwks.url": "https://kubernetes.default.svc.cluster.local",
                  "use.jwks.url": "true",
                },
              })}
            </td>
          </tr>
          <tr>
            <td>
              <code>keyauthority-kubernetes-2-dev</code>
            </td>
            <td>Client for all Kubernetes service accounts</td>
            <td>
              <code>KEYAUTHORITY_OPERATOR_dev</code>
            </td>
            <td>
              {prettyCode("json", {
                clientId: "keyauthority-kubernetes-2-dev",
                clientAuthenticatorType: "client-jwt",
                attributes: {
                  "jwks.url": "https://kubernetes.default.svc.cluster.local",
                  "use.jwks.url": "true",
                },
              })}
            </td>
          </tr>
        </tbody>
      </Table>

      <p>
        As you can observe, the only difference between the two clients config
        is that the first one has a <code>description</code> attribute
        specifying required claims for environment scoping. This ensures that
        only tokens from service accounts in the <code>prod</code> namespace
        will be accepted by that client, therefore only these tokens get access
        to secrets in both <code>dev</code> and <code>prod</code> environments.
        Note also that the client names/IDs were purposely set in a way that{" "}
        <code>keyauthority-kubernetes-1-prod</code> comes before{" "}
        <code>keyauthority-kubernetes-2-dev</code> alphabetically, so that it is
        evaluated first during token verification. As a general rule, more
        specific clients (i.e., those with claim requirements) should be named
        in a way that they come first alphabetically.
      </p>
      <p>
        Similarly, you can use this approach to set scoped access for other
        external identity providers by configuring the appropriate claim
        requirements in Keycloak. You simply need to ensure that the claims used
        for scoping are present in the tokens issued by those providers.
      </p>

      <Alert variant="info">
        <Alert.Heading className="fw-bold fs-6">Tip</Alert.Heading>
        <p>
          When configuring external OIDC providers, it is crucial to ensure that
          JWKS URLs are correctly set and accessible. For example, while the
          typical JWKS URL for Kubernetes is{" "}
          <code>https://kubernetes.default.svc.cluster.local</code>, providers
          like Google Cloud or Microsoft Azure may have different URLs. The
          KeyAuthority backend will signal such issues in the DEBUG logs. For
          example:
        </p>

        {prettyCode(
          "log",
          `time=2026-02-18T09:50:50.817Z level=DEBUG msg="skipping client for external OIDC provider discovery" clientID=keyauthority-kubernetes reason="oidc: issuer URL provided to client (\\"https://kubernetes.default.svc.cluster.local\\") did not match the issuer URL returned by provider (\\"https://container.googleapis.com/v1/projects/keyauthority-test/locations/europe-central2/clusters/keyauthority-cluster-1\\")".`,
          false,
        )}

        <p>
          This means that the client's JWKS URL should be set to{" "}
          <code>
            https://container.googleapis.com/v1/projects/keyauthority-test/locations/europe-central2/clusters/keyauthority-cluster-1
          </code>{" "}
          for the setup to work correctly.
        </p>
      </Alert>*/}
    </>
  );
}

export function UseSigners() {
  const sampleSigner = "my-signer";
  const apiUrl = new URL(getApi().defaults.baseURL);
  const apiRootUrl = apiUrl.href.replace(/\/v1\/?$/, "");
  return (
    <>
      <p>
        KeyAuthority offers a flexible and secure platform that allows you to
        automate TLS provisioning, rotation, and other PKI operations. In
        Kubernetes environments, KeyAuthority integrates seamlessly with{" "}
        <a
          href="https://cert-manager.io"
          target="_blank"
          rel="noopener noreferrer"
        >
          cert-manager
        </a>{" "}
        to provide dynamic certificate issuance and renewal.
      </p>
      <p>
        This section walks you through integrating KeyAuthority signers with
        Kubernetes resources (e.g., Issuers, Certificates, Ingresses) to bring
        SSL into your applications. We assume that you have a KeyAuthority
        signer named <code>{sampleSigner}</code> and a user{" "}
        <code>{`${sampleSigner}@keyauthority.net`}</code>, otherwise you can
        replace these values with your own.
      </p>

      {signerUsageExample(sampleSigner, apiRootUrl)}
    </>
  );
}

export function UseSecrets() {
  const sampleSecret = {
    name: "pg-credentials",
    data: {
      PGUSER: "...",
      PGPASSWORD: "...",
    },
  };
  const apiUrl = new URL(getApi().defaults.baseURL);
  const apiRootUrl = apiUrl.href.replace(/\/v1\/?$/, "");

  return (
    <>
      <p>
        KeyAuthority doesn't stop at PKI — it also acts as a flexible secrets
        management system. You can use it to securely store and retrieve
        sensitive values like API tokens, credentials, or configuration data.
        Each secret is encrypted prior to storage and decrypted on access.
      </p>
      <p>
        This section demonstrates how to deliver secrets to workloads using the
        API.
      </p>

      <h4>Examples</h4>

      <p>
        The following examples demonstrate how secrets stored in KeyAuthority
        can be seamlessly injected into your applications and automation
        environments. Let's assume you have a script named <code>run.sh</code>{" "}
        that performs database operations using credentials stored in a secret.
        Below is a simplified version of that script:
      </p>

      {prettyCode(
        "bash",
        `#!/bin/bash

# Connect to PostgreSQL using environment variables
psql -h "postgres.local" -p "5432" -U "$PGUSER" -d "mydb" <<EOF
UPDATE events SET status='processing' WHERE status='pending';
EOF

# Continue with additional logic, e.g. process pending events
...`,
      )}

      <p>
        Let's also assume that the required PostgreSQL credentials{" "}
        <code>{JSON.stringify(sampleSecret.data, null, 2)}</code> are stored in
        the secret <code>{sampleSecret.name}</code>. KeyAuthority supports
        several ways to securely expose these secrets to applications:
      </p>

      <ul>
        <li>
          <strong>Shell</strong>: Source secrets dynamically at runtime using{" "}
          <code>curl</code>.
        </li>
        <li>
          <strong>GitLab Runners</strong>: Use the Vault integration to expose
          secrets as environment variables in CI/CD jobs.
        </li>
        <li>
          <strong>Kubernetes Pods</strong>: Inject secrets into pods using
          annotations and Vault Agent sidecars.
        </li>
      </ul>

      <p>The examples below demonstrate each of these scenarios in detail.</p>

      {secretUsageExamples(
        `${sampleSecret.name}`,
        sampleSecret.data,
        apiRootUrl,
      )}
    </>
  );
}

export function Architecture() {
  const rootRef = useRef(null);
  const nodeRefs = useRef({});
  const [points, setPoints] = useState({});

  const setNodeRef = (key) => (el) => {
    nodeRefs.current[key] = el;
  };

  useEffect(() => {
    const updatePoints = () => {
      const root = rootRef.current;
      if (!root) return;
      const rootBox = root.getBoundingClientRect();

      const next = {};
      Object.entries(nodeRefs.current).forEach(([key, el]) => {
        if (!el) return;
        const box = el.getBoundingClientRect();
        next[key] = {
          x: box.left - rootBox.left + box.width / 2,
          y: box.top - rootBox.top + box.height / 2,
        };
      });

      setPoints(next);
    };

    updatePoints();
    window.addEventListener("resize", updatePoints);

    const ro = new ResizeObserver(updatePoints);
    if (rootRef.current) ro.observe(rootRef.current);

    return () => {
      window.removeEventListener("resize", updatePoints);
      ro.disconnect();
    };
  }, []);

  const card = (variant = "secondary", title, description, icon, content) => (
    <Alert
      variant={variant}
      className="rounded-4 p-4 mb-0 shadow w-100 h-100 d-flex flex-column justify-content-center"
      //style={{ minWidth: 120 }}
    >
      <div className="d-flex align-items-center mb-3">
        <i className={`bi ${icon}`} style={{ fontSize: "2rem" }}></i>
        <div className="ms-3">
          <h5 className="mb-0">{title}</h5>
          <div className="small">{description}</div>
        </div>
      </div>
      <div className="small">{content}</div>
    </Alert>
  );

  const line = (from, to, color = "#c62828", dashed = false) => {
    if (!points[from] || !points[to]) return null;
    return (
      <line
        key={`${from}-${to}`}
        x1={points[from].x}
        y1={points[from].y}
        x2={points[to].x}
        y2={points[to].y}
        stroke={color}
        strokeWidth="3"
        //strokeDasharray={dashed ? "6 4" : "0"}
        markerEnd="url(#archArrow)"
        //className="shadow"
      />
    );
  };

  return (
    <>
      <p className="mb-3">
        The following diagram illustrates the architecture of KeyAuthority,
        showing its components and their interactions. KeyAuthority components
        are the frontend, the backend, the identity provider (Keycloak), and the
        database. The diagram also shows the interactions with humans, machines,
        and the HSM.
      </p>
      <div ref={rootRef} className="position-relative">
        {/* Connection layer */}
        <svg
          className="position-absolute top-0 start-0 w-100 h-100"
          style={{ pointerEvents: "none", zIndex: 0 }}
        >
          {line("humans", "frontend")}
          {line("apps", "backend")}
          {line("frontend", "backend")}
          {line("keycloak", "frontend")}
          {line("keycloak", "backend")}
          {line("keycloak", "database")}
          {line("backend", "database")}
          {line("backend", "hsm")}
        </svg>

        {/* Nodes */}
        <div
          className="position-relative row g-4 align-items-center"
          style={{ zIndex: 1, minHeight: 640 }}
        >
          <div className="col-12 col-xl-3 d-flex flex-column justify-content-center gap-4 h-100">
            <div ref={setNodeRef("humans")} className="d-flex w-100">
              {card(
                "success",
                "Humans",
                "End Users",
                "bi-people-fill",
                <ul className="mb-0">
                  <li>Operators</li>
                  <li>Auditors</li>
                  <li>Approvers</li>
                </ul>,
              )}
            </div>

            <div ref={setNodeRef("apps")} className="d-flex w-100">
              {card(
                "info",
                "Machines",
                "Applications and Services",
                "bi-cpu-fill",
                <ul className="mb-0">
                  <li>CI/CD pipelines</li>
                  <li>Kubernetes workloads</li>
                  <li>External services</li>
                </ul>,
              )}
            </div>

            <div ref={setNodeRef("hsm")} className="d-flex w-100">
              {card(
                "secondary",
                "HSM",
                "Hardware Security Module",
                "bi-safe-fill",
                <ul className="mb-0">
                  <li>Secure key custody</li>
                  <li>Cryptographic operations</li>
                  <li>PKCS#11 integration</li>
                </ul>,
              )}
            </div>
          </div>

          <div className="col-12 col-xl-9 d-flex flex-column justify-content-center gap-4 h-100">
            <div className="row g-4">
              <div
                className="col-12 col-md-6 d-flex"
                ref={setNodeRef("frontend")}
              >
                {card(
                  "warning",
                  "Frontend",
                  "Human Entry Point",
                  "bi-browser-chrome",
                  <ul className="mb-0">
                    <li>Web UI</li>
                    <li>Role-based views</li>
                    <li>Environment-scoped access</li>
                  </ul>,
                )}
              </div>

              <div
                className="col-12 col-md-6 d-flex"
                ref={setNodeRef("keycloak")}
              >
                {card(
                  "dark",
                  "Keycloak",
                  "Authentication and Authorization",
                  "bi-person-badge-fill",
                  <ul className="mb-0">
                    <li>OIDC/JWT identity provider</li>
                    <li>Role and client management</li>
                    <li>Token issuance and verification</li>
                  </ul>,
                )}
              </div>
            </div>

            <div className="row g-4">
              <div
                className="col-12 col-md-6 d-flex"
                ref={setNodeRef("backend")}
              >
                {card(
                  "primary",
                  "Backend",
                  "API and Business Logic",
                  "bi-hdd-rack-fill",
                  <ul className="mb-0">
                    <li>REST API</li>
                    <li>Authorization enforcement</li>
                    <li>Workflows and audit logs</li>
                  </ul>,
                )}
              </div>

              <div
                className="col-12 col-md-6 d-flex"
                ref={setNodeRef("database")}
              >
                {card(
                  "light",
                  "Database",
                  "Scalable Persistent Storage",
                  "bi-database-fill",
                  <ul className="mb-0">
                    <li>User and config data</li>
                    <li>Crypto resources and metadata</li>
                    <li>Access and audit logs</li>
                  </ul>,
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export const signerUsageExample = (signerName, apiRootUrl) => {
  return (
    <>
      <h4>Configure Issuer</h4>
      <p>
        KeyAuthority allows cert-manager to request certificates from
        KeyAuthority-managed signers and supports two types of cert-manager
        issuers:{" "}
        <a
          href="https://cert-manager.io/docs/configuration/acme/"
          target="_blank"
          rel="noopener noreferrer"
        >
          ACME{" "}
        </a>
        and{" "}
        <a
          href="https://cert-manager.io/docs/configuration/vault/"
          target="_blank"
          rel="noopener noreferrer"
        >
          Vault
        </a>{" "}
        . The former uses ACME protocol to obtain certificates via HTTP-01
        challenges and the latter uses the HashiCorp Vault API.
      </p>

      <h5>ACME Issuer</h5>

      {acmeIssuerExample(
        signerName,
        `${signerName}@keyauthority.net`,
        apiRootUrl,
      )}

      <h5>Vault Issuer</h5>

      <p>
        In the case of Vault issuers, the authentication methods supported are
        based on:
      </p>

      <p>
        <ul>
          {/* <li>Kubernetes token issued by a service account</li> */}
          <li>Kubernetes token issued by a cron job</li>
          <li>Credentials (client id and secret)</li>
        </ul>
      </p>

      {/* <h6>Kubernetes Authentication through Service Account Tokens</h6> */}

      {/* {vaultK8sSAAuthIssuerExample(signerName, apiRootUrl)} */}

      <h6>Kubernetes Authentication through CronJob Tokens</h6>

      {vaultK8sTokenAuthIssuerExample(signerName, apiRootUrl)}

      <h6>Authentication through Credentials</h6>

      {vaultAppRoleIssuerExample(
        signerName,
        `${signerName}@keyauthority.net`,
        apiRootUrl,
      )}

      <h4>Secure Application</h4>
      <p>
        Once your issuer is configured, you can use it to issue TLS certificates
        for your applications inside Kubernetes. This is typically done using an{" "}
        <code>Ingress</code> resource or by directly requesting a{" "}
        <code>Certificate</code> resource.
      </p>

      <h5>Option 1 (Recommended): Secure an Ingress</h5>
      <p>
        The recommended approach is to annotate your Ingress resources to
        automatically request and manage TLS certificates for your domains.
        Below is an example of an Ingress resource that secures the host{" "}
        <code>my-app.example.com</code>.
      </p>
      {prettyCode(
        "yaml",
        `# Ingress resource
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
  annotations:
    cert-manager.io/issuer: ${signerName} # or cert-manager.io/cluster-issuer: ${signerName}
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - my-app.example.com
      secretName: my-app-tls
  rules:
    - host: my-app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-app-service
                port:
                  number: 80`,
      )}

      <h5>Option 2: Request a Certificate</h5>

      <p>
        Alternatively, you can request a Certificate resource directly, as shown
        is an example below.
      </p>

      {prettyCode(
        "yaml",
        `# Certificate resource
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-app-cert
spec:
  secretName: my-app-tls
  issuerRef:
    name: ${signerName}
    kind: Issuer # or ClusterIssuer
  commonName: my-app.example.com
  dnsNames:
    - my-app.example.com
  duration: 2160h`,
      )}

      <p>
        Once the resource is applied, cert-manager will detect the need for a
        TLS cert for <code>my-app.example.com</code>, request it from your
        signer, and create a secret named <code>my-app-tls</code> containing the
        certificate and key, which can be mounted into your application
        deployments.
      </p>

      {disclaimer()}
    </>
  );
};

function vaultAppRoleIssuerExample(signerName, username, apiRootUrl) {
  return prettyCode(
    "yaml",
    `# Secret holding the AppRole secret ID (password)
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: ${signerName}-password
stringData:
  password: "..." # password for '${username}'
---
# Vault issuer using AppRole authentication
apiVersion: cert-manager.io/v1
kind: Issuer # or ClusterIssuer
metadata:
  name: ${signerName}
spec:
  vault:
    path: signers/${signerName}/sign
    server: "${apiRootUrl}"
    caBundle: "..." # optional, Base64-encoded CA cert of '${apiRootUrl}'
    auth:
      appRole:
        path: approle
        roleId: ${username} # or your actual username
        secretRef:
          name: ${signerName}-password
          key: password`,
  );
}

function vaultK8sSAAuthIssuerExample(signerName, apiRootUrl) {
  return prettyCode(
    "yaml",
    `# Role to allow creating tokens for the ServiceAccount
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${signerName}-role
rules:
  - apiGroups: ['']
    resources: ['serviceaccounts/token']
    resourceNames: ['${signerName}-sa']
    verbs: ['create']
---
# RoleBinding to bind the Role to cert-manager's ServiceAccount
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${signerName}-role-binding
subjects:
  - kind: ServiceAccount
    name: cert-manager
    namespace: cert-manager # or your cert-manager namespace
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${signerName}-role
---
# ServiceAccount for cert-manager to use
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${signerName}-sa
---
# Vault issuer using Kubernetes ServiceAccount authentication
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ${signerName}
spec:
  vault:
    path: signers/${signerName}/sign
    server: "${apiRootUrl}"
    caBundle: "..." # optional, Base64-encoded CA cert of '${apiRootUrl}'
    auth:
      kubernetes:
        role: ${signerName}-role
        mountPath: /v1/auth/jwt
        serviceAccountRef:
          name: ${signerName}-sa`,
  );
}

function vaultK8sTokenAuthIssuerExample(signerName, apiRootUrl) {
  return prettyCode(
    "yaml",
    `# Role to allow creating secrets
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${signerName}-role
rules:
  - apiGroups: ['']
    resources: ['serviceaccounts/token']
    resourceNames: ['${signerName}-sa']
    verbs: ['create']
  - apiGroups: ['']
    resources: ['secrets']
    verbs: ['create']
  - apiGroups: ['']
    resources: ['secrets']
    resourceNames: ['${signerName}-token']
    verbs: ['get', 'update', 'patch']
---
# RoleBinding to bind the Role to ServiceAccount
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${signerName}-role-binding
subjects:
  - kind: ServiceAccount
    name: ${signerName}-sa
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${signerName}-role
---
# ServiceAccount for the cronjob
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${signerName}-sa
---
# CronJob token rotator: creates single-audience token and stores in Secret
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ${signerName}-token-rotator
spec:
  schedule: "*/10 * * * *" # rotate every 10 minutes
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 1
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: ${signerName}-sa
          restartPolicy: OnFailure
          containers:
            - name: rotate
              image: alpine/kubectl:latest
              command: ["/bin/sh", "-ec"]
              args:
                - |
                  NS="$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)"
                  AUD="${apiRootUrl}"
                  TOKEN="$(kubectl -n "$NS" create token ${signerName}-sa --audience "$AUD" --duration=1h)"
                  kubectl -n "$NS" create secret generic ${signerName}-token --from-literal=token="$TOKEN" --dry-run=client -o yaml | kubectl -n "$NS" apply -f -
---
# Vault issuer using token authentication
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ${signerName}
spec:
  vault:
    path: signers/${signerName}/sign
    server: "${apiRootUrl}"
    caBundle: "..." # optional, Base64-encoded CA cert of '${apiRootUrl}'
    auth:
      kubernetes:
        role: ${signerName}-role
        mountPath: /v1/auth/jwt
        secretRef:
          name: ${signerName}-token
          key: token`,
  );
}

function acmeIssuerExample(signerName, email, apiRootUrl) {
  const isValidEmail = (email) => {
    if (!email || typeof email !== "string") return false;
    // Basic format check
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return false;
    // Additional checks
    if (email.length > 254) return false; // RFC limit
    if (email.includes("..")) return false; // No consecutive dots
    if (email.startsWith(".") || email.endsWith(".")) return false;
    return true;
  };

  const validEmail = isValidEmail(email) ? email : "issuer@example.com";

  return prettyCode(
    "yaml",
    `# ACME issuer
apiVersion: cert-manager.io/v1
kind: Issuer # or ClusterIssuer
metadata:
  name: ${signerName}
spec:
  acme:
    server: "${apiRootUrl}/v1/signers/${signerName}/acme/directory"
    email: ${validEmail} # or your actual email
    caBundle: "..." # optional, Base64-encoded CA cert of '${apiRootUrl}'
    privateKeySecretRef:
      name: ${signerName}-acme-key
    solvers:
      - http01:
          ingress:
            class: nginx`,
  );
}

function isValidEnvVarName(name) {
  // Must start with letter or underscore, followed by letters, numbers, or underscores
  return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name);
}

function gitlabUsageYaml(secret, data, apiRootUrl) {
  const secretsYaml = Object.keys(data)
    .filter((k) => isValidEnvVarName(k))
    .map((k) => {
      return `    ${k}: \n      vault: ${secret}/${k}@secrets\n      file: false`;
    })
    .join("\n");
  return `# project: my-group/my-project
# branch: my-branch
job:
  variables:
    VAULT_SERVER_URL: ${apiRootUrl}
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://gitlab.com
  secrets:
${secretsYaml}
  script: |
    ./run.sh`;
}

function k8sUsageYaml(secret, data) {
  const template = Object.keys(data)
    .filter((k) => isValidEnvVarName(k))
    .map((k) => {
      return `      export ${k}='{{ .Data.data.${k} }}'`;
    })
    .join("\n");

  return `apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: my-namespace
  annotations:
    vault.hashicorp.com/role: keyauthority
    vault.hashicorp.com/agent-inject: 'true'
    vault.hashicorp.com/agent-inject-secret-env: ${secret}
    vault.hashicorp.com/agent-inject-template-env: |
      {{ with secret "${secret}" }}
${template}
      {{ end }}
spec:
  serviceAccountName: my-serviceaccount
  containers:
  - name: my-app
    image: my-app:0.1.0
    command:
      - sh
      - -c
      - source /vault/secrets/env && ./run.sh`;
}

function k8sVaultInjectorValuesYaml(apiRootUrl) {
  return `global:
  externalVaultAddr: ${apiRootUrl}
server:
  enabled: false
csi:
  enabled: false
injector:
  enabled: true
  extraEnvironmentVars:
    AGENT_INJECT_VAULT_CACERT_BYTES: "..." # optional, PEM-encoded CA cert of '${apiRootUrl}'
  namespaceSelector:
    matchExpressions: 
      - key: kubernetes.io/metadata.name
        operator: In
        values:
          - my-namespace`;
}

function shellUsage(secret, apiRootUrl) {
  return `source <(
  curl -s -H "Authorization: Bearer $JWT" \\
    "${apiRootUrl}/v1/secrets/${secret}?output=shell"
) && ./run.sh`;
}

export const secretUsageExamples = (secret, data, apiRootUrl) => {
  return (
    <>
      <h4>Shell</h4>
      <p>
        Use the following command to fetch and source the secret directly into
        your shell environment using a JWT token for authentication. The secrets
        will be exported as environment variables.
      </p>
      {prettyCode("bash", shellUsage(secret, apiRootUrl))}
      <h4>GitLab Runners</h4>
      <p>
        The following example shows how to consume the secret in a GitLab job,
        using{" "}
        <a
          href="https://docs.gitlab.com/ci/secrets/hashicorp_vault/"
          target="_blank"
          rel="noopener noreferrer"
        >
          GitLab CI's Vault integration
        </a>
        . Each key will be exposed as an environment variable in your pipeline.
      </p>

      {prettyCode("yaml", gitlabUsageYaml(secret, data, apiRootUrl))}

      <p>
        A user must exist in Keycloak with the permissions to access the secret,
        and the user must have an <strong>Identity provider link</strong>{" "}
        configured with GitLab as the provider and User ID set to{" "}
        <code>
          project_path:my-group/my-project:ref_type:branch:ref:my-branch
        </code>
        . This allows Keycloak to associate the Gitlab-issued token with an
        existing user, enabling secure access to the secrets based on the GitLab
        project and branch context. Check the{" "}
        <Link to="/docs/admin">administration docs</Link> for more details on
        how to set this up.
      </p>

      <h4>Kubernetes Pods</h4>
      <p>
        To inject KeyAuthority secrets into Kubernetes pods, you can use the{" "}
        <a
          href="https://developer.hashicorp.com/vault/docs/deploy/kubernetes/injector"
          target="_blank"
          rel="noopener noreferrer"
        >
          Vault Agent Injector
        </a>
        , which can be installed using the following{" "}
        <a href="https://helm.sh" target="_blank" rel="noopener noreferrer">
          Helm
        </a>{" "}
        commands:
      </p>

      {prettyCode(
        "bash",
        `# add the Hashicorp Helm repository
helm repo add hashicorp https://helm.releases.hashicorp.com
# install/upgrade the Vault Injector
helm upgrade --install injector hashicorp/vault -f values.yaml`,
      )}

      <p>
        where <code>values.yaml</code> contains:
      </p>

      {prettyCode("yaml", k8sVaultInjectorValuesYaml(apiRootUrl))}

      <p>
        Secrets can now be injected into your pods using annotations as shown
        below. The secret will be written to a shell-compatible file that can be
        sourced before launching your application.
      </p>

      {prettyCode("yaml", k8sUsageYaml(secret, data))}

      <p>
        Similar to GitLab, it is required that a user exists in Keycloak with
        the permissions to access the secret, and that the user has an{" "}
        <strong>Identity provider link</strong> configured with Kubernetes as
        the provider and User ID set to{" "}
        <code>system:serviceaccount:my-namespace:my-serviceaccount</code>.
      </p>

      {disclaimer()}
    </>
  );
};
