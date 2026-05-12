import { useState, useEffect } from "react";
import { Button, Form, Modal, Spinner, Row, Col } from "react-bootstrap";
import {
  showToast,
  decryptData,
  copyToClipboard,
  prettyCode,
  showImportResultToast,
} from "../utils/utils";
import { getApi } from "../axios";
import { errorToString } from "../utils/error";

export default function ImportHashiVaultSecretsModal({
  show,
  onHide,
  onSuccess,
}) {
  const [vaultAddr, setVaultAddr] = useState("");
  const [vaultToken, setVaultToken] = useState("");
  const [environmentPrefix, setEnvironmentPrefix] = useState("hv-");
  const [isImporting, setIsImporting] = useState(false);
  const [onSecretExist, setOnSecretExist] = useState("skip");

  const api = getApi();

  useEffect(() => {
    if (!show) {
      setVaultAddr("");
      setVaultToken("");
      setEnvironmentPrefix("hv-");
      setOnSecretExist("skip");
    }
  }, [show]);

  const fetchSecretsRecursively = async (mount, path) => {
    const secrets = [];
    try {
      const res = await fetch(vaultAddr + "/v1/" + mount + "metadata/" + path, {
        method: "LIST",
        headers: {
          "Content-Type": "application/json",
          "X-Vault-Token": vaultToken,
        },
      }).then((res) => res.json());

      if (res.data && res.data.keys) {
        for (const key of res.data.keys) {
          if (key.endsWith("/")) {
            try {
              // If it's a folder, recursively fetch secrets
              const nestedSecrets = await fetchSecretsRecursively(
                mount,
                path + key,
              );
              secrets.push(...nestedSecrets);
            } catch (error) {
              // ignore
            }
          } else {
            // Fetch the secret value
            const secretRes = await fetch(
              vaultAddr + "/v1/" + mount + "data/" + path + key,
              {
                method: "GET",
                headers: {
                  "Content-Type": "application/json",
                  "X-Vault-Token": vaultToken,
                },
              },
            )
              .then((res) => {
                return res.json();
              })
              .catch((error) => {
                // ignore
              });

            if (secretRes.data) {
              secrets.push({
                mount,
                path: path + key,
                data: secretRes.data.data,
              });
            }
          }
        }
      }
    } catch (error) {
      throw error;
    }
    return secrets;
  };

  const handleImport = async () => {
    setIsImporting(true);

    try {
      const res = await fetch(vaultAddr + "/v1/sys/mounts", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "X-Vault-Token": vaultToken,
        },
      }).then((res) => res.json());

      // filter KV2 mounts
      const kvMounts = {};
      for (const key in res.data) {
        const mount = res.data[key];
        if (
          mount.type === "kv" &&
          mount.options &&
          mount.options.version === "2"
        )
          kvMounts[key] = mount;
      }

      // process each KV mount and fetch secrets
      const vaultSecrets = [];
      const importedSecrets = new Set();
      const skippedSecrets = new Set();
      const failedSecrets = new Set();
      const missingSecrets = [];

      for (const mount in kvMounts) {
        const secrets = await fetchSecretsRecursively(mount, "");
        vaultSecrets.push(...secrets);
      }

      // Patch or update existing secrets
      for (const secret of vaultSecrets) {
        const secretName = secret.mount + secret.path;
        try {
          await api.get(`/secrets/${secretName}`);
          try {
            switch (onSecretExist) {
              case "patch":
                await api.patch(`/secrets/${secretName}`, secret.data);
                importedSecrets.add(secretName);
                break;
              case "overwrite":
                await api.post(`/secrets/${secretName}`, secret.data);
                importedSecrets.add(secretName);
                break;
              case "overwrite":
                await api.post(`/secrets/${secretName}`, secret.data);
                importedSecrets.add(secretName);
                break;
              default:
                skippedSecrets.add(secretName);
                break;
            }
          } catch (err) {
            failedSecrets.add(secretName);
          }
        } catch (err) {
          missingSecrets.push(secret);
        }
      }

      // Prepare keys and insert missing secrets
      const envToKey = {};
      for (const secret of missingSecrets) {
        const secretName = secret.mount + secret.path;
        const environment = environmentPrefix + secret.mount.replace(/\/$/, "");
        if (!envToKey[environment]) {
          // if not found, create a key in the env
          try {
            const res = await api.post(
              `/keys?environment=${encodeURIComponent(environment)}`,
              {
                type: "AES",
                mode: "GCM",
                bits: 256,
              },
            );
            envToKey[environment] = res.data;
          } catch (error) {
            // ignore
          }
        }

        if (!envToKey[environment]) {
          failedSecrets.add(secretName);
          continue;
        }

        // encrypt the secret value with the environment key
        try {
          const encryptionKeyID = envToKey[environment];
          await api.put(
            `/secrets/${encodeURIComponent(secretName)}?encryptionKeyID=${encryptionKeyID}`,
            secret.data,
          );
          importedSecrets.add(secretName);
        } catch (error) {
          failedSecrets.add(secretName);
        }
      }

      onHide();
      if (onSuccess) {
        onSuccess(importedSecrets, skippedSecrets, failedSecrets);
      }
    } catch (error) {
      showToast("error", errorToString(error));
    } finally {
      setIsImporting(false);
    }
  };

  return (
    <Modal show={show} onHide={onHide} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>Import: Secrets</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Form.Group className="mb-3">
          <Form.Label>Vault Address</Form.Label>
          <Form.Control
            type="text"
            placeholder="e.g. https://vault.example.com"
            value={vaultAddr}
            onChange={(e) => setVaultAddr(e.target.value)}
          />
          <Form.Text className="text-muted">
            Make sure to include the protocol (<code>http://</code> or{" "}
            <code>https://</code>) and port if needed. Also, ensure that CORS is
            configured on your Vault server, which can be done with a command
            like:{" "}
            <code>
              vault write sys/config/cors enabled=true
              allowed_origins="https://staging.keyauthority.com"
              allowed_headers="Content-Type,Authorization,X-Vault-Token"
              allowed_methods="GET,POST,PUT,DELETE,LIST,OPTIONS,PATCH"
            </code>
          </Form.Text>
        </Form.Group>
        <Form.Group className="mb-3">
          <Form.Label>Vault Token</Form.Label>
          <Form.Control
            type="password"
            placeholder="e.g. hvs.xxxxxxxx"
            value={vaultToken}
            onChange={(e) => setVaultToken(e.target.value)}
          />
          <Form.Text className="text-muted">
            The token must have permissions to list mounts and read secrets
          </Form.Text>
        </Form.Group>
        <Form.Group className="mb-3">
          <Form.Label>Environment Prefix</Form.Label>
          <Form.Control
            type="text"
            placeholder="Enter prefix for environments"
            value={environmentPrefix}
            onChange={(e) => setEnvironmentPrefix(e.target.value)}
          />
          <Form.Text className="text-muted">
            This value will be prepended to engine mount to compose the
            environment for the newly-imported secrets. This does not affect
            existing secrets. For example, if the prefix is <code>hv-</code> and
            you have a secret with path <code>myapp/creds</code> in the KV2
            secret mount <code>dev</code>, it will be imported with the name{" "}
            <code>myapp/creds</code> and the environment <code>hv-dev</code>.
          </Form.Text>
        </Form.Group>
        <Form.Group className="mb-3">
          <Form.Label>On Secret Exist</Form.Label>
          <Form.Select
            value={onSecretExist}
            onChange={(e) => setOnSecretExist(e.target.value)}
          >
            <option value="skip">Skip (keep existing secret unchanged)</option>
            <option value="patch">
              Patch (merge new data with existing secret)
            </option>
            <option value="overwrite">
              Overwrite (replace existing secret with new data)
            </option>
          </Form.Select>
        </Form.Group>
      </Modal.Body>

      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Close
        </Button>
        <Button
          variant="primary"
          disabled={!vaultAddr || !vaultToken || isImporting}
          onClick={handleImport}
        >
          {isImporting ? (
            <>
              <Spinner
                animation="border"
                size="sm"
                className="text-light me-2"
              />
              Importing...
            </>
          ) : (
            "Import"
          )}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
