import { useState, useEffect } from "react";
import { Button, Form, Modal, Spinner, Row, Col, Table } from "react-bootstrap";
import {
  showToast,
  decryptData,
  copyToClipboard,
  prettyCode,
  showImportResultToast,
  withTooltipDescription,
} from "../utils/utils";
import { getApi } from "../axios";
import { errorToString } from "../utils/error";

export default function ImportSecretsModal({ show, onHide, onSuccess }) {
  const [vaultAddr, setVaultAddr] = useState("");
  const [vaultToken, setVaultToken] = useState("");
  const [vaultSecrets, setVaultSecrets] = useState([]);
  const [isLoading, setIsLoading] = useState(false);

  const api = getApi();

  useEffect(() => {
    if (!show) {
      setVaultAddr("");
      setVaultToken("");
      setVaultSecrets([]);
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
                // defaults for target secret - can be customized by user in the UI
                name: path + key,
                environment: mount.replace(/\/$/, ""),
                import: true,
                onSecretExist: "skip",
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

  const handleDiscoverSecrets = async () => {
    setIsLoading(true);
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

      const vs = [];
      for (const mount in kvMounts) {
        const secrets = await fetchSecretsRecursively(mount, "");
        vs.push(...secrets);
      }

      if (vs.length === 0) {
        showToast("info", "No secrets found in the specified Vault.");
      } else {
        setVaultSecrets(vs);
      }
    } catch (error) {
      showToast("error", errorToString(error));
    } finally {
      setIsLoading(false);
    }
  };

  const handleImport = async () => {
    setIsLoading(true);

    try {
      // process each KV mount and fetch secrets
      const importedSecrets = new Set();
      const skippedSecrets = new Set();
      const failedSecrets = new Set();
      const missingSecrets = [];

      // Patch or update existing secrets
      for (const secret of vaultSecrets) {
        if (secret.import === false) continue; // skip if user unchecked import
        const secretName = secret.name;
        try {
          await api.get(`/secrets/${secretName}`);
          try {
            switch (secret.onSecretExist) {
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
        if (secret.import === false) continue; // skip if user unchecked import
        const secretName = secret.name;
        const environment = secret.environment;
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
      setIsLoading(false);
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

        {vaultSecrets.length === 0 ? (
          <Button
            variant="primary"
            onClick={handleDiscoverSecrets}
            disabled={
              !vaultAddr || !vaultToken || isLoading || vaultSecrets.length > 0
            }
            className="mb-3"
          >
            {isLoading ? (
              <>
                <Spinner
                  animation="border"
                  size="sm"
                  className="text-light me-2"
                />
                Finding...
              </>
            ) : (
              "Find Secrets To Import"
            )}
          </Button>
        ) : (
          <Table hover responsive striped className="align-middle mb-3">
            <thead>
              <tr>
                <th>Import</th>
                <th>Source Secret</th>
                <th>Target Name</th>
                <th>Target Environment</th>
                <th>
                  {withTooltipDescription(
                    "On Secret Exist",
                    "Action to take if the secret already exists. Options are: Skip (Leave unchanged), Patch (Merge new data with existing secret), Overwrite (Replace existing secret with new data).",
                  )}
                </th>
              </tr>
            </thead>
            <tbody>
              {vaultSecrets.map((secret, index) => (
                <tr key={index}>
                  <td>
                    <Form.Check
                      type="checkbox"
                      checked={vaultSecrets[index].import}
                      onChange={(e) => {
                        const newSecrets = [...vaultSecrets];
                        newSecrets[index].import = e.target.checked;
                        setVaultSecrets(newSecrets);
                      }}
                    />
                  </td>
                  <td>{secret.mount + secret.path}</td>
                  <td>
                    <Form.Control
                      type="text"
                      value={vaultSecrets[index].name}
                      onChange={(e) => {
                        // allow only contains alphanumeric, dash, underscore, and slash
                        const regex = /^[a-zA-Z0-9-_\/]*$/;
                        if (!regex.test(e.target.value)) return;

                        const newSecrets = [...vaultSecrets];
                        newSecrets[index].name = e.target.value;
                        setVaultSecrets(newSecrets);
                      }}
                    />
                  </td>
                  <td>
                    <Form.Control
                      type="text"
                      value={vaultSecrets[index].environment}
                      onChange={(e) => {
                        // allow only letters, numbers, dashes and underscores
                        const regex = /^[a-zA-Z0-9-_]*$/;
                        if (!regex.test(e.target.value)) return;

                        const newSecrets = [...vaultSecrets];
                        newSecrets[index].environment = e.target.value;
                        setVaultSecrets(newSecrets);
                      }}
                    />
                  </td>
                  <td>
                    <Form.Select
                      value={vaultSecrets[index].onSecretExist}
                      onChange={(e) => {
                        const newSecrets = [...vaultSecrets];
                        newSecrets[index].onSecretExist = e.target.value;
                        setVaultSecrets(newSecrets);
                      }}
                    >
                      <option value="skip">Skip</option>
                      <option value="patch">Patch</option>
                      <option value="overwrite">Overwrite</option>
                    </Form.Select>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Modal.Body>

      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Close
        </Button>
        {vaultSecrets.length > 0 && (
          <Button
            variant="primary"
            disabled={!vaultAddr || !vaultToken || isLoading}
            onClick={handleImport}
          >
            {isLoading ? (
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
        )}
      </Modal.Footer>
    </Modal>
  );
}
