import { useState, useEffect } from "react";
import { Button, Form, Modal, Spinner, Row, Col } from "react-bootstrap";
import { showToast, decryptData } from "../utils/utils";
import { errorToString } from "../utils/error";
import { getApi } from "../axios";

export const getOrCreateKey = async (api, keyID, environment, keys) => {
  let newKeyID;

  // If a key with the same ID and environment exists, then use it
  try {
    const res = await api.get(`/keys/${keyID}`);
    if (res.data.environment === environment) {
      newKeyID = keyID;
    }
  } catch (err) {
    // ignore
  }

  // If a key with the same environment and config exists, then reuse it with a new ID
  if (!newKeyID) {
    try {
      const exportedKey = keys.find((k) => k.id === keyID);
      const res = await api.get(
        `/keys?environment=${encodeURIComponent(environment)}&type=${encodeURIComponent(exportedKey.type)}&pageSize=10000`,
      );
      const existingKeys = res.data;
      for (const existingKey of existingKeys) {
        if (
          existingKey.environment === environment &&
          JSON.stringify(existingKey.config) ===
            JSON.stringify(exportedKey.config)
        ) {
          newKeyID = existingKey.id;
          break;
        }
      }
    } catch (err) {
      // ignore
    }
  }

  // If no compatible key exists, then create it
  if (!newKeyID) {
    try {
      const exportedKey = keys.find((k) => k.id === keyID);
      if (!exportedKey) {
        throw new Error(
          "Missing encryption key for secret with keyID: " + keyID,
        );
      }
      const res = await api.post(
        `/keys?environment=${encodeURIComponent(environment)}`,
        exportedKey.config,
      );
      newKeyID = res.data;
    } catch (err) {
      throw err;
    }
  }

  return newKeyID;
};

export default function ImportSecretsModal({ show, onHide, onSuccess }) {
  const [isImporting, setIsImporting] = useState(false);
  const [password, setPassword] = useState("");
  const [file, setFile] = useState(null);
  const [environmentPrefix, setEnvironmentPrefix] = useState("");
  const [onSecretExist, setOnSecretExist] = useState("skip");

  const api = getApi();

  useEffect(() => {
    if (!show) {
      setPassword("");
      setFile(null);
      setEnvironmentPrefix("");
      setOnSecretExist("skip");
    }
  }, [show]);

  const handleImport = async () => {
    setIsImporting(true);

    try {
      const fileContent = await file.text();
      const data = await decryptData(fileContent, password);

      const { secrets, keys } = JSON.parse(data);
      const skippedSecrets = new Set();
      const importedSecrets = new Set();
      const failedSecrets = new Set();
      const missingSecrets = [];

      // Patch or update existing secrets
      for (const secret of secrets) {
        try {
          await api.get(`/secrets/${secret.name}`);
          try {
            switch (onSecretExist) {
              case "patch":
                await api.patch(`/secrets/${secret.name}`, secret.data);
                importedSecrets.add(secret.name);
                break;
              case "overwrite":
                await api.post(`/secrets/${secret.name}`, secret.data);
                importedSecrets.add(secret.name);
                break;
              default:
                skippedSecrets.add(secret.name);
                break;
            }
          } catch (err) {
            failedSecrets.add(secret.name);
          }
        } catch (err) {
          missingSecrets.push(secret);
        }
      }

      // Prepare keys and insert missing secrets
      for (const secret of missingSecrets) {
        try {
          const newKeyID = await getOrCreateKey(
            api,
            secret.encryptionKeyID,
            environmentPrefix + secret.environment,
            keys,
          );

          // Create the secret
          await api.put(
            `/secrets/${secret.name}?encryptionKeyID=${newKeyID}`,
            secret.data,
          );
          importedSecrets.add(secret.name);
        } catch (err) {
          failedSecrets.add(secret.name);
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
    <Modal show={show} onHide={onHide}>
      <Modal.Header closeButton>
        <Modal.Title>Import: Secrets</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Form.Group className="mb-3">
          <Form.Label>Encrypted File</Form.Label>
          <Form.Control
            type="file"
            accept="*/*"
            onChange={(e) => {
              setFile(e.target.files[0]);
            }}
          />
        </Form.Group>
        <Form.Group className="mb-3">
          <Form.Label>Password</Form.Label>
          <Form.Control
            type="password"
            placeholder="Enter password to decrypt the imported data"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Form.Group>
        <Form.Group className="mb-3">
          <Form.Label>Environment Prefix</Form.Label>
          <Form.Control
            type="text"
            placeholder="Add a prefix to the environment of all imported secrets (e.g. 'prod-')"
            value={environmentPrefix}
            onChange={(e) => setEnvironmentPrefix(e.target.value)}
          />
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
          disabled={!password || !file || isImporting}
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
