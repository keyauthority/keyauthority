import { useState, useEffect } from "react";
import { Button, Form, Modal, Spinner, Row, Col, Alert } from "react-bootstrap";
import { getApi } from "../axios";
import { showToast, decryptData } from "../utils/utils";
import { errorToString } from "../utils/error";
import { getOrCreateKey } from "./ImportSecretsModal";

export default function ImportSignersModal({
  show,
  onHide,
  modalTitle,
  onSuccess,
}) {
  const [isImporting, setIsImporting] = useState(false);
  const [password, setPassword] = useState("");
  const [file, setFile] = useState(null);
  const [environmentPrefix, setEnvironmentPrefix] = useState("");
  const [onSignerExist, setOnSignerExist] = useState("skip");

  const api = getApi();

  useEffect(() => {
    if (!show) {
      setPassword("");
      setFile(null);
      setEnvironmentPrefix("");
      setOnSignerExist("skip");
    }
  }, [show]);

  const handleImport = async () => {
    setIsImporting(true);

    try {
      const fileContent = await file.text();
      const data = await decryptData(fileContent, password);

      const { signers, keys } = JSON.parse(data);
      const skippedSigners = new Set();
      const importedSigners = new Set();
      const failedSigners = new Set();
      const missingSigners = [];

      // Update existing signers
      for (const signer of signers) {
        try {
          await api.get(`/signers/${signer.name}/private-key`);
          try {
            switch (onSignerExist) {
              case "update":
                await api.put(`/signers/${signer.name}/config`, signer.config);
                // try to set the CA chain, but ignore errors
                if (signer.caChain) {
                  try {
                    await api.put(
                      `/signers/${signer.name}/ca-chain`,
                      signer.caChain,
                    );
                  } catch (err) {
                    // ignore
                  }
                }
                importedSigners.add(signer.name);
                break;
              default:
                skippedSigners.add(signer.name);
                break;
            }
          } catch (err) {
            failedSigners.add(signer.name);
          }
        } catch (err) {
          missingSigners.push(signer);
        }
      }

      // Prepare keys and create missing signers
      for (const signer of missingSigners) {
        try {
          const newKeyID = await getOrCreateKey(
            api,
            signer.privateKeyID,
            environmentPrefix + signer.environment,
            keys,
          );

          // Create the signer
          await api.post(
            `/signers/${signer.name}?privateKeyID=${newKeyID}`,
            signer.config,
          );

          // try to set the CA chain, but ignore errors as it's not critical and can be updated later if needed
          if (signer.caChain) {
            try {
              await api.put(`/signers/${signer.name}/ca-chain`, signer.caChain);
            } catch (err) {
              // ignore
            }
          }
          importedSigners.add(signer.name);
        } catch (err) {
          failedSigners.add(signer.name);
        }
      }

      onHide();
      if (onSuccess) {
        onSuccess(importedSigners, skippedSigners, failedSigners);
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
        <Modal.Title>Import: Signers</Modal.Title>
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
            placeholder="Optionally specify a prefix to add to the imported signers' environments (e.g. 'prod-')"
            value={environmentPrefix}
            onChange={(e) => setEnvironmentPrefix(e.target.value)}
          />
        </Form.Group>
        <Form.Group className="mb-3">
          <Form.Label>On Signer Exist</Form.Label>
          <Form.Select
            value={onSignerExist}
            onChange={(e) => setOnSignerExist(e.target.value)}
          >
            <option value="skip">Skip (keep existing signer unchanged)</option>
            <option value="update">
              Update (replace existing signer's configuration, not its private
              key)
            </option>
          </Form.Select>
        </Form.Group>
        <Alert variant="warning" className="small">
          Some imported signers might have their CA chains missing after the
          import, unless their private keys were in the system before the import
          (e.g. some HSM keys). You will need to re-create the CA chains of such
          signers.
        </Alert>
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
