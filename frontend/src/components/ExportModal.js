import { useState, useEffect } from "react";
import { Button, Form, Modal, Spinner } from "react-bootstrap";
import { copyToClipboard, showToast } from "../utils/utils";
import { errorToString } from "../utils/error";
import { generateSecret } from "./SecretModal";

const encryptData = async (data, password) => {
  // AES GCM encryption
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);
  const encodedPassword = encoder.encode(password);

  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM
  const salt = window.crypto.getRandomValues(new Uint8Array(16)); // Random salt for PBKDF2

  // Use PBKDF2 to derive a 32-byte key from the password
  const pwd = await window.crypto.subtle.importKey(
    "raw",
    encodedPassword,
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    pwd,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  // Actual encryption with AES-GCM
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encodedData,
  );

  // Combine IV, salt, and encrypted data for storage (IV and salt are needed for decryption)
  const combined = new Uint8Array(
    iv.byteLength + salt.byteLength + encrypted.byteLength,
  );
  combined.set(iv, 0);
  combined.set(salt, iv.byteLength);
  combined.set(new Uint8Array(encrypted), iv.byteLength + salt.byteLength);
  return btoa(String.fromCharCode(...combined));
};

export default function ExportModal({ show, onHide, modalTitle, modalData }) {
  const [password, setPassword] = useState("");
  const [isEncrypting, setIsEncrypting] = useState(false);

  useEffect(() => {
    if (!show) {
      setPassword("");
    }
  }, [show]);

  return (
    <Modal show={show} onHide={onHide}>
      <Modal.Header closeButton>
        <Modal.Title className="text-truncate">{`Export: ${modalTitle}`}</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Form.Group className="mb-3">
          <Form.Label>Password</Form.Label>
          <div className="input-group">
            <Form.Control
              type="password"
              placeholder="Enter password to encrypt the exported data"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <Button
              variant="outline-secondary"
              onClick={() => {
                const samplePassword = generateSecret();
                setPassword(samplePassword);
                copyToClipboard(
                  samplePassword,
                  "Password generated and copied!",
                );
              }}
            >
              <i className="bi bi-arrow-repeat"></i>
            </Button>
          </div>
          <Form.Text className="text-muted">
            Must contain at least 8 characters
          </Form.Text>
        </Form.Group>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Close
        </Button>
        <Button
          variant="primary"
          disabled={!password || isEncrypting || password.length < 8}
          onClick={async () => {
            setIsEncrypting(true);
            try {
              const encryptedData = await encryptData(modalData, password);
              const blob = new Blob([encryptedData], { type: "text/plain" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = `${modalTitle.replace(/\s+/g, "_").toLowerCase()}.enc`;
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              URL.revokeObjectURL(url);
              setIsEncrypting(false);
              showToast("success", "Data exported!");
              onHide();
            } catch (error) {
              showToast("error", errorToString(error));
            } finally {
              setIsEncrypting(false);
            }
          }}
        >
          {isEncrypting ? (
            <>
              <Spinner
                animation="border"
                size="sm"
                className="text-light me-2"
              />
              Exporting...
            </>
          ) : (
            "Export"
          )}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
