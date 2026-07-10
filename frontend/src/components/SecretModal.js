import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { Button, Modal, Form, Col, Card, Spinner } from "react-bootstrap";
import { prettyTime, showToast } from "../utils/utils";
import { errorToString } from "../utils/error";
import { getApi } from "../axios";
import KeyInput from "./KeyInput";

export const generateSecret = () => {
  const array = new Uint8Array(32); // 256-bit secret
  window.crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
};

export default function SecretModal({
  show,
  onHide,
  onSuccess = null,
  editMode = false,
}) {
  const location = useLocation();
  const secretFromPath =
    decodeURIComponent(location.pathname.replaceAll("/secrets/", "")) || "";

  const [isLoading, setIsLoading] = useState(false);

  const [secretName, setSecretName] = useState("");
  const [environment, setEnvironment] = useState(""); // controlled by key input when creating new secret
  const [isFetchingData, setIsFetchingData] = useState(false);
  const [dataEntries, setDataEntries] = useState([{ key: "", value: "" }]);

  const [isFetchingKeys, setIsFetchingKeys] = useState(false);
  const [keys, setKeys] = useState([]);
  const [keyID, setKeyID] = useState("new");

  // new key
  const [keyType, setKeyType] = useState("AES");
  const [bits, setBits] = useState(256);
  const [mode, setMode] = useState("GCM");
  const [pkcs11URI, setPkcs11URI] = useState("");

  const api = getApi();
  const [visibleSecrets, setVisibleSecrets] = useState(new Set()); // Track which secrets are visible

  useEffect(() => {
    if (show && editMode) {
      setSecretName(secretFromPath);
    }
  }, [show, editMode, secretFromPath]);

  const fetchDataEntries = async (secretName) => {
    setIsFetchingData(true);
    try {
      const res = await api.get(`/secrets/${secretName}`);
      const secretData = res.data.data || {};
      setKeyID(res.data.encryptionKeyID || "");
      setDataEntries(
        secretData
          ? Object.entries(secretData).map(([key, value]) => ({
              key,
              value,
            }))
          : [{ key: "", value: "" }],
      );
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsFetchingData(false);
    }
  };

  useEffect(() => {
    if (show && editMode) {
      fetchDataEntries(secretFromPath);
    }
  }, [show, editMode, secretFromPath]);

  const fetchKeys = async () => {
    setIsFetchingKeys(true);
    try {
      const res = await api.get("/keys?type=AES&pageSize=10000");
      const aesKeys = res.data.data || [];
      setKeys(aesKeys);
      setKeyID(aesKeys.length > 0 ? aesKeys[0].id : "new");
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsFetchingKeys(false);
    }
  };

  useEffect(() => {
    if (show && !editMode) {
      fetchKeys();
    }
  }, [show, editMode]);

  useEffect(() => {
    if (!show) {
      // reset everything on hide modal
      setSecretName("");
      setEnvironment("");
      setDataEntries([{ key: "", value: "" }]);
      setKeyID("");

      setKeyType("AES");
      setBits(256);
      setMode("GCM");
      setPkcs11URI("");

      setVisibleSecrets(new Set());
    }
  }, [show]);

  const handleUpsertSecret = async () => {
    setIsLoading(true);
    // validate/parse data input
    const data = {};
    for (const entry of dataEntries) {
      if (entry.key) data[entry.key] = entry.value;
    }

    let encryptionKeyID = keyID;

    // create new keyID if needed
    if (keyID === "new") {
      try {
        let cfg = { pkcs11URI };
        switch (keyType) {
          case "AES":
            cfg.type = "AES";
            cfg.bits = bits;
            cfg.mode = mode;
            break;
          default:
            throw new Error("Invalid key type");
        }

        const response = await api.post(
          `/keys?environment=${environment}`,
          cfg,
        );
        encryptionKeyID = response.data;
        showToast("success", "New key created!");
      } catch (err) {
        encryptionKeyID = null; // so that upsert secret won't be attempted
        showToast("error", errorToString(err));
        onHide();
      } finally {
        setIsLoading(false);
      }
    }
    if (encryptionKeyID === null) {
      return;
    }

    // upsert secret
    try {
      if (!editMode) {
        await api.put(
          `/secrets/${secretName}?encryptionKeyID=${encryptionKeyID}`,
          data,
        );
        showToast("success", "Secret inserted!");
      } else {
        await api.post(`/secrets/${secretName}`, data);
        showToast("success", "Secret updated!");
      }

      if (onSuccess) {
        onSuccess(secretName);
      }
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
      onHide();
    }
  };

  return (
    <Modal show={show} onHide={onHide} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>
          {editMode ? "Edit Secret: " + secretName : "New Secret"}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <>
          {!editMode && (
            <Form.Group className="col mb-3">
              <Form.Label>Name</Form.Label>
              <Form.Control
                type="text"
                placeholder="e.g. db-credentials"
                value={secretName}
                onChange={(e) => {
                  // check that only contains alphanumeric, dash, underscore, and slash
                  const regex = /^[a-zA-Z0-9-_\/]*$/;
                  if (regex.test(e.target.value)) {
                    setSecretName(e.target.value);
                  }
                }}
              />
            </Form.Group>
          )}

          <Card className="mb-3">
            <Card.Header>
              <h6 className="mb-0">
                Data{" "}
                {isFetchingData && (
                  <Spinner
                    animation="border"
                    size="sm"
                    className="text-primary ms-1"
                  />
                )}
              </h6>
              <div className="text-muted small">
                Key-value pairs to store in the secret
              </div>
            </Card.Header>
            <Card.Body>
              <Form.Group className="mb-3 row g-3">
                {dataEntries.map((entry, idx) => (
                  <Col
                    md={12}
                    key={idx}
                    className="d-flex align-items-start gap-3"
                  >
                    <Form.Control
                      placeholder="Key"
                      value={entry.key}
                      onChange={(e) => {
                        const newEntries = [...dataEntries];
                        newEntries[idx].key = e.target.value;
                        setDataEntries(newEntries);
                      }}
                    />
                    <Form.Control
                      as="textarea"
                      rows={3}
                      placeholder="Value"
                      value={entry.value}
                      onChange={(e) => {
                        const newEntries = [...dataEntries];
                        newEntries[idx].value = e.target.value;
                        setDataEntries(newEntries);
                      }}
                      style={
                        !visibleSecrets.has(idx)
                          ? { WebkitTextSecurity: "disc" }
                          : {}
                      }
                    />
                    <div className="d-flex align-items-center gap-1">
                      <Button
                        variant="outline-secondary"
                        size="sm"
                        onClick={() => {
                          const newVisibleSecrets = new Set(visibleSecrets);
                          if (visibleSecrets.has(idx)) {
                            newVisibleSecrets.delete(idx);
                          } else {
                            newVisibleSecrets.add(idx);
                          }
                          setVisibleSecrets(newVisibleSecrets);
                        }}
                        disabled={!entry.value}
                        title="Show/Hide value"
                      >
                        {visibleSecrets.has(idx) ? (
                          <i className="bi bi-eye-slash"></i>
                        ) : (
                          <i className="bi bi-eye"></i>
                        )}
                      </Button>
                      <Button
                        variant="outline-secondary"
                        size="sm"
                        onClick={() => {
                          const newEntries = [...dataEntries];
                          newEntries[idx].value = generateSecret();
                          setDataEntries(newEntries);
                          setVisibleSecrets(new Set([...visibleSecrets, idx]));
                        }}
                        //disabled={!entry.key}
                        title="Generate value"
                      >
                        <i className="bi bi-arrow-repeat"></i>
                      </Button>
                      <Button
                        variant="outline-secondary"
                        size="sm"
                        onClick={() => {
                          setDataEntries(
                            dataEntries.filter((_, i) => i !== idx),
                          );
                          setVisibleSecrets(new Set());
                        }}
                        disabled={dataEntries.length === 1}
                      >
                        <i className="bi bi-x-lg"></i>
                      </Button>
                    </div>
                  </Col>
                ))}
                <Col md={12}>
                  <Button
                    variant="outline-primary"
                    onClick={() =>
                      setDataEntries([...dataEntries, { key: "", value: "" }])
                    }
                  >
                    <i className="bi bi-plus-lg"></i> Add
                  </Button>
                </Col>
              </Form.Group>
            </Card.Body>
          </Card>

          {!editMode && (
            <Card className="mb-3">
              <Card.Header>
                <h6 className="mb-0">
                  Encryption Key{" "}
                  {isFetchingKeys && (
                    <Spinner
                      animation="border"
                      size="sm"
                      className="text-primary ms-1"
                    />
                  )}
                </h6>
                <div className="text-muted small">
                  Key used to encrypt the secret
                </div>
              </Card.Header>
              <Card.Body>
                <Form.Group className="mb-3">
                  <Form.Select
                    value={keyID}
                    onChange={(e) => setKeyID(e.target.value)}
                  >
                    {keys.map((keyInfo) => (
                      <option key={keyInfo.id} value={keyInfo.id}>
                        {[
                          keyInfo.environment,
                          keyInfo.id.substring(0, 18) + "...",
                          keyInfo.config.type +
                            (keyInfo.config.pkcs11URI
                              ? " (HSM)"
                              : " (Software)"),
                          `created ${prettyTime(keyInfo.createdAt)}`,
                        ].join(" | ")}
                      </option>
                    ))}
                    <option key="new" value="new">
                      New...
                    </option>
                  </Form.Select>
                </Form.Group>

                {keyID === "new" && (
                  <KeyInput
                    environment={environment}
                    setEnvironment={setEnvironment}
                    keyTypes={["AES"]}
                    keyType={keyType}
                    setKeyType={setKeyType}
                    bits={bits}
                    setBits={setBits}
                    mode={mode}
                    setMode={setMode}
                    pkcs11URI={pkcs11URI}
                    setPkcs11URI={setPkcs11URI}
                  />
                )}
              </Card.Body>
            </Card>
          )}
        </>
      </Modal.Body>

      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Cancel
        </Button>
        <Button
          variant="primary"
          onClick={() => {
            handleUpsertSecret();
          }}
          disabled={
            !secretName ||
            (!editMode && keyID === "new" && !environment) ||
            isLoading ||
            isFetchingData ||
            isFetchingKeys ||
            dataEntries.some((entry) => entry.key === "")
          }
        >
          {isLoading ? (
            <>
              <Spinner
                animation="border"
                size="sm"
                className="text-light me-2"
              />
              {editMode ? "Saving..." : "Inserting..."}
            </>
          ) : editMode ? (
            "Save"
          ) : (
            "Insert"
          )}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
