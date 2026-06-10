import { useEffect, useState, useCallback, use } from "react";
import { useLocation } from "react-router-dom";
import { Alert, Tab, Tabs, Button } from "react-bootstrap";
import { Link } from "react-router-dom";
import KeyValueTable from "./KeyValueTable";
import JSONModal from "./JSONModal";
import { copyToClipboard, prettyTime } from "../utils/utils";
import { secretUsageExamples } from "./Docs";
import { errorToString } from "../utils/error";
import { getApi } from "../axios";

function SecretDetails({ isLoading, setIsLoading, setTitle, setSubtitle }) {
  const location = useLocation();
  const secretName =
    decodeURIComponent(location.pathname.replaceAll("/secrets/", "")) || "";

  const [error, setError] = useState(null);
  const [visibleSecrets, setVisibleSecrets] = useState(new Set()); // Track which secrets are visible

  const api = getApi();
  const apiUrl = new URL(api.defaults.baseURL);
  const apiRootUrl = apiUrl.href.replace(/\/v1\/?$/, "");

  const [secretData, setSecretData] = useState(null);
  const [secretMetadata, setSecretMetadata] = useState(null);

  const [showKeyModal, setShowKeyModal] = useState(false);
  const [keyModalTitle, setKeyModalTitle] = useState("");
  const [keyModalData, setKeyModalData] = useState(null);

  useEffect(() => {
    setTitle(secretName);
  }, [secretName, setTitle, secretData]);

  useEffect(() => {
    setSubtitle(
      //secretMetadata ? `Updated ${prettyTime(secretMetadata.updatedAt)}` : null,
      secretMetadata ? (
        <Link
          style={{ textDecoration: "none" }}
          className="text-muted"
          onClick={() => handleShowKey(secretMetadata.encryptionKeyID)}
        >
          <i className="bi bi-key me-1"></i>
          {secretMetadata.encryptionKeyID}
        </Link>
      ) : null,
    );
  }, [secretMetadata, setSubtitle]);

  const fetchSecret = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    setSecretData(null);
    setVisibleSecrets(new Set()); // Reset visibility when loading new secret

    try {
      const res = await api.get(`/secrets/${secretName}`);
      const { data, ...metadata } = res.data;
      setSecretData(data);
      setSecretMetadata(metadata);
    } catch (err) {
      setError(errorToString(err));
      navigation.navigate("/secrets");
    } finally {
      setIsLoading(false);
    }
  }, [api, secretName, setIsLoading]);

  const handleShowKey = async (keyID) => {
    setIsLoading(true);
    try {
      const res = await api.get(`/keys/${keyID}`);
      setKeyModalData(res.data);
      setKeyModalTitle(`Encryption Key: ${keyID}`);
      setShowKeyModal(true);
    } catch (err) {
      setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchSecret();
  }, [fetchSecret]);

  const getDisplayValue = (key, value) => {
    return visibleSecrets.has(key) ? value : "•".repeat(10);
  };

  // Normalize secretData.data to an array of { key, value }
  const secretEntries = secretData
    ? Object.entries(secretData).map(([key, value]) => ({ key, value }))
    : [];

  // Build the body for KeyValueTable with React elements as values
  const keyValueTableBody =
    secretEntries.length > 0
      ? Object.fromEntries(
          secretEntries.map((entry) => [
            entry.key,
            <div
              className="d-flex justify-content-between align-items-start gap-3"
              key={entry.key}
            >
              <div
                className="font-body"
                style={
                  !visibleSecrets.has(entry.key)
                    ? { WebkitTextSecurity: "disc" }
                    : {}
                }
              >
                <pre
                  className="mb-0"
                  style={{
                    fontFamily: "inherit", // use body font
                    fontSize: "inherit",
                    whiteSpace: "pre-wrap", // keep newlines, wrap long lines
                    wordBreak: "break-word",
                  }}
                >
                  {getDisplayValue(entry.key, entry.value)}
                </pre>
              </div>{" "}
              <div className="d-flex gap-1">
                <Button
                  variant="outline-secondary"
                  size="sm"
                  onClick={() => {
                    const newVisibleSecrets = new Set(visibleSecrets);
                    if (visibleSecrets.has(entry.key)) {
                      newVisibleSecrets.delete(entry.key);
                    } else {
                      newVisibleSecrets.add(entry.key);
                    }
                    setVisibleSecrets(newVisibleSecrets);
                  }}
                >
                  <i
                    className={`bi ${visibleSecrets.has(entry.key) ? "bi-eye-slash" : "bi-eye"}`}
                  ></i>
                </Button>
                <Button
                  variant="outline-secondary"
                  size="sm"
                  onClick={() => {
                    copyToClipboard(
                      entry.value,
                      "Value for '" + entry.key + "' copied!",
                    );
                  }}
                >
                  <i className="bi bi-clipboard"></i>
                </Button>
              </div>
            </div>,
          ]),
        )
      : {};

  return (
    <>
      <JSONModal
        show={showKeyModal}
        onHide={() => setShowKeyModal(false)}
        modalTitle={keyModalTitle}
        modalData={keyModalData}
      />

      {error && <Alert variant="danger">{error}</Alert>}

      {secretData && (
        <Tabs className="mb-3">
          <Tab eventKey="data" title="Data">
            {secretData && Object.keys(secretData).length > 0 ? (
              <>
                <KeyValueTable
                  body={keyValueTableBody}
                  borderBottom={true}
                  header={["Key", "Value"]}
                  minKeyLen={32}
                />
                <div className="text-muted small w-100 text-end">
                  Last Updated: {prettyTime(secretMetadata.updatedAt)}
                </div>
              </>
            ) : (
              <Alert variant="info">No data available for this secret.</Alert>
            )}
          </Tab>
          <Tab eventKey="usages" title="Usage Examples">
            {secretUsageExamples(secretName, secretData, apiRootUrl)}
          </Tab>
        </Tabs>
      )}
    </>
  );
}

export default SecretDetails;
