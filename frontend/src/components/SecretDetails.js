import { useEffect, useState, useCallback } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Alert, Tab, Tabs, Button } from "react-bootstrap";
import { Link } from "react-router-dom";
import KeyValueTable from "./KeyValueTable";
import JSONModal from "./JSONModal";
import SecretModal from "./SecretModal";
import { copyToClipboard, prettyTime, showToast } from "../utils/utils";
import { secretUsageExamples } from "./Docs";
import { errorToString } from "../utils/error";
import { getApi } from "../axios";

function SecretDetails({
  isLoading,
  setIsLoading,
  setTitle,
  setSubtitle,
  setDropdownActions,
}) {
  const location = useLocation();
  const secretName =
    decodeURIComponent(location.pathname.replaceAll("/secrets/", "")) || "";
  const navigate = useNavigate();

  const [showSecretModal, setShowSecretModal] = useState(false);

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

  const [dataEntries, setDataEntries] = useState({});

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
      navigate("/secrets");
    } finally {
      setIsLoading(false);
    }
  }, [api, secretName]);

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

  const normalizeSecretData = (data) => {
    if (!data) return [];
    return Object.entries(data).map(([key, value]) => ({ key, value }));
  };

  const buildDataEntries = useCallback(() => {
    const kv = normalizeSecretData(secretData);
    const dataEntries =
      kv.length > 0
        ? Object.fromEntries(
            kv.map((entry) => [
              entry.key,
              <div
                className="d-flex justify-content-between align-items-center gap-3"
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
                  <div className="p-1 rounded">
                    {getDisplayValue(entry.key, entry.value)}
                  </div>
                </div>
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
                      className={`bi ${
                        visibleSecrets.has(entry.key)
                          ? "bi-eye-slash"
                          : "bi-eye"
                      }`}
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
    setDataEntries(dataEntries);
  }, [secretData, visibleSecrets]);

  useEffect(() => {
    buildDataEntries();
  }, [buildDataEntries]);

  const handleDeleteSecret = useCallback(async () => {
    // ask user to enter the secret path to confirm deletion
    const confirmedPath = window.prompt(
      `To confirm deletion, please enter the secret path: ${secretName}`,
    );

    // Cancel pressed: do nothing
    if (confirmedPath === null) {
      return;
    }

    if (confirmedPath !== secretName) {
      showToast("error", "Secret path does not match. Deletion cancelled.");
      return;
    }

    setIsLoading(true);
    try {
      await api.delete(`/secrets/${secretName}`);
      showToast("success", "Secret deleted!");
      navigate("/secrets");
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  }, [api, secretName, navigate]);

  useEffect(() => {
    setDropdownActions?.([
      {
        key: "edit-secret",
        label: "Edit",
        iconClass: "bi bi-pencil-square",
        onClick: () => setShowSecretModal(true),
      },
      {
        key: "delete-secret",
        label: "Delete",
        iconClass: "bi bi-trash",
        onClick: handleDeleteSecret,
      },
    ]);
    return () => setDropdownActions?.([]);
  }, [setDropdownActions, handleDeleteSecret]);

  return (
    <>
      <JSONModal
        show={showKeyModal}
        onHide={() => setShowKeyModal(false)}
        modalTitle={keyModalTitle}
        modalData={keyModalData}
      />

      <SecretModal
        show={showSecretModal}
        editMode={true}
        onHide={() => setShowSecretModal(false)}
        onSuccess={(updatedSecret) => {
          fetchSecret();
        }}
      />

      {error && <Alert variant="danger">{error}</Alert>}

      {secretData && secretMetadata && (
        <Tabs className="mb-3">
          <Tab eventKey="data" title="Data">
            <>
              <KeyValueTable
                body={dataEntries}
                borderBottom={true}
                header={["Key", "Value"]}
                minKeyLen={32}
              />
              <div className="text-muted small w-100 text-end">
                Last Updated: {prettyTime(secretMetadata.updatedAt)}
              </div>
            </>
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
