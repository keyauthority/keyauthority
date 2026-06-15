import { useCallback, useState, useEffect } from "react";
import { Alert, Table } from "react-bootstrap";
import { Link, useNavigate } from "react-router-dom";
import Filters from "./Filters";
import Paginator from "./Paginator";
import { prettyTime, prettyEnv, buildURLParams } from "../utils/utils";
import { getApi } from "../axios";

import ImportSecretsModal from "./ImportSecretsModal";
import SecretModal from "./SecretModal";

export default function Secrets({
  isLoading,
  setIsLoading,
  setDropdownActions,
}) {
  const [error, setError] = useState(null);
  const [secrets, setSecrets] = useState([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [totalCount, setTotalCount] = useState(0);
  const [filters, setFilters] = useState({});

  const [showSecretModal, setShowSecretModal] = useState(false);
  const [showImportSecretsModal, setShowImportSecretsModal] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const api = getApi();
  const navigate = useNavigate();

  const fetchSecrets = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const params = buildURLParams(filters, page, pageSize);
      const res = await api.get(`/secrets?${params.toString()}`);
      setSecrets(res.data.data || []);
      setTotalCount(res.data.totalCount || 0);
    } catch (err) {
      setError(err.message || "Failed to fetch secrets");
    } finally {
      setIsLoading(false);
    }
  }, [api, page, pageSize, filters, setIsLoading]);

  useEffect(() => {
    fetchSecrets();
  }, [fetchSecrets]);

  useEffect(() => {
    setDropdownActions?.([
      {
        key: "new-secret",
        label: "New",
        iconClass: "bi bi-plus-lg",
        onClick: () => {
          setShowSecretModal(true);
        },
      },
      {
        key: "import-secrets",
        label: "Import From HC Vault",
        iconClass: "bi bi-upload",
        onClick: () => {
          setShowImportSecretsModal(true);
        },
      },
    ]);
    return () => setDropdownActions?.([]);
  }, [setDropdownActions]);

  return (
    <>
      <SecretModal
        show={showSecretModal}
        editMode={false}
        onHide={() => setShowSecretModal(false)}
        onSuccess={(updatedSecret) => {
          navigate(`/secrets/${encodeURIComponent(updatedSecret)}`);
        }}
      />

      <ImportSecretsModal
        show={showImportSecretsModal}
        onHide={() => setShowImportSecretsModal(false)}
        onSuccess={(imported, skipped, failed) => {
          showImportResultToast(imported, skipped, failed);
          if (imported.size > 0) {
            setRefreshTrigger((prev) => prev + 1);
          }
        }}
      />

      {error && <Alert variant="danger">{error}</Alert>}

      <Filters
        filters={filters}
        setFilters={setFilters}
        colsPerRow={2}
        filtersTemplate={[
          {
            key: "name",
            label: "Name",
            type: "text",
            placeholder: "e.g. my-secret",
          },
          {
            key: "environment",
            label: "Environment",
            type: "text",
            placeholder: "e.g. dev, staging, prod",
          },
          {
            key: "encryptionKeyID",
            label: "Encryption Key ID",
            type: "text",
            placeholder: "e.g. 123e4567-e89b-12d3-a456-426614174000",
          },
          {
            key: "updatedFrom",
            label: "Updated After",
            type: "date",
          },
        ]}
      />

      <Table
        striped
        hover
        className="align-middle mb-3"
        key={`secrets-${refreshTrigger}`}
      >
        <thead>
          <tr>
            <th>Name</th>
            <th>Environment</th>
            <th>Encryption Key ID</th>
            <th>Last Updated</th>
          </tr>
        </thead>
        <tbody>
          {secrets.map((secret, idx) => (
            <tr key={idx}>
              <td>
                <Link
                  to={`/secrets/${encodeURIComponent(secret.name)}`}
                  //className="fw-medium"
                >
                  {secret.name}
                </Link>
              </td>
              <td>{prettyEnv(secret.environment)}</td>
              {/* <td>{shortUUID(secret.encryptionKeyID)}</td> */}
              <td>{secret.encryptionKeyID}</td>
              <td>{prettyTime(secret.updatedAt)}</td>
            </tr>
          ))}
        </tbody>
      </Table>

      <Paginator
        page={page}
        setPage={setPage}
        pageSize={pageSize}
        setPageSize={setPageSize}
        totalCount={totalCount}
      />
    </>
  );
}
