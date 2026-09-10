import { useState, useEffect } from "react";
import { Alert, Table } from "react-bootstrap";
import { Link, useNavigate } from "react-router-dom";
import Filters from "./Filters";
import Paginator from "./Paginator";
import { prettyTime, prettyEnv } from "../utils/utils";

import SecretModal from "./SecretModal";

export default function Secrets({
  isLoading,
  setIsLoading,
  setDropdownActions,
}) {
  const [error, setError] = useState(null);
  const [secrets, setSecrets] = useState([]);
  const [filters, setFilters] = useState({});
  const [showSecretModal, setShowSecretModal] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const navigate = useNavigate();

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

      {error && <Alert variant="danger">{error}</Alert>}

      <Filters
        filters={filters}
        setFilters={setFilters}
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
        setError={setError}
        isLoading={isLoading}
        setIsLoading={setIsLoading}
        filters={filters}
        items={secrets}
        setItems={setSecrets}
        apiPath="/secrets"
      />
    </>
  );
}
