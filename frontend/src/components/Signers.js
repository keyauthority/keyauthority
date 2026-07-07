import { useCallback, useState, useEffect } from "react";
import { Alert, Table } from "react-bootstrap";
import { Link, useNavigate } from "react-router-dom";
import Paginator from "./Paginator";
import SignerModal from "./SignerModal";
import Filters from "./Filters";
import { prettyTime, prettyEnv } from "../utils/utils";

export default function Signers({
  isLoading,
  setIsLoading,
  setDropdownActions,
}) {
  const [error, setError] = useState(null);
  const [signers, setSigners] = useState([]);
  const [filters, setFilters] = useState({});
  const [showSignerModal, setShowSignerModal] = useState(false);

  const navigate = useNavigate();

  useEffect(() => {
    setDropdownActions?.([
      {
        key: "new-signer",
        label: "New",
        iconClass: "bi bi-plus-lg",
        onClick: () => {
          setShowSignerModal(true);
        },
      },
    ]);
    return () => setDropdownActions?.([]);
  }, [setDropdownActions]);

  return (
    <>
      <SignerModal
        show={showSignerModal}
        onHide={() => setShowSignerModal(false)}
        editMode={false}
        onSuccess={(updatedSigner) => {
          navigate(`/signers/${encodeURIComponent(updatedSigner)}`);
        }}
      />

      {error && <Alert variant="danger">{error}</Alert>}

      <Filters
        filters={filters}
        setFilters={setFilters}
        filtersTemplate={[
          {
            key: "name",
            type: "text",
            label: "Name",
            placeholder: "e.g. signer1",
            value: filters.name,
          },
          {
            key: "environment",
            type: "text",
            label: "Environment",
            placeholder: "e.g. dev, staging, prod",
            value: filters.environment,
          },
          {
            key: "privateKeyID",
            type: "text",
            label: "Private Key ID",
            placeholder: "e.g. 1234-5678-9012",
            value: filters.privateKeyID,
            colSpan: 4,
          },
          {
            key: "isRoot",
            type: "select",
            label: "Is Root",
            options: [
              { value: "", label: "-" },
              { value: "true", label: "Yes" },
              { value: "false", label: "No" },
            ],
            value: filters.isRoot,
            colSpan: 2,
          },
        ]}
      />

      <Table striped hover className="align-middle mb-3">
        <thead>
          <tr>
            <th>Name</th>
            <th>Environment</th>
            <th>Common Name</th>
            <th>Private Key ID</th>
            <th>Last Updated</th>
          </tr>
        </thead>
        <tbody>
          {signers.map((signer, idx) => (
            <tr key={idx}>
              <td>
                <Link to={`/signers/${encodeURIComponent(signer.name)}`}>
                  {signer.name}
                </Link>
              </td>
              <td>{prettyEnv(signer.environment)}</td>
              <td>{signer.config?.caTemplate?.subject?.commonName || "-"}</td>
              <td>{signer.privateKeyID}</td>
              <td>{prettyTime(signer.updatedAt)}</td>
            </tr>
          ))}
        </tbody>
      </Table>

      <Paginator
        setError={setError}
        isLoading={isLoading}
        setIsLoading={setIsLoading}
        filters={filters}
        items={signers}
        setItems={setSigners}
        apiPath="/signers"
      />
    </>
  );
}
