import { useCallback, useState, useEffect } from "react";
import { Alert, Button, Table } from "react-bootstrap";
import { Link } from "react-router-dom";
import Paginator from "./Paginator";
import Filters from "./Filters";
import JSONModal from "./JSONModal";

import { getApi } from "../axios";
import {
  prettyTime,
  prettyEnv,
  showToast,
  buildURLParams,
} from "../utils/utils";

export default function Keys({ isLoading, setIsLoading }) {
  const [error, setError] = useState(null);
  const [keys, setKeys] = useState([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [totalCount, setTotalCount] = useState(0);
  const [filters, setFilters] = useState({});

  const [showModal, setShowModal] = useState(false);
  const [modalTitle, setModalTitle] = useState(null);
  const [modalData, setModalData] = useState(null);

  const api = getApi();

  const fetchKeys = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const params = buildURLParams(filters, page, pageSize);
      const res = await api.get(`/keys?${params.toString()}`);
      setKeys(res.data.data || []);
      setTotalCount(res.data.totalCount || 0);
    } catch (err) {
      setError(err.message || "Failed to fetch keys");
    } finally {
      setIsLoading(false);
    }
  }, [api, page, pageSize, filters, setIsLoading]);

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  return (
    <>
      <JSONModal
        show={showModal}
        onHide={() => setShowModal(false)}
        modalTitle={modalTitle}
        modalData={modalData}
      />

      {error && <Alert variant="danger">{error}</Alert>}

      <Filters
        filters={filters}
        setFilters={setFilters}
        cols={{ xs: 12, md: 3, lg: 3 }}
        filtersTemplate={[
          {
            key: "id",
            label: "ID",
            type: "text",
            placeholder: "e.g. 123e4567-e89b-...",
          },
          {
            key: "environment",
            label: "Environment",
            type: "text",
            placeholder: "e.g. dev, staging, prod",
          },
          {
            key: "type",
            label: "Type",
            type: "select",
            options: [
              { value: "", label: "-" },
              { value: "RSA", label: "RSA" },
              { value: "ECDSA", label: "ECDSA" },
              { value: "Ed25519", label: "Ed25519" },
              { value: "AES", label: "AES" },
            ],
          },
          {
            key: "storage",
            label: "Storage",
            type: "select",
            options: [
              { value: "", label: "-" },
              { value: "Software", label: "Software" },
              { value: "HSM", label: "HSM" },
            ],
          },
        ]}
      />

      <Table striped hover className="mb-3">
        <thead>
          <tr>
            <th>ID</th>
            <th>Environment</th>
            <th>Type</th>
            <th>Storage</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((key, idx) => (
            <tr key={idx}>
              <td>
                <Link
                  as={Button}
                  //to={`/keys/${encodeURIComponent(key.id)}`}
                  //className="fw-medium"
                  onClick={() => {
                    setModalTitle(`Key: ${key.id}`);
                    setModalData(key);
                    setShowModal(true);
                  }}
                >
                  {key.id}
                </Link>
              </td>
              <td>{prettyEnv(key.environment)}</td>
              <td>{key.config.type}</td>
              <td>
                {key.config.pkcs11URI ? (
                  <>
                    <i className="bi-safe me-1"></i> HSM
                  </>
                ) : (
                  <>
                    <i className="bi-laptop me-1"></i> Software
                  </>
                )}
              </td>
              <td>{prettyTime(key.createdAt)}</td>
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
