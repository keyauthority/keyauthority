import { useCallback, useState, useEffect } from "react";
import { Alert, Button, Table, Dropdown } from "react-bootstrap";
import { Link } from "react-router-dom";
import { getApi } from "../axios";
import Paginator from "./Paginator";
import Filters from "./Filters";
import JSONModal from "./JSONModal";

import {
  prettyTime,
  prettyEnv,
  showToast,
  buildURLParams,
  copyToClipboard,
} from "../utils/utils";

import { errorToString } from "../utils/error";

export default function Keys({ isLoading, setIsLoading, setDropdownActions }) {
  const [error, setError] = useState(null);
  const [keys, setKeys] = useState([]);
  const [filters, setFilters] = useState({});

  const [showModal, setShowModal] = useState(false);
  const [modalTitle, setModalTitle] = useState(null);
  const [modalData, setModalData] = useState(null);

  const api = getApi();

  const handleCheckReadiness = async (keyId) => {
    setIsLoading(true);
    try {
      await api.get(`/keys/${keyId}/ready`);
      showToast("success", `Key ${keyId} is ready`);
    } catch (err) {
      showToast("error", `Key ${keyId} not ready`);
    } finally {
      setIsLoading(false);
    }
  };

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
            placeholder: "e.g. dev, qa, prod",
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

      <Table striped hover className="align-middle mb-3">
        <thead>
          <tr>
            <th>ID</th>
            <th>Environment</th>
            <th>Type</th>
            <th>Storage</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {keys.map((key, idx) => (
            <tr key={idx}>
              <td>{key.id}</td>
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
              <td>
                <Dropdown>
                  <Dropdown.Toggle
                    as={Link}
                    className="no-caret"
                    id={`dropdown-${idx}`}
                  >
                    <i className="bi-three-dots-vertical mx-1"></i>
                  </Dropdown.Toggle>

                  <Dropdown.Menu>
                    <Dropdown.Item
                      onClick={() => {
                        setModalTitle(`Key: ${key.id}`);
                        setModalData(key);
                        setShowModal(true);
                      }}
                    >
                      <i className="bi-eye me-1"></i> View as JSON
                    </Dropdown.Item>
                    <Dropdown.Item
                      onClick={() => handleCheckReadiness(key.id)}
                      disabled={isLoading}
                    >
                      <i className="bi-check2-circle me-1"></i> Check Readiness
                    </Dropdown.Item>
                  </Dropdown.Menu>
                </Dropdown>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>

      <Paginator
        setError={setError}
        isLoading={isLoading}
        setIsLoading={setIsLoading}
        filters={filters}
        items={keys}
        setItems={setKeys}
        apiPath="/keys"
        orderCol="createdAt"
        idCol="id"
      />
    </>
  );
}
