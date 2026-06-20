import { useCallback, useState, useEffect } from "react";
import { Alert, Button, Table, Dropdown } from "react-bootstrap";
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
  copyToClipboard,
} from "../utils/utils";

import { errorToString } from "../utils/error";

export default function Keys({ isLoading, setIsLoading, setDropdownActions }) {
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
      setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  }, [api, page, pageSize, filters, setIsLoading]);

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

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  /*const handleDeleteUnusedKeys = async (storage) => {
    let deletedKeysCount = 0;
    const deleteKeyByID = async (keyId) => {
      try {
        await api.delete(`/keys/${keyId}`);
        deletedKeysCount++;
      } catch (err) {
        // do nothing, just log the error
      }
    };

    setIsLoading(true);
    try {
      const params = buildURLParams({ storage }, 1, 1000); // Fetch all keys of the specified storage type
      const res = await api.get(`/keys?${params.toString()}`);
      console.log("Unused keys to delete:", res.data.data);

      
      for (const key of res.data.data || []) {
        await deleteKeyByID(key.id);
      }

      if (deletedKeysCount > 0) {
        showToast(
          "success",
          `Deleted ${deletedKeysCount} unused ${storage} key(s)`,
        );
        fetchKeys(); // Refresh the keys list after deletion
      } else {
        showToast("info", `No unused ${storage} keys deleted`);
      }
    } catch (err) {
      setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    setDropdownActions?.([
      {
        key: "delete-unused-software-keys",
        label: "Delete Unused Software Keys",
        iconClass: "bi bi-trash",
        onClick: () => handleDeleteUnusedKeys("Software"),
      },
      {
        key: "delete-unused-hsm-keys",
        label: "Delete Unused HSM Keys",
        iconClass: "bi bi-trash",
        onClick: () => handleDeleteUnusedKeys("HSM"),
      },
    ]);
  }, [keys, setDropdownActions]);*/

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
        colsPerRow={2}
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
        page={page}
        setPage={setPage}
        pageSize={pageSize}
        setPageSize={setPageSize}
        totalCount={totalCount}
      />
    </>
  );
}
