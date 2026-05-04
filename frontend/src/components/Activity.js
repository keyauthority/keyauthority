import { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { Alert, Button, Table } from "react-bootstrap";
import {
  showToast,
  downloadOrCopy,
  prettyTime,
  copyToClipboard,
  prettyEnv,
  boxedContent,
} from "../utils/utils";
import { errorToString } from "../utils/error";
import { getApi } from "../axios";
import Filters from "./Filters";
import Paginator from "./Paginator";
import JSONModal from "./JSONModal";

export function Certificates({ isLoading, setIsLoading }) {
  const [error, setError] = useState(null);
  const [certs, setCerts] = useState([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [totalCount, setTotalCount] = useState(0);

  const [showModal, setShowModal] = useState(false);
  const [modalTitle, setModalTitle] = useState(null);
  const [modalData, setModalData] = useState(null);

  const [filters, setFilters] = useState({});

  const api = getApi();

  const fetchCerts = useCallback(async () => {
    setCerts([]);
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value) params.append(key, value);
      });
      params.append("page", page);
      params.append("pageSize", pageSize);

      const res = await api.get(`/certs?${params.toString()}`);
      setCerts(res.data.data || []);
      setTotalCount(res.data.totalCount || 0);
    } catch (err) {
      setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  }, [api, filters, page, pageSize, setIsLoading]);

  useEffect(() => {
    fetchCerts();
  }, [fetchCerts]);

  const cnAndSan = (cert) => {
    let names = [];
    if (cert.cn) names.push(cert.cn);
    if (cert.sans && cert.sans.length > 0) {
      // remove cert.cn from cert.sans to avoid duplication
      const filteredSans = cert.sans.filter((san) => san !== cert.cn);
      names = names.concat(filteredSans);
    }
    return names;
  };

  const copyPEM = async (cert) => {
    try {
      const res = await api.get(`/certs/${cert.serial}/pem`);
      copyToClipboard(res.data, "PEM copied!");
    } catch (err) {
      showToast("error", errorToString(err));
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
        colsPerRow={3}
        filtersTemplate={[
          {
            key: "serial",
            type: "text",
            label: "Serial",
            placeholder: "e.g. 1234567890",
            value: filters.serial,
          },
          {
            key: "cn",
            type: "text",
            label: "CN",
            value: filters.cn,
            placeholder: "e.g. example.com",
          },
          {
            key: "san",
            type: "text",
            label: "SAN",
            value: filters.san,
            placeholder: "e.g. www.example.com",
          },
          {
            key: "notBeforeFrom",
            type: "date",
            label: "Valid From",
            value: filters.notBeforeFrom,
          },
          {
            key: "notAfterTo",
            type: "date",
            label: "Valid To",
            value: filters.notAfterTo,
          },
          {
            key: "revoked",
            type: "select",
            label: "Revoked",
            value: filters.revoked,
            options: [
              { value: "", label: "-" },
              { value: "true", label: "Yes" },
              { value: "false", label: "No" },
            ],
          },
          {
            key: "signerName",
            type: "text",
            label: "Signer",
            value: filters.signerName,
            placeholder: "e.g. signer1",
          },
        ]}
      />

      <Table hover responsive striped>
        <thead>
          <tr>
            <th>Serial</th>
            <th>CN/SAN</th>
            <th>Valid From</th>
            <th>Valid To</th>
            <th>Signer</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {certs.map((cert) => (
            <tr key={cert.serial}>
              <td>{cert.serial.substr(0, 10)}...</td>
              <td
                className={cert.revoked ? "text-decoration-line-through" : ""}
              >
                {cnAndSan(cert).length > 0 ? cnAndSan(cert).join(", ") : "-"}
              </td>
              <td>{prettyTime(cert.notBefore)}</td>
              <td>{prettyTime(cert.notAfter)}</td>
              <td>
                <Link to={`/signers/${encodeURIComponent(cert.signerName)}`}>
                  {cert.signerName}
                </Link>
              </td>
              <td>
                <div className="d-flex gap-1">
                  <Button
                    variant="outline-secondary"
                    size="sm"
                    title="View Details"
                    onClick={() => {
                      setModalData(cert);
                      setModalTitle(`Certificate: ${cert.serial}`);
                      setShowModal(true);
                    }}
                  >
                    <i className="bi bi-eye"></i>
                  </Button>
                  <Button
                    variant="outline-secondary"
                    size="sm"
                    title="Copy PEM"
                    onClick={() => copyPEM(cert)}
                  >
                    <i className="bi bi-clipboard"></i>
                  </Button>
                </div>
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

export function Logs({ isLoading, setIsLoading }) {
  const [error, setError] = useState(null);
  const [logs, setLogs] = useState([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [totalCount, setTotalCount] = useState(0);

  const [showModal, setShowModal] = useState(false);
  const [modalTitle, setModalTitle] = useState(null);
  const [modalData, setModalData] = useState(null);

  const [filters, setFilters] = useState({});

  const api = getApi();

  const fetchLogs = useCallback(async () => {
    setLogs([]);
    // const loadingToast = showLoadingToast("Loading logs...");
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value) params.append(key, value);
      });
      params.append("page", page);
      params.append("pageSize", pageSize);

      const res = await api.get(`/logs?${params.toString()}`);
      setLogs(res.data.data || []);
      setTotalCount(res.data.totalCount || 0);
    } catch (err) {
      setError(errorToString(err));
    } finally {
      // loadingToast.dismiss();
      setIsLoading(false);
    }
  }, [api, filters, page, pageSize, setIsLoading]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const levelVariant = {
    ERROR: "danger",
    WARN: "warning",
    INFO: "info",
    DEBUG: "secondary",
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
        colsPerRow={3}
        filtersTemplate={[
          {
            key: "level",
            type: "select",
            label: "Level",
            value: filters.level,
            options: [
              { value: "", label: "-" },
              { value: "ERROR", label: "ERROR" },
              { value: "WARN", label: "WARN" },
              { value: "INFO", label: "INFO" },
              // { value: "DEBUG", label: "DEBUG" },
            ],
          },
          {
            key: "user",
            type: "text",
            label: "User",
            placeholder: "e.g. alice@keyauthority.net",
            value: filters.user,
          },
          {
            key: "environment",
            type: "text",
            label: "Environment",
            placeholder: "e.g. production",
            value: filters.environment,
          },
          {
            key: "url",
            type: "text",
            label: "URL",
            placeholder: "e.g. /v1/secrets/my-secret",
            value: filters.url,
          },
          {
            key: "from",
            type: "date",
            label: "From",
            value: filters.from,
          },
          {
            key: "to",
            type: "date",
            label: "To",
            value: filters.to,
          },
          {
            key: "msg",
            type: "text",
            label: "Message",
            placeholder: "e.g. secret read",
            value: filters.msg,
          },
        ]}
      />

      <Table hover responsive striped>
        <thead>
          <tr>
            <th>Level</th>
            <th>Message</th>
            <th>User</th>
            <th>Environment</th>
            <th>API Call</th>
            <th>Time</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, index) => (
            <tr key={index}>
              <td>
                {boxedContent(
                  log.level,
                  levelVariant[log.level] || "secondary",
                )}
              </td>
              <td>{log.msg}</td>
              <td>{log.token?.user || "-"}</td>
              <td>{log.environment && prettyEnv(log.environment)}</td>
              <td>
                {log.method} {log.url}
              </td>
              <td>{prettyTime(log.time)}</td>
              <td>
                <div className="d-flex gap-1">
                  <Button
                    variant="outline-secondary"
                    size="sm"
                    title="View Details"
                    onClick={() => {
                      setModalTitle(`Log Entry: ${log.msg}`);
                      setModalData(log);
                      setShowModal(true);
                    }}
                  >
                    <i className="bi bi-eye"></i>
                  </Button>
                </div>
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

export function PendingRequests({ isLoading, setIsLoading }) {
  const [error, setError] = useState(null);
  const [requests, setRequests] = useState([]);
  const [files, setFiles] = useState({});
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [totalCount, setTotalCount] = useState(0);

  const [showModal, setShowModal] = useState(false);
  const [modalTitle, setModalTitle] = useState(null);
  const [modalData, setModalData] = useState(null);

  const [filters, setFilters] = useState({});

  const api = getApi();

  const fetchRequests = useCallback(async () => {
    setRequests([]);
    // const loadingToast = showLoadingToast("Loading requests...");
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value) params.append(key, value);
      });
      params.append("page", page);
      params.append("pageSize", pageSize);

      const res = await api.get(`/pending-requests?${params.toString()}`);
      setRequests(res.data.data || []);
      setTotalCount(res.data.totalCount || 0);
    } catch (err) {
      setError(errorToString(err));
    } finally {
      // loadingToast.dismiss();
      setIsLoading(false);
    }
  }, [api, page, pageSize, filters, setIsLoading]);

  useEffect(() => {
    fetchRequests();
  }, [fetchRequests]);

  const handleAuthorizeRequest = async (requestID, useOwnToken) => {
    const confirmed = window.confirm(
      `Are you sure you want to authorize the request '${requestID}'?`,
    );
    if (!confirmed) return;

    setIsLoading(true);
    try {
      const response = await api.post(
        `/pending-requests/${requestID}?useOwnToken=${useOwnToken}`,
      );
      const contentTypeFromHeader = response.headers["content-type"];
      setFiles((prev) => ({
        ...prev,
        [requestID]: { data: response.data, contentTypeFromHeader },
      }));
      fetchRequests();
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  const handleRejectRequest = async (requestID) => {
    const confirmed = window.confirm(
      `Are you sure you want to reject the request '${requestID}'?`,
    );
    if (!confirmed) return;

    setIsLoading(true);
    try {
      await api.delete(`/pending-requests/${requestID}`);
      showToast("success", "Request rejected!");
      fetchRequests();
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  const handleViewJSON = async (req) => {
    setIsLoading(true);
    let modalData = req;
    try {
      const response = await api.get(`/pending-requests/${req.id}/body`);
      if (response.data) {
        modalData = { ...req, body: response.data };
      }
    } catch (err) {
      // don't show error if body can't be fetched, just show the rest of the request data
      // showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
      setModalTitle(`Request: ${req.id}`);
      setModalData(modalData);
      setShowModal(true);
    }
  };

  const contentTypeToExtension = {
    "application/json": "json",
    "application/x-pem-file": "pem",
    "application/pkix-cert": "crt",
    "application/octet-stream": "bin",
    "text/plain": "txt",
  };

  return (
    <>
      <JSONModal
        show={showModal}
        onHide={() => setShowModal(false)}
        modalTitle={modalTitle}
        modalData={modalData}
        size="lg"
      />

      {error && <Alert variant="danger">{error}</Alert>}

      <div>
        {Object.keys(files).map((requestID) =>
          downloadOrCopy(
            `Request '${requestID}' authorized!`,
            files[requestID].data,
            `response-${requestID}.${contentTypeToExtension[files[requestID].contentTypeFromHeader] || "txt"}`,
          ),
        )}
      </div>

      <Filters
        filters={filters}
        setFilters={setFilters}
        colsPerRow={2}
        filtersTemplate={[
          {
            key: "id",
            type: "text",
            label: "ID",
            placeholder: "e.g. 3fa85f64-57...",
            value: filters.id,
          },
          {
            key: "url",
            type: "text",
            label: "URL",
            placeholder: "e.g. /v1/signers/my-signer",
            value: filters.url,
          },
          {
            key: "from",
            type: "date",
            label: "From",
            value: filters.from,
          },
          {
            key: "to",
            type: "date",
            label: "To",
            value: filters.to,
          },
          {
            key: "user",
            type: "text",
            label: "Requester",
            placeholder: "e.g. alice@keyauthority.net",
            value: filters.user,
          },
        ]}
      />

      <Table hover responsive striped>
        <thead>
          <tr>
            <th>ID</th>
            <th>Requester</th>
            <th>API Call</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {requests.map((req) => (
            <tr key={req.id}>
              <td>{req.id.substring(0, 18) + "..."}</td>
              <td>{req.tokenInfo?.user || "-"}</td>
              <td>
                {req.method} {req.url}
              </td>
              <td>{prettyTime(req.createdAt)}</td>
              <td>
                <div className="d-flex gap-1">
                  <Button
                    variant="outline-secondary"
                    size="sm"
                    title="View Details"
                    onClick={() => handleViewJSON(req)}
                  >
                    <i className="bi bi-eye"></i>
                  </Button>
                  <Button
                    variant="outline-success"
                    size="sm"
                    title="Authorize and Execute with Requester's Token"
                    onClick={() => handleAuthorizeRequest(req.id, false)}
                  >
                    <i className="bi bi-check-lg"></i>
                  </Button>
                  <Button
                    variant="outline-success"
                    size="sm"
                    title="Authorize and Execute with My Own Token"
                    onClick={() => handleAuthorizeRequest(req.id, true)}
                  >
                    <i className="bi bi-person-check-fill"></i>
                  </Button>
                  <Button
                    variant="outline-danger"
                    size="sm"
                    title="Reject Request"
                    onClick={() => handleRejectRequest(req.id)}
                  >
                    <i className="bi bi-x-lg"></i>
                  </Button>
                </div>
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
