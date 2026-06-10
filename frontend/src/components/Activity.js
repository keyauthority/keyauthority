import { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import {
  Alert,
  Button,
  Card,
  Table,
  Row,
  Col,
  Tooltip,
  OverlayTrigger,
  Dropdown,
} from "react-bootstrap";
import {
  showToast,
  downloadOrCopy,
  prettyTime,
  copyToClipboard,
  prettyEnv,
  buildURLParams,
  getRoles,
} from "../utils/utils";
import { errorToString } from "../utils/error";
import { getApi } from "../axios";
import { getKeycloak } from "../keycloak";
import Filters from "./Filters";
import Paginator from "./Paginator";
import JSONModal from "./JSONModal";

export function Dashboard({ isLoading, setIsLoading }) {
  const [error, setError] = useState(null);
  const [certCountByExpiring, setCertCountByExpiring] = useState({});
  const [logCountByLevel, setLogCountByLevel] = useState({});
  const [logCountByMsg, setLogCountByMsg] = useState({});
  const [keyCountByStorage, setKeyCountByStorage] = useState({});
  const [keyCountByType, setKeyCountByType] = useState({});
  const [signerCountByRoot, setSignerCountByRoot] = useState({});
  const [secretCountByUpdated, setSecretCountByUpdated] = useState({});

  const keycloak = getKeycloak();
  const roles = getRoles(keycloak?.tokenParsed || {});
  const isAuditor =
    roles.findIndex((role) => role === "KEYAUTHORITY_AUDITOR") !== -1;

  const api = getApi();
  const infiniteDays = 1000000; // used to count all certs/secrets by using a very large number of days

  const dashboardBody = (cards, colsPerRow = 4) => {
    const safeColsPerRow =
      Number.isInteger(colsPerRow) && colsPerRow > 0 ? colsPerRow : 4;

    const baseSpan = 12 / safeColsPerRow;
    const supportsFill = Number.isInteger(baseSpan); // exact fill only when colsPerRow divides 12
    const remainder = supportsFill ? cards.length % safeColsPerRow : 0;

    return (
      <Row className="g-3">
        {cards.map((card, index) => {
          const isLast = index === cards.length - 1;

          const md =
            supportsFill && isLast && remainder !== 0
              ? 12 - baseSpan * (remainder - 1) // last item fills remaining space
              : supportsFill
                ? baseSpan
                : undefined;
          return (
            <Col xs={12} md={md} key={index}>
              <Alert
                variant="light"
                className="d-flex flex-column justify-content-between gap-1"
              >
                <div className="text-muted small d-flex justify-content-between align-items-start gap-1">
                  {
                    <i
                      className={`${card.iconClass} text-${card.variant || ""}`}
                    ></i>
                  }
                  {card.key}
                </div>
                <h4 className="m-0 text-end">
                  {card.valueReady !== undefined && card.valueReady !== null
                    ? card.value
                    : "-"}
                </h4>
              </Alert>
            </Col>
          );
        })}
      </Row>
    );
  };

  const dashboardSection = (title, iconClass, cards, colsPerRow) => (
    <div className="mb-2">
      <h6 className="mb-3">
        {/* <i className={`${iconClass} me-2`}></i> */}
        {title}
      </h6>
      {dashboardBody(cards, colsPerRow)}
    </div>
  );

  const countCertsByExpiring = async (days) => {
    setIsLoading(true);
    const now = new Date();
    const d = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
    try {
      const params = new URLSearchParams();
      params.set("notAfterFrom", now.toISOString());
      params.set("notAfterTo", d.toISOString());
      params.set("revoked", "false");
      params.set("totalCountOnly", "true");

      const res = await api.get(`/certs?${params.toString()}`);
      setCertCountByExpiring((prev) => ({
        ...prev,
        [days]: res.data.totalCount || 0,
      }));
    } catch (err) {
      // setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  const countLogsByLevel = async (level) => {
    setIsLoading(true);
    const now = new Date();
    const d = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    try {
      const params = new URLSearchParams();
      params.set("level", level);
      params.set("from", d.toISOString());
      params.set("totalCountOnly", "true");

      const res = await api.get(`/logs?${params.toString()}`);
      setLogCountByLevel((prev) => ({
        ...prev,
        [level]: res.data.totalCount || 0,
      }));
    } catch (err) {
      // setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  const countLogsByMsg = async (msg) => {
    setIsLoading(true);
    const now = new Date();
    const d = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    try {
      const params = new URLSearchParams();
      params.set("msg", msg);
      params.set("from", d.toISOString());
      params.set("totalCountOnly", "true");

      const res = await api.get(`/logs?${params.toString()}`);
      setLogCountByMsg((prev) => ({
        ...prev,
        [msg]: res.data.totalCount || 0,
      }));
    } catch (err) {
      // setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  const countKeysByStorage = async (storage) => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("storage", storage);
      params.set("totalCountOnly", "true");

      const res = await api.get(`/keys?${params.toString()}`);
      setKeyCountByStorage((prev) => ({
        ...prev,
        [storage]: res.data.totalCount || 0,
      }));
    } catch (err) {
      // setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  const countKeysByType = async (type) => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("type", type);
      params.set("totalCountOnly", "true");

      const res = await api.get(`/keys?${params.toString()}`);
      setKeyCountByType((prev) => ({
        ...prev,
        [type]: res.data.totalCount || 0,
      }));
    } catch (err) {
      // setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  const countSignersByRoot = async (isRoot) => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("isRoot", isRoot);
      params.set("totalCountOnly", "true");

      const res = await api.get(`/signers?${params.toString()}`);
      setSignerCountByRoot((prev) => ({
        ...prev,
        [isRoot]: res.data.totalCount || 0,
      }));
    } catch (err) {
      // setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  const countSecretsByUpdated = async (daysAgo) => {
    setIsLoading(true);
    const now = new Date();
    const d = new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000);
    try {
      const params = new URLSearchParams();
      params.set("updatedFrom", d.toISOString());
      params.set("totalCountOnly", "true");

      const res = await api.get(`/secrets?${params.toString()}`);
      setSecretCountByUpdated((prev) => ({
        ...prev,
        [daysAgo]: res.data.totalCount || 0,
      }));
    } catch (err) {
      // setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isAuditor) {
      countLogsByLevel("ERROR");
      countLogsByMsg("secret read");
      countLogsByMsg("certificate signed");
      countLogsByMsg("key created");
    }
    countCertsByExpiring(infiniteDays);
    countCertsByExpiring(3);
    countCertsByExpiring(7);
    countCertsByExpiring(30);
    countKeysByStorage("Software");
    countKeysByStorage("HSM");
    countKeysByType("RSA");
    countKeysByType("ECDSA");
    countKeysByType("Ed25519");
    countKeysByType("AES");
    countSignersByRoot(true);
    countSignersByRoot(false);
    countSecretsByUpdated(infiniteDays); // count all secrets by using a very large number of days
    countSecretsByUpdated(60);
  }, [api, isAuditor]);

  return (
    <>
      {error && <Alert variant="danger">{error}</Alert>}

      {isAuditor &&
        dashboardSection(
          "Recent Activity",
          "bi bi-clock-history",
          [
            {
              key: "Errors in Last 24h",
              iconClass: "bi bi-x-circle-fill",
              value: logCountByLevel["ERROR"],
              valueReady: logCountByLevel?.["ERROR"],
              variant: "danger",
            },
            // {
            //   key: "Keys Created in Last 24h",
            //   iconClass: "bi bi-key-fill",
            //   value: logCountByMsg["key created"],
            //   valueReady: logCountByMsg?.["key created"],
            // },
            {
              key: "Certificates Signed in Last 24h",
              iconClass: "bi bi-award-fill",
              value: logCountByMsg["certificate signed"],
              valueReady: logCountByMsg?.["certificate signed"],
            },
            {
              key: "Secrets Read in Last 24h",
              iconClass: "bi bi-lock-fill",
              value: logCountByMsg["secret read"],
              valueReady: logCountByMsg?.["secret read"],
            },
          ],
          3,
        )}

      {dashboardSection(
        "Certificates",
        "bi bi-award",
        [
          {
            key: "Valid and Not Expiring Soon",
            iconClass: "bi bi-check-circle-fill",
            value: certCountByExpiring[infiniteDays] - certCountByExpiring[30], // all valid certs minus those expiring in ≤30 days
            valueReady:
              certCountByExpiring?.[infiniteDays] && certCountByExpiring?.[30],
            variant: "success",
          },
          {
            key: "Valid and Expiring in ≤3d",
            iconClass: "bi bi-exclamation-circle-fill",
            value: certCountByExpiring[3],
            valueReady: certCountByExpiring?.[3],
            variant: "danger",
          },
          // {
          //   key: "Valid and Expiring in ≤7d",
          //   iconClass: "bi bi-exclamation-triangle-fill",
          //   value: certCountByExpiring[7],
          //   valueReady: certCountByExpiring?.[7],
          //   variant: "warning",
          // },
          {
            key: "Valid and Expiring in ≤30d",
            iconClass: "bi bi-exclamation-triangle-fill",
            value: certCountByExpiring[30],
            valueReady: certCountByExpiring?.[30],
            variant: "warning",
          },
        ],
        3,
      )}

      {dashboardSection(
        "Keys",
        "bi bi-key",
        [
          {
            key: "Software",
            iconClass: "bi bi-laptop",
            value: keyCountByStorage["Software"],
            valueReady: keyCountByStorage?.["Software"],
          },
          {
            key: "HSM",
            iconClass: "bi bi-safe",
            value: keyCountByStorage["HSM"],
            valueReady: keyCountByStorage?.["HSM"],
          },
          {
            key: "RSA",
            value: keyCountByType["RSA"],
            valueReady: keyCountByType?.["RSA"],
          },
          {
            key: "ECDSA",
            value: keyCountByType["ECDSA"],
            valueReady: keyCountByType?.["ECDSA"],
          },
          {
            key: "Ed25519",
            value: keyCountByType["Ed25519"],
            valueReady: keyCountByType?.["Ed25519"],
          },
          {
            key: "AES",
            value: keyCountByType["AES"],
            valueReady: keyCountByType?.["AES"],
          },
        ],
        6,
      )}

      {dashboardSection(
        "Signers",
        "bi bi-pen",
        [
          {
            key: "Root CAs",
            iconClass: "bi bi-award-fill",
            value: signerCountByRoot[true],
            valueReady: signerCountByRoot?.[true],
          },
          {
            key: "Intermediate CAs",
            iconClass: "bi bi-award",
            value: signerCountByRoot[false],
            valueReady: signerCountByRoot?.[false],
          },
        ],
        2,
      )}

      {dashboardSection(
        "Secrets",
        "bi bi-three-dots",
        [
          {
            key: "Updated in Last 60d",
            iconClass: "bi bi-check-circle-fill",
            value: secretCountByUpdated[60],
            valueReady: secretCountByUpdated?.[60],
            variant: "success",
          },
          {
            key: "Not Updated in Last 60d",
            iconClass: "bi bi-clock-fill",
            value:
              secretCountByUpdated[infiniteDays] - secretCountByUpdated[60],
            valueReady:
              secretCountByUpdated?.[infiniteDays] &&
              secretCountByUpdated?.[60],
            variant: "warning",
          },
        ],
        2,
      )}
    </>
  );
}

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
      const params = buildURLParams(filters, page, pageSize);
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
        colsPerRow={4}
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
          {
            key: "comment",
            type: "text",
            label: "Comment",
            value: filters.comment,
            placeholder: "e.g. Issued for Alice's laptop",
          },
        ]}
      />

      <Table hover responsive striped className="align-middle">
        <thead>
          <tr>
            <th>Status</th>
            <th>Serial</th>
            <th>CN/SAN</th>
            <th>Valid From</th>
            <th>Valid To</th>
            <th>Signer</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {certs.map((cert) => (
            <tr key={cert.serial}>
              <td>
                {cert.revoked ? (
                  <OverlayTrigger overlay={<Tooltip>Revoked</Tooltip>}>
                    <i className="bi bi-x-circle-fill text-danger"></i>
                  </OverlayTrigger>
                ) : new Date(cert.notAfter) < new Date() ? (
                  <OverlayTrigger overlay={<Tooltip>Expired</Tooltip>}>
                    <i className="bi bi-clock-fill text-danger"></i>
                  </OverlayTrigger>
                ) : new Date(cert.notBefore) > new Date() ? (
                  <OverlayTrigger overlay={<Tooltip>Not Valid Yet</Tooltip>}>
                    <i className="bi bi-clock-fill text-warning"></i>
                  </OverlayTrigger>
                ) : (
                  <OverlayTrigger overlay={<Tooltip>Valid</Tooltip>}>
                    <i className="bi bi-check-circle-fill text-success"></i>
                  </OverlayTrigger>
                )}
              </td>
              <td
                style={{ maxWidth: "12rem" }}
                className="text-truncate"
                //className={`${cert.revoked ? "text-decoration-line-through" : ""} text-truncate`}
              >
                {cert.serial}
              </td>
              <td>
                {cnAndSan(cert).length > 0 ? cnAndSan(cert).join(", ") : "-"}
              </td>
              <td>{prettyTime(cert.notBefore)}</td>
              <td>{prettyTime(cert.notAfter)}</td>
              <td>{cert.signerName}</td>
              <td>
                <Dropdown>
                  <Dropdown.Toggle
                    as={Link}
                    className="no-caret"
                    id={`dropdown-${cert.serial}`}
                  >
                    <i className="bi-three-dots-vertical"></i>
                  </Dropdown.Toggle>
                  <Dropdown.Menu>
                    <Dropdown.Item
                      onClick={() => {
                        setModalData(cert);
                        setModalTitle(`Certificate: ${cert.serial}`);
                        setShowModal(true);
                      }}
                    >
                      <i className="bi bi-eye me-1"></i> View as JSON
                    </Dropdown.Item>
                    {/*<Dropdown.Item
                      as={Link}
                      to={`/signers/${encodeURIComponent(cert.signerName)}`}
                    >
                      <i className="bi bi-pen me-1"></i> Go to Signer
                    </Dropdown.Item>*/}
                    <Dropdown.Item onClick={() => copyPEM(cert)}>
                      <i className="bi bi-clipboard me-1"></i> Copy PEM
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
      const params = buildURLParams(filters, page, pageSize);
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
        colsPerRow={4}
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

      <Table hover responsive striped className="align-middle">
        <thead>
          <tr>
            <th>Level</th>
            <th>Message</th>
            <th>User</th>
            <th>Environment</th>
            <th>API Call</th>
            <th>Time</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, index) => (
            <tr key={index}>
              <td>
                <OverlayTrigger overlay={<Tooltip>{log.level}</Tooltip>}>
                  {(() => {
                    switch (log.level) {
                      case "ERROR":
                        return (
                          <i className="bi bi-x-circle-fill text-danger"></i>
                        );
                      case "WARN":
                        return (
                          <i className="bi bi-exclamation-triangle-fill text-warning"></i>
                        );
                      case "INFO":
                        return (
                          <i className="bi bi-info-circle-fill text-info"></i>
                        );
                      case "DEBUG":
                        return (
                          <i className="bi bi-bug-fill text-secondary"></i>
                        );
                      default:
                        return (
                          <i
                            className={`bi bi-circle-fill text-${levelVariant[log.level] || "secondary"}`}
                          ></i>
                        );
                    }
                  })()}
                </OverlayTrigger>
              </td>
              <td style={{ maxWidth: "12rem" }}>{log.msg}</td>
              <td>{log.token?.user || "-"}</td>
              <td>{log.environment ? prettyEnv(log.environment) : "-"}</td>
              <td>
                {log.method && log.url ? (
                  <>
                    {log.method} {log.url.split("?")[0]}
                  </>
                ) : (
                  "-"
                )}
              </td>
              <td>{prettyTime(log.time)}</td>
              <td>
                <Dropdown>
                  <Dropdown.Toggle
                    as={Link}
                    className="no-caret"
                    id={`dropdown-${index}`}
                  >
                    <i className="bi-three-dots-vertical"></i>
                  </Dropdown.Toggle>
                  <Dropdown.Menu>
                    <Dropdown.Item
                      onClick={() => {
                        setModalTitle(`Log Entry: ${log.msg}`);
                        setModalData(log);
                        setShowModal(true);
                      }}
                    >
                      <i className="bi bi-eye me-1"></i> View as JSON
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
      const params = buildURLParams(filters, page, pageSize);
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

  const handleApproveRequest = async (requestID, useOwnToken) => {
    const confirmed = window.confirm(
      `Are you sure you want to approve the request '${requestID}'?`,
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
            `Request '${requestID}' approved!`,
            files[requestID].data,
            `response-${requestID}.${contentTypeToExtension[files[requestID].contentTypeFromHeader] || "txt"}`,
          ),
        )}
      </div>

      <Filters
        filters={filters}
        setFilters={setFilters}
        colsPerRow={3}
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

      <Table hover responsive striped className="align-middle">
        <thead>
          <tr>
            <th>ID</th>
            <th>Requester</th>
            <th>API Call</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {requests.map((req) => (
            <tr key={req.id}>
              <td style={{ maxWidth: "12rem" }} className="text-truncate">
                {req.id}
              </td>
              <td>{req.tokenInfo?.user || "-"}</td>
              <td>
                {req.method && req.url ? (
                  <>
                    {req.method} {req.url.split("?")[0]}
                  </>
                ) : (
                  "-"
                )}
              </td>
              <td>{prettyTime(req.createdAt)}</td>
              <td>
                <Dropdown>
                  <Dropdown.Toggle
                    as={Link}
                    className="no-caret"
                    id={`dropdown-${req.id}`}
                  >
                    <i className="bi-three-dots-vertical"></i>
                  </Dropdown.Toggle>
                  <Dropdown.Menu>
                    <Dropdown.Item onClick={() => handleViewJSON(req)}>
                      <i className="bi bi-eye me-1"></i> View as JSON
                    </Dropdown.Item>
                    <Dropdown.Divider />
                    <Dropdown.Item
                      onClick={() => handleApproveRequest(req.id, false)}
                    >
                      <i className="bi bi-check-lg me-1"></i> Approve with
                      Requester's Token
                    </Dropdown.Item>
                    <Dropdown.Item
                      onClick={() => handleApproveRequest(req.id, true)}
                    >
                      <i className="bi bi-person-check-fill me-1"></i> Approve
                      with My Own Token
                    </Dropdown.Item>
                    <Dropdown.Divider />
                    <Dropdown.Item onClick={() => handleRejectRequest(req.id)}>
                      <i className="bi bi-x-lg me-1"></i> Reject
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
