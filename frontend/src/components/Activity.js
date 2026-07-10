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
  const [dashboard, setDashboard] = useState(null);

  const keycloak = getKeycloak();
  const roles = getRoles(keycloak?.tokenParsed || {});
  const isAuditor =
    roles.findIndex((role) => role === "KEYAUTHORITY_AUDITOR") !== -1;

  const api = getApi();

  useEffect(() => {
    let cancelled = false;

    const loadDashboard = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const res = await api.get("/dashboard");
        if (!cancelled) {
          setDashboard(res.data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(errorToString(err));
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    };

    loadDashboard();

    return () => {
      cancelled = true;
    };
  }, [api, setIsLoading]);

  const dashboardBody = (cards, colsPerRow = 4) => {
    const safeColsPerRow =
      Number.isInteger(colsPerRow) && colsPerRow > 0 ? colsPerRow : 4;

    const baseSpan = 12 / safeColsPerRow;
    const supportsFill = Number.isInteger(baseSpan);
    const remainder = supportsFill ? cards.length % safeColsPerRow : 0;

    return (
      <Row className="g-3">
        {cards.map((card, index) => {
          const isLast = index === cards.length - 1;

          const md =
            supportsFill && isLast && remainder !== 0
              ? 12 - baseSpan * (remainder - 1)
              : supportsFill
                ? baseSpan
                : undefined;

          return (
            <Col xs={12} md={md} key={index}>
              <Card>
                <Card.Header>{card.key}</Card.Header>
                <Card.Body>
                  <h4 className={`m-0 text-${card.variant || ""}`}>
                    {card.valueReady !== undefined && card.valueReady !== null
                      ? card.value
                      : "-"}
                  </h4>
                </Card.Body>
              </Card>
            </Col>
          );
        })}
      </Row>
    );
  };

  const dashboardSection = (title, iconClass, cards, colsPerRow) => (
    <div className="mt-3">
      <h6 className="mb-3">{title}</h6>
      {dashboardBody(cards, colsPerRow)}
    </div>
  );

  if (!dashboard) {
    return null;
  }

  return (
    <>
      {error && <Alert variant="danger">{error}</Alert>}

      {isAuditor &&
        dashboardSection(
          "Activity in the Last 24h",
          "bi bi-clock-history",
          [
            {
              key: "Errors",
              iconClass: "bi bi-x-circle-fill",
              value: dashboard.logs.errorCount24h,
              valueReady: dashboard.logs !== undefined,
              variant: "danger",
            },
            {
              key: "Certificates Signed",
              iconClass: "bi bi-award-fill",
              value: dashboard.logs.certificatesSignedCount24h,
              valueReady: dashboard.logs !== undefined,
            },
            {
              key: "Secret Read Requests",
              iconClass: "bi bi-lock-fill",
              value: dashboard.logs.secretReadCount24h,
              valueReady: dashboard.logs !== undefined,
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
            value: dashboard.certs.notExpiringSoon,
            valueReady: dashboard.certs !== undefined,
            variant: "success",
          },
          {
            key: "Valid and Expiring Within 3 Days",
            iconClass: "bi bi-exclamation-circle-fill",
            value: dashboard.certs.expiringIn3Days,
            valueReady: dashboard.certs !== undefined,
            variant: "danger",
          },
          {
            key: "Valid and Expiring Within 30 Days",
            iconClass: "bi bi-exclamation-triangle-fill",
            value: dashboard.certs.expiringIn30Days,
            valueReady: dashboard.certs !== undefined,
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
            value: dashboard.keys.softwareTotal,
            valueReady: dashboard.keys !== undefined,
          },
          {
            key: "HSM",
            iconClass: "bi bi-safe",
            value: dashboard.keys.hsmTotal,
            valueReady: dashboard.keys !== undefined,
          },
          {
            key: "RSA",
            value: dashboard.keys.rsaTotal,
            valueReady: dashboard.keys !== undefined,
          },
          {
            key: "ECDSA",
            value: dashboard.keys.ecdsaTotal,
            valueReady: dashboard.keys !== undefined,
          },
          {
            key: "Ed25519",
            value: dashboard.keys.ed25519Total,
            valueReady: dashboard.keys !== undefined,
          },
          {
            key: "AES",
            value: dashboard.keys.aesTotal,
            valueReady: dashboard.keys !== undefined,
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
            value: dashboard.signers.rootTotal,
            valueReady: dashboard.signers !== undefined,
          },
          {
            key: "Intermediate CAs",
            iconClass: "bi bi-award",
            value: dashboard.signers.intermediateTotal,
            valueReady: dashboard.signers !== undefined,
          },
        ],
        2,
      )}

      {dashboardSection(
        "Secrets",
        "bi bi-three-dots",
        [
          {
            key: "Updated in the Last 60 Days",
            iconClass: "bi bi-check-circle-fill",
            value: dashboard.secrets.updatedInLast60Days,
            valueReady: dashboard.secrets !== undefined,
            variant: "success",
          },
          {
            key: "Not Updated in the Last 60 Days",
            iconClass: "bi bi-clock-fill",
            value: dashboard.secrets.notUpdatedInLast60Days,
            valueReady: dashboard.secrets !== undefined,
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
  const [filters, setFilters] = useState({});

  const [showModal, setShowModal] = useState(false);
  const [modalTitle, setModalTitle] = useState(null);
  const [modalData, setModalData] = useState(null);

  const api = getApi();

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
            label: "Common Name",
            value: filters.cn,
            placeholder: "e.g. example.com",
          },
          {
            key: "san",
            type: "text",
            label: "SAN",
            value: filters.san,
            placeholder: "e.g. www.example.com",
            colSpan: 4,
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
            colSpan: 2,
          },
          {
            key: "notBeforeFrom",
            type: "date",
            label: "Not Before From",
            value: filters.notBeforeFrom,
          },
          {
            key: "notBeforeTo",
            type: "date",
            label: "Not Before To",
            value: filters.notBeforeTo,
          },
          {
            key: "notAfterFrom",
            type: "date",
            label: "Not After From",
            value: filters.notAfterFrom,
          },
          {
            key: "notAfterTo",
            type: "date",
            label: "Not After To",
            value: filters.notAfterTo,
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
                    <i className="bi-three-dots-vertical mx-1"></i>
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
        setError={setError}
        isLoading={isLoading}
        setIsLoading={setIsLoading}
        filters={filters}
        items={certs}
        setItems={setCerts}
        apiPath="/certs"
        orderCol="notBefore"
        idCol="serial"
      />
    </>
  );
}

export function Logs({ isLoading, setIsLoading, setDropdownActions }) {
  const [error, setError] = useState(null);
  const [logs, setLogs] = useState([]);
  const [filters, setFilters] = useState({});

  const [showModal, setShowModal] = useState(false);
  const [modalTitle, setModalTitle] = useState(null);
  const [modalData, setModalData] = useState(null);

  const api = getApi();

  const levelVariant = {
    ERROR: "danger",
    WARN: "warning",
    INFO: "info",
    DEBUG: "secondary",
  };

  const handleExportLogs = useCallback(async () => {
    showToast("warning", "Sorry, feature not implemented yet.");
    return;

    /*setIsLoading(true);

    const flattenLogItem = (item) => {
      // convert logs JSONs to .log format
      // for example: [2024-01-01T00:00:00.000Z] INFO key created {...}
      const { time, level, msg, ...rest } = item;
      return `[${new Date(time).toISOString()}] ${level.toUpperCase()} ${msg} ${Object.keys(rest).length > 0 ? JSON.stringify(rest) : ""}`;
    };

    try {
      const logContent = logs.map(flattenLogItem).join("\n");
      const blob = new Blob([logContent], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `keyauthority-logs-${Date.now()}.log`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }*/
  }, [api, filters, setIsLoading]);

  useEffect(() => {
    setDropdownActions?.([
      {
        key: "export-logs",
        label: "Export",
        iconClass: "bi bi-download",
        onClick: () => handleExportLogs(),
      },
    ]);
    return () => setDropdownActions?.([]);
  }, [setDropdownActions, handleExportLogs]);

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
            key: "level",
            type: "select",
            label: "Level",
            value: filters.level,
            colSpan: 2,
            options: [
              { value: "", label: "-" },
              { value: "ERROR", label: "ERROR" },
              { value: "WARN", label: "WARN" },
              { value: "INFO", label: "INFO" },
              // { value: "DEBUG", label: "DEBUG" },
            ],
          },
          {
            key: "msg",
            type: "text",
            label: "Message",
            placeholder: "e.g. secret read",
            value: filters.msg,
          },
          {
            key: "user",
            type: "text",
            label: "User",
            placeholder: "e.g. alice@keyauthority.net",
            value: filters.user,
            colSpan: 4,
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
            colSpan: 5,
          },
          {
            key: "from",
            type: "date",
            label: "From",
            value: filters.from,
            colSpan: 4,
          },
          {
            key: "to",
            type: "date",
            label: "To",
            value: filters.to,
            colSpan: 3,
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
                    <i className="bi-three-dots-vertical mx-1"></i>
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
        setError={setError}
        isLoading={isLoading}
        setIsLoading={setIsLoading}
        filters={filters}
        items={logs}
        setItems={setLogs}
        apiPath="/logs"
        orderCol="time"
        idCol="logEntryID"
      />
    </>
  );
}

export function PendingRequests({ isLoading, setIsLoading }) {
  const [error, setError] = useState(null);
  const [requests, setRequests] = useState([]);
  const [files, setFiles] = useState({});
  const [filters, setFilters] = useState({});

  const [refreshTrigger, setRefreshTrigger] = useState(0); // used to trigger re-fetching requests after approving/rejecting

  const [showModal, setShowModal] = useState(false);
  const [modalTitle, setModalTitle] = useState(null);
  const [modalData, setModalData] = useState(null);

  const api = getApi();

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
      setRefreshTrigger((prev) => prev + 1); // trigger re-fetching requests
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
      setRefreshTrigger((prev) => prev + 1); // trigger re-fetching requests
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
        filtersTemplate={[
          {
            key: "id",
            type: "text",
            label: "ID",
            placeholder: "e.g. 3fa85f64-57...",
            value: filters.id,
          },
          {
            key: "user",
            type: "text",
            label: "Requester",
            placeholder: "e.g. alice@keyauthority.net",
            value: filters.user,
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
                    <i className="bi-three-dots-vertical mx-1"></i>
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
        key={`pending-requests-paginator-${refreshTrigger}`}
        setError={setError}
        isLoading={isLoading}
        setIsLoading={setIsLoading}
        filters={filters}
        items={requests}
        setItems={setRequests}
        apiPath="/pending-requests"
        orderCol="createdAt"
        idCol="id"
      />
    </>
  );
}
