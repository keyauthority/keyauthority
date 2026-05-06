import { useEffect, useState, useCallback } from "react";
import { useLocation } from "react-router-dom";
import {
  Card,
  Alert,
  Form,
  Button,
  Tabs,
  Tab,
  Row,
  Col,
} from "react-bootstrap";
import {
  showToast,
  parseChain,
  downloadOrCopy,
  prettyTime,
  copyToClipboard,
  prettyCode,
  boxedContent,
} from "../utils/utils";
import { Link } from "react-router-dom";
import JSONModal from "./JSONModal";
import { errorToString } from "../utils/error";
import { getApi } from "../axios";
import { signerUsageExample } from "./Docs";
import KeyValueTable from "./KeyValueTable";

function SignerDetails({ isLoading, setIsLoading, setTitle, setSubtitle }) {
  const location = useLocation();
  const signerName =
    decodeURIComponent(location.pathname.replaceAll("/signers/", "")) || "";

  // these are all loaded from the CA Chain Tab,
  // but we need them here in the parent component to pass down to other tabs
  const [hasWarnings, setHasWarnings] = useState(false);
  const [canSign, setCanSign] = useState(false);
  const [signerConfig, setSignerConfig] = useState(null);

  const api = getApi();

  const apiUrl = new URL(api.defaults.baseURL);
  const apiRootUrl = apiUrl.href.replace(/\/v1\/?$/, "");

  const [error, setError] = useState("");

  useEffect(() => {
    setTitle(signerName);
  }, [signerName, setTitle, signerConfig]);

  useEffect(() => {
    setSubtitle(
      signerConfig ? (
        <div>
          <i className="bi bi-award me-1"></i>{" "}
          {signerConfig?.caTemplate?.subject?.commonName}
        </div>
      ) : null,
    );
  }, [signerConfig, setSubtitle]);

  return (
    <>
      {error && <Alert variant="danger">{error || "An error occurred."}</Alert>}

      <Tabs className="mb-3">
        {/* Config Tab */}
        <Tab eventKey="config" title="Configuration">
          <ConfigTab
            signerName={signerName}
            isLoading={isLoading}
            signerConfig={signerConfig}
            setSignerConfig={setSignerConfig}
            setIsLoading={setIsLoading}
            setError={setError}
          />
        </Tab>

        {/* CA CSR & Chain Tab */}
        <Tab
          eventKey="chain"
          title={
            <div>
              CA CSR & Chain{" "}
              {hasWarnings && (
                <i className="bi bi-exclamation-triangle ms-1"></i>
              )}
            </div>
          }
        >
          <CSRAndChainTab
            signerName={signerName}
            isLoading={isLoading}
            setIsLoading={setIsLoading}
            setHasWarnings={setHasWarnings}
            setCanSign={setCanSign}
          />
        </Tab>

        {/* Sign Certificate Tab */}
        <Tab eventKey="sign" title="Sign Certificate" disabled={!canSign}>
          <SignCertificateTab
            signerName={signerName}
            isLoading={isLoading}
            setIsLoading={setIsLoading}
          />
        </Tab>

        {/* Revoke Tab */}
        <Tab eventKey="revoke" title="Revoke Certificate" disabled={!canSign}>
          <RevokeCertificateTab
            signerName={signerName}
            isLoading={isLoading}
            setIsLoading={setIsLoading}
          />
        </Tab>

        {/* Sign Doc Tab */}
        <Tab
          eventKey="signdoc"
          title="Sign Document (beta)"
          disabled={!canSign || signerConfig?.isCA}
        >
          <SignDocumentTab
            signerName={signerName}
            isLoading={isLoading}
            setIsLoading={setIsLoading}
          />
        </Tab>
        {/* Usage Examples Tab */}
        <Tab
          eventKey="examples"
          title="Usage Examples"
          disabled={signerConfig?.isCA}
        >
          {signerUsageExample(signerName, apiRootUrl)}
        </Tab>
      </Tabs>
    </>
  );
}

function ConfigTab({
  signerName,
  signerConfig,
  setSignerConfig,
  isLoading,
  setIsLoading,
  setError,
}) {
  const [privateKeyConfig, setPrivateKeyConfig] = useState(null);

  const [showKeyModal, setShowKeyModal] = useState(false);
  const [keyModalTitle, setKeyModalTitle] = useState("");
  const [keyModalData, setKeyModalData] = useState(null);

  const api = getApi();

  const fetchConfig = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await api.get(`/signers/${signerName}/config`);
      setSignerConfig(res.data || {});
    } catch (err) {
      //showToast("error", errorToString(err));
      setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  }, [api, signerName, setIsLoading, setSignerConfig, setError]);

  const fetchPrivateKeyConfig = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await api.get(`/signers/${signerName}/private-key`);
      const privateKeyID = res.data;
      const res2 = await api.get(`/keys/${privateKeyID}`);
      setPrivateKeyConfig(res2.data);
    } catch (err) {
      //showToast("error", errorToString(err));
      setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  }, [api, signerName, setIsLoading, setError]);

  useEffect(() => {
    fetchConfig();
  }, [fetchConfig]);

  useEffect(() => {
    fetchPrivateKeyConfig();
  }, [fetchPrivateKeyConfig]);

  const handleShowKey = async (keyID) => {
    setIsLoading(true);
    try {
      const res = await api.get(`/keys/${keyID}`);
      setKeyModalData(res.data);
      setKeyModalTitle(`Private Key: ${keyID}`);
      setShowKeyModal(true);
    } catch (err) {
      setError(errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    signerConfig &&
    privateKeyConfig && (
      <>
        <JSONModal
          show={showKeyModal}
          onHide={() => setShowKeyModal(false)}
          modalTitle={keyModalTitle}
          modalData={keyModalData}
        />

        <Row>
          {/* Private Key Section */}
          <Col md={6} className="mb-3">
            <Card>
              <Card.Header>Private Key</Card.Header>
              <Card.Body>
                <KeyValueTable
                  body={{
                    ID: (
                      <Link
                        style={{ textDecoration: "none" }}
                        className="text-body"
                        onClick={() => handleShowKey(privateKeyConfig.id)}
                      >
                        {privateKeyConfig.id}
                      </Link>
                    ),
                    Type: (
                      <div className="d-flex align-items-center gap-2">
                        <div>{privateKeyConfig.config.type}</div>
                        <div>
                          {privateKeyConfig.config.pkcs11URI ? (
                            <div className="d-flex gap-2 align-items-center">
                              <i className="bi bi-safe"></i>HSM
                            </div>
                          ) : (
                            <div className="d-flex gap-2 align-items-center">
                              <i className="bi bi-laptop"></i>Software
                            </div>
                          )}
                        </div>
                      </div>
                    ),
                    Bits: privateKeyConfig.config.bits || null,
                    Curve: privateKeyConfig.config.curve || null,
                    // "PKCS11 URI": privateKeyConfig.config.pkcs11URI || null,
                    // "PKCS11 Key URI": privateKeyConfig.config.pkcs11KeyURI || null,
                  }}
                  keysClass="fw-bold"
                />
              </Card.Body>
            </Card>
          </Col>

          {/* CA Template Section */}
          <Col md={6} className="mb-3">
            <Card>
              <Card.Header>CA Template</Card.Header>
              <Card.Body>
                <KeyValueTable
                  body={{
                    "Common Name": signerConfig.caTemplate.subject.commonName,
                    Country: signerConfig.caTemplate.subject.country
                      ? signerConfig.caTemplate.subject.country.join(", ")
                      : null,
                    Organization: signerConfig.caTemplate.subject.organization
                      ? signerConfig.caTemplate.subject.organization.join(", ")
                      : null,
                    "Organizational Unit": signerConfig.caTemplate.subject
                      .organizationalUnit
                      ? signerConfig.caTemplate.subject.organizationalUnit.join(
                          ", ",
                        )
                      : null,
                    Locality: signerConfig.caTemplate.subject.locality
                      ? signerConfig.caTemplate.subject.locality.join(", ")
                      : null,
                    Province: signerConfig.caTemplate.subject.province
                      ? signerConfig.caTemplate.subject.province.join(", ")
                      : null,
                    "Street Address": signerConfig.caTemplate.subject
                      .streetAddress
                      ? signerConfig.caTemplate.subject.streetAddress.join(", ")
                      : null,
                    "Postal Code": signerConfig.caTemplate.subject.postalCode
                      ? signerConfig.caTemplate.subject.postalCode.join(", ")
                      : null,
                  }}
                  keysClass="fw-bold"
                />
              </Card.Body>
            </Card>
          </Col>

          {/* Certificate Template Section */}
          <Col md={6} className="mb-3">
            <Card>
              <Card.Header>Certificate Template</Card.Header>
              <Card.Body>
                <KeyValueTable
                  body={{
                    "Is CA": signerConfig.isCA ? (
                      <div className="d-flex gap-2 align-items-start">
                        <i className="bi bi-check-circle"></i>Yes
                      </div>
                    ) : (
                      <div className="d-flex gap-2 align-items-start">
                        <i className="bi bi-x-circle"></i>No
                      </div>
                    ),
                    CDP: signerConfig.cdp
                      ? signerConfig.cdp.map((cdp, idx) => (
                          <div
                            key={idx}
                            className="d-flex gap-2 align-items-start"
                          >
                            <a
                              href={cdp}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              <i className="bi bi-download"></i>
                            </a>
                            {cdp}
                          </div>
                        ))
                      : "-",
                  }}
                  keysClass="fw-bold"
                />
              </Card.Body>
            </Card>
          </Col>

          {/* Policy Section */}
          <Col md={6} className="mb-3">
            <Card>
              <Card.Header>Policy</Card.Header>
              <Card.Body>
                <KeyValueTable
                  body={{
                    "Allowed Key Usages":
                      signerConfig.allowedKeyUsages?.length > 0
                        ? signerConfig.allowedKeyUsages.map((ku, idx) => (
                            <div key={idx}>{ku}</div>
                          ))
                        : "-",
                    "Allowed Domains":
                      signerConfig?.allowedDomains?.length > 0
                        ? signerConfig.allowedDomains.map((d, idx) => (
                            <div key={idx}>{d}</div>
                          ))
                        : ".*",
                    "Max TTL": signerConfig.maxTTL,
                    "Additional Authorization": signerConfig.authzRequired ? (
                      <div className="d-flex gap-2 align-items-start">
                        <i className="bi bi-exclamation-circle text-warning"></i>
                        Required for non-trivial requests
                      </div>
                    ) : (
                      <>Not required</>
                    ),
                  }}
                  keysClass="fw-bold"
                />
              </Card.Body>
            </Card>
          </Col>
        </Row>
      </>
    )
  );
}

function CSRAndChainTab({
  signerName,
  isLoading,
  setIsLoading,
  setHasWarnings,
  setCanSign,
}) {
  const [caCSR, setCACSR] = useState(null);
  const [caChain, setCAChain] = useState(null);
  const [signerConfig, setSignerConfig] = useState(null);
  const [newChain, setNewChain] = useState("");
  const [warnings, setWarnings] = useState([]);

  const api = getApi();

  const fecthConfig = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await api.get(`/signers/${signerName}/config`);
      setSignerConfig(res.data || null);
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  }, [api, signerName]);

  const fetchCAChain = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await api.get(`/signers/${signerName}/ca-chain`);
      if (res.data) {
        setCAChain(parseChain(res.data));
      }
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  }, [api, signerName, setIsLoading]);

  useEffect(() => {
    fecthConfig();
  }, [fecthConfig]);

  const handleSetChain = async () => {
    setIsLoading(true);
    try {
      await api.put(`/signers/${signerName}/ca-chain`, newChain);
      setCAChain(parseChain(newChain));
      setNewChain("");
      showToast("success", "CA chain updated!");
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  const createWarnings = useCallback(() => {
    let warns = [];
    let canSign = true;

    // No CA chain
    if (!caChain || caChain.length === 0) {
      canSign = false;
      if (signerConfig?.isCA) {
        warns.push(
          "No CA chain found, thus can only sign certificates for self.",
        );
        canSign = true; // allow self-signing but with warning
      } else
        warns.push(
          "No CA chain found and signer is not a CA signer, thus cannot sign any certificates.",
        );
    }

    // Check for mismatch between signerConfig and caChain[0]
    if (
      signerConfig?.caTemplate?.subject?.commonName &&
      caChain &&
      caChain.length > 0
    ) {
      const certCN = caChain[0].subject.match(/CN=([^,/]+)/);
      const caTemplateCN = signerConfig.caTemplate.subject.commonName;

      if (caTemplateCN !== certCN?.[1]) {
        warns.push(
          `The subject in the CA certificate ('${certCN?.[1]}') does not match the one in the CA template ('${caTemplateCN}'). This is likely because the signer CA template was updated after the CA chain was last set.`,
        );
      }
    }

    // Check for expiration soon
    if (caChain && caChain.length > 0) {
      const now = new Date();
      const soon = new Date();
      soon.setDate(now.getDate() + 30); // 30 days from now

      const notAfter = new Date(caChain[0].notAfter);
      if (notAfter < now) {
        warns.push("The CA certificate has expired.");
      } else if (notAfter < soon) {
        warns.push(
          `The CA certificate will expire soon, on ${prettyTime(notAfter)}.`,
        );
      }
    }

    if (caChain && caChain.length > 0) {
      const lastCert = caChain[caChain.length - 1];
      if (lastCert.issuer !== lastCert.subject) {
        warns.push(
          "The CA chain does not end with a self-signed (root) certificate, which may cause trust issues for some clients.",
        );
      }
    }
    setWarnings(warns);
    setHasWarnings(warns.length > 0);
    setCanSign(canSign);
  }, [caChain, signerConfig, setHasWarnings, setCanSign]);

  useEffect(() => {
    fetchCAChain();
  }, [fetchCAChain]);

  useEffect(() => {
    createWarnings();
  }, [createWarnings]);

  const handleCreateCSR = async () => {
    setIsLoading(true);
    try {
      const response = await api.get(`/signers/${signerName}/ca-csr`);
      setCACSR(response.data);
      // showToast("success", "CA CSR created!");
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Row>
      {/* Show warnings if any */}
      {warnings?.map((w, i) => (
        <Col md={12} key={i}>
          <Alert variant="warning">{w}</Alert>
        </Col>
      ))}

      {/* Create CA CSR */}
      <Col md={12} className="mb-3">
        <Button onClick={() => handleCreateCSR()} disabled={isLoading}>
          Create CA CSR
        </Button>
        {caCSR &&
          downloadOrCopy("CA CSR created!", caCSR, "ca-csr.pem", "mt-3 mb-0")}
      </Col>

      {/* Show CA Chain */}
      {caChain?.length > 0 && (
        <Col md={6} className="mb-3">
          {[...caChain].map((cert, index) => {
            return (
              <Card className="mb-3" key={index}>
                <Card.Header>
                  Certificate {index + 1} -{" "}
                  {cert.subject === cert.issuer ? "Root" : "Intermediate"}
                </Card.Header>
                <Card.Body>
                  <KeyValueTable
                    body={{
                      Serial: cert.serial,
                      Subject: cert.subject,
                      Issuer: cert.issuer,
                      "Not Before": prettyTime(cert.notBefore),
                      "Not After": prettyTime(cert.notAfter),
                      PEM: (
                        <Button
                          variant="outline-secondary"
                          size="sm"
                          onClick={() => {
                            copyToClipboard(cert.pem, "PEM copied!");
                          }}
                        >
                          <i className="bi bi-clipboard"></i>
                        </Button>
                      ),
                    }}
                    keysClass="fw-bold"
                  />
                </Card.Body>
              </Card>
            );
          })}
        </Col>
      )}

      {/* Update CA Chain */}
      <Col md={caChain?.length > 0 ? 6 : 12} className="mb-3">
        <Form.Group className="mb-3">
          <Form.Control
            as="textarea"
            rows={10}
            placeholder="Enter PEM-encoded chain of certificates"
            value={newChain}
            onChange={(e) => setNewChain(e.target.value)}
          />
        </Form.Group>
        <div className="d-flex justify-content-end">
          <Button
            variant="primary"
            onClick={handleSetChain}
            disabled={!newChain || isLoading}
          >
            Update CA Chain
          </Button>
        </div>
      </Col>
    </Row>
  );
}

function SignCertificateTab({ signerName, isLoading, setIsLoading }) {
  const [csr, setCSR] = useState("");
  const [ttl, setTTL] = useState(720);
  const [comment, setComment] = useState("");
  const [signedCert, setSignedCert] = useState("");
  const api = getApi();

  useEffect(() => {
    setCSR("");
    setTTL(720);
    setComment("");
    setSignedCert("");
  }, [signerName]);

  const handleSignCertificate = async () => {
    setIsLoading(true);
    try {
      const response = await api.post(
        `/signers/${signerName}/sign?output=pem`,
        { csr, ttl: `${ttl}h`, comment },
      );
      setCSR("");
      setTTL(720);
      setComment("");
      setSignedCert(response.data);
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <Form>
        <Row>
          <Col md={6} className="mb-3">
            <Form.Group>
              <Form.Label>CSR</Form.Label>
              <Form.Control
                as="textarea"
                rows={10}
                value={csr}
                placeholder="Enter PEM-encoded request"
                onChange={(e) => setCSR(e.target.value)}
              />
            </Form.Group>
          </Col>
          <Col
            md={6}
            className="mb-3 d-flex flex-column justify-content-between gap-3"
          >
            <Form.Group>
              <Form.Label>TTL</Form.Label>
              <div className="input-group">
                <Form.Control
                  type="number"
                  placeholder="e.g. 8760"
                  value={ttl}
                  onChange={(e) => setTTL(Number(e.target.value))}
                />
                <span className="input-group-text">hours</span>
              </div>
            </Form.Group>
            <Form.Group>
              <Form.Label>Comment</Form.Label>
              <Form.Control
                as="textarea"
                rows={6}
                placeholder="Optional comment (e.g. 'Issued for Alice's laptop')"
                value={comment}
                onChange={(e) => setComment(e.target.value)}
              />
            </Form.Group>
          </Col>
          <Col md={12} className="d-flex justify-content-end mb-3">
            <Form.Group>
              <Button
                variant="primary"
                onClick={handleSignCertificate}
                disabled={!csr || ttl === 0}
              >
                Sign Certificate
              </Button>
            </Form.Group>
          </Col>
        </Row>
      </Form>

      {/* {signedCert && prettyCode("pem", signedCert)} */}
      {signedCert &&
        downloadOrCopy("Certificate signed!", signedCert, "cert.pem")}
    </>
  );
}

function RevokeCertificateTab({ signerName, isLoading, setIsLoading }) {
  const [serial, setSerial] = useState("");
  const [reason, setReason] = useState(0);
  const api = getApi();

  useEffect(() => {
    setSerial("");
    setReason(0);
  }, [signerName]);

  const handleRevoke = async () => {
    if (!serial.trim()) return;

    const confirmed = window.confirm(
      `Revoke certificate with serial ${serial}?`,
    );
    if (!confirmed) return;

    setIsLoading(true);
    try {
      await api.post(`/signers/${signerName}/revoke`, { serial, reason });
      setSerial("");
      setReason(0);
      showToast("success", "Certificate revoked!");
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Form>
      <Row>
        <Col md={6}>
          <Form.Group>
            <Form.Label>Certificate Serial</Form.Label>
            <Form.Control
              type="text"
              value={serial}
              placeholder="e.g. 01ab23cd45ef6789"
              onChange={(e) => setSerial(e.target.value)}
            />
            <Form.Text>
              Enter the serial of the certificate to revoke -serial must be in
              hexadecimal format
            </Form.Text>
          </Form.Group>
        </Col>
        <Col md={6}>
          <Form.Group>
            <Form.Label>Reason</Form.Label>
            <Form.Select
              value={reason}
              onChange={(e) => setReason(Number(e.target.value))}
            >
              <option value={0}>Unspecified</option>
              <option value={1}>Key Compromise</option>
              <option value={2}>CA Compromise</option>
              <option value={3}>Affiliation Changed</option>
              <option value={4}>Superseded</option>
              <option value={5}>Cessation of Operation</option>
              <option value={6}>Certificate Hold</option>
            </Form.Select>
          </Form.Group>
        </Col>
      </Row>
      <div className="d-flex justify-content-end gap-2 mb-3">
        <Button variant="danger" onClick={handleRevoke} disabled={!serial}>
          Revoke Certificate
        </Button>
      </div>
    </Form>
  );
}

function SignDocumentTab({ signerName, isLoading, setIsLoading }) {
  const [file, setFile] = useState(null);
  const [signedFileUrl, setSignedFileUrl] = useState("");

  const api = getApi();

  useEffect(() => {
    setFile(null);
    setSignedFileUrl("");
  }, [signerName]);

  const handleSignDocument = async () => {
    if (!file) return;

    setIsLoading(true);
    try {
      const formData = new FormData();
      formData.append("document", file);
      //formData.append("ttl", `${ttl}h`);

      const response = await api.post(
        `/signers/${signerName}/sign-document`,
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
          responseType: "blob", // Important for file downloads
        },
      );
      setSignedFileUrl(window.URL.createObjectURL(new Blob([response.data])));
      setFile(null);
      //setTTL(0);
    } catch (err) {
      // Axios error with blob response
      if (err.response && err.response.data instanceof Blob) {
        try {
          const text = await err.response.data.text();
          showToast("error", errorToString({ response: { data: text } }));
        } catch {
          showToast("error", errorToString(err));
        }
      } else {
        showToast("error", errorToString(err));
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <Form.Group>
        <Form.Label>Document</Form.Label>
        <Form.Control
          type="file"
          accept="application/pdf"
          onChange={(e) => {
            setFile(e.target.files[0]);
          }}
        />
        <Form.Text>Upload a PDF document</Form.Text>
      </Form.Group>

      <div className="d-flex justify-content-end mb-3">
        <Button
          variant="primary"
          onClick={handleSignDocument}
          disabled={!file || file.type !== "application/pdf"}
        >
          Sign Document
        </Button>
      </div>

      {signedFileUrl && (
        <Alert variant="success" className="mb-2">
          Document signed! Click{" "}
          <a href={signedFileUrl} download={"signed-document.pdf"}>
            here
          </a>{" "}
          to download it.
        </Alert>
      )}
    </div>
  );
}

export default SignerDetails;
