import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import {
  Row,
  Col,
  Button,
  Modal,
  Form,
  Card,
  Accordion,
  Spinner,
} from "react-bootstrap";
import { showToast } from "../utils/utils";
import { errorToString } from "../utils/error";
import { getApi } from "../axios";
import KeyInput from "./KeyInput";

export default function SignerModal({
  show,
  onHide,
  onSuccess = null,
  editMode = false,
}) {
  const location = useLocation();
  const signerNameFromPath =
    decodeURIComponent(location.pathname.replaceAll("/signers/", "")) || "";

  const [isLoading, setIsLoading] = useState(false);
  const [environment, setEnvironment] = useState(""); // controlled by key input
  const [signerName, setSignerName] = useState("");
  const [signerConfig, setSignerConfig] = useState(null);

  // Private Key
  const [keyType, setKeyType] = useState("RSA");
  const [bits, setBits] = useState(2048);
  const [curve, setCurve] = useState("P-256");
  const [pkcs11URI, setPkcs11URI] = useState("");

  // CA Template
  const [commonName, setCommonName] = useState("");
  const [country, setCountry] = useState("");
  const [organization, setOrganization] = useState("");
  const [organizationalUnit, setOrganizationalUnit] = useState("");
  const [locality, setLocality] = useState("");
  const [province, setProvince] = useState("");
  const [streetAddress, setStreetAddress] = useState("");
  const [postalCode, setPostalCode] = useState("");

  // Certificate Template
  const [cdp, setCDP] = useState("");
  const [isCA, setIsCA] = useState(false);

  // Policy
  const [allowedDomains, setAllowedDomains] = useState("");
  const [maxTTL, setMaxTTL] = useState(720);
  const [authzRequired, setAuthzRequired] = useState(false);
  const [allowedKeyUsages, setAllowedKeyUsages] = useState([
    "digital signature",
    "key encipherment",
    "server auth",
    "client auth",
  ]);

  const api = getApi();

  const baseURL = new URL(api.defaults.baseURL);
  const defaultCDPBaseURL = "http://crl." + baseURL.hostname + "/v1/crl/";

  const toHours = (durationStr) => {
    if (!durationStr) return 0;
    const match = durationStr.match(/^(\d+)([smhd])$/);
    if (!match) return 0;
    const value = Number(match[1]);
    const unit = match[2];
    switch (unit) {
      case "s":
        return value / 3600;
      case "m":
        return value / 60;
      case "h":
        return value;
      case "d":
        return value * 24;
      default:
        return 0;
    }
  };

  useEffect(() => {
    if (show && editMode) {
      setSignerName(signerNameFromPath);
    }
  }, [show, signerNameFromPath, editMode]);

  const fetchSignerConfig = async (signerName) => {
    setSignerConfig(null);
    try {
      const res = await api.get(`/signers/${signerName}/config`);
      setSignerConfig(res.data);
    } catch (err) {
      showToast("error", errorToString(err));
    }
  };

  const createSignerHashForCRL = async (signerName) => {
    // compute sha256 hash of the signer name, and return the first 32 characters of the base64 string
    const encoder = new TextEncoder();
    const data = encoder.encode(signerName);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    // convert to base64 URL safe string
    const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, ""); // Remove padding
    return hashBase64.slice(0, 32);
  };

  useEffect(() => {
    if (show && editMode && signerName) {
      fetchSignerConfig(signerName);
    }
  }, [show, editMode, signerName]);

  useEffect(() => {
    if (signerConfig) {
      // Prefill fields
      const subject = signerConfig.caTemplate?.subject || {};
      setCommonName(subject.commonName || "");
      setCountry((subject.country || []).join(", "));
      setOrganization((subject.organization || []).join(", "));
      setOrganizationalUnit((subject.organizationalUnit || []).join(", "));
      setLocality((subject.locality || []).join(", "));
      setProvince((subject.province || []).join(", "));
      setStreetAddress((subject.streetAddress || []).join(", "));
      setPostalCode((subject.postalCode || []).join(", "));

      setCDP((signerConfig.cdp || []).join(", "));
      setIsCA(signerConfig.isCA || false);

      setAllowedDomains(signerConfig.allowedDomains?.join(", ") || "");
      setAllowedKeyUsages(signerConfig.allowedKeyUsages || []);
      setMaxTTL(toHours(signerConfig.maxTTL) || 720);
      setAuthzRequired(signerConfig.authzRequired || false);
    }
  }, [signerConfig]);

  useEffect(() => {
    // Reset everything when the modal is closed
    if (!show) {
      setSignerName("");
      setEnvironment("");
      setSignerConfig(null);

      setCommonName("");
      setCountry("");
      setOrganization("");
      setOrganizationalUnit("");
      setLocality("");
      setProvince("");
      setStreetAddress("");
      setPostalCode("");

      setKeyType("RSA");
      setBits(2048);
      setCurve("P-256");
      setPkcs11URI("");

      setCDP("");
      setIsCA(false);

      setAllowedDomains("");
      setMaxTTL(720);
      setAuthzRequired(false);
      setAllowedKeyUsages([
        "digital signature",
        "key encipherment",
        "server auth",
        "client auth",
      ]);
    }
  }, [show]);

  const handleUpdateOrCreateSigner = async (signerName) => {
    setIsLoading(true);
    const subject = {
      commonName: commonName.trim() || undefined,
      country: country
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      organization: organization
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      organizationalUnit: organizationalUnit
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      locality: locality
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      province: province
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      streetAddress: streetAddress
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      postalCode: postalCode
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    };

    const config = {
      caTemplate: {
        subject,
      },
      maxTTL: `${maxTTL}h`,
      isCA,
      cdp: cdp
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      allowedDomains: allowedDomains
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      allowedKeyUsages,
      authzRequired,
    };

    if (!editMode) {
      const privateKeyConfig =
        keyType === "RSA"
          ? { type: "RSA", bits, pkcs11URI }
          : keyType === "ECDSA"
            ? { type: "ECDSA", curve, pkcs11URI }
            : keyType === "Ed25519"
              ? { type: "Ed25519", pkcs11URI }
              : { type: "Unknown" };
      try {
        // create private key
        const res = await api.post(
          `/keys?environment=${environment}`,
          privateKeyConfig,
        );
        const privateKeyID = res.data;
        // create signer with the private key
        await api.post(
          `/signers/${signerName}?privateKeyID=${privateKeyID}`,
          config,
        );
        showToast("success", "Signer created!");
        if (onSuccess) {
          onSuccess(signerName);
        }
      } catch (err) {
        showToast("error", errorToString(err));
      } finally {
        setIsLoading(false);
        onHide();
      }
    } else {
      try {
        await api.put(`/signers/${signerName}/config`, config);
        showToast("success", "Signer updated!");
        if (onSuccess) {
          onSuccess(signerName);
        }
      } catch (err) {
        showToast("error", errorToString(err));
      } finally {
        setIsLoading(false);
        onHide();
      }
    }
  };

  return (
    <Modal show={show} onHide={onHide} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>
          {editMode ? "Edit Signer: " + signerName : "New Signer"}
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {/* Signer Name */}
        {!editMode && (
          <Form.Group className="col mb-3">
            <Form.Label>Name</Form.Label>
            <Form.Control
              type="text"
              placeholder="e.g. pki-issuer"
              value={signerName}
              onChange={(e) => {
                // check that only contains alphanumeric, dash, and underscore
                const regex = /^[a-zA-Z0-9-_]*$/;
                const value = e.target.value;
                if (regex.test(value)) {
                  setSignerName(value);
                }
              }}
            />
          </Form.Group>
        )}

        {/* Private Key Section */}
        {!editMode && (
          <Card className="mb-3">
            <Card.Header className="d-flex justify-content-between align-items-center gap-1">
              <div>Private Key</div>
              <div className="text-muted small fw-normal">
                The private key associated with this signer
              </div>
            </Card.Header>
            <Card.Body>
              <KeyInput
                environment={environment}
                setEnvironment={setEnvironment}
                keyTypes={["RSA", "ECDSA", "Ed25519"]}
                keyType={keyType}
                setKeyType={setKeyType}
                bits={bits}
                setBits={setBits}
                curve={curve}
                setCurve={setCurve}
                pkcs11URI={pkcs11URI}
                setPkcs11URI={setPkcs11URI}
              />
            </Card.Body>
          </Card>
        )}

        {/* CA Template Section */}
        <Card className="mb-3">
          <Card.Header className="d-flex justify-content-between align-items-center gap-1">
            <div>CA Template</div>
            <div className="text-muted small fw-normal">
              Fields of the certificate template used when creating CA CSRs
            </div>
          </Card.Header>
          <Card.Body>
            <Form.Group className="mb-3">
              <Form.Label>Common Name</Form.Label>
              <Form.Control
                type="text"
                placeholder="e.g. KeyAuthority CA"
                value={commonName}
                onChange={(e) => setCommonName(e.target.value)}
              />
            </Form.Group>

            <Accordion className="mb-3">
              <Accordion.Item eventKey="0">
                <Accordion.Header>More Fields</Accordion.Header>
                <Accordion.Body>
                  <Form.Group className="mb-3">
                    <Form.Label>Country</Form.Label>
                    <Form.Control
                      type="text"
                      placeholder="e.g. CH"
                      value={country}
                      onChange={(e) => setCountry(e.target.value)}
                    />
                  </Form.Group>

                  <Form.Group className="mb-3">
                    <Form.Label>Organization</Form.Label>
                    <Form.Control
                      type="text"
                      placeholder="e.g. MyCompany"
                      value={organization}
                      onChange={(e) => setOrganization(e.target.value)}
                    />
                  </Form.Group>

                  <Form.Group className="mb-3">
                    <Form.Label>Organizational Unit</Form.Label>
                    <Form.Control
                      type="text"
                      placeholder="e.g. Security"
                      value={organizationalUnit}
                      onChange={(e) => setOrganizationalUnit(e.target.value)}
                    />
                  </Form.Group>

                  <Form.Group className="mb-3">
                    <Form.Label>Locality</Form.Label>
                    <Form.Control
                      type="text"
                      placeholder="e.g. Zurich"
                      value={locality}
                      onChange={(e) => setLocality(e.target.value)}
                    />
                  </Form.Group>

                  <Form.Group className="mb-3">
                    <Form.Label>Province</Form.Label>
                    <Form.Control
                      type="text"
                      placeholder="e.g. ZH"
                      value={province}
                      onChange={(e) => setProvince(e.target.value)}
                    />
                  </Form.Group>

                  <Form.Group className="mb-3">
                    <Form.Label>Street Address</Form.Label>
                    <Form.Control
                      type="text"
                      placeholder="e.g. Bahnhofstrasse 30"
                      value={streetAddress}
                      onChange={(e) => setStreetAddress(e.target.value)}
                    />
                  </Form.Group>

                  <Form.Group className="mb-3">
                    <Form.Label>Postal Code</Form.Label>
                    <Form.Control
                      type="text"
                      placeholder="e.g. 8001"
                      value={postalCode}
                      onChange={(e) => setPostalCode(e.target.value)}
                    />
                  </Form.Group>
                </Accordion.Body>
              </Accordion.Item>
            </Accordion>
          </Card.Body>
        </Card>

        {/* Certificate Template Section */}
        <Card className="mb-3">
          <Card.Header className="d-flex justify-content-between align-items-center gap-1">
            <div>Certificate Template</div>
            <div className="text-muted small fw-normal">
              Fields included in the certificates issued by this signer
            </div>
          </Card.Header>
          <Card.Body>
            <Form.Group className="mb-3">
              <Form.Check
                type="checkbox"
                label="Is CA"
                checked={isCA}
                onChange={(e) => setIsCA(e.target.checked)}
              />
              <Form.Text className="text-muted">
                Defines what type of certificates this signer issues (CA or
                leaf)
              </Form.Text>
            </Form.Group>
            <Form.Group className="mb-3">
              <Form.Label>CDP (CRL Distribution Points)</Form.Label>
              <div className="input-group">
                <Form.Control
                  type="text"
                  value={cdp}
                  placeholder="e.g. http://example.com/crl1, http://example.com/crl2"
                  onChange={(e) => {
                    setCDP(e.target.value);
                  }}
                />
                <Button
                  variant="outline-secondary"
                  onClick={async () => {
                    if (defaultCDPBaseURL && signerName) {
                      const hash = await createSignerHashForCRL(signerName);
                      setCDP(defaultCDPBaseURL + hash);
                    }
                  }}
                  disabled={!defaultCDPBaseURL || !signerName}
                >
                  <i className="bi bi-arrow-clockwise"></i> Set Default
                </Button>
              </div>
              <Form.Text className="text-muted">
                Comma-separated list of URLs
              </Form.Text>
            </Form.Group>
          </Card.Body>
        </Card>

        {/* Policy Section */}
        <Card className="mb-3">
          <Card.Header className="d-flex justify-content-between align-items-center gap-1">
            <div>Policy</div>
            <div className="text-muted small fw-normal">
              Restrictions applied when using this signer
            </div>
          </Card.Header>
          <Card.Body>
            <Form.Group className="mb-3">
              <Form.Label>Allowed Key Usages</Form.Label>
              <Row>
                {[
                  "cert sign",
                  "crl sign",
                  "digital signature",
                  "key encipherment",
                  "server auth",
                  "client auth",
                ].map((usage) => (
                  <Col md={6} key={usage}>
                    <Form.Check
                      type="checkbox"
                      label={usage}
                      value={usage}
                      checked={allowedKeyUsages.includes(usage)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setAllowedKeyUsages([...allowedKeyUsages, usage]);
                        } else {
                          setAllowedKeyUsages(
                            allowedKeyUsages.filter((u) => u !== usage),
                          );
                        }
                      }}
                    />
                  </Col>
                ))}
              </Row>
              <Form.Text className="text-muted">
                Key usages allowed in issued certificates
              </Form.Text>
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>Allowed Domains</Form.Label>
              <Form.Control
                type="text"
                placeholder="e.g. ^.*\.example\.com$, ^mydomain\.org$"
                value={allowedDomains}
                onChange={(e) => {
                  setAllowedDomains(e.target.value);
                }}
              />
              <Form.Text className="text-muted">
                Comma-separated list of{" "}
                <a
                  href="https://pkg.go.dev/regexp/syntax"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  regex patterns
                </a>{" "}
                that will be matched against the requested certificate's domains
              </Form.Text>
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>Max duration (TTL) of issued certificates</Form.Label>
              <div className="input-group">
                <Form.Control
                  type="number"
                  placeholder="e.g. 8760"
                  value={maxTTL}
                  onChange={(e) => setMaxTTL(Number(e.target.value))}
                />
                <span className="input-group-text">hours</span>
              </div>
            </Form.Group>
            <Form.Group className="mb-3">
              <Form.Check
                type="checkbox"
                label="Additional Authorization Required"
                checked={authzRequired}
                onChange={(e) => setAuthzRequired(e.target.checked)}
              />
              <Form.Text className="text-muted">
                If set, non-trivial requests such as signing, revocation, etc.
                will require authorization from a second user
              </Form.Text>
            </Form.Group>
          </Card.Body>
        </Card>
      </Modal.Body>

      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Cancel
        </Button>
        <Button
          onClick={() => handleUpdateOrCreateSigner(signerName)}
          disabled={!signerName || (!editMode && !environment) || isLoading}
        >
          {isLoading ? (
            <>
              <Spinner
                animation="border"
                size="sm"
                className="text-light me-2"
              />
              {editMode ? "Saving..." : "Creating..."}
            </>
          ) : editMode ? (
            "Save"
          ) : (
            "Create"
          )}
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
