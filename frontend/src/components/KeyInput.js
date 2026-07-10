import { useEffect, useState } from "react";
import { Row, Col, Form, Dropdown, DropdownButton } from "react-bootstrap";
import { getRoles } from "../utils/utils";
import { getKeycloak } from "../keycloak";

function getDefaultPkcs11URIs() {
  return {
    "SoftHSM (dev)":
      "pkcs11:module-path=/usr/lib64/pkcs11/libsofthsm2.so;token=keyauthority?pin-source=/etc/softhsm/.pin",
    "Securosys Primus":
      "pkcs11:module-path=/usr/local/primus/lib/libprimusP11.so;slot-id=0?pin-source=/etc/primus/.pin",
  };
}

export default function KeyInput({
  environment,
  setEnvironment,
  keyTypes,
  keyType,
  setKeyType,
  bits,
  setBits,
  mode,
  setMode,
  curve,
  setCurve,
  pkcs11URI,
  setPkcs11URI,
}) {
  const [pkcs11URIDisabled, setPkcs11URIDisabled] = useState(false);

  const defaultPkcs11URIs = getDefaultPkcs11URIs();
  const keycloak = getKeycloak();
  const token = keycloak?.tokenParsed || {};
  const roles = getRoles(token);
  const roleEnvironments = roles
    .filter((role) => role.startsWith("KEYAUTHORITY_OPERATOR_"))
    .map((role) => role.replace("KEYAUTHORITY_OPERATOR_", ""));

  const isGlobalOperator = roles.includes("KEYAUTHORITY_OPERATOR");

  useEffect(() => {
    if (!isGlobalOperator && !environment && roleEnvironments.length > 0) {
      setEnvironment(roleEnvironments[0]);
    }
  }, [isGlobalOperator, environment, roleEnvironments, setEnvironment]);

  return (
    <>
      <Row className="g-3 mb-3">
        <Col>
          <Form.Group>
            <Form.Label>Environment</Form.Label>
            {isGlobalOperator ? (
              <Form.Control
                value={environment}
                placeholder="e.g. dev, team2, qa, prod"
                onChange={(e) => {
                  const regex = /^[a-zA-Z0-9-_]*$/; // allow only letters, numbers, dashes and underscores
                  if (regex.test(e.target.value))
                    setEnvironment(e.target.value);
                }}
              />
            ) : (
              <Form.Select
                value={environment || ""}
                onChange={(e) => setEnvironment(e.target.value)}
              >
                {roleEnvironments.map((env) => (
                  <option key={env} value={env}>
                    {env}
                  </option>
                ))}
              </Form.Select>
            )}
            {/* <Form.Text className="text-muted">
            <i className="bi bi-exclamation-triangle"></i> Everyone with access
            to this environment will be able to use this key as well as any
            other resources such as signers, secrets, etc. within this
            environment. Contact your administrator if you're unsure.
          </Form.Text> */}
          </Form.Group>
        </Col>

        <Col>
          <Form.Group>
            <Form.Label>Type</Form.Label>
            <Form.Select
              value={keyType}
              onChange={(e) => setKeyType(e.target.value)}
            >
              {keyTypes.map((kt) => (
                <option key={kt} value={kt}>
                  {kt}
                </option>
              ))}
            </Form.Select>
          </Form.Group>
        </Col>

        {keyType === "AES" && (
          <>
            <Col>
              <Form.Group>
                <Form.Label>Bits</Form.Label>
                <Form.Select
                  value={bits}
                  onChange={(e) => setBits(Number(e.target.value))}
                >
                  <option value={128}>128</option>
                  <option value={192}>192</option>
                  <option value={256}>256</option>
                </Form.Select>
              </Form.Group>
            </Col>
            <Col>
              <Form.Group>
                <Form.Label>Mode</Form.Label>
                <Form.Select
                  value={mode}
                  onChange={(e) => setMode(e.target.value)}
                >
                  <option value="GCM">GCM</option>
                </Form.Select>
              </Form.Group>
            </Col>
          </>
        )}

        {keyType === "RSA" && (
          <Col>
            <Form.Group>
              <Form.Label>Bits</Form.Label>
              <Form.Select
                value={bits}
                onChange={(e) => setBits(Number(e.target.value))}
              >
                <option value={2048}>2048</option>
                <option value={3072}>3072</option>
                <option value={4096}>4096</option>
              </Form.Select>
            </Form.Group>
          </Col>
        )}

        {keyType === "ECDSA" && (
          <Col>
            <Form.Group>
              <Form.Label>Curve</Form.Label>
              <Form.Select
                value={curve}
                onChange={(e) => setCurve(e.target.value)}
              >
                <option value="P-224">P-224</option>
                <option value="P-256">P-256</option>
                <option value="P-384">P-384</option>
                <option value="P-521">P-521</option>
              </Form.Select>
            </Form.Group>
          </Col>
        )}
      </Row>

      <Form.Group>
        <Form.Label className="d-flex justify-content-between align-items-center gap-2">
          <span>HSM PKCS11 URI</span>
          <span className="text-muted small">
            <i className="bi bi-info-circle me-1"></i>Leave empty for software
            key
          </span>
        </Form.Label>
        <div className="input-group">
          <Form.Select
            className="input-group-text"
            style={{ maxWidth: "14rem" }}
            onChange={(e) => {
              setPkcs11URI(e.target.value);
              setPkcs11URIDisabled(e.target.value !== "");
            }}
          >
            <option key="Manual" value="">
              Manual Entry
            </option>
            {Object.entries(defaultPkcs11URIs).map(([name, uri]) => (
              <option key={name} value={uri}>
                {name}
              </option>
            ))}
          </Form.Select>
          <Form.Control
            placeholder="e.g. pkcs11:module-path=/path/to/module.so;token=keyauthority?pin-source=/path/to/pinfile"
            value={pkcs11URI}
            disabled={pkcs11URIDisabled}
            onChange={(e) => setPkcs11URI(e.target.value)}
          />
        </div>
        <Form.Text className="text-muted">
          Refer to the Golang package{" "}
          <a
            href="https://pkg.go.dev/go.step.sm/crypto/kms/pkcs11"
            target="_blank"
            rel="noopener noreferrer"
          >
            pkcs11
          </a>{" "}
          for further details
        </Form.Text>
      </Form.Group>
    </>
  );
}
