import {
  Navbar,
  Dropdown,
  ButtonGroup,
  Modal,
  Button,
  Container,
} from "react-bootstrap";
import { Link } from "react-router-dom";
import { useState } from "react";
import { copyToClipboard, getRoles } from "../utils/utils";
import { getKeycloak } from "../keycloak";
import KeyValueTable from "./KeyValueTable";

export default function Topbar() {
  const [showProfile, setShowProfile] = useState(false);
  const keycloak = getKeycloak();

  const user =
    keycloak?.tokenParsed?.preferred_username ||
    keycloak?.tokenParsed?.email ||
    "";

  const handleLogout = () => {
    keycloak.logout({ redirectUri: window.location.origin });
  };

  const handleKeycloakAction = (kcAction) => {
    keycloak.login({ action: kcAction, redirectUri: window.location.origin });
  };

  return (
    <>
      <ProfileModal
        show={showProfile}
        onHide={() => setShowProfile(false)}
        keycloak={keycloak}
      />
      <Navbar data-bs-theme="dark" className="px-1">
        <Container fluid>
          <Navbar.Brand as={Link} to="/" className="fw-semibold">
            <img
              src="/favicon.png"
              alt="Logo"
              width="38"
              height="38"
              className="d-inline-block align-text-top me-2"
            />
          </Navbar.Brand>

          <Dropdown as={ButtonGroup}>
            <Dropdown.Toggle id="user-dropdown" variant="outline-secondary">
              <i className="bi bi-person-fill"></i>
            </Dropdown.Toggle>
            <Dropdown.Menu align="end">
              <Dropdown.Item
                disabled
                className="text-truncate"
                style={{ maxWidth: "12rem" }}
              >
                {user}
              </Dropdown.Item>
              <Dropdown.Divider />
              <Dropdown.Item onClick={() => setShowProfile(true)}>
                <i className="bi bi-person me-1"></i> View Profile
              </Dropdown.Item>
              <Dropdown.Item
                onClick={() => handleKeycloakAction("UPDATE_PASSWORD")}
              >
                <i className="bi bi-three-dots me-1"></i> Change Password
              </Dropdown.Item>
              <Dropdown.Item
                onClick={() => handleKeycloakAction("CONFIGURE_TOTP")}
              >
                <i className="bi bi-qr-code-scan me-1"></i> Configure 2FA
              </Dropdown.Item>
              <Dropdown.Divider />
              <Dropdown.Item onClick={handleLogout}>
                <i className="bi bi-box-arrow-right me-1"></i> Logout
              </Dropdown.Item>
            </Dropdown.Menu>
          </Dropdown>
        </Container>
      </Navbar>
    </>
  );
}

const ProfileModal = ({ show, onHide, keycloak }) => {
  const token = keycloak?.tokenParsed || {};
  const roles = getRoles(token);

  return (
    <Modal show={show} onHide={onHide}>
      <Modal.Header closeButton>
        <Modal.Title>Profile</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <KeyValueTable
          striped={false}
          borderBottom={false}
          body={{
            User: token.preferred_username || "-",
            Roles:
              roles?.length > 0 ? (
                <>
                  {roles.map((role, index) => (
                    <div key={index}>{role}</div>
                  ))}
                </>
              ) : (
                "No roles assigned, please contact your administrator."
              ),
            Token: (
              <Button
                variant="outline-secondary"
                size="sm"
                onClick={() => {
                  copyToClipboard(keycloak?.token || "", "Token copied!");
                }}
                title="Copy to clipboard"
              >
                <i className="bi bi-clipboard"></i>
              </Button>
            ),
          }}
        />
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};
