import { useRef, useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Row,
  Container,
  Col,
  Spinner,
  DropdownButton,
  Dropdown,
  Alert,
  Button,
} from "react-bootstrap";
import { ToastContainer } from "react-toastify";
import Sidebar from "./Sidebar";
import { Dashboard, Certificates, Logs, PendingRequests } from "./Activity";
import { Installation, Administration, UseSigners, UseSecrets } from "./Docs";
import Keys from "./Keys";
import Signers from "./Signers";
import Secrets from "./Secrets";
import SignerModal from "./SignerModal";
import SecretModal from "./SecretModal";
import SignerDetails from "./SignerDetails";
import SecretDetails from "./SecretDetails";
import Footer from "./Footer";
import ImportSecretsModal from "./ImportSecretsModal";

import { getApi } from "../axios";
import { errorToString } from "../utils/error";
import {
  showToast,
  copyToClipboard,
  showImportResultToast,
} from "../utils/utils";

export default function Main() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  //const [signers, setSigners] = useState([]);
  const [showSignerModal, setShowSignerModal] = useState(false);
  const [signerIsEdit, setSignerIsEdit] = useState(false);

  const [showSecretModal, setShowSecretModal] = useState(false);
  const [secretIsEdit, setSecretIsEdit] = useState(false);

  const [showImportSecretsModal, setShowImportSecretsModal] = useState(false);

  const exportLogsRef = useRef(() => {});

  const [title, setTitle] = useState("");
  const [subtitle, setSubtitle] = useState("");

  // selectedItem is redundant 'cause we can get the selected item from the location,
  // but it makes it easier to set the page title and other things in the future
  const [selectedItem, setSelectedItem] = useState(null);

  const location = useLocation();
  const navigate = useNavigate();
  const api = getApi();

  const apiUrl = new URL(getApi().defaults.baseURL);
  const apiRootUrl = apiUrl.href.replace(/\/v1\/?$/, "");
  const swaggerUrl = apiRootUrl + "/swagger/";

  const sidebarSections = [
    {
      key: "activity",
      title: "Activity",
      //icon: "bi-speedometer2",
      items: [
        {
          title: "Dashboard",
          subtitle: "Get an overview of your system's resources and activity",
          to: "/activity/dashboard",
          icon: "bi-speedometer",
        },
        {
          title: "Application Logs",
          subtitle: "View recorded logs for auditing purposes",
          to: "/activity/logs",
          icon: "bi-file-text-fill",
        },
        {
          title: "Issued Certificates",
          subtitle: "View certificates issued by your CAs",
          to: "/activity/certs",
          icon: "bi-award-fill",
        },
        {
          title: "Pending Requests",
          subtitle: "Review and approve/reject pending requests",
          to: "/activity/pending-requests",
          icon: "bi-clock-fill",
        },
      ],
    },
    {
      key: "resources",
      title: "Resources",
      //icon: "bi-folder",
      items: [
        {
          title: "Keys",
          subtitle: "View your cryptographic keys",
          to: "/keys",
          icon: "bi-key-fill",
        },
        {
          title: "Signers",
          subtitle: "Manage your CAs",
          to: "/signers",
          icon: "bi-pen-fill",
        },
        {
          title: "Secrets",
          subtitle: "Manage your secrets",
          to: "/secrets",
          icon: "bi-lock-fill",
        },
      ],
    },
    {
      key: "documentation",
      title: "Documentation",
      //icon: "bi-file-earmark-text",
      items: [
        {
          title: "Installation",
          to: "https://artifacthub.io/packages/helm/keyauthority/keyauthority",
          icon: "bi-box-seam-fill",
        },
        {
          title: "Administration",
          subtitle: "Learn how to manage access for your KeyAuthority users",
          to: "/docs/admin",
          icon: "bi-gear-fill",
        },
        {
          title: "Rest API",
          to: swaggerUrl,
          icon: "bi-braces-asterisk",
        },
        {
          title: "Build a PKI",
          subtitle: "Learn how to use signers to build a PKI for Kubernetes",
          to: "/docs/signers",
          icon: "bi-award-fill",
        },
        {
          title: "Use Secrets",
          subtitle: "Learn how your applications can access secrets",
          to: "/docs/secrets",
          icon: "bi-lock-fill",
        },
      ],
    },
  ];

  const handleDeleteSigner = async () => {
    const signerName = decodeURIComponent(
      location.pathname.replace("/signers/", ""),
    );
    // ask user to enter the signer name to confirm deletion
    const confirmedName = window.prompt(
      `To confirm deletion, please enter the signer name: ${signerName}`,
    );

    // Cancel pressed: do nothing
    if (confirmedName === null) {
      return;
    }

    if (confirmedName !== signerName) {
      showToast("error", "Signer name does not match. Deletion cancelled.");
      return;
    }

    setIsLoading(true);
    try {
      await api.delete(`/signers/${signerName}`);
      navigate("/signers");
      showToast("success", "Signer deleted!");
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeleteSecret = async () => {
    const selectedSecret =
      decodeURIComponent(location.pathname.replaceAll("/secrets/", "")) || "";

    // ask user to enter the secret path to confirm deletion
    const confirmedPath = window.prompt(
      `To confirm deletion, please enter the secret path: ${selectedSecret}`,
    );

    // Cancel pressed: do nothing
    if (confirmedPath === null) {
      return;
    }

    if (confirmedPath !== selectedSecret) {
      showToast("error", "Secret path does not match. Deletion cancelled.");
      return;
    }

    setIsLoading(true);
    try {
      await api.delete(`/secrets/${selectedSecret}`);
      showToast("success", "Secret deleted!");
      navigate("/secrets");
    } catch (err) {
      showToast("error", errorToString(err));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    // window.scrollTo({ top: 0, behavior: "instant" });

    for (const section of sidebarSections) {
      const foundItem = section.items?.find(
        (item) =>
          item.to &&
          (location.pathname.startsWith(item.to + "/") ||
            item.to === location.pathname),
      );
      if (foundItem) {
        setSelectedItem(foundItem);
        setTitle(foundItem.title);
        setSubtitle(foundItem.subtitle || null);
        return;
      }
    }
    setSelectedItem(null);
    setTitle(null);
    setSubtitle(null);
  }, [location.pathname]);

  const isValidPath = (path) => {
    return sidebarSections.some((section) =>
      section.items?.some(
        (item) => item.to === path || path.startsWith(item.to + "/"),
      ),
    );
  };

  return (
    <>
      <ToastContainer position="bottom-right" />

      <SignerModal
        show={showSignerModal}
        onHide={() => setShowSignerModal(false)}
        editMode={signerIsEdit}
        onSuccess={(updatedSigner) => {
          navigate(`/signers/${encodeURIComponent(updatedSigner)}`);
          setRefreshTrigger((prev) => prev + 1);
        }}
      />

      <SecretModal
        show={showSecretModal}
        editMode={secretIsEdit}
        onHide={() => setShowSecretModal(false)}
        onSuccess={(updatedSecret) => {
          navigate(`/secrets/${encodeURIComponent(updatedSecret)}`);
          setRefreshTrigger((prev) => prev + 1);
        }}
      />

      <ImportSecretsModal
        show={showImportSecretsModal}
        onHide={() => setShowImportSecretsModal(false)}
        onSuccess={(imported, skipped, failed) => {
          showImportResultToast(imported, skipped, failed);
          if (imported.size > 0) {
            setRefreshTrigger((prev) => prev + 1);
          }
        }}
      />

      <Container fluid>
        <Row>
          <Sidebar
            sidebarSections={sidebarSections}
            selectedItem={selectedItem}
          />

          {/* Main content */}
          <Col md={9} lg={10} className="pt-4 px-md-5">
            {error && <Alert variant="danger">{error}</Alert>}

            {(() => {
              if (!isValidPath(location.pathname)) {
                return <Alert variant="danger">404 Not Found</Alert>;
              }

              const top = () => (
                <div
                  className={`d-flex justify-content-between align-items-center mb-4`}
                >
                  <div>
                    <h2 className="m-0">{title}</h2>
                    <div className="text-muted mt-1">{subtitle}</div>
                  </div>

                  {isLoading && (
                    <Spinner animation="border" className="text-primary ms-3" />
                  )}

                  <div>
                    {(() => {
                      if (location.pathname === "/activity/logs") {
                        return (
                          <DropdownButton
                            title="Actions"
                            //variant="outline-primary"
                            onSelect={(key) => {
                              switch (key) {
                                case "export":
                                  exportLogsRef.current?.();
                                  break;
                                default:
                                  break;
                              }
                            }}
                          >
                            <Dropdown.Item eventKey="export">
                              <i className="bi bi-download me-1"></i> Export
                            </Dropdown.Item>
                          </DropdownButton>
                        );
                      }

                      if (location.pathname === "/signers") {
                        return (
                          <DropdownButton
                            title="Actions"
                            //variant="outline-primary"
                            onSelect={(key) => {
                              switch (key) {
                                case "new":
                                  setSignerIsEdit(false);
                                  setShowSignerModal(true);
                                  break;
                                default:
                                  break;
                              }
                            }}
                          >
                            <Dropdown.Item eventKey="new">
                              <i className="bi bi-plus-lg me-1"></i> New
                            </Dropdown.Item>
                          </DropdownButton>
                        );
                      }

                      if (location.pathname.startsWith("/signers/")) {
                        return (
                          <DropdownButton
                            title="Actions"
                            //variant="outline-primary"
                            onSelect={(key) => {
                              switch (key) {
                                case "edit":
                                  setSignerIsEdit(true);
                                  setShowSignerModal(true);
                                  break;
                                case "delete":
                                  handleDeleteSigner();
                                  break;
                                default:
                                  break;
                              }
                            }}
                          >
                            <Dropdown.Item eventKey="edit">
                              <i className="bi bi-pencil-square"></i> Edit
                            </Dropdown.Item>
                            <Dropdown.Item eventKey="delete">
                              <i className="bi bi-trash"></i> Delete
                            </Dropdown.Item>
                          </DropdownButton>
                        );
                      }

                      if (location.pathname === "/secrets") {
                        return (
                          <DropdownButton
                            title="Actions"
                            //variant="outline-primary"
                            onSelect={(key) => {
                              switch (key) {
                                case "new":
                                  setSecretIsEdit(false);
                                  setShowSecretModal(true);
                                  break;
                                case "import":
                                  setShowImportSecretsModal(true);
                                  break;
                                default:
                                  break;
                              }
                            }}
                          >
                            <Dropdown.Item eventKey="new">
                              <i className="bi bi-plus-lg me-1"></i> New
                            </Dropdown.Item>
                            <Dropdown.Item eventKey="import">
                              <i className="bi bi-upload me-1"></i> Import From
                              HC Vault
                            </Dropdown.Item>
                          </DropdownButton>
                        );
                      }

                      if (location.pathname.startsWith("/secrets/")) {
                        return (
                          <DropdownButton
                            title="Actions"
                            //variant="outline-primary"
                            onSelect={(key) => {
                              switch (key) {
                                case "edit":
                                  setSecretIsEdit(true);
                                  setShowSecretModal(true);
                                  break;
                                case "delete":
                                  handleDeleteSecret();
                                  break;
                                default:
                                  break;
                              }
                            }}
                          >
                            <Dropdown.Item eventKey="edit">
                              <i className="bi bi-pencil-square"></i> Edit
                            </Dropdown.Item>
                            <Dropdown.Item eventKey="delete">
                              <i className="bi bi-trash"></i> Delete
                            </Dropdown.Item>
                          </DropdownButton>
                        );
                      }

                      return null;
                    })()}
                  </div>
                </div>
              );

              const content = () => {
                switch (location.pathname) {
                  case "/activity/dashboard":
                    return (
                      <Dashboard
                        key={`${location.pathname}-${refreshTrigger}`}
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                      />
                    );
                  case "/activity/logs":
                    return (
                      <Logs
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                        setHandleExportLogs={(fn) => {
                          exportLogsRef.current = fn;
                        }}
                      />
                    );
                  case "/activity/certs":
                    return (
                      <Certificates
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                      />
                    );
                  case "/activity/pending-requests":
                    return (
                      <PendingRequests
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                      />
                    );
                  case "/docs/install":
                    return <Installation />;
                  case "/docs/admin":
                    return <Administration />;
                  case "/docs/signers":
                    return <UseSigners />;
                  case "/docs/secrets":
                    return <UseSecrets />;
                  case "/keys":
                    return (
                      <Keys
                        key={`${location.pathname}-${refreshTrigger}`}
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                      />
                    );
                  case "/signers":
                    return (
                      <Signers
                        key={`${location.pathname}-${refreshTrigger}`}
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                      />
                    );
                  case "/secrets":
                    return (
                      <Secrets
                        key={`${location.pathname}-${refreshTrigger}`}
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                      />
                    );
                  default:
                    if (location.pathname.startsWith("/secrets/")) {
                      return (
                        <SecretDetails
                          key={`${location.pathname}-${refreshTrigger}`}
                          isLoading={isLoading}
                          setIsLoading={setIsLoading}
                          setTitle={setTitle}
                          setSubtitle={setSubtitle}
                        />
                      );
                    } else if (location.pathname.startsWith("/signers/")) {
                      return (
                        <SignerDetails
                          key={`${location.pathname}-${refreshTrigger}`}
                          isLoading={isLoading}
                          setIsLoading={setIsLoading}
                          setTitle={setTitle}
                          setSubtitle={setSubtitle}
                        />
                      );
                    }
                    return null;
                }
              };

              return (
                <>
                  {top()}
                  {content()}
                </>
              );
            })()}
          </Col>
          <Footer />
        </Row>
      </Container>
    </>
  );
}
