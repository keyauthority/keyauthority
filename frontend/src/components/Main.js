import { useEffect, useState, useCallback } from "react";
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
import {
  Administration,
  UseSigners,
  UseSecrets,
  Architecture,
  UsefulLinks,
} from "./Docs";
import Keys from "./Keys";
import Signers from "./Signers";
import Secrets from "./Secrets";
import SignerDetails from "./SignerDetails";
import SecretDetails from "./SecretDetails";
import Footer from "./Footer";

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

  const [dropdownActions, setDropdownActions] = useState([]);

  const [title, setTitle] = useState("");
  const [subtitle, setSubtitle] = useState("");

  // selectedItem is redundant 'cause we can get the selected item from the location,
  // but it makes it easier to set the page title and other things in the future
  const [selectedItem, setSelectedItem] = useState(null);

  const location = useLocation();
  const navigate = useNavigate();
  const api = getApi();

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
        {
          title: "Application Logs",
          subtitle: "View recorded logs for auditing purposes",
          to: "/activity/logs",
          icon: "bi-file-text-fill",
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
          dontShowInSidebar: true, // this page can be accessed directly, but not in the sidebar
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
          title: "Architecture",
          subtitle:
            "Get an overview of components and actors in KeyAuthority workflows",
          to: "/docs/architecture",
          icon: "bi-diagram-3-fill",
        },
        {
          title: "Administration",
          subtitle: "Learn how to manage access for your KeyAuthority users",
          to: "/docs/admin",
          icon: "bi-gear-fill",
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
        {
          title: "Useful Links",
          subtitle: "Links to related resources and tools",
          to: "/docs/links",
          icon: "bi-link-45deg",
        },
      ],
    },
  ];

  useEffect(() => {
    // window.scrollTo({ top: 0, behavior: "instant" });
    // setDropdownActions([]); // clear actions when route changes

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

                  <DropdownButton
                    title="Actions"
                    // disabled={dropdownActions.length === 0}
                    className={dropdownActions.length > 0 ? "" : " invisible"}
                    onSelect={(key) => {
                      const action = dropdownActions.find(
                        (action) => action.key === key,
                      );
                      if (action && action.onClick) {
                        action.onClick();
                      }
                    }}
                  >
                    {dropdownActions.map((action) => (
                      <Dropdown.Item key={action.key} eventKey={action.key}>
                        <i className={`${action.iconClass} me-2`}></i>
                        {action.label}
                      </Dropdown.Item>
                    ))}
                  </DropdownButton>
                </div>
              );

              const content = () => {
                switch (location.pathname) {
                  case "/activity/dashboard":
                    return (
                      <Dashboard
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                      />
                    );
                  case "/activity/logs":
                    return (
                      <Logs
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                        setDropdownActions={setDropdownActions}
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
                  case "/docs/architecture":
                    return <Architecture />;
                  case "/docs/admin":
                    return <Administration />;
                  case "/docs/signers":
                    return <UseSigners />;
                  case "/docs/secrets":
                    return <UseSecrets />;
                  case "/docs/links":
                    return <UsefulLinks />;
                  case "/keys":
                    return (
                      <Keys
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                        setDropdownActions={setDropdownActions}
                      />
                    );
                  case "/signers":
                    return (
                      <Signers
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                        setDropdownActions={setDropdownActions}
                      />
                    );
                  case "/secrets":
                    return (
                      <Secrets
                        isLoading={isLoading}
                        setIsLoading={setIsLoading}
                        setDropdownActions={setDropdownActions}
                      />
                    );
                  default:
                    if (location.pathname.startsWith("/secrets/")) {
                      return (
                        <SecretDetails
                          isLoading={isLoading}
                          setIsLoading={setIsLoading}
                          setTitle={setTitle}
                          setSubtitle={setSubtitle}
                          setDropdownActions={setDropdownActions}
                        />
                      );
                    } else if (location.pathname.startsWith("/signers/")) {
                      return (
                        <SignerDetails
                          isLoading={isLoading}
                          setIsLoading={setIsLoading}
                          setTitle={setTitle}
                          setSubtitle={setSubtitle}
                          setDropdownActions={setDropdownActions}
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
