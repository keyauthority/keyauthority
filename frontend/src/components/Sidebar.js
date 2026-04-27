import { Nav, Col, ListGroup } from "react-bootstrap";
import { NavLink as RouterNavLink } from "react-router-dom";
import Topbar from "./Topbar";

export default function Sidebar({ sidebarSections, selectedItem }) {
  return (
    <Col
      md={3}
      lg={2}
      className="bg-dark-subtle min-vh-100 px-0 pt-2 pb-4"
      data-bs-theme="dark"
    >
      <div
        style={{
          position: "sticky",
          top: 0,
          zIndex: 1,
        }}
      >
        <Topbar />

        <ListGroup
          className="m-0 p-0"
          style={{
            "--bs-list-group-border-color": "transparent",
            "--bs-list-group-bg": "transparent",
            //"--bs-list-group-active-bg": "var(--bs-list-group-action-hover-bg)",
            "--bs-list-group-active-bg": "var(--bs-dark-border-subtle)",
            "--bs-list-group-action-hover-bg": "var(--bs-dark-border-subtle)",
            "--bs-list-group-active-border-color": "transparent",
          }}
        >
          {sidebarSections.map((section) => (
            <>
              <ListGroup.Item
                disabled
                key={section.key}
                className="bg-dark-subtle fw-semibold mt-3"
              >
                {section.title}
              </ListGroup.Item>
              {section.items &&
                section.items.length > 0 &&
                section.items.map((item) => (
                  <ListGroup.Item
                    action
                    key={item.to}
                    as={RouterNavLink}
                    to={item.to}
                    //className="rounded"
                  >
                    {item.icon && (
                      <i
                        className={`bi ${item.icon} text-primary-emphasis me-2`}
                      />
                    )}
                    {item.title}
                  </ListGroup.Item>
                ))}
            </>
          ))}
        </ListGroup>
      </div>
    </Col>
  );
}
