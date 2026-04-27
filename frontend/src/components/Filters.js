import { Alert, Accordion, Button, Col, Form, Row } from "react-bootstrap";

/*

filtersTemplate input example:
{
  key: "name",
  type: "text", // can be "text", "select", "date", etc.
  value: filters.name,
  placeholder: "Name...",
}

filters, setFilters: state and setter for filters object (for parent component to react to filter changes)

*/

export default function Filters({
  filters,
  setFilters,
  filtersTemplate,
  cols = { xs: 12, md: 3 },
}) {
  return (
    <Accordion className="mb-2">
      <Accordion.Item eventKey="filters">
        <Accordion.Header>
          <div className="d-flex justify-content-between align-items-center w-100 gap-3 me-3">
            <span>
              <i className="bi bi-funnel"></i> Filters
            </span>
            <span className="text-muted">
              Applied {Object.values(filters).filter((v) => v).length} of{" "}
              {filtersTemplate.length}
            </span>
          </div>
        </Accordion.Header>
        <Accordion.Body>
          <Row className="g-3">
            {filtersTemplate.map((filter) => (
              <Col {...cols} key={filter.key}>
                <div className="input-group">
                  {filter.type === "text" && (
                    <>
                      <span className="input-group-text">{filter.label}</span>
                      <Form.Control
                        type="text"
                        value={filters[filter.key]}
                        placeholder={filter.placeholder}
                        onChange={(e) =>
                          setFilters((prev) => ({
                            ...prev,
                            [filter.key]: e.target.value,
                          }))
                        }
                      />
                    </>
                  )}

                  {filter.type === "select" && (
                    <>
                      <span className="input-group-text">{filter.label}</span>
                      <Form.Select
                        value={filters[filter.key]}
                        onChange={(e) =>
                          setFilters((prev) => ({
                            ...prev,
                            [filter.key]: e.target.value,
                          }))
                        }
                      >
                        {filter.options.map((option) => (
                          <option key={option.value} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </Form.Select>
                    </>
                  )}

                  {filter.type === "date" && (
                    <>
                      <span className="input-group-text">{filter.label}</span>
                      <Form.Control
                        type="date"
                        value={filters[filter.key]}
                        onChange={(e) =>
                          setFilters((prev) => ({
                            ...prev,
                            [filter.key]: e.target.value,
                          }))
                        }
                      />
                    </>
                  )}
                </div>
              </Col>
            ))}

            <div className="col-12 d-flex justify-content-end align-items-center gap-2">
              <Button
                variant="outline-secondary"
                onClick={() =>
                  setFilters((prev) => {
                    const newFilters = { ...prev };
                    Object.keys(newFilters).forEach((key) => {
                      newFilters[key] = "";
                    });
                    return newFilters;
                  })
                }
                style={{ minWidth: "6rem" }}
              >
                <i className="bi bi-x-circle"></i> Clear
              </Button>
            </div>
          </Row>
        </Accordion.Body>
      </Accordion.Item>
    </Accordion>
  );
}
