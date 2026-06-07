import { Accordion, Button, Card, Col, Form, Row } from "react-bootstrap";

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
  colsPerRow = 4,
}) {
  const safeColsPerRow =
    Number.isInteger(colsPerRow) && colsPerRow > 0 ? colsPerRow : 4;

  const baseSpan = 12 / safeColsPerRow;
  const supportsFill = Number.isInteger(baseSpan); // exact fill only when colsPerRow divides 12
  const remainder = supportsFill ? filtersTemplate.length % safeColsPerRow : 0;

  return (
    <Card className="mb-3 border-light-subtle">
      <Card.Header>
        <div className="d-flex justify-content-between align-items-center gap-2">
          <h6 className="mb-0">Filters</h6>
          <Button
            variant="outline-secondary"
            size="sm"
            onClick={() =>
              setFilters((prev) => {
                const newFilters = { ...prev };
                Object.keys(newFilters).forEach((key) => {
                  newFilters[key] = "";
                });
                return newFilters;
              })
            }
          >
            <i className="bi bi-x-lg"></i> Clear
          </Button>
        </div>
      </Card.Header>
      <Card.Body>
        <Row className="g-3">
          {filtersTemplate.map((filter, index) => {
            const isLast = index === filtersTemplate.length - 1;

            const md =
              supportsFill && isLast && remainder !== 0
                ? 12 - baseSpan * (remainder - 1) // last item fills remaining space
                : supportsFill
                  ? baseSpan
                  : undefined;

            return (
              <Col xs={12} md={md} key={filter.key}>
                <div className="input-group">
                  {filter.type === "text" && (
                    <>
                      <span className="input-group-text">{filter.label}</span>
                      <Form.Control
                        type="text"
                        value={filters[filter.key] ?? ""}
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
                        value={filters[filter.key] ?? ""}
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
                        type="datetime-local"
                        value={filters[filter.key] ?? ""}
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
            );
          })}
        </Row>
      </Card.Body>
    </Card>
  );
}
