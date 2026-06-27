import { useEffect, useState } from "react";
import { Button, Card, Col, Form, Row } from "react-bootstrap";

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
  const [draftFilters, setDraftFilters] = useState({ ...filters });

  useEffect(() => {
    setDraftFilters({ ...filters });
  }, [filters]);

  const safeColsPerRow =
    Number.isInteger(colsPerRow) && colsPerRow > 0 ? colsPerRow : 4;

  const baseSpan = 12 / safeColsPerRow;
  const supportsFill = Number.isInteger(baseSpan); // exact fill only when colsPerRow divides 12
  const remainder = supportsFill ? filtersTemplate.length % safeColsPerRow : 0;

  const toRFC3339 = (value) => {
    if (!value) return "";
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? value : d.toISOString();
  };

  const toDateTimeLocal = (value) => {
    if (!value) return "";
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return value;

    const pad = (n) => String(n).padStart(2, "0");
    const yyyy = d.getFullYear();
    const mm = pad(d.getMonth() + 1);
    const dd = pad(d.getDate());
    const hh = pad(d.getHours());
    const mi = pad(d.getMinutes());
    return `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
  };

  return (
    <Card className="mb-3">
      <Card.Header>
        <div className="d-flex justify-content-between align-items-center gap-2">
          <h6 className="mb-0">Filters</h6>
          <div className="d-flex gap-2 align-items-center">
            {/* Show how many filters are applied */}
            {Object.keys(filters).filter((key) => filters[key]).length > 0 && (
              <span className="text-muted">
                {Object.keys(filters).filter((key) => filters[key]).length}{" "}
                filter(s) applied
              </span>
            )}
            <Button
              variant="outline-secondary"
              size="sm"
              onClick={() => setFilters({ ...draftFilters })}
              //disabled={Object.keys(draftFilters).every((key) => draftFilters[key] === filters[key])}
            >
              <i className="bi bi-funnel"></i> Apply
              {/*{" "}
              {
                Object.keys(draftFilters).filter((key) => draftFilters[key])
                  .length
              }{" "}
              of {filtersTemplate.length}*/}
            </Button>
            <Button
              variant="outline-secondary"
              size="sm"
              onClick={() => {
                setDraftFilters({});
                setFilters({});
              }}
            >
              <i className="bi bi-x-lg"></i> Clear
            </Button>
          </div>
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
                        value={draftFilters[filter.key] ?? ""}
                        placeholder={filter.placeholder}
                        onChange={(e) =>
                          setDraftFilters((prev) => ({
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
                        value={draftFilters[filter.key] ?? ""}
                        onChange={(e) =>
                          setDraftFilters((prev) => ({
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
                        value={toDateTimeLocal(draftFilters[filter.key] ?? "")}
                        onChange={(e) =>
                          setDraftFilters((prev) => ({
                            ...prev,
                            [filter.key]: toRFC3339(e.target.value),
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
