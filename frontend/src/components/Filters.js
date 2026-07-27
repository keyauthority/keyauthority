import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  Row,
  CloseButton,
} from "react-bootstrap";

/*

filtersTemplate input example:
{
  key: "name",
  type: "text", // can be "text", "select", "date", etc.
  placeholder: "Name...",
  label: "Name",
  options: [{ value: "", label: "All" }], // for select
}

filters, setFilters: state and setter for filters object (for parent component to react to filter changes)

*/

export default function Filters({ filters, setFilters, filtersTemplate }) {
  const hasValue = (v) => v !== undefined && v !== null && v !== "";

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

  const appliedEntries = useMemo(
    () => Object.entries(filters || {}).filter(([, v]) => hasValue(v)),
    [filters],
  );

  const appliedKeys = useMemo(
    () => new Set(appliedEntries.map(([k]) => k)),
    [appliedEntries],
  );

  const availableFilters = useMemo(
    () => (filtersTemplate || []).filter((f) => !appliedKeys.has(f.key)),
    [filtersTemplate, appliedKeys],
  );

  const [selectedFilterKey, setSelectedFilterKey] = useState(
    availableFilters[0]?.key ?? "",
  );
  const [draftValue, setDraftValue] = useState("");

  useEffect(() => {
    if (!availableFilters.length) {
      setSelectedFilterKey("");
      setDraftValue("");
      return;
    }

    const exists = availableFilters.some((f) => f.key === selectedFilterKey);
    if (!exists) {
      setSelectedFilterKey(availableFilters[0].key);
      setDraftValue("");
    }
  }, [availableFilters, selectedFilterKey]);

  const selectedFilter = useMemo(
    () => (filtersTemplate || []).find((f) => f.key === selectedFilterKey),
    [filtersTemplate, selectedFilterKey],
  );

  const applyOneFilter = () => {
    if (!selectedFilter) return;

    const raw = draftValue;
    const normalized =
      selectedFilter.type === "date" ? toRFC3339(raw) : (raw ?? "");

    if (!hasValue(normalized)) return;

    setFilters((prev) => ({
      ...(prev || {}),
      [selectedFilter.key]: normalized,
    }));
    setDraftValue("");
  };

  const removeFilter = (key) => {
    setFilters((prev) => {
      const next = { ...(prev || {}) };
      delete next[key];
      return next;
    });
  };

  const clearAll = () => {
    setFilters({});
    setDraftValue("");
  };

  const getFilterByKey = (key) => filtersTemplate.find((f) => f.key === key);

  const getDisplayValue = (filter, value) => {
    if (!filter) return String(value ?? "");
    if (filter.type === "select") {
      const opt = (filter.options || []).find((o) => o.value === value);
      return opt?.label ?? String(value);
    }
    if (filter.type === "date") {
      const d = new Date(value);
      return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
    }
    return String(value ?? "");
  };

  return (
    <Row className={`mb-3 ${appliedEntries?.length > 0 ? "g-3" : "g-0"}`}>
      <Col>
        <div className="input-group">
          <Form.Select
            value={selectedFilterKey}
            onChange={(e) => {
              setSelectedFilterKey(e.target.value);
              setDraftValue("");
            }}
            className="input-group-text"
            style={{ maxWidth: "15rem" }}
            disabled={!availableFilters.length}
          >
            {availableFilters.length === 0 ? (
              <option value="">No filters available</option>
            ) : (
              availableFilters.map((f) => (
                <option key={f.key} value={f.key}>
                  {f.label}
                </option>
              ))
            )}
          </Form.Select>
          {!selectedFilter && (
            <Form.Control
              type="text"
              value={draftValue}
              //placeholder="No filter selected"
              disabled
            />
          )}
          {selectedFilter?.type === "text" && (
            <Form.Control
              type="text"
              value={draftValue}
              placeholder={selectedFilter.placeholder}
              onChange={(e) => setDraftValue(e.target.value)}
            />
          )}

          {selectedFilter?.type === "select" && (
            <Form.Select
              value={draftValue}
              onChange={(e) => setDraftValue(e.target.value)}
            >
              {(selectedFilter.options || []).map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Form.Select>
          )}

          {selectedFilter?.type === "date" && (
            <Form.Control
              type="datetime-local"
              value={toDateTimeLocal(draftValue)}
              onChange={(e) => setDraftValue(e.target.value)}
            />
          )}
          <Button
            variant="secondary"
            onClick={applyOneFilter}
            disabled={!selectedFilter || !hasValue(draftValue)}
          >
            <i className="bi bi-funnel me-1"></i>Apply
          </Button>
        </div>
      </Col>
      <Col xs="auto">
        {appliedEntries?.length > 0 && (
          <div className="d-flex flex-wrap align-items-center gap-2">
            {appliedEntries.map(([key, value]) => {
              const def = getFilterByKey(key);
              return (
                <Alert
                  key={key}
                  variant="light"
                  className="px-3 py-2 d-flex align-items-center gap-2 m-0"
                >
                  <span>
                    <strong>{def?.label || key}:</strong>{" "}
                    {getDisplayValue(def, value)}
                  </span>
                  <CloseButton
                    className="small m-0 p-0"
                    onClick={() => removeFilter(key)}
                  />
                </Alert>
              );
            })}
          </div>
        )}
      </Col>
    </Row>
  );
}
