import { useState, useEffect } from "react";
import { Button, Modal, Form } from "react-bootstrap";
import { prettyCode } from "../utils/utils";

export default function JWKSModal({ show, onHide }) {
  const [mergedJWKS, setMergedJWKS] = useState(null);
  const [loading, setLoading] = useState(false);
  const [jwksEntries, setJWKSEntries] = useState([{ url: "", json: "" }]);
  const [entryStatuses, setEntryStatuses] = useState([
    { state: "idle", message: "" },
  ]);

  const mergeJWKS = async (entries) => {
    const mergedKeys = [];
    const seenKids = new Set();
    const statuses = entries.map(() => ({ state: "idle", message: "" }));

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      let jwks;

      if (!entry.url && !entry.json) {
        statuses[i] = { state: "idle", message: "" };
        continue;
      }

      if (entry.url) {
        try {
          const response = await fetch(entry.url);
          if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
          }
          jwks = await response.json();
        } catch (error) {
          statuses[i] = {
            state: "error",
            message: `Fetch failed: ${error.message}`,
          };
          continue;
        }
      } else if (entry.json) {
        try {
          jwks = JSON.parse(entry.json);
        } catch (error) {
          statuses[i] = { state: "error", message: "Invalid JSON" };
          continue;
        }
      }

      if (jwks && Array.isArray(jwks.keys)) {
        mergedKeys.push(
          ...jwks.keys.filter((key) => {
            if (seenKids.has(key.kid)) {
              return false;
            }
            seenKids.add(key.kid);
            return true;
          }),
        );
        statuses[i] = {
          state: "success",
          message: `Merged ${jwks.keys.length} key(s)`,
        };
      } else {
        statuses[i] = { state: "error", message: 'Missing "keys" array' };
      }
    }

    return { merged: { keys: mergedKeys }, statuses };
  };

  useEffect(() => {
    if (!show) {
      setMergedJWKS(null);
      setJWKSEntries([{ url: "", json: "" }]);
      setEntryStatuses([{ state: "idle", message: "" }]);
    }
  }, [show]);

  useEffect(() => {
    let cancelled = false;

    const fetchAndMergeJWKS = async () => {
      setLoading(true);
      setEntryStatuses(
        jwksEntries.map((e) =>
          e.url || e.json
            ? { state: "loading", message: "Merging..." }
            : { state: "idle", message: "" },
        ),
      );

      const { merged, statuses } = await mergeJWKS(jwksEntries);

      if (cancelled) return;
      setMergedJWKS(merged);
      setEntryStatuses(statuses);
      setLoading(false);
    };

    fetchAndMergeJWKS();

    return () => {
      cancelled = true;
    };
  }, [jwksEntries]);

  return (
    <Modal show={show} onHide={onHide}>
      <Modal.Header closeButton>
        <Modal.Title className="text-truncate">Merge Multiple JWKS</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {jwksEntries.map((entry, index) => {
          const status = entryStatuses[index]?.state;
          const message = entryStatuses[index]?.message || "";

          return (
            <div key={index} className="mb-3 d-flex align-items-center gap-2">
              <Form.Control
                placeholder="Enter JWKS URL or JSON string"
                id={`jwks-url-${index}`}
                value={entry.url || entry.json}
                onChange={(e) => {
                  const newEntries = [...jwksEntries];
                  if (e.target.value.trim().startsWith("{")) {
                    newEntries[index].json = e.target.value;
                    newEntries[index].url = "";
                  } else if (
                    e.target.value.trim().startsWith("http") ||
                    e.target.value.trim().startsWith("https")
                  ) {
                    newEntries[index].url = e.target.value;
                    newEntries[index].json = "";
                  } else {
                    newEntries[index].url = "";
                    newEntries[index].json = e.target.value;
                  }
                  setJWKSEntries(newEntries);
                }}
              />

              <div title={message} aria-label={message}>
                {status === "loading" && (
                  <span
                    className="spinner-border spinner-border-sm text-primary"
                    role="status"
                    aria-hidden="true"
                  ></span>
                )}
                {status === "success" && (
                  <i className="bi bi-check-circle-fill text-success"></i>
                )}
                {status === "error" && (
                  <i className="bi bi-x-circle-fill text-danger"></i>
                )}
                {status === "idle" && (
                  <i className="bi bi-dash-circle text-muted invisible"></i>
                )}
              </div>
            </div>
          );
        })}

        <Button
          variant="outline-primary"
          onClick={() =>
            setJWKSEntries([...jwksEntries, { url: "", json: "" }])
          }
        >
          <i className="bi bi-plus-lg"></i> Add
        </Button>

        {mergedJWKS?.keys.length > 0 && (
          <div className="mt-4">
            <h6>
              Merged JWKS{" "}
              {loading && (
                <span
                  className="spinner-border spinner-border-sm"
                  role="status"
                  aria-hidden="true"
                ></span>
              )}
            </h6>
            {prettyCode("json", mergedJWKS)}
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
}
