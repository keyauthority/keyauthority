import { useCallback, useState, useEffect } from "react";
import { Alert, Table } from "react-bootstrap";
import { Link } from "react-router-dom";
import { getApi } from "../axios";
import Paginator from "./Paginator";
import { prettyTime, prettyEnv } from "../utils/utils";
import Filters from "./Filters";

export default function Signers({ isLoading, setIsLoading }) {
  const [error, setError] = useState(null);
  const [signers, setSigners] = useState([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [totalCount, setTotalCount] = useState(0);
  const [filters, setFilters] = useState({});

  const api = getApi();

  const fetchSigners = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value) params.append(key, value);
      });
      params.append("page", page);
      params.append("pageSize", pageSize);

      const res = await api.get(`/signers?${params.toString()}`);
      setSigners(res.data.data || []);
      setTotalCount(res.data.totalCount || 0);
    } catch (err) {
      setError(err.message || "Failed to fetch signers");
    } finally {
      setIsLoading(false);
    }
  }, [api, page, pageSize, filters, setIsLoading]);

  useEffect(() => {
    fetchSigners();
  }, [fetchSigners]);

  return (
    <>
      {error && <Alert variant="danger">{error}</Alert>}

      <Filters
        filters={filters}
        setFilters={setFilters}
        cols={{ xs: 12, md: 4 }}
        filtersTemplate={[
          {
            key: "name",
            type: "text",
            label: "Name",
            placeholder: "e.g. signer1",
            value: filters.name,
          },
          {
            key: "environment",
            type: "text",
            label: "Environment",
            placeholder: "e.g. dev, staging, prod",
            value: filters.environment,
          },
          {
            key: "privateKeyID",
            type: "text",
            label: "Private Key ID",
            placeholder: "e.g. 1234-5678-9012",
            value: filters.privateKeyID,
          },
        ]}
      />

      <Table striped hover className="mb-3">
        <thead>
          <tr>
            <th>Name</th>
            <th>Environment</th>
            <th>Common Name</th>
            {/* <th>Is Root</th> */}
            <th>Private Key ID</th>
            <th>Last Updated</th>
          </tr>
        </thead>
        <tbody>
          {signers.map((signer, idx) => (
            <tr key={idx}>
              <td>
                <Link
                  to={`/signers/${encodeURIComponent(signer.name)}`}
                  //className="fw-medium"
                >
                  {signer.name}
                </Link>
              </td>
              <td>{prettyEnv(signer.environment)}</td>
              <td>{signer.config.caTemplate?.subject?.commonName || "-"}</td>
              {/* <td>
                {signer.config.isCA ? (
                  <>
                    <i className="bi bi-check-circle me-1"></i>Yes
                  </>
                ) : (
                  <>
                    <i className="bi bi-x-circle me-1"></i>No
                  </>
                )}
              </td> */}
              {/* <td>{shortUUID(signer.privateKeyID)}</td> */}
              <td>{signer.privateKeyID}</td>
              <td>{prettyTime(signer.updatedAt)}</td>
            </tr>
          ))}
        </tbody>
      </Table>

      <Paginator
        page={page}
        setPage={setPage}
        pageSize={pageSize}
        setPageSize={setPageSize}
        totalCount={totalCount}
      />
    </>
  );
}
