import { Pagination, Form } from "react-bootstrap";

export default function Paginator({
  page,
  setPage,
  pageSize,
  setPageSize,
  totalCount,
}) {
  return (
    <div className="d-flex justify-content-end align-items-center gap-2">
      <Pagination className="m-0">
        <Pagination.First disabled={page === 1} onClick={() => setPage(1)} />
        <Pagination.Prev
          disabled={page === 1}
          onClick={() => setPage((p) => Math.max(1, p - 1))}
        />
        <Pagination.Item active disabled>
          Page {page}
          {" of "}
          {Math.max(1, Math.ceil(totalCount / pageSize))}
        </Pagination.Item>
        <Pagination.Next
          disabled={page >= Math.ceil(totalCount / pageSize)}
          onClick={() => setPage((p) => p + 1)}
        />
        <Pagination.Last
          disabled={page >= Math.ceil(totalCount / pageSize)}
          onClick={() => setPage(Math.ceil(totalCount / pageSize))}
        />
      </Pagination>
      <Form.Select
        className="m-0 w-auto"
        value={pageSize}
        onChange={(e) => {
          setPageSize(Number(e.target.value));
          setPage(1);
        }}
      >
        {[20, 50, 100].map((size) => (
          <option key={size} value={size}>
            {size}
          </option>
        ))}
      </Form.Select>
    </div>
  );
}
