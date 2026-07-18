import { Pagination, Form } from "react-bootstrap";
import { useCallback, useState, useEffect } from "react";
import { getApi } from "../axios";
import { errorToString } from "../utils/error";

export default function Paginator({
  setError,
  isLoading,
  setIsLoading,
  filters,
  items,
  setItems,
  apiPath,
  orderCol = "updatedAt",
  idCol = "name",
}) {
  const [cursorStack, setCursorStack] = useState([null]);
  const [pageSize, setPageSize] = useState(20);
  const [hasMore, setHasMore] = useState(false);

  const api = getApi();

  // Fetch items with current cursor from stack
  const fetchItems = useCallback(
    async (stackToUse) => {
      setIsLoading(true);
      setError(null);

      // Use the provided stack or current stack
      const currentCursor = stackToUse[stackToUse.length - 1] || null;

      try {
        const params = new URLSearchParams(filters);
        params.set("pageSize", pageSize);
        if (currentCursor) {
          params.set("cursor", currentCursor);
        }

        const res = await api.get(`${apiPath}?${params.toString()}`);
        const { data, nextCursor, hasMore } = res.data;

        setItems(data);
        setHasMore(hasMore);
      } catch (err) {
        setError(errorToString(err));
      } finally {
        setIsLoading(false);
      }
    },
    [api, filters, pageSize, setIsLoading, apiPath, orderCol, idCol],
  );

  // Fetch when filters or pageSize change
  useEffect(() => {
    const newStack = [null];
    setCursorStack(newStack);
    fetchItems(newStack);
  }, [filters, pageSize, fetchItems]);

  const handleNextPage = () => {
    if (!hasMore || items.length === 0) return;
    const s = items[items.length - 1];
    const nextCursor = `${s[orderCol]}|${s[idCol]}`;
    const newStack = [...cursorStack, nextCursor];
    setCursorStack(newStack);
    fetchItems(newStack);
  };

  const handlePreviousPage = () => {
    if (cursorStack.length <= 1) return;
    const newStack = cursorStack.slice(0, -1);
    setCursorStack(newStack);
    fetchItems(newStack);
  };

  return (
    <div className="d-flex justify-content-end align-items-center gap-2">
      <Pagination className="m-0">
        <Pagination.Prev
          disabled={cursorStack.length <= 1}
          onClick={handlePreviousPage}
        />
        <Pagination.Item active disabled>
          Page {cursorStack.length}
        </Pagination.Item>
        <Pagination.Next disabled={!hasMore} onClick={handleNextPage} />
      </Pagination>
      <Form.Select
        className="m-0 w-auto"
        value={pageSize}
        onChange={(e) => {
          setPageSize(Number(e.target.value));
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
