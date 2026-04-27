import React from "react";
import { Table } from "react-bootstrap";

export default function KeyValueTable({
  body,
  header,
  borderBottom = false,
  keysClass = "",
  keysTag = "",
  minKeyLen = -1,
}) {
  // Helper to pad key with non-breaking spaces if too short
  function padKey(key, minLen) {
    const strKey = String(key);
    if (minLen < 0) return String(key);
    if (strKey.length >= minLen) return strKey;
    return strKey + "\u00A0".repeat(minLen - strKey.length);
  }

  return (
    <Table
      responsive
      className={`keyvalue-table ${borderBottom ? "border-bottom" : ""}`}
    >
      {header && (
        <thead>
          <tr>
            {header.map((h, idx) => (
              <th key={idx}>{h}</th>
            ))}
          </tr>
        </thead>
      )}
      <tbody>
        {Object.entries(body).map(
          ([key, value]) =>
            value !== null &&
            value !== undefined && (
              <tr key={key}>
                <td className={keysClass}>
                  {keysTag
                    ? React.createElement(keysTag, {}, padKey(key, minKeyLen))
                    : padKey(key, minKeyLen)}
                </td>
                <td>{value}</td>
              </tr>
            ),
        )}
      </tbody>
    </Table>
  );
}
