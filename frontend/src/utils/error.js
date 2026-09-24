import { Link } from "react-router-dom";

export function errorToString(err, fallback = "An unexpected error occurred.") {
  if (!err) return fallback;

  // handle forbidden error
  if (err.response && err.response.status === 403) {
    return (
      <span>
        Insufficient permissions, contact your administrator. Visit this{" "}
        <Link to="/docs/admin">guide</Link> to know more.
      </span>
    );
  }

  // Axios-style error with server response
  if (err.response?.data) {
    const data = err.response.data;

    // try parsing JSON error message
    const msg = extractErrorMessage(data);
    if (msg) return msg;

    // Fallback to HTTP status text
    if (err.response.statusText)
      return `${err.response.status} ${beautify(err.response.statusText)}`;
    return fallback;
  }

  // Network or JS errors
  if (err.message) {
    return beautify(err.message);
  }

  return fallback;
}

function beautify(str) {
  if (!str || str.length === 0) return str;
  str = ("" + str).trim();
  try {
    str = str.charAt(0).toUpperCase() + str.slice(1);
    // add a period at the end if missing
    if (!str.endsWith(".")) str += ".";
    return str;
  } catch {
    return str;
  }
}

function extractErrorMessage(data) {
  if (!data) return null;
  const text = (typeof data === "string" ? data : "" + data).trim();
  if (!text) return null;

  if (data.errors && Array.isArray(data.errors)) {
    return beautify(data.errors.join(": "));
  }
  if (data.error && typeof data.error === "string") {
    return beautify(data.error);
  }
  if (data.message && typeof data.message === "string") {
    return beautify(data.message);
  }

  // Try to parse JSON
  try {
    const parsed = JSON.parse(text);
    if (parsed.errors && Array.isArray(parsed.errors)) {
      return beautify(parsed.errors.join(": "));
    }
    if (parsed.message) return beautify(parsed.message);
    if (parsed.error) return beautify(parsed.error);
  } catch {}
  return null;
}
