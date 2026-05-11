import React, { useState, useEffect } from "react";
import { toast } from "react-toastify";
import {
  Button,
  Alert,
  Tab,
  Table,
  OverlayTrigger,
  Tooltip,
} from "react-bootstrap";
import { X509Certificate } from "@peculiar/x509";

import { Light as SyntaxHighlighter } from "react-syntax-highlighter";
import {
  atomOneLight,
  atomOneDark,
} from "react-syntax-highlighter/dist/esm/styles/hljs";
import json from "react-syntax-highlighter/dist/esm/languages/hljs/json";
import yaml from "react-syntax-highlighter/dist/esm/languages/hljs/yaml";
import bash from "react-syntax-highlighter/dist/esm/languages/hljs/bash";

SyntaxHighlighter.registerLanguage("json", json);
SyntaxHighlighter.registerLanguage("yaml", yaml);
SyntaxHighlighter.registerLanguage("bash", bash);

export const isDarkMode =
  document.documentElement.getAttribute("data-bs-theme") === "dark";

/*export function showLoadingToast(content) {
  const id = "loading-toast"; // new Date().getTime();
  toast.loading(content, {
    //position: "top-center",
    autoClose: false,
    closeOnClick: false,
    draggable: false,
    closeButton: false,
    toastId: id,
  });
  return {
    dismiss: () => toast.dismiss(id),
  };
}*/

export function showToast(type, content, autoClose = "auto", options = {}) {
  // Calculate autoClose time based on content length
  let calculatedAutoClose;

  if (autoClose === "auto") {
    // Get the text content length
    let textLength;
    if (typeof content === "string") {
      textLength = content.length;
    } else if (React.isValidElement(content)) {
      // For React elements, try to extract text content
      textLength = extractTextContent(content).length;
    } else {
      // Fallback for other types
      textLength = String(content).length;
    }

    // Calculate autoClose time
    // Base time: 2 seconds
    // Additional time: 50ms per character
    // Minimum: 2 seconds, Maximum: 10 seconds
    const baseTime = 2000;
    const timePerChar = 50;
    const maxTime = 10000;

    calculatedAutoClose = Math.min(
      Math.max(baseTime, baseTime + textLength * timePerChar),
      maxTime,
    );
  } else if (autoClose === "never") {
    calculatedAutoClose = false;
  } else {
    calculatedAutoClose = autoClose;
  }

  toast[type](content, {
    theme: isDarkMode ? "dark" : "light",
    autoClose: calculatedAutoClose,
    ...options,
  });
}

// Helper function to extract text content from React elements
function extractTextContent(element) {
  if (typeof element === "string") {
    return element;
  }

  if (typeof element === "number") {
    return String(element);
  }

  if (React.isValidElement(element)) {
    if (element.props.children) {
      if (Array.isArray(element.props.children)) {
        return element.props.children.map(extractTextContent).join("");
      } else {
        return extractTextContent(element.props.children);
      }
    }
  }

  return "";
}

export function parsePem(pem) {
  const cert = new X509Certificate(pem);
  return {
    serial: cert.serialNumber.replace(/^0+/, ""), // remove leading zeros
    subject: cert.subject,
    issuer: cert.issuer,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
    pem: pem,
  };
}

export function parseChain(data) {
  const pemCerts = data
    .split(/(?=-----BEGIN CERTIFICATE-----)/)
    .map((pem) => pem.trim())
    .filter((pem) => pem.startsWith("-----BEGIN CERTIFICATE-----"));

  //return pemCerts.map((pem) => pemToHtml(pem, true));
  return pemCerts.map((pem) => parsePem(pem));
}

export function breakLines(text, maxLineLength) {
  const regex = new RegExp(`(.{1,${maxLineLength}})`, "g");
  return text.match(regex).join("\n");
}

export function downloadOrCopy(successMsg, data, filename, classes = "") {
  const dataIsEmpty = !data || data.length === 0;
  const dataIsBlob = data && data instanceof Blob;

  if (dataIsEmpty || dataIsBlob) {
    return (
      <Alert variant="success" className={classes}>
        {successMsg}
      </Alert>
    );
  }

  return (
    <Alert
      variant="success"
      className={`d-flex justify-content-between align-items-center ${classes}`}
    >
      <span>{successMsg}</span>
      <div>
        <Button
          size="sm"
          variant="outline-secondary"
          onClick={() => {
            copyToClipboard(data, "Copied to clipboard!");
          }}
        >
          <i className="bi bi-clipboard"></i>
        </Button>
        <Button
          variant="outline-secondary"
          size="sm"
          className="ms-2"
          onClick={() => {
            const blob = new Blob([data], { type: "text/plain" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
          }}
        >
          <i className="bi bi-download"></i>
        </Button>
      </div>
    </Alert>
  );
}

export function prettyTime(isoString) {
  const date = new Date(isoString);
  const isToday = (date) => {
    const today = new Date();
    return (
      date.getDate() === today.getDate() &&
      date.getMonth() === today.getMonth() &&
      date.getFullYear() === today.getFullYear()
    );
  };
  const isYesterday = (date) => {
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    return (
      date.getDate() === yesterday.getDate() &&
      date.getMonth() === yesterday.getMonth() &&
      date.getFullYear() === yesterday.getFullYear()
    );
  };

  // if today
  if (isToday(date)) {
    return (
      "Today, " +
      date.toLocaleString([], {
        hour: "2-digit",
        minute: "2-digit",
      })
    );
  }
  // if yesterday
  if (isYesterday(date)) {
    return (
      "Yesterday, " +
      date.toLocaleString([], {
        hour: "2-digit",
        minute: "2-digit",
      })
    );
  }

  return date.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function prettyCode(language, code, copyButton = true) {
  let codeString = code;
  if (language === "json") {
    try {
      codeString = JSON.stringify(code, null, 2);
    } catch (e) {
      codeString = code;
    }
  }

  return (
    <div className="position-relative">
      <SyntaxHighlighter
        language={language}
        style={isDarkMode ? atomOneDark : atomOneLight}
        className="rounded p-2"
      >
        {codeString}
      </SyntaxHighlighter>
      {copyButton && (
        <Button
          variant="outline-secondary"
          size="sm"
          className="position-absolute top-0 end-0 m-2"
          onClick={() => {
            copyToClipboard(codeString, "Code copied!");
          }}
          title="Copy to clipboard"
        >
          <i className="bi bi-clipboard"></i>
        </Button>
      )}
    </div>
  );
}

export function disclaimer() {
  return (
    <Alert variant="info">
      <Alert.Heading className="fs-6 fw-bold">Disclaimer</Alert.Heading>
      This product partially implements a HashiCorp Vault-compatible API.
      HashiCorp Vault, Vault Agent (injector), and the <code>vault</code> CLI
      are trademarks of HashiCorp, Inc. This project is not affiliated with or
      endorsed by HashiCorp.
    </Alert>
  );
}

export function getDefaultPkcs11URIs() {
  return {
    SoftHSM:
      "pkcs11:module-path=/usr/lib64/pkcs11/libsofthsm2.so;token=keyauthority?pin-source=/etc/softhsm/.pin",
    Primus:
      "pkcs11:module-path=/usr/local/primus/lib/libprimusP11.so;slot-id=0?pin-source=/etc/primus/.pin",
  };
}

export async function copyToClipboard(
  text,
  successMsg = "Copied to clipboard!",
) {
  // Try modern clipboard API first
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      showToast("success", successMsg);
    } catch (clipboardErr) {
      copyToClipboardFallback(text);
    }
  } else {
    // Fallback for older browsers
    copyToClipboardFallback(text);
  }
}

const copyToClipboardFallback = (text) => {
  // download instead of copy
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "clipboard.txt";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast(
    "warning",
    "Your browser doesn't support clipboard API at the moment. The content has been downloaded as clipboard.txt.",
  );
};

export const prettyEnv = (env) => boxedContent(env);

export const boxedContent = (content, variant = "secondary") => (
  <Alert
    variant={variant}
    className="px-2 py-0 m-0 d-inline-block text-truncate"
    style={{ maxWidth: "12rem" }}
  >
    {content}
  </Alert>
);

export const decryptData = async (encryptedData, password) => {
  // AES GCM decryption
  const combined = Uint8Array.from(atob(encryptedData), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12); // Extract IV (first 12 bytes)
  const salt = combined.slice(12, 28); // Extract salt (next 16 bytes)
  const encrypted = combined.slice(28); // Extract encrypted data (remaining bytes)

  const encoder = new TextEncoder();
  const encodedPassword = encoder.encode(password);

  // Use PBKDF2 to derive a 32-byte key from the password
  const pwd = await window.crypto.subtle.importKey(
    "raw",
    encodedPassword,
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    pwd,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encrypted,
  );
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
};

export const showImportResultToast = (succeeded, skipped, failed) => {
  showToast(
    "info",
    <div>
      <div>Import completed:</div>
      <div>
        <div className="d-flex gap-2">
          <i className="bi bi-check-circle text-success"></i> {succeeded.size}{" "}
          succeeded
          {succeeded.size > 0 ? `: ${Array.from(succeeded).join(", ")}` : ""}
        </div>
        <div className="d-flex gap-2">
          <i className="bi bi-exclamation-circle text-warning"></i>{" "}
          {skipped.size} skipped
          {skipped.size > 0 ? `: ${Array.from(skipped).join(", ")}` : ""}
        </div>
        <div className="d-flex gap-2">
          <i className="bi bi-x-circle text-danger"></i> {failed.size} failed
          {failed.size > 0 ? `: ${Array.from(failed).join(", ")}` : ""}
        </div>
      </div>
    </div>,
  );
};

export const getRoles = (token) => {
  const realmRoles = token?.realm_access?.roles || [];
  const clientRoles = Object.values(token?.resource_access || {}).flatMap(
    (res) => res.roles || [],
  );

  const allRoles = [...realmRoles, ...clientRoles];
  return allRoles.filter((role) => role.startsWith("KEYAUTHORITY_"));
};

export const withTooltipDescription = (title, description) => {
  const tooltipId = `tooltip-${String(title)
    .toLowerCase()
    .replaceAll(/[^a-z0-9]+/g, "-")}`;

  return (
    <div className="d-flex align-items-center gap-2">
      <div>{title}</div>
      {description ? (
        <div>
          <OverlayTrigger
            placement="top"
            overlay={<Tooltip id={tooltipId}>{description}</Tooltip>}
          >
            <span
              role="button"
              tabIndex={0}
              aria-label={description}
              className="text-muted small"
              //style={{ cursor: "help" }}
            >
              <i className="bi bi-question-circle"></i>
            </span>
          </OverlayTrigger>
        </div>
      ) : null}
    </div>
  );
};
