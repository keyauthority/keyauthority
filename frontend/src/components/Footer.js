import { useEffect, useState, useCallback } from "react";
import { appVersion } from "../version";
import { getApi } from "../axios";
import { Col } from "react-bootstrap";

const Footer = () => {
  const [backendData, setBackendData] = useState({
    version: "unknown",
    enterprise: false,
  });
  const api = getApi();

  const getBackendData = useCallback(async () => {
    try {
      const res = await api.get("/health");
      setBackendData(res.data || { version: "unknown", enterprise: false });
    } catch {}
  }, [api]);

  useEffect(() => {
    getBackendData();
  }, [getBackendData]);

  return (
    <>
      <Col md={3} lg={2} data-bs-theme="dark" className="bg-dark-subtle" />
      <Col
        md={9}
        lg={10}
        className="text-muted small border-top d-flex justify-content-center gap-4 px-md-5 py-2 mt-5"
      >
        <span>
          Backend: {backendData.version}
          {backendData.enterprise && " Enterprise"}
        </span>
        <span>Frontend: {appVersion}</span>
        <span>© {new Date().getFullYear()} KeyAuthority</span>
      </Col>
    </>
  );
};

export default Footer;
