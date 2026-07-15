import { useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { getKeycloak } from "./keycloak";
import Main from "./components/Main";

function App() {
  const keycloak = getKeycloak();

  useEffect(() => {
    // document title
    document.title =
      keycloak.realm.charAt(0).toUpperCase() +
      keycloak.realm.slice(1) +
      " | KeyAuthority";

    // set theme as per user preference
    const prefersDarkScheme = window.matchMedia(
      "(prefers-color-scheme: dark)",
    ).matches;
    document.documentElement.setAttribute(
      "data-bs-theme",
      prefersDarkScheme ? "dark" : "light",
    );

    // auto-logout
    const idleTimeout = 5 * 60 * 1000; // 5 minutes
    const events = [
      "mousemove",
      "keydown",
      "scroll",
      "click",
      "touchstart",
      "touchmove",
      "touchend",
      "wheel",
      "pointermove",
      "pointerdown",
      "pointerup",
    ];
    let timeoutRef = setTimeout(logout, idleTimeout);

    function resetTimer() {
      clearTimeout(timeoutRef);
      timeoutRef = setTimeout(logout, idleTimeout);
    }

    function logout() {
      keycloak.logout();
    }

    events.forEach((event) => window.addEventListener(event, resetTimer));

    return () => {
      clearTimeout(timeoutRef);
      events.forEach((event) => window.removeEventListener(event, resetTimer));
    };
  }, [keycloak]);

  if (!keycloak) return null;

  return (
    <Routes>
      <Route path="/" element={<Navigate to="/docs/architecture" />} />
      <Route path="*" element={<Main />} />
    </Routes>
  );
}

export default App;
