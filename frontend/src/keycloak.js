import Keycloak from "keycloak-js";

let keycloakInstance = null;

export const initKeycloak = async () => {
  if (!keycloakInstance) {
    const config = await fetch("/config/keycloak.json").then((res) =>
      res.json(),
    );

    keycloakInstance = new Keycloak({
      url: config.url,
      realm: config.realm,
      clientId: config.clientId,
    });

    await keycloakInstance.init({
      onLoad: "login-required",
      pkceMethod: "S256",
    });

    // auto-refresh token every 60 seconds
    setInterval(() => {
      if (keycloakInstance.token) {
        keycloakInstance
          .updateToken(60)
          .then((refreshed) => {
            if (refreshed) {
              //console.log("Token refreshed");
            }
          })
          .catch(() => {
            //console.warn("Token refresh failed — logging out");
            keycloakInstance.logout();
          });
      }
    }, 60000); // 60 seconds
  }

  return keycloakInstance;
};

export const getKeycloak = () => keycloakInstance;
