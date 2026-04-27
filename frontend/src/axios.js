import axios from "axios";
import { getKeycloak } from "./keycloak";

let api = null;

export const createApi = async () => {
  if (!api) {
    const config = await fetch("/config/axios.json").then((res) => res.json());
    api = axios.create(config);

    api.interceptors.request.use((conf) => {
      const keycloak = getKeycloak();
      if (keycloak?.token) {
        conf.headers.Authorization = `Bearer ${keycloak.token}`;
      }
      return conf;
    });

    api.interceptors.response.use(
      (response) => response,
      (error) => {
        // Handle 401
        if (error.response && error.response.status === 401) {
          const keycloak = getKeycloak();
          if (keycloak) {
            keycloak.logout({ redirectUri: window.location.origin });
          }
        }
        return Promise.reject(error);
      },
    );
  }
};

export const getApi = () => api;
