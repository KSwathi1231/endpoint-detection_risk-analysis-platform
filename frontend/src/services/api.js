import axios from "axios";

const API = axios.create({
  baseURL: "http://127.0.0.1:8000",
  headers: {
    "Content-Type": "application/json",
  },
});

export const getLatestEndpointAnalysis = () => {
  return API.get("/endpoint/latest");
};

export const getIncidents = () => {
  return API.get("/incidents/");
};
export const getLatestEndpoint = () => {
  return API.get("/endpoint/latest");
};

export default API;