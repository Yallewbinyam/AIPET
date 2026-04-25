/**
 * MITRE ATT&CK API client — all calls to /api/mitre/*
 */
import axios from "axios";

const BASE = "http://localhost:5001/api/mitre";
const TIMEOUT = 30000;

function headers(token) {
  return { Authorization: `Bearer ${token}` };
}

async function call(method, url, token, data) {
  try {
    const res = await axios({ method, url, headers: headers(token), data, timeout: TIMEOUT });
    return res.data;
  } catch (err) {
    const status = err.response?.status ?? 0;
    const msg    = err.response?.data?.error ?? err.message ?? "Request failed";
    throw Object.assign(new Error(`[${status}] ${msg}`), { status });
  }
}

export const getTechniques     = (token, ids)  => call("get",  ids ? `${BASE}/techniques?ids=${ids}` : `${BASE}/techniques`, token);
export const getTechnique      = (token, id)   => call("get",  `${BASE}/techniques/${id}`, token);
export const getMitreStats     = (token)       => call("get",  `${BASE}/stats`, token);
export const mapDetection      = (token, body) => call("post", `${BASE}/map_detection`, token, body);
