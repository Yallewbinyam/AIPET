/**
 * threat_intel API client — all calls to /api/threatintel/*
 * Each function accepts `token` as first arg and returns a Promise.
 */
import axios from "axios";

const BASE = "http://localhost:5001/api/threatintel";
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

export const getStats      = (token)           => call("get",  `${BASE}/stats`,                      token);
export const getRecentIocs = (token, limit=50) => call("get",  `${BASE}/iocs/recent?limit=${limit}`, token);
export const syncNow       = (token)           => call("post", `${BASE}/sync_now`,                   token, {});
export const getSyncStatus = (token, taskId)   => call("get",  `${BASE}/sync_status/${taskId}`,      token);
export const checkHost     = (token, hostIp)   => call("post", `${BASE}/check_host`,                 token, { host_ip: hostIp });
