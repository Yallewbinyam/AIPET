/**
 * Central Events API client — all calls to /api/events/*
 */
import axios from "axios";

const BASE = "http://localhost:5001/api/events";
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

export const getEventFeed    = (token, params = {}) => {
  const qs = new URLSearchParams(params).toString();
  return call("get", `${BASE}/feed${qs ? "?" + qs : ""}`, token);
};
export const getEventStats   = (token, days = 7)   => call("get",  `${BASE}/stats?days=${days}`, token);
export const getEvent        = (token, id)          => call("get",  `${BASE}/${id}`,              token);
export const getEntityEvents = (token, entity, days) =>
  call("get", `${BASE}/entity/${encodeURIComponent(entity)}?days=${days}`, token);
